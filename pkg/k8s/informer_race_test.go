package k8s

import (
	"sort"
	"sync"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TestInformer_InstanceTypeBackfill_NoRace reproduces the data race that an
// in-place InstanceType back-fill in onNode would create. pkg/idle and
// pkg/agent read fields off a *PodMeta returned by Lookup* WITHOUT holding
// inf.mu (e.g. pkg/idle/informer_source.go reads m.InstanceType after the
// RLock is released). If onNode mutates that already-published struct in place
// when the node is observed after the pod, the detector flags a
// write-after-publish race against those lock-free reads.
//
// The fix (replace-don't-mutate: onNode swaps in a fresh *PodMeta) makes every
// published *PodMeta write-once, so this passes under -race. Proof it actually
// catches the bug: reverting onNode to an in-place mutation makes this fail
// with `WARNING: DATA RACE` citing informer.go's onNode line. Run:
//
//	go test -race -run TestInformer_InstanceTypeBackfill_NoRace ./pkg/k8s/
func TestInformer_InstanceTypeBackfill_NoRace(t *testing.T) {
	inf := newTestInformer()

	// Pod observed BEFORE its node → InstanceType starts empty, the exact
	// ordering that triggers onNode's back-fill.
	inf.onPod(gpuPod("trainer", "ml", "gpu-node", 8, false))

	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "gpu-node",
			Labels: map[string]string{
				"topology.kubernetes.io/zone":      "us-east-1a",
				"node.kubernetes.io/instance-type": "p5.48xlarge",
			},
		},
	}

	const readers = 4
	var wg sync.WaitGroup
	stop := make(chan struct{})
	// Each reader writes ONLY its own slot — no shared write, so the only
	// memory the race detector can flag is the lock-free read of the product's
	// *PodMeta.InstanceType below (exactly the access we're testing). A shared
	// sink here would be a test-induced race that masks the real signal.
	seen := make([]string, readers)

	// Lock-free readers, mimicking pkg/idle / pkg/agent: fetch via Lookup*
	// (which RLocks only for the fetch) then read the field with no lock held.
	for r := 0; r < readers; r++ {
		r := r
		wg.Add(1)
		go func() {
			defer wg.Done()
			var last string
			for {
				select {
				case <-stop:
					seen[r] = last // own slot; observed after wg.Wait to defeat elision
					return
				default:
					if m := inf.LookupPodByName("ml", "trainer"); m != nil {
						last = m.InstanceType // the racing read against onNode's write
					}
				}
			}
		}()
	}

	// Writer: observe the node repeatedly so the back-fill runs while the
	// readers are live.
	for i := 0; i < 200; i++ {
		inf.onNode(node)
	}
	close(stop)
	wg.Wait()
	_ = seen // observed: keeps the field reads above from being optimized out

	// Correctness alongside race-safety: the back-fill must have converged.
	if m := inf.LookupPodByName("ml", "trainer"); m == nil || m.InstanceType != "p5.48xlarge" {
		got := "<nil>"
		if m != nil {
			got = m.InstanceType
		}
		t.Errorf("InstanceType after back-fill = %q, want p5.48xlarge", got)
	}
}

// TestInformer_LookupService_NoRaceWithSliceChurn reproduces the
// podIPToServices backing-array race: LookupService returns the map's slice
// itself, and pkg/agent's handlePoll reads its elements (svcs[0].ServiceName)
// AFTER the RLock is released. The old EndpointSlice paths mutated that
// published backing array in place — removeSliceLocked shifted survivors with
// append(seps[:i], seps[i+1:]...) and the add path appended into spare
// capacity — so slice churn could rewrite elements under a lock-free reader
// (torn read / wrong dst_service attribution).
//
// The fix (copy-on-write: every mutation builds a NEW slice and swaps the map
// value — the same replace-don't-mutate invariant the *PodMeta maps follow,
// see onNode) makes every published backing array write-once, so this passes
// under -race. Proof it actually catches the bug: reverting removeSliceLocked
// and the onEndpointSlice add path to in-place mutation makes this fail with
// `WARNING: DATA RACE` citing those informer.go lines. Run:
//
//	go test -race -run TestInformer_LookupService_NoRaceWithSliceChurn ./pkg/k8s/
func TestInformer_LookupService_NoRaceWithSliceChurn(t *testing.T) {
	inf := newTestInformer()

	const addr = "10.0.0.9"
	web := mkSlice("prod", "web-1", "web", 8080, addr)
	api := mkSlice("prod", "api-1", "api", 9090, addr)

	// Seed BOTH services on the same pod IP: with two entries in the list,
	// removing web's shifts api's entry down (an element write), and
	// re-adding web appends into the array's spare capacity (another write) —
	// the two in-place writes the old code performed on a published array.
	inf.onEndpointSlice(web)
	inf.onEndpointSlice(api)

	const readers = 4
	var wg sync.WaitGroup
	stop := make(chan struct{})
	// Each reader writes ONLY its own slot — no shared write, so the only
	// memory the race detector can flag is the lock-free element read below
	// (exactly the access we're testing).
	seen := make([]string, readers)

	// Lock-free readers, mimicking pkg/agent's handlePoll: fetch the slice via
	// LookupService (which RLocks only for the map fetch) then read its
	// elements with no lock held.
	for r := 0; r < readers; r++ {
		r := r
		wg.Add(1)
		go func() {
			defer wg.Done()
			var last string
			for {
				select {
				case <-stop:
					seen[r] = last // own slot; observed after wg.Wait to defeat elision
					return
				default:
					for _, se := range inf.LookupService(addr) {
						last = se.ServiceName // the racing read against slice churn
					}
				}
			}
		}()
	}

	// Writer: churn the web slice while readers are live. Each upsert removes
	// the slice's previous entry and re-adds it; the delete/re-add pair also
	// exercises removeSliceLocked's standalone path.
	for i := 0; i < 500; i++ {
		inf.onEndpointSlice(web)
		inf.onEndpointSliceDelete(web)
		inf.onEndpointSlice(web)
	}
	close(stop)
	wg.Wait()
	_ = seen // observed: keeps the element reads above from being optimized out

	// Correctness alongside race-safety: both services must still resolve
	// after the churn settles.
	var names []string
	for _, se := range inf.LookupService(addr) {
		names = append(names, se.ServiceName)
	}
	sort.Strings(names)
	if len(names) != 2 || names[0] != "api" || names[1] != "web" {
		t.Errorf("LookupService(%s) services = %v, want [api web]", addr, names)
	}
}
