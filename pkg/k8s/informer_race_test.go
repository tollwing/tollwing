package k8s

import (
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
