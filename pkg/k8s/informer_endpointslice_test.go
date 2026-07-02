package k8s

import (
	"context"
	"sort"
	"testing"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
)

// mkSlice builds an EndpointSlice for tests. svc == "" leaves the service
// label unset (an unmanaged slice).
func mkSlice(ns, name, svc string, port int32, addrs ...string) *discoveryv1.EndpointSlice {
	labels := map[string]string{}
	if svc != "" {
		labels[discoveryv1.LabelServiceName] = svc
	}
	endpoints := make([]discoveryv1.Endpoint, 0, len(addrs))
	for _, a := range addrs {
		endpoints = append(endpoints, discoveryv1.Endpoint{Addresses: []string{a}})
	}
	return &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Labels: labels},
		Endpoints:  endpoints,
		Ports:      []discoveryv1.EndpointPort{{Port: &port}},
	}
}

// epsEvent is one informer event in a scenario.
type epsEvent struct {
	op    string // "upsert" (Add/Update), "delete", "delete-tombstone"
	slice *discoveryv1.EndpointSlice
}

// TestInformer_EndpointSlice_PerSliceBookkeeping is the regression suite for
// the multi-slice bookkeeping bug: the old code purged ALL of a service's
// entries on any slice event and re-added only that slice's endpoints, so
// services spanning multiple slices (>100 endpoints) lost dst_service
// attribution for every sibling slice on any single-slice update — and with
// no DeleteFunc registered, deleted services leaked entries forever.
func TestInformer_EndpointSlice_PerSliceBookkeeping(t *testing.T) {
	tests := []struct {
		name   string
		events []epsEvent
		// want maps podIP → expected service names (sorted). IPs listed with
		// nil want zero entries.
		want map[string][]string
		// wantSliceStateEmpty asserts every internal map is fully drained —
		// the bounded-state (P2) check.
		wantSliceStateEmpty bool
	}{
		{
			name: "single slice indexes its endpoints",
			events: []epsEvent{
				{op: "upsert", slice: mkSlice("prod", "web-1", "web", 8080, "10.0.0.1", "10.0.0.2")},
			},
			want: map[string][]string{
				"10.0.0.1": {"web"},
				"10.0.0.2": {"web"},
			},
		},
		{
			name: "updating one slice keeps the sibling slice's entries",
			events: []epsEvent{
				{op: "upsert", slice: mkSlice("prod", "web-1", "web", 8080, "10.0.0.1")},
				{op: "upsert", slice: mkSlice("prod", "web-2", "web", 8080, "10.0.0.2")},
				// web-1 rolls its endpoint: 10.0.0.1 → 10.0.0.3. The old
				// service-wide purge also wiped web-2's 10.0.0.2 here.
				{op: "upsert", slice: mkSlice("prod", "web-1", "web", 8080, "10.0.0.3")},
			},
			want: map[string][]string{
				"10.0.0.1": nil,
				"10.0.0.2": {"web"}, // the sibling must survive
				"10.0.0.3": {"web"},
			},
		},
		{
			name: "slice deletion removes exactly its own entries",
			events: []epsEvent{
				{op: "upsert", slice: mkSlice("prod", "web-1", "web", 8080, "10.0.0.1")},
				{op: "upsert", slice: mkSlice("prod", "web-2", "web", 8080, "10.0.0.2")},
				{op: "delete", slice: mkSlice("prod", "web-1", "web", 8080, "10.0.0.1")},
			},
			want: map[string][]string{
				"10.0.0.1": nil,
				"10.0.0.2": {"web"},
			},
		},
		{
			name: "service deletion (all slices deleted) leaves no state",
			events: []epsEvent{
				{op: "upsert", slice: mkSlice("prod", "web-1", "web", 8080, "10.0.0.1")},
				{op: "upsert", slice: mkSlice("prod", "web-2", "web", 8080, "10.0.0.2")},
				{op: "delete", slice: mkSlice("prod", "web-1", "web", 8080, "10.0.0.1")},
				{op: "delete", slice: mkSlice("prod", "web-2", "web", 8080, "10.0.0.2")},
			},
			want: map[string][]string{
				"10.0.0.1": nil,
				"10.0.0.2": nil,
			},
			wantSliceStateEmpty: true,
		},
		{
			name: "tombstone delete is unwrapped and cleaned up",
			events: []epsEvent{
				{op: "upsert", slice: mkSlice("prod", "web-1", "web", 8080, "10.0.0.1")},
				{op: "delete-tombstone", slice: mkSlice("prod", "web-1", "web", 8080, "10.0.0.1")},
			},
			want: map[string][]string{
				"10.0.0.1": nil,
			},
			wantSliceStateEmpty: true,
		},
		{
			name: "two services sharing a pod IP stay independent",
			events: []epsEvent{
				{op: "upsert", slice: mkSlice("prod", "web-1", "web", 8080, "10.0.0.1")},
				{op: "upsert", slice: mkSlice("prod", "api-1", "api", 9090, "10.0.0.1")},
				// Re-sync web-1: api's mapping for the shared IP must survive.
				{op: "upsert", slice: mkSlice("prod", "web-1", "web", 8080, "10.0.0.1")},
			},
			want: map[string][]string{
				"10.0.0.1": {"api", "web"},
			},
		},
		{
			name: "same service name in different namespaces stays independent",
			events: []epsEvent{
				{op: "upsert", slice: mkSlice("prod", "web-1", "web", 8080, "10.0.0.1")},
				{op: "upsert", slice: mkSlice("staging", "web-1", "web", 8080, "10.0.0.2")},
				{op: "delete", slice: mkSlice("prod", "web-1", "web", 8080, "10.0.0.1")},
			},
			want: map[string][]string{
				"10.0.0.1": nil,
				"10.0.0.2": {"web"},
			},
		},
		{
			name: "slice that loses its service label purges its old entries",
			events: []epsEvent{
				{op: "upsert", slice: mkSlice("prod", "web-1", "web", 8080, "10.0.0.1")},
				{op: "upsert", slice: mkSlice("prod", "web-1", "", 8080, "10.0.0.1")},
			},
			want: map[string][]string{
				"10.0.0.1": nil,
			},
			wantSliceStateEmpty: true,
		},
		{
			name: "duplicate addr+service across two slices removes one instance per slice",
			events: []epsEvent{
				// During endpoint moves two slices can briefly advertise the
				// same addr+service+port. Deleting one slice must leave the
				// other's copy in place.
				{op: "upsert", slice: mkSlice("prod", "web-1", "web", 8080, "10.0.0.1")},
				{op: "upsert", slice: mkSlice("prod", "web-2", "web", 8080, "10.0.0.1")},
				{op: "delete", slice: mkSlice("prod", "web-1", "web", 8080, "10.0.0.1")},
			},
			want: map[string][]string{
				"10.0.0.1": {"web"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inf := newTestInformer()
			for _, ev := range tt.events {
				switch ev.op {
				case "upsert":
					inf.onEndpointSlice(ev.slice)
				case "delete":
					inf.onEndpointSliceDelete(ev.slice)
				case "delete-tombstone":
					inf.onEndpointSliceDelete(cache.DeletedFinalStateUnknown{
						Key: ev.slice.Namespace + "/" + ev.slice.Name,
						Obj: ev.slice,
					})
				default:
					t.Fatalf("unknown op %q", ev.op)
				}
			}

			for ip, wantSvcs := range tt.want {
				got := inf.LookupService(ip)
				var gotNames []string
				for _, se := range got {
					gotNames = append(gotNames, se.ServiceName)
				}
				sort.Strings(gotNames)
				if len(gotNames) != len(wantSvcs) {
					t.Fatalf("LookupService(%s) = %v, want services %v", ip, got, wantSvcs)
				}
				for i := range wantSvcs {
					if gotNames[i] != wantSvcs[i] {
						t.Errorf("LookupService(%s)[%d] = %q, want %q", ip, i, gotNames[i], wantSvcs[i])
					}
				}
			}

			if tt.wantSliceStateEmpty {
				inf.mu.RLock()
				nIP, nSlice := len(inf.podIPToServices), len(inf.endpointsBySlice)
				inf.mu.RUnlock()
				if nIP != 0 || nSlice != 0 {
					t.Errorf("state not drained: podIPToServices=%d endpointsBySlice=%d, want 0/0 (bounded state, P2)", nIP, nSlice)
				}
			}
		})
	}
}

// TestInformer_EndpointSliceDelete_BogusObject ensures the delete handler
// tolerates objects that are neither a slice nor a tombstone.
func TestInformer_EndpointSliceDelete_BogusObject(t *testing.T) {
	inf := newTestInformer()
	inf.onEndpointSliceDelete("not-a-slice")
	inf.onEndpointSliceDelete(cache.DeletedFinalStateUnknown{Key: "x", Obj: "still-not-a-slice"})
	// Nothing to assert beyond "no panic" and no state invented.
	if n := len(inf.podIPToServices); n != 0 {
		t.Errorf("podIPToServices = %d entries, want 0", n)
	}
}

func TestInformer_ClusterUID(t *testing.T) {
	tests := []struct {
		name    string
		objects []corev1.Namespace
		wantUID string
		wantErr bool
	}{
		{
			name: "returns kube-system UID",
			objects: []corev1.Namespace{
				{ObjectMeta: metav1.ObjectMeta{Name: "kube-system", UID: types.UID("3f8a2c1e-9b7d-4e2a-8c1f-0d5e6a7b8c9d")}},
			},
			wantUID: "3f8a2c1e-9b7d-4e2a-8c1f-0d5e6a7b8c9d",
		},
		{
			name:    "kube-system missing yields error",
			objects: nil,
			wantErr: true,
		},
		{
			name: "empty UID yields error",
			objects: []corev1.Namespace{
				{ObjectMeta: metav1.ObjectMeta{Name: "kube-system"}},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := fake.NewSimpleClientset()
			for i := range tt.objects {
				if _, err := client.CoreV1().Namespaces().Create(context.Background(), &tt.objects[i], metav1.CreateOptions{}); err != nil {
					t.Fatalf("seed namespace: %v", err)
				}
			}
			inf := newTestInformer()
			inf.client = client

			uid, err := inf.ClusterUID(context.Background())
			if (err != nil) != tt.wantErr {
				t.Fatalf("ClusterUID() error = %v, wantErr %v", err, tt.wantErr)
			}
			if uid != tt.wantUID {
				t.Errorf("ClusterUID() = %q, want %q", uid, tt.wantUID)
			}
		})
	}
}
