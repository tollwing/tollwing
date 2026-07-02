package k8s

import (
	"log/slog"
	"net/netip"
	"testing"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	resource "k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func newTestInformer() *Informer {
	return &Informer{
		log:               slog.Default(),
		containerToPod:    make(map[string]*PodMeta),
		podIPToMeta:       make(map[string]*PodMeta),
		podNameToMeta:     make(map[string]*PodMeta),
		podIPToServices:   make(map[string][]ServiceEndpoint),
		nodeZones:         make(map[string]string),
		nodeInstanceTypes: make(map[string]string),
		podCIDRs:          make(map[string]struct{}),
		endpointsBySlice:  make(map[string][]sliceEndpointEntry),
	}
}

func TestInformer_OnPod(t *testing.T) {
	inf := newTestInformer()

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "web-abc123",
			Namespace: "default",
			Labels:    map[string]string{"app": "web"},
		},
		Spec: corev1.PodSpec{
			NodeName: "node-1",
		},
		Status: corev1.PodStatus{
			PodIP:  "10.0.1.50",
			HostIP: "192.168.1.10",
			ContainerStatuses: []corev1.ContainerStatus{
				{ContainerID: "containerd://aabbccdd1122334455667788"},
			},
		},
	}

	inf.onPod(pod)

	// Verify container ID lookup.
	meta := inf.LookupContainerID("aabbccdd1122334455667788")
	if meta == nil {
		t.Fatal("expected to find pod by container ID")
	}
	if meta.Name != "web-abc123" {
		t.Errorf("Name = %q, want web-abc123", meta.Name)
	}
	if meta.Namespace != "default" {
		t.Errorf("Namespace = %q, want default", meta.Namespace)
	}

	// Verify pod IP lookup.
	meta2 := inf.LookupPodIP("10.0.1.50")
	if meta2 == nil {
		t.Fatal("expected to find pod by IP")
	}
	if meta2.Name != "web-abc123" {
		t.Errorf("Name = %q, want web-abc123", meta2.Name)
	}
}

func TestInformer_OnPodDelete(t *testing.T) {
	inf := newTestInformer()

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "web-1", Namespace: "default"},
		Spec:       corev1.PodSpec{NodeName: "node-1"},
		Status: corev1.PodStatus{
			PodIP: "10.0.1.50",
			ContainerStatuses: []corev1.ContainerStatus{
				{ContainerID: "containerd://abcd1234"},
			},
		},
	}

	inf.onPod(pod)
	if inf.LookupContainerID("abcd1234") == nil {
		t.Fatal("expected pod in cache after add")
	}

	inf.onPodDelete(pod)
	if inf.LookupContainerID("abcd1234") != nil {
		t.Error("expected pod removed from cache after delete")
	}
	if inf.LookupPodIP("10.0.1.50") != nil {
		t.Error("expected pod IP removed from cache after delete")
	}
}

func TestInformer_OnNode(t *testing.T) {
	inf := newTestInformer()

	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "node-1",
			Labels: map[string]string{
				"topology.kubernetes.io/zone": "us-east-1a",
			},
		},
	}

	inf.onNode(node)

	zone := inf.NodeZone("node-1")
	if zone != "us-east-1a" {
		t.Errorf("NodeZone = %q, want us-east-1a", zone)
	}
}

func TestInformer_OnNode_LegacyLabel(t *testing.T) {
	inf := newTestInformer()

	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "node-2",
			Labels: map[string]string{
				"failure-domain.beta.kubernetes.io/zone": "eu-west-1b",
			},
		},
	}

	inf.onNode(node)

	zone := inf.NodeZone("node-2")
	if zone != "eu-west-1b" {
		t.Errorf("NodeZone = %q, want eu-west-1b", zone)
	}
}

func TestInformer_OnNode_NoZoneLabel(t *testing.T) {
	inf := newTestInformer()

	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "node-3",
			Labels: map[string]string{"role": "worker"},
		},
	}

	inf.onNode(node)

	zone := inf.NodeZone("node-3")
	if zone != "" {
		t.Errorf("expected empty zone for node without zone label, got %q", zone)
	}
}

func TestInformer_OnZoneUpdate_Callback(t *testing.T) {
	inf := newTestInformer()

	var callbackIP netip.Addr
	var callbackZone string
	inf.OnZoneUpdate = func(ip netip.Addr, zone string) {
		callbackIP = ip
		callbackZone = zone
	}

	// First add the node zone.
	inf.onNode(&corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "node-1",
			Labels: map[string]string{"topology.kubernetes.io/zone": "us-east-1a"},
		},
	})

	// Then add a pod on that node — should trigger callback.
	inf.onPod(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "web-1", Namespace: "default"},
		Spec:       corev1.PodSpec{NodeName: "node-1"},
		Status: corev1.PodStatus{
			PodIP: "10.0.1.50",
			ContainerStatuses: []corev1.ContainerStatus{
				{ContainerID: "containerd://abc123"},
			},
		},
	})

	if callbackZone != "us-east-1a" {
		t.Errorf("callback zone = %q, want us-east-1a", callbackZone)
	}
	if callbackIP != netip.MustParseAddr("10.0.1.50") {
		t.Errorf("callback IP = %v, want 10.0.1.50", callbackIP)
	}
}

func TestInformer_OnEndpointSlice(t *testing.T) {
	inf := newTestInformer()

	port := int32(8080)
	eps := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-svc-abc",
			Namespace: "production",
			Labels: map[string]string{
				discoveryv1.LabelServiceName: "my-svc",
			},
		},
		Endpoints: []discoveryv1.Endpoint{
			{Addresses: []string{"10.0.1.50", "10.0.1.51"}},
		},
		Ports: []discoveryv1.EndpointPort{
			{Port: &port},
		},
	}

	inf.onEndpointSlice(eps)

	svcs := inf.LookupService("10.0.1.50")
	if len(svcs) != 1 {
		t.Fatalf("expected 1 service, got %d", len(svcs))
	}
	if svcs[0].ServiceName != "my-svc" {
		t.Errorf("ServiceName = %q, want my-svc", svcs[0].ServiceName)
	}
	if svcs[0].ServiceNamespace != "production" {
		t.Errorf("ServiceNamespace = %q, want production", svcs[0].ServiceNamespace)
	}
	if svcs[0].Port != 8080 {
		t.Errorf("Port = %d, want 8080", svcs[0].Port)
	}

	// Second IP should also resolve.
	svcs2 := inf.LookupService("10.0.1.51")
	if len(svcs2) != 1 {
		t.Fatalf("expected 1 service for second IP, got %d", len(svcs2))
	}
}

func TestExtractContainerID(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"containerd://aabbccdd", "aabbccdd"},
		{"docker://aabbccdd", "aabbccdd"},
		{"cri-o://aabbccdd", "aabbccdd"},
		{"aabbccdd", "aabbccdd"},
		{"", ""},
	}

	for _, tt := range tests {
		got := extractContainerID(tt.input)
		if got != tt.want {
			t.Errorf("extractContainerID(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestInformer_LookupService_Empty(t *testing.T) {
	inf := newTestInformer()

	svcs := inf.LookupService("10.0.0.1")
	if svcs != nil {
		t.Errorf("expected nil for unknown IP, got %v", svcs)
	}
}

// gpuPod builds a Pod requesting `gpus` nvidia.com/gpu in a single container.
// When useLimitsOnly is true, the request is set only via Limits (the common
// real-world spec) to exercise the limit→request fallback in onPod.
func gpuPod(name, namespace, nodeName string, gpus int64, useLimitsOnly bool) *corev1.Pod {
	rl := corev1.ResourceList{"nvidia.com/gpu": *resource.NewQuantity(gpus, resource.DecimalSI)}
	c := corev1.Container{Name: "main"}
	if useLimitsOnly {
		c.Resources.Limits = rl
	} else {
		c.Resources.Requests = rl
	}
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec:       corev1.PodSpec{NodeName: nodeName, Containers: []corev1.Container{c}},
		Status:     corev1.PodStatus{PodIP: "10.1.1.1"},
	}
}
