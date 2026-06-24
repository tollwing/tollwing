// Package k8s provides Kubernetes Pod/Service/Node metadata via informers.
//
// Maps container IDs to pod metadata and pod IPs to service names.
// Feeds the zone resolver with node topology labels and the classifier
// with service endpoint mappings.
package k8s

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
)

// PodMeta holds enriched metadata for a Kubernetes pod.
type PodMeta struct {
	Name       string
	Namespace  string
	NodeName   string
	Labels     map[string]string
	PodIP      string
	HostIP     string
	Containers []string // container IDs (runtime://sha256)

	// Resource requests — summed across all containers. Used by cost
	// attribution (idle detection, per-pod billing).
	CPURequestMilli int64
	MemoryRequestMB int64

	// InstanceType is the node's instance type label
	// (node.kubernetes.io/instance-type). Empty if missing.
	InstanceType string

	// CreatedAt is pod.CreationTimestamp — needed for pod-age heuristics.
	CreatedAt time.Time
}

// ServiceEndpoint maps a pod IP:port to a service.
type ServiceEndpoint struct {
	ServiceName      string
	ServiceNamespace string
	Port             int32
}

// ServiceRef identifies a Kubernetes service by namespace + name.
type ServiceRef struct {
	Namespace string
	Name      string
}

// Informer watches Kubernetes resources and maintains lookup caches.
type Informer struct {
	log     *slog.Logger
	client  kubernetes.Interface
	factory informers.SharedInformerFactory

	mu                sync.RWMutex
	containerToPod    map[string]*PodMeta          // containerID → pod
	podIPToMeta       map[string]*PodMeta          // podIP → pod
	podNameToMeta     map[string]*PodMeta          // "namespace/name" → pod
	podIPToServices   map[string][]ServiceEndpoint // podIP → services
	clusterIPToSvc    map[string]ServiceRef        // ClusterIP → service (pre-DNAT intent)
	nodeZones         map[string]string            // nodeName → zone
	nodeInstanceTypes map[string]string            // nodeName → instance type

	// podCIDRs is the aggregated set of Pod CIDRs across all observed
	// nodes (Node.spec.podCIDR + Node.spec.podCIDRs for dual-stack).
	// Fed to the classifier so non-RFC-1918 cluster CIDRs (e.g. EKS
	// Custom Networking with 100.64.0.0/10) are still recognised as
	// cluster-internal traffic. Stored as map[string]struct{} so the
	// CIDR string itself dedupes.
	podCIDRs map[string]struct{}

	// OnZoneUpdate is called when a node's zone is discovered.
	// Used to feed the zone resolver.
	OnZoneUpdate func(ip netip.Addr, zone string)

	// OnPodCIDR is called once for each newly discovered Pod CIDR.
	// Wired by the agent to call classifier.AddClusterCIDR. Idempotent:
	// the informer dedupes before invoking, so a CIDR fires at most once.
	OnPodCIDR func(prefix netip.Prefix)
}

// Config controls the informer.
type Config struct {
	// Kubeconfig path. Empty = in-cluster config.
	Kubeconfig string

	// ResyncInterval for informer list operations. Default: 5m.
	ResyncInterval time.Duration
}

func (c *Config) setDefaults() {
	if c.ResyncInterval == 0 {
		c.ResyncInterval = 5 * time.Minute
	}
}

// NewInformer creates a K8s informer. Call Start to begin watching.
func NewInformer(cfg Config, log *slog.Logger) (*Informer, error) {
	cfg.setDefaults()

	var restConfig *rest.Config
	var err error

	if cfg.Kubeconfig != "" {
		restConfig, err = clientcmd.BuildConfigFromFlags("", cfg.Kubeconfig)
	} else {
		restConfig, err = rest.InClusterConfig()
	}
	if err != nil {
		return nil, fmt.Errorf("k8s config: %w", err)
	}

	client, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return nil, fmt.Errorf("k8s client: %w", err)
	}

	return newInformerWithClient(client, cfg, log), nil
}

// newInformerWithClient builds an Informer over an existing clientset. Split
// from NewInformer so integration tests can drive the *real* informer
// machinery (shared factory, event handlers, cache sync) against a
// fake.Clientset — exercising onPod/onNode end to end, not just the unit-level
// onPod() call.
func newInformerWithClient(client kubernetes.Interface, cfg Config, log *slog.Logger) *Informer {
	cfg.setDefaults()
	return &Informer{
		log:               log,
		client:            client,
		factory:           informers.NewSharedInformerFactory(client, cfg.ResyncInterval),
		containerToPod:    make(map[string]*PodMeta),
		podIPToMeta:       make(map[string]*PodMeta),
		podNameToMeta:     make(map[string]*PodMeta),
		podIPToServices:   make(map[string][]ServiceEndpoint),
		clusterIPToSvc:    make(map[string]ServiceRef),
		nodeZones:         make(map[string]string),
		nodeInstanceTypes: make(map[string]string),
		podCIDRs:          make(map[string]struct{}),
	}
}

// PodCIDRs returns a snapshot of the discovered Pod CIDRs.
func (inf *Informer) PodCIDRs() []netip.Prefix {
	inf.mu.RLock()
	defer inf.mu.RUnlock()
	out := make([]netip.Prefix, 0, len(inf.podCIDRs))
	for s := range inf.podCIDRs {
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p)
		}
	}
	return out
}

// Start begins watching Pods, Nodes, and EndpointSlices.
func (inf *Informer) Start(ctx context.Context) {
	// Watch pods for container ID → pod mapping.
	podInformer := inf.factory.Core().V1().Pods().Informer()
	podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj interface{}) { inf.onPod(obj.(*corev1.Pod)) },
		UpdateFunc: func(_, obj interface{}) { inf.onPod(obj.(*corev1.Pod)) },
		DeleteFunc: func(obj interface{}) { inf.onPodDelete(obj) },
	})

	// Watch nodes for topology zone labels.
	nodeInformer := inf.factory.Core().V1().Nodes().Informer()
	nodeInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj interface{}) { inf.onNode(obj.(*corev1.Node)) },
		UpdateFunc: func(_, obj interface{}) { inf.onNode(obj.(*corev1.Node)) },
	})

	// Watch EndpointSlices for pod IP → service mapping.
	epsInformer := inf.factory.Discovery().V1().EndpointSlices().Informer()
	epsInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj interface{}) { inf.onEndpointSlice(obj.(*discoveryv1.EndpointSlice)) },
		UpdateFunc: func(_, obj interface{}) { inf.onEndpointSlice(obj.(*discoveryv1.EndpointSlice)) },
	})

	// Watch Services for ClusterIP → service mapping. This recovers the
	// pre-DNAT "service intent": the agent correlates a flow's original
	// (pre-DNAT) ClusterIP back to the service the client actually dialed.
	svcInformer := inf.factory.Core().V1().Services().Informer()
	svcInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj interface{}) { inf.onService(obj.(*corev1.Service)) },
		UpdateFunc: func(_, obj interface{}) { inf.onService(obj.(*corev1.Service)) },
		DeleteFunc: inf.onServiceDelete,
	})

	inf.factory.Start(ctx.Done())
	inf.factory.WaitForCacheSync(ctx.Done())

	inf.log.Info("k8s informers synced")
}

// LookupContainerID returns pod metadata for a container ID.
// The containerID should be the 64-char hex ID (without runtime:// prefix).
func (inf *Informer) LookupContainerID(containerID string) *PodMeta {
	inf.mu.RLock()
	defer inf.mu.RUnlock()
	return inf.containerToPod[containerID]
}

// LookupPodIP returns pod metadata for a pod IP.
func (inf *Informer) LookupPodIP(ip string) *PodMeta {
	inf.mu.RLock()
	defer inf.mu.RUnlock()
	return inf.podIPToMeta[ip]
}

// LookupService returns the service(s) behind a pod IP.
func (inf *Informer) LookupService(podIP string) []ServiceEndpoint {
	inf.mu.RLock()
	defer inf.mu.RUnlock()
	return inf.podIPToServices[podIP]
}

// NodeZone returns the zone for a node name.
func (inf *Informer) NodeZone(nodeName string) string {
	inf.mu.RLock()
	defer inf.mu.RUnlock()
	return inf.nodeZones[nodeName]
}

func (inf *Informer) onPod(pod *corev1.Pod) {
	meta := &PodMeta{
		Name:      pod.Name,
		Namespace: pod.Namespace,
		NodeName:  pod.Spec.NodeName,
		Labels:    pod.Labels,
		PodIP:     pod.Status.PodIP,
		HostIP:    pod.Status.HostIP,
		CreatedAt: pod.CreationTimestamp.Time,
	}

	// Sum container resource requests (the same accounting kube-scheduler
	// uses for bin-packing). Init containers are excluded — they don't
	// consume resources during steady-state running.
	for _, c := range pod.Spec.Containers {
		if cpuQ, ok := c.Resources.Requests["cpu"]; ok {
			meta.CPURequestMilli += cpuQ.MilliValue()
		}
		if memQ, ok := c.Resources.Requests["memory"]; ok {
			meta.MemoryRequestMB += memQ.Value() / (1024 * 1024)
		}
	}

	inf.mu.Lock()
	defer inf.mu.Unlock()

	// Enrich with instance type from node cache if available.
	if it, ok := inf.nodeInstanceTypes[pod.Spec.NodeName]; ok {
		meta.InstanceType = it
	}

	// Map container IDs → pod.
	for _, cs := range pod.Status.ContainerStatuses {
		cid := extractContainerID(cs.ContainerID)
		if cid != "" {
			meta.Containers = append(meta.Containers, cid)
			inf.containerToPod[cid] = meta
		}
	}

	// Map pod IP → pod.
	if pod.Status.PodIP != "" {
		inf.podIPToMeta[pod.Status.PodIP] = meta

		// Feed the zone resolver if we know the node's zone.
		if zone, ok := inf.nodeZones[pod.Spec.NodeName]; ok && inf.OnZoneUpdate != nil {
			if addr, err := netip.ParseAddr(pod.Status.PodIP); err == nil {
				inf.OnZoneUpdate(addr, zone)
			}
		}
	}

	// Map "namespace/name" → pod, used by idle detection and per-pod cost.
	inf.podNameToMeta[pod.Namespace+"/"+pod.Name] = meta
}

// LookupPodByName returns pod metadata by namespace + name.
// Returns nil if the pod is not in the cache.
func (inf *Informer) LookupPodByName(namespace, name string) *PodMeta {
	inf.mu.RLock()
	defer inf.mu.RUnlock()
	return inf.podNameToMeta[namespace+"/"+name]
}

func (inf *Informer) onPodDelete(obj interface{}) {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			return
		}
		pod, ok = tombstone.Obj.(*corev1.Pod)
		if !ok {
			return
		}
	}

	inf.mu.Lock()
	defer inf.mu.Unlock()

	for _, cs := range pod.Status.ContainerStatuses {
		cid := extractContainerID(cs.ContainerID)
		if cid != "" {
			delete(inf.containerToPod, cid)
		}
	}
	delete(inf.podIPToMeta, pod.Status.PodIP)
	delete(inf.podNameToMeta, pod.Namespace+"/"+pod.Name)
}

func (inf *Informer) onNode(node *corev1.Node) {
	zone := node.Labels["topology.kubernetes.io/zone"]
	if zone == "" {
		zone = node.Labels["failure-domain.beta.kubernetes.io/zone"] // legacy
	}
	instanceType := node.Labels["node.kubernetes.io/instance-type"]
	if instanceType == "" {
		instanceType = node.Labels["beta.kubernetes.io/instance-type"] // legacy
	}

	// Pod CIDRs: spec.podCIDR (legacy single-stack) + spec.podCIDRs
	// (modern dual-stack list). Both fields are populated by the
	// kube-controller-manager once the node has been allocated a range.
	var newCIDRs []netip.Prefix
	cidrCandidates := make([]string, 0, 2)
	if node.Spec.PodCIDR != "" {
		cidrCandidates = append(cidrCandidates, node.Spec.PodCIDR)
	}
	cidrCandidates = append(cidrCandidates, node.Spec.PodCIDRs...)

	inf.mu.Lock()
	if zone != "" {
		inf.nodeZones[node.Name] = zone
	}
	if instanceType != "" {
		inf.nodeInstanceTypes[node.Name] = instanceType
		// Back-fill InstanceType onto pods already cached for this node. onPod
		// enriches from nodeInstanceTypes only if the node was observed first;
		// when a pod's handler runs before its node's, the pod would otherwise
		// stay at InstanceType="" until its next resync (≤ ResyncInterval),
		// leaving GPU/cost attribution unable to price it.
		//
		// CRITICAL: follow the cache's replace-don't-mutate invariant. Every
		// other writer builds a NEW *PodMeta and swaps it into the maps, so a
		// pointer already handed to a lock-free reader (pkg/idle and pkg/agent
		// read fields off Lookup*-returned *PodMeta without holding inf.mu) is
		// effectively immutable. Mutating meta.InstanceType in place here would
		// be a write-after-publish data race against those readers. So copy the
		// struct, set the field on the copy, and swap the new pointer into every
		// map the pod appears in (name, IP, and each container ID).
		for key, meta := range inf.podNameToMeta {
			if meta.NodeName != node.Name || meta.InstanceType == instanceType {
				continue
			}
			updated := *meta // shallow copy; Labels/Containers are never mutated in place post-publish, so sharing them is safe
			updated.InstanceType = instanceType
			inf.podNameToMeta[key] = &updated
			if updated.PodIP != "" {
				inf.podIPToMeta[updated.PodIP] = &updated
			}
			for _, cid := range updated.Containers {
				inf.containerToPod[cid] = &updated
			}
		}
	}
	for _, raw := range cidrCandidates {
		if raw == "" {
			continue
		}
		// Aggregate to a /16 (IPv4) or /48 (IPv6) cluster-wide CIDR
		// when possible. We don't have visibility into the cluster
		// CIDR here — only per-node ranges (typically /24 for IPv4).
		// Storing each per-node CIDR is fine: the classifier's lookup
		// is linear over a small list (≤ N nodes) and dedup'd.
		if _, exists := inf.podCIDRs[raw]; exists {
			continue
		}
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			inf.log.Debug("invalid podCIDR on node", "node", node.Name, "cidr", raw, "err", err)
			continue
		}
		inf.podCIDRs[raw] = struct{}{}
		newCIDRs = append(newCIDRs, p)
	}
	inf.mu.Unlock()

	// Fire callback after releasing the lock so subscribers don't
	// block other informer callbacks.
	for _, p := range newCIDRs {
		if inf.OnPodCIDR != nil {
			inf.OnPodCIDR(p)
		}
		inf.log.Info("discovered pod CIDR", "node", node.Name, "cidr", p.String())
	}

	if zone == "" {
		return
	}

	// Update zone for all pods on this node.
	if inf.OnZoneUpdate != nil {
		inf.mu.RLock()
		for _, meta := range inf.podIPToMeta {
			if meta.NodeName == node.Name && meta.PodIP != "" {
				if addr, err := netip.ParseAddr(meta.PodIP); err == nil {
					inf.OnZoneUpdate(addr, zone)
				}
			}
		}
		inf.mu.RUnlock()
	}

	inf.log.Debug("node zone updated", "node", node.Name, "zone", zone)
}

func (inf *Informer) onEndpointSlice(eps *discoveryv1.EndpointSlice) {
	svcName := eps.Labels[discoveryv1.LabelServiceName]
	if svcName == "" {
		return
	}

	inf.mu.Lock()
	defer inf.mu.Unlock()

	// Clear existing entries for this service to avoid stale accumulation.
	// Then re-add current endpoints. This prevents the leak where deleted
	// endpoints were never cleaned up from podIPToServices.
	for addr, seps := range inf.podIPToServices {
		filtered := seps[:0]
		for _, se := range seps {
			if se.ServiceName != svcName || se.ServiceNamespace != eps.Namespace {
				filtered = append(filtered, se)
			}
		}
		if len(filtered) == 0 {
			delete(inf.podIPToServices, addr)
		} else {
			inf.podIPToServices[addr] = filtered
		}
	}

	// Re-add current endpoints.
	for _, ep := range eps.Endpoints {
		for _, addr := range ep.Addresses {
			for _, port := range eps.Ports {
				if port.Port == nil {
					continue
				}
				inf.podIPToServices[addr] = append(inf.podIPToServices[addr], ServiceEndpoint{
					ServiceName:      svcName,
					ServiceNamespace: eps.Namespace,
					Port:             *port.Port,
				})
			}
		}
	}
}

// onService indexes a service's ClusterIP(s) so the agent can resolve a
// flow's pre-DNAT destination back to the dialed service.
func (inf *Informer) onService(svc *corev1.Service) {
	ref := ServiceRef{Namespace: svc.Namespace, Name: svc.Name}
	inf.mu.Lock()
	defer inf.mu.Unlock()
	for _, ip := range clusterIPsOf(svc) {
		inf.clusterIPToSvc[ip] = ref
	}
}

func (inf *Informer) onServiceDelete(obj interface{}) {
	svc, ok := obj.(*corev1.Service)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			return
		}
		svc, ok = tombstone.Obj.(*corev1.Service)
		if !ok {
			return
		}
	}
	inf.mu.Lock()
	defer inf.mu.Unlock()
	for _, ip := range clusterIPsOf(svc) {
		delete(inf.clusterIPToSvc, ip)
	}
}

// clusterIPsOf returns a service's routable ClusterIPs, skipping headless
// ("None") and unset entries — neither ever appears as a pre-DNAT destination.
func clusterIPsOf(svc *corev1.Service) []string {
	var out []string
	add := func(ip string) {
		if ip != "" && ip != corev1.ClusterIPNone {
			out = append(out, ip)
		}
	}
	add(svc.Spec.ClusterIP)
	for _, ip := range svc.Spec.ClusterIPs {
		add(ip)
	}
	return out
}

// LookupClusterIP resolves a pre-DNAT ClusterIP to its owning service.
func (inf *Informer) LookupClusterIP(ip string) (ServiceRef, bool) {
	inf.mu.RLock()
	defer inf.mu.RUnlock()
	ref, ok := inf.clusterIPToSvc[ip]
	return ref, ok
}

// extractContainerID strips the runtime prefix from a container ID.
// Input: "containerd://abc123..." → "abc123..."
// Input: "docker://abc123..." → "abc123..."
func extractContainerID(raw string) string {
	if idx := strings.Index(raw, "://"); idx != -1 {
		return raw[idx+3:]
	}
	return raw
}

// IsAvailable checks if Kubernetes API is reachable.
func IsAvailable() bool {
	_, err := rest.InClusterConfig()
	if err == nil {
		return true
	}
	// Also check KUBECONFIG or default path.
	kubeconfig := clientcmd.NewDefaultClientConfigLoadingRules().GetDefaultFilename()
	_, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
	return err == nil
}

// Needed to satisfy the compiler for metav1 import.
var _ = metav1.NamespaceAll
