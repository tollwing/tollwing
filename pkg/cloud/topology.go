package cloud

import (
	"context"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/tollwing/tollwing/pkg/classifier"
)

// TopologyRefresher periodically queries the cloud provider for network
// topology changes and updates the classifier accordingly.
type TopologyRefresher struct {
	provider   Provider
	classifier *classifier.Classifier
	resolver   *classifier.ZoneResolver
	log        *slog.Logger
	interval   time.Duration

	mu     sync.RWMutex
	natGWs []NATGateway
}

// NewTopologyRefresher creates a refresher that syncs cloud topology
// into the classifier and zone resolver.
func NewTopologyRefresher(
	provider Provider,
	cls *classifier.Classifier,
	resolver *classifier.ZoneResolver,
	log *slog.Logger,
) *TopologyRefresher {
	return &TopologyRefresher{
		provider:   provider,
		classifier: cls,
		resolver:   resolver,
		log:        log,
		interval:   5 * time.Minute,
	}
}

// Start performs an initial sync and then refreshes periodically.
func (t *TopologyRefresher) Start(ctx context.Context) {
	t.refresh(ctx)
	go func() {
		ticker := time.NewTicker(t.interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				t.refresh(ctx)
			case <-ctx.Done():
				return
			}
		}
	}()
}

// NATGateways returns the last discovered NAT gateways.
func (t *TopologyRefresher) NATGateways() []NATGateway {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]NATGateway, len(t.natGWs))
	copy(out, t.natGWs)
	return out
}

func (t *TopologyRefresher) refresh(ctx context.Context) {
	t.refreshNATGateways(ctx)
	t.refreshVPCPeerings(ctx)
	t.refreshTransitGateways(ctx)
	t.refreshServiceCIDRs(ctx)
	t.refreshSubnetZones(ctx)
}

func (t *TopologyRefresher) refreshNATGateways(ctx context.Context) {
	gateways, err := t.provider.GetNATGateways(ctx)
	if err != nil {
		t.log.Warn("failed to fetch NAT gateways", "err", err)
		return
	}

	t.mu.Lock()
	t.natGWs = gateways
	t.mu.Unlock()

	ips := make([]netip.Addr, 0, len(gateways))
	for _, gw := range gateways {
		if gw.PrivateIP.IsValid() {
			ips = append(ips, gw.PrivateIP)
		}
	}
	t.classifier.SetNATGatewayIPs(ips)
	t.log.Info("refreshed NAT gateways", "count", len(gateways))
}

func (t *TopologyRefresher) refreshVPCPeerings(ctx context.Context) {
	peerings, err := t.provider.GetVPCPeerings(ctx)
	if err != nil {
		t.log.Warn("failed to fetch VPC peerings", "err", err)
		return
	}

	var cidrs []netip.Prefix
	for _, p := range peerings {
		cidrs = append(cidrs, p.PeerCIDRs...)
	}
	t.classifier.SetVPCPeeringCIDRs(cidrs)
	t.log.Info("refreshed VPC peerings", "peerings", len(peerings), "cidrs", len(cidrs))
}

func (t *TopologyRefresher) refreshTransitGateways(ctx context.Context) {
	gateways, err := t.provider.GetTransitGateways(ctx)
	if err != nil {
		t.log.Warn("failed to fetch transit gateways", "err", err)
		return
	}

	var cidrs []netip.Prefix
	for _, gw := range gateways {
		cidrs = append(cidrs, gw.CIDRs...)
	}
	t.classifier.SetTransitGatewayCIDRs(cidrs)
	t.log.Info("refreshed transit gateways", "gateways", len(gateways), "cidrs", len(cidrs))
}

func (t *TopologyRefresher) refreshServiceCIDRs(ctx context.Context) {
	services, err := t.provider.GetServiceCIDRs(ctx)
	if err != nil {
		t.log.Warn("failed to fetch service CIDRs", "err", err)
		return
	}

	// Flatten all service CIDRs into the VPC endpoint set.
	// The classifier will match against these to distinguish
	// VPC endpoint traffic from public internet egress.
	var endpointCIDRs []netip.Prefix
	totalCIDRs := 0
	for _, cidrs := range services {
		endpointCIDRs = append(endpointCIDRs, cidrs...)
		totalCIDRs += len(cidrs)
	}
	t.classifier.SetVPCEndpointCIDRs(endpointCIDRs)
	t.log.Info("refreshed service CIDRs", "services", len(services), "cidrs", totalCIDRs)
}

func (t *TopologyRefresher) refreshSubnetZones(ctx context.Context) {
	mapping, err := t.provider.GetSubnetZoneMapping(ctx)
	if err != nil {
		t.log.Warn("failed to fetch subnet-zone mapping", "err", err)
		return
	}
	if len(mapping) == 0 {
		return
	}
	t.resolver.SetCIDRZones(mapping)
	t.log.Info("refreshed subnet-zone mapping", "subnets", len(mapping))
}
