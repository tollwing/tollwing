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
	t.refreshNATRoute(ctx)
	t.refreshVPCPeerings(ctx)
	t.refreshTransitGateways(ctx)
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

// localVPCCIDRSource is the optional provider capability to report the local
// VPC's own address space (currently AWS). The refresher uses it to guard
// the classifier's peering prefix set against local-CIDR poisoning.
type localVPCCIDRSource interface {
	LocalVPCCIDRs(ctx context.Context) ([]netip.Prefix, error)
}

func (t *TopologyRefresher) refreshVPCPeerings(ctx context.Context) {
	peerings, err := t.provider.GetVPCPeerings(ctx)
	if err != nil {
		t.log.Warn("failed to fetch VPC peerings", "err", err)
		return
	}

	localCIDRs := t.localVPCCIDRs(ctx)

	var cidrs []netip.Prefix
	for _, p := range peerings {
		for _, cidr := range p.PeerCIDRs {
			// Belt-and-braces (P5): a "peer" CIDR overlapping the local
			// VPC's own space is never a real peer (clouds refuse to peer
			// overlapping VPCs). Letting it into the prefix set repriced
			// every non-cluster private flow inside the local VPC as
			// vpc_peering — the classifier consults the peering prefixes
			// before the zone fallback.
			if local, overlaps := overlapsAny(cidr, localCIDRs); overlaps {
				t.log.Warn("dropping peering CIDR overlapping the local VPC",
					"peering", p.ID, "cidr", cidr.String(), "local_cidr", local.String())
				continue
			}
			cidrs = append(cidrs, cidr)
		}
	}
	t.classifier.SetVPCPeeringCIDRs(cidrs)
	t.log.Info("refreshed VPC peerings", "peerings", len(peerings), "cidrs", len(cidrs))
}

// localVPCCIDRs asks the provider for the local VPC's address space, when it
// can report it. Failure is non-fatal: the guard degrades to a no-op and the
// provider-side fix (peer-side selection) remains the primary defense.
func (t *TopologyRefresher) localVPCCIDRs(ctx context.Context) []netip.Prefix {
	src, ok := t.provider.(localVPCCIDRSource)
	if !ok {
		return nil
	}
	cidrs, err := src.LocalVPCCIDRs(ctx)
	if err != nil {
		t.log.Warn("failed to fetch local VPC CIDRs, peering guard disabled", "err", err)
		return nil
	}
	return cidrs
}

// overlapsAny reports whether prefix overlaps any of the given prefixes,
// returning the first overlapping one. Two prefixes overlap iff either
// contains the other's base address.
func overlapsAny(prefix netip.Prefix, others []netip.Prefix) (netip.Prefix, bool) {
	for _, o := range others {
		if prefix.Contains(o.Addr()) || o.Contains(prefix.Addr()) {
			return o, true
		}
	}
	return netip.Prefix{}, false
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

// Published service IP ranges (AWS ip-ranges.json, GCP cloud.json, Azure
// service tags) are deliberately NOT fed into the classifier's VPC-endpoint
// set. Per DEC-015 (and P5): a public range — including the giant AMAZON/EC2
// blocks — says nothing about whether THIS VPC has an endpoint for it, and
// flattening them into SetVPCEndpointCIDRs repriced public-EC2/internet
// egress (~$0.09/GB) as vpc_endpoint ($0.01/GB). Endpoint CIDRs must come
// from actually-deployed endpoints (a future DescribeVpcEndpoints feed, or an
// operator calling classifier.SetVPCEndpointCIDRs directly).

// natRouteDetector is the optional provider capability for route-based NAT
// detection (DEC-015). Only providers that can inspect their route tables
// implement it (currently AWS).
type natRouteDetector interface {
	NodeRoutesViaNAT(ctx context.Context) (bool, error)
}

func (t *TopologyRefresher) refreshNATRoute(ctx context.Context) {
	detector, ok := t.provider.(natRouteDetector)
	if !ok {
		return
	}
	viaNAT, err := detector.NodeRoutesViaNAT(ctx)
	if err != nil {
		t.log.Warn("failed to detect NAT default route", "err", err)
		return
	}
	t.classifier.SetDefaultRouteNAT(viaNAT)
	t.log.Info("refreshed NAT route detection", "default_route_via_nat", viaNAT)
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
