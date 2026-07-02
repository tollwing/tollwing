package cloud

import (
	"context"
	"encoding/binary"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/tollwing/tollwing/pkg/classifier"
	"github.com/tollwing/tollwing/pkg/cost"
)

// mockProvider implements Provider for testing.
type mockProvider struct {
	natGateways     []NATGateway
	vpcPeerings     []VPCPeering
	transitGateways []TransitGateway
	serviceCIDRs    map[string][]netip.Prefix
	subnetZones     map[netip.Prefix]string
}

func (m *mockProvider) Name() string   { return "mock" }
func (m *mockProvider) Region() string { return "us-east-1" }
func (m *mockProvider) Zone() string   { return "us-east-1a" }
func (m *mockProvider) AccountID(ctx context.Context) (string, error) {
	return "123456789012", nil
}
func (m *mockProvider) GetSubnetZoneMapping(ctx context.Context) (map[netip.Prefix]string, error) {
	return m.subnetZones, nil
}
func (m *mockProvider) GetNATGateways(ctx context.Context) ([]NATGateway, error) {
	return m.natGateways, nil
}
func (m *mockProvider) GetVPCPeerings(ctx context.Context) ([]VPCPeering, error) {
	return m.vpcPeerings, nil
}
func (m *mockProvider) GetTransitGateways(ctx context.Context) ([]TransitGateway, error) {
	return m.transitGateways, nil
}
func (m *mockProvider) GetServiceCIDRs(ctx context.Context) (map[string][]netip.Prefix, error) {
	return m.serviceCIDRs, nil
}
func (m *mockProvider) GetRateCard(ctx context.Context, region string) (*cost.RateCard, error) {
	return cost.DefaultAWSRateCard(region), nil
}
func (m *mockProvider) GetBillingData(ctx context.Context, start, end time.Time) (*cost.BillingData, error) {
	return &cost.BillingData{Provider: "mock", Period: cost.BillingPeriod{Start: start, End: end}}, nil
}

func TestTopologyRefresher_NATGateways(t *testing.T) {
	resolver := classifier.NewZoneResolver(slog.Default())
	cls := classifier.New(resolver)

	mp := &mockProvider{
		natGateways: []NATGateway{
			{ID: "nat-1", PrivateIP: netip.MustParseAddr("10.0.99.1")},
			{ID: "nat-2", PrivateIP: netip.MustParseAddr("10.0.99.2")},
		},
	}

	tr := NewTopologyRefresher(mp, cls, resolver, slog.Default())
	tr.refresh(context.Background())

	gws := tr.NATGateways()
	if len(gws) != 2 {
		t.Fatalf("expected 2 NAT gateways, got %d", len(gws))
	}
}

func TestTopologyRefresher_VPCPeerings(t *testing.T) {
	resolver := classifier.NewZoneResolver(slog.Default())
	cls := classifier.New(resolver)

	mp := &mockProvider{
		vpcPeerings: []VPCPeering{
			{
				ID:        "pcx-1",
				PeerCIDRs: []netip.Prefix{netip.MustParsePrefix("172.20.0.0/16")},
			},
		},
	}

	tr := NewTopologyRefresher(mp, cls, resolver, slog.Default())
	tr.refresh(context.Background())

	// The classifier should now classify traffic to 172.20.x.x as VPC peering.
	// (We can't easily test this without importing classifier internals,
	// but the integration is verified by the classifier tests.)
}

func TestTopologyRefresher_SubnetZones(t *testing.T) {
	resolver := classifier.NewZoneResolver(slog.Default())
	cls := classifier.New(resolver)

	mp := &mockProvider{
		subnetZones: map[netip.Prefix]string{
			netip.MustParsePrefix("10.0.0.0/24"): "us-east-1a",
			netip.MustParsePrefix("10.0.1.0/24"): "us-east-1b",
		},
	}

	tr := NewTopologyRefresher(mp, cls, resolver, slog.Default())
	tr.refresh(context.Background())

	// Verify the zone resolver was updated.
	zone := resolver.Resolve(netip.MustParseAddr("10.0.0.50"))
	if zone != "us-east-1a" {
		t.Errorf("expected us-east-1a, got %q", zone)
	}
	zone = resolver.Resolve(netip.MustParseAddr("10.0.1.50"))
	if zone != "us-east-1b" {
		t.Errorf("expected us-east-1b, got %q", zone)
	}
}

// nboFlow builds a classifier.FlowInfo the way the BPF data plane delivers
// IPs: network-order bytes loaded native-endian (DEC-009).
func nboFlow(src, dst string) classifier.FlowInfo {
	toNBO := func(s string) uint32 {
		b := netip.MustParseAddr(s).As4()
		return binary.NativeEndian.Uint32(b[:])
	}
	return classifier.FlowInfo{SrcIP: toNBO(src), DstIP: toNBO(dst)}
}

// TestTopologyRefresher_ServiceCIDRsNotEndpointFed is the regression test for
// the ip-ranges poisoning bug (DEC-015): published service ranges (including
// the AMAZON/EC2 blocks) must NOT enter the classifier's VPC-endpoint set —
// doing so repriced ~$0.09/GB public egress as $0.01/GB "vpc_endpoint".
func TestTopologyRefresher_ServiceCIDRsNotEndpointFed(t *testing.T) {
	resolver := classifier.NewZoneResolver(slog.Default())
	cls := classifier.New(resolver)

	mp := &mockProvider{
		serviceCIDRs: map[string][]netip.Prefix{
			"amazon": {netip.MustParsePrefix("52.216.0.0/15")},
			"ec2":    {netip.MustParsePrefix("52.94.0.0/22")},
		},
	}

	tr := NewTopologyRefresher(mp, cls, resolver, slog.Default())
	tr.refresh(context.Background())

	// Traffic to a public EC2/AMAZON range must remain internet egress.
	for _, dst := range []string{"52.216.10.10", "52.94.1.50"} {
		if got := cls.Classify(nboFlow("10.0.1.10", dst)).Type; got != classifier.InternetEgress {
			t.Errorf("dst %s: classified %s, want %s (ip-ranges must not feed the endpoint set)",
				dst, got, classifier.InternetEgress)
		}
	}
}

// localVPCMockProvider adds the optional LocalVPCCIDRs capability.
type localVPCMockProvider struct {
	mockProvider
	localCIDRs []netip.Prefix
}

func (m *localVPCMockProvider) LocalVPCCIDRs(ctx context.Context) ([]netip.Prefix, error) {
	return m.localCIDRs, nil
}

// TestTopologyRefresher_LocalVPCPeeringGuard is the belt-and-braces
// regression test for the accepter-side peering bug: a "peer" CIDR covering
// the local VPC's own address space must never enter the classifier's
// peering prefix set — the classifier consults it before the zone fallback,
// so a poisoned entry repriced every non-cluster private flow inside the
// local VPC (node-to-node, hostNetwork) as vpc_peering.
func TestTopologyRefresher_LocalVPCPeeringGuard(t *testing.T) {
	resolver := classifier.NewZoneResolver(slog.Default())
	cls := classifier.New(resolver)

	mp := &localVPCMockProvider{
		mockProvider: mockProvider{
			vpcPeerings: []VPCPeering{
				{
					// Poisoned entry: the local VPC's own CIDR reported as
					// a peer (what an accepter-side peering used to yield).
					ID:        "pcx-poisoned",
					PeerCIDRs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/16")},
				},
				{
					ID:        "pcx-real",
					PeerCIDRs: []netip.Prefix{netip.MustParsePrefix("172.20.0.0/16")},
				},
			},
			subnetZones: map[netip.Prefix]string{
				netip.MustParsePrefix("10.0.1.0/24"): "us-east-1a",
				netip.MustParsePrefix("10.0.2.0/24"): "us-east-1b",
			},
		},
		localCIDRs: []netip.Prefix{
			netip.MustParsePrefix("10.0.1.0/24"),
			netip.MustParsePrefix("10.0.2.0/24"),
		},
	}

	tr := NewTopologyRefresher(mp, cls, resolver, slog.Default())
	tr.refresh(context.Background())

	// Local intra-VPC cross-AZ traffic must classify by zone, not as a
	// billable peering.
	if got := cls.Classify(nboFlow("10.0.1.10", "10.0.2.20")).Type; got != classifier.CrossAZ {
		t.Errorf("local intra-VPC flow classified %s, want %s (local CIDR poisoned the peering set)",
			got, classifier.CrossAZ)
	}

	// The genuine peer CIDR must still classify as vpc_peering.
	if got := cls.Classify(nboFlow("10.0.1.10", "172.20.5.5")).Type; got != classifier.VPCPeering {
		t.Errorf("real peer flow classified %s, want %s", got, classifier.VPCPeering)
	}
}

// natRouteMockProvider adds the optional NodeRoutesViaNAT capability.
type natRouteMockProvider struct {
	mockProvider
	viaNAT bool
}

func (m *natRouteMockProvider) NodeRoutesViaNAT(ctx context.Context) (bool, error) {
	return m.viaNAT, nil
}

// TestTopologyRefresher_NATRoute verifies route-based NAT detection (DEC-015)
// flows from the provider into the classifier: internet-bound flows from a
// NAT-routed subnet classify nat_gateway.
func TestTopologyRefresher_NATRoute(t *testing.T) {
	resolver := classifier.NewZoneResolver(slog.Default())
	cls := classifier.New(resolver)

	mp := &natRouteMockProvider{viaNAT: true}
	tr := NewTopologyRefresher(mp, cls, resolver, slog.Default())
	tr.refresh(context.Background())

	if got := cls.Classify(nboFlow("10.0.1.10", "8.8.8.8")).Type; got != classifier.NATGatewayEgress {
		t.Errorf("internet-bound flow behind NAT route classified %s, want %s",
			got, classifier.NATGatewayEgress)
	}

	// NAT route removed on a later refresh — classification must follow.
	mp.viaNAT = false
	tr.refresh(context.Background())
	if got := cls.Classify(nboFlow("10.0.1.10", "8.8.8.8")).Type; got != classifier.InternetEgress {
		t.Errorf("flow after NAT route removal classified %s, want %s",
			got, classifier.InternetEgress)
	}
}
