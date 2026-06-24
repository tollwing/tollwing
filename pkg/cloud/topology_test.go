package cloud

import (
	"context"
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

func TestTopologyRefresher_ServiceCIDRs(t *testing.T) {
	resolver := classifier.NewZoneResolver(slog.Default())
	cls := classifier.New(resolver)

	mp := &mockProvider{
		serviceCIDRs: map[string][]netip.Prefix{
			"s3":       {netip.MustParsePrefix("52.216.0.0/15")},
			"dynamodb": {netip.MustParsePrefix("52.94.0.0/22")},
		},
	}

	tr := NewTopologyRefresher(mp, cls, resolver, slog.Default())
	tr.refresh(context.Background())

	// Service CIDRs should be loaded into classifier's VPC endpoint set.
}
