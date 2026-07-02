package aws

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

// mockEC2 implements ec2Client for testing.
type mockEC2 struct {
	subnets     []ec2Subnet
	natGateways []ec2NatGateway
	peerings    []ec2VpcPeering
	tgwAttach   []ec2TGWAttachment
	routeTables []ec2RouteTable

	subnetsErr  error
	natErr      error
	peeringsErr error
	tgwErr      error
	routeErr    error

	// routeTablesVPCFilter records the vpc-id filter DescribeRouteTables
	// was called with. The mock deliberately does NOT apply it — returning
	// every VPC's tables exercises the caller's own VPC filtering.
	routeTablesVPCFilter string
}

func (m *mockEC2) DescribeSubnets(ctx context.Context) ([]ec2Subnet, error) {
	return m.subnets, m.subnetsErr
}

func (m *mockEC2) DescribeNatGateways(ctx context.Context) ([]ec2NatGateway, error) {
	return m.natGateways, m.natErr
}

func (m *mockEC2) DescribeVpcPeeringConnections(ctx context.Context) ([]ec2VpcPeering, error) {
	return m.peerings, m.peeringsErr
}

func (m *mockEC2) DescribeTransitGatewayAttachments(ctx context.Context) ([]ec2TGWAttachment, error) {
	return m.tgwAttach, m.tgwErr
}

func (m *mockEC2) DescribeRouteTables(ctx context.Context, vpcID string) ([]ec2RouteTable, error) {
	m.routeTablesVPCFilter = vpcID
	return m.routeTables, m.routeErr
}

func TestProvider_GetSubnetZoneMapping(t *testing.T) {
	p := New(Config{Region: "us-east-1"}, slog.Default())
	p.SetEC2Client(&mockEC2{
		subnets: []ec2Subnet{
			{SubnetID: "subnet-1", CidrBlock: "10.0.1.0/24", AvailabilityZone: "us-east-1a"},
			{SubnetID: "subnet-2", CidrBlock: "10.0.2.0/24", AvailabilityZone: "us-east-1b"},
		},
	})

	result, err := p.GetSubnetZoneMapping(context.Background())
	if err != nil {
		t.Fatalf("GetSubnetZoneMapping: %v", err)
	}

	if len(result) != 2 {
		t.Fatalf("expected 2 subnets, got %d", len(result))
	}

	prefix1 := netip.MustParsePrefix("10.0.1.0/24")
	if result[prefix1] != "us-east-1a" {
		t.Errorf("subnet-1 zone = %q, want us-east-1a", result[prefix1])
	}

	prefix2 := netip.MustParsePrefix("10.0.2.0/24")
	if result[prefix2] != "us-east-1b" {
		t.Errorf("subnet-2 zone = %q, want us-east-1b", result[prefix2])
	}
}

func TestProvider_GetSubnetZoneMapping_NilClient(t *testing.T) {
	p := New(Config{Region: "us-east-1"}, slog.Default())

	result, err := p.GetSubnetZoneMapping(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != nil {
		t.Errorf("expected nil result, got %v", result)
	}
}

func TestProvider_GetNATGateways(t *testing.T) {
	p := New(Config{Region: "us-east-1"}, slog.Default())
	p.SetEC2Client(&mockEC2{
		natGateways: []ec2NatGateway{
			{
				NatGatewayID: "nat-1",
				SubnetID:     "subnet-1",
				VpcID:        "vpc-1",
				State:        "available",
				Addresses: []ec2NatAddress{
					{PrivateIP: "10.0.1.5", PublicIP: "54.1.2.3"},
				},
			},
			{
				NatGatewayID: "nat-2",
				State:        "deleting", // should be skipped
			},
		},
	})

	result, err := p.GetNATGateways(context.Background())
	if err != nil {
		t.Fatalf("GetNATGateways: %v", err)
	}

	if len(result) != 1 {
		t.Fatalf("expected 1 NAT gateway, got %d", len(result))
	}

	if result[0].ID != "nat-1" {
		t.Errorf("ID = %q, want nat-1", result[0].ID)
	}
	if result[0].PrivateIP != netip.MustParseAddr("10.0.1.5") {
		t.Errorf("PrivateIP = %v, want 10.0.1.5", result[0].PrivateIP)
	}
	if result[0].PublicIP != netip.MustParseAddr("54.1.2.3") {
		t.Errorf("PublicIP = %v, want 54.1.2.3", result[0].PublicIP)
	}
}

// TestProvider_GetVPCPeerings verifies peer-side selection (P5): the
// reported peer must be whichever side of the connection is NOT the local
// VPC. The old code always reported the accepter, so an accepter-side
// peering registered the LOCAL VPC's own CIDR as a "peer" — repricing every
// non-cluster RFC 1918 flow inside the local VPC as vpc_peering — while the
// real (requester) peer's CIDR was never registered.
func TestProvider_GetVPCPeerings(t *testing.T) {
	local := ec2PeeringVpc{
		VpcID:     "vpc-local",
		OwnerID:   "111111111111",
		CidrBlock: "10.0.0.0/16",
		Region:    "us-east-1",
	}
	remote := ec2PeeringVpc{
		VpcID:     "vpc-peer-1",
		OwnerID:   "123456789",
		CidrBlock: "172.16.0.0/16",
		Region:    "us-west-2",
	}

	tests := []struct {
		name     string
		peering  ec2VpcPeering
		wantPeer bool // false: peering must be skipped
	}{
		{
			name: "local VPC is the requester",
			peering: ec2VpcPeering{
				PeeringID:    "pcx-1",
				Status:       "active",
				RequesterVpc: local,
				AccepterVpc:  remote,
			},
			wantPeer: true,
		},
		{
			// Regression for the accepter-side bug: the old code reported
			// pc.AccepterVpc here — the local VPC itself.
			name: "local VPC is the accepter",
			peering: ec2VpcPeering{
				PeeringID:    "pcx-2",
				Status:       "active",
				RequesterVpc: remote,
				AccepterVpc:  local,
			},
			wantPeer: true,
		},
		{
			name: "foreign peering involving neither side is skipped",
			peering: ec2VpcPeering{
				PeeringID:    "pcx-3",
				Status:       "active",
				RequesterVpc: ec2PeeringVpc{VpcID: "vpc-other-a", CidrBlock: "192.168.0.0/16"},
				AccepterVpc:  ec2PeeringVpc{VpcID: "vpc-other-b", CidrBlock: "172.31.0.0/16"},
			},
			wantPeer: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := New(Config{Region: "us-east-1", VPCID: "vpc-local"}, slog.Default())
			p.SetEC2Client(&mockEC2{peerings: []ec2VpcPeering{tt.peering}})

			result, err := p.GetVPCPeerings(context.Background())
			if err != nil {
				t.Fatalf("GetVPCPeerings: %v", err)
			}

			if !tt.wantPeer {
				if len(result) != 0 {
					t.Fatalf("expected foreign peering to be skipped, got %+v", result)
				}
				return
			}

			if len(result) != 1 {
				t.Fatalf("expected 1 peering, got %d", len(result))
			}
			if result[0].PeerVPCID != remote.VpcID {
				t.Errorf("PeerVPCID = %q, want %q (the non-local side)", result[0].PeerVPCID, remote.VpcID)
			}
			if result[0].PeerAccountID != remote.OwnerID {
				t.Errorf("PeerAccountID = %q, want %q", result[0].PeerAccountID, remote.OwnerID)
			}
			if result[0].PeerRegion != remote.Region {
				t.Errorf("PeerRegion = %q, want %q", result[0].PeerRegion, remote.Region)
			}
			if len(result[0].PeerCIDRs) != 1 {
				t.Fatalf("expected 1 CIDR, got %d", len(result[0].PeerCIDRs))
			}
			if want := netip.MustParsePrefix(remote.CidrBlock); result[0].PeerCIDRs[0] != want {
				t.Errorf("PeerCIDR = %v, want %v — the local VPC's own CIDR must never be the peer",
					result[0].PeerCIDRs[0], want)
			}
		})
	}
}

// TestProvider_LocalVPCCIDRs verifies the topology refresher's guard input:
// only subnets of the local VPC are reported.
func TestProvider_LocalVPCCIDRs(t *testing.T) {
	p := New(Config{Region: "us-east-1", VPCID: "vpc-local"}, slog.Default())
	p.SetEC2Client(&mockEC2{
		subnets: []ec2Subnet{
			{SubnetID: "subnet-1", CidrBlock: "10.0.1.0/24", VpcID: "vpc-local"},
			{SubnetID: "subnet-2", CidrBlock: "10.0.2.0/24", VpcID: "vpc-local"},
			{SubnetID: "subnet-other", CidrBlock: "172.16.1.0/24", VpcID: "vpc-other"},
		},
	})

	cidrs, err := p.LocalVPCCIDRs(context.Background())
	if err != nil {
		t.Fatalf("LocalVPCCIDRs: %v", err)
	}
	want := []netip.Prefix{
		netip.MustParsePrefix("10.0.1.0/24"),
		netip.MustParsePrefix("10.0.2.0/24"),
	}
	if len(cidrs) != len(want) {
		t.Fatalf("expected %d CIDRs, got %d: %v", len(want), len(cidrs), cidrs)
	}
	for i := range want {
		if cidrs[i] != want[i] {
			t.Errorf("cidrs[%d] = %v, want %v", i, cidrs[i], want[i])
		}
	}
}

func TestProvider_GetTransitGateways(t *testing.T) {
	p := New(Config{Region: "us-east-1"}, slog.Default())
	p.SetEC2Client(&mockEC2{
		tgwAttach: []ec2TGWAttachment{
			{
				TransitGatewayAttachmentID: "tgw-attach-1",
				TransitGatewayID:           "tgw-1",
				ResourceType:               "vpc",
				ResourceID:                 "vpc-1",
				State:                      "available",
			},
			{
				TransitGatewayAttachmentID: "tgw-attach-2",
				State:                      "deleting", // skipped
			},
		},
	})

	result, err := p.GetTransitGateways(context.Background())
	if err != nil {
		t.Fatalf("GetTransitGateways: %v", err)
	}

	if len(result) != 1 {
		t.Fatalf("expected 1 TGW attachment, got %d", len(result))
	}
	if result[0].TransitGWID != "tgw-1" {
		t.Errorf("TransitGWID = %q, want tgw-1", result[0].TransitGWID)
	}
}

// TestProvider_NodeRoutesViaNAT verifies route-based NAT detection (DEC-015):
// the node's subnet route table (or the node VPC's main table when no
// explicit association exists) decides whether internet-bound flows traverse
// a NAT gateway. The old dst==NAT-ENI check never matched real internet
// flows, and the old unfiltered lookup let ANY VPC's main table decide,
// flipping the flag with API ordering.
func TestProvider_NodeRoutesViaNAT(t *testing.T) {
	tests := []struct {
		name    string
		subnet  string
		tables  []ec2RouteTable
		want    bool
		wantErr bool
	}{
		{
			name:   "subnet default-routes through NAT",
			subnet: "subnet-1",
			tables: []ec2RouteTable{{
				RouteTableID: "rtb-1",
				VpcID:        "vpc-local",
				Associations: []ec2RTAssociation{{SubnetID: "subnet-1"}},
				Routes: []ec2Route{
					{DestinationCidrBlock: "10.0.0.0/16", GatewayID: "local"},
					{DestinationCidrBlock: "0.0.0.0/0", NatGatewayID: "nat-abc"},
				},
			}},
			want: true,
		},
		{
			name:   "subnet default-routes through IGW",
			subnet: "subnet-1",
			tables: []ec2RouteTable{{
				RouteTableID: "rtb-1",
				VpcID:        "vpc-local",
				Associations: []ec2RTAssociation{{SubnetID: "subnet-1"}},
				Routes: []ec2Route{
					{DestinationCidrBlock: "0.0.0.0/0", GatewayID: "igw-abc"},
				},
			}},
			want: false,
		},
		{
			name:   "no explicit association falls back to the main table",
			subnet: "subnet-orphan",
			tables: []ec2RouteTable{
				{
					RouteTableID: "rtb-other",
					VpcID:        "vpc-local",
					Associations: []ec2RTAssociation{{SubnetID: "subnet-other"}},
					Routes:       []ec2Route{{DestinationCidrBlock: "0.0.0.0/0", GatewayID: "igw-abc"}},
				},
				{
					RouteTableID: "rtb-main",
					VpcID:        "vpc-local",
					Associations: []ec2RTAssociation{{Main: true}},
					Routes:       []ec2Route{{DestinationCidrBlock: "0.0.0.0/0", NatGatewayID: "nat-abc"}},
				},
			},
			want: true,
		},
		{
			name:   "no default route at all",
			subnet: "subnet-1",
			tables: []ec2RouteTable{{
				RouteTableID: "rtb-1",
				VpcID:        "vpc-local",
				Associations: []ec2RTAssociation{{SubnetID: "subnet-1"}},
				Routes:       []ec2Route{{DestinationCidrBlock: "10.0.0.0/16", GatewayID: "local"}},
			}},
			want: false,
		},
		{
			// Regression: the old unfiltered fallback took the LAST main
			// table seen from ANY VPC. Here a foreign VPC's main table
			// (routing via IGW) comes last; the node VPC's main table
			// routes via NAT. Old code returned false.
			name:   "another VPC's main table must not decide the fallback",
			subnet: "subnet-orphan",
			tables: []ec2RouteTable{
				{
					RouteTableID: "rtb-main-local",
					VpcID:        "vpc-local",
					Associations: []ec2RTAssociation{{Main: true}},
					Routes:       []ec2Route{{DestinationCidrBlock: "0.0.0.0/0", NatGatewayID: "nat-abc"}},
				},
				{
					RouteTableID: "rtb-main-foreign",
					VpcID:        "vpc-foreign",
					Associations: []ec2RTAssociation{{Main: true}},
					Routes:       []ec2Route{{DestinationCidrBlock: "0.0.0.0/0", GatewayID: "igw-xyz"}},
				},
			},
			want: true,
		},
		{
			// Same shape reversed: the foreign main table routes via NAT,
			// the node VPC's does not. Old code returned true here when
			// the foreign table sorted last.
			name:   "foreign NAT main table must not turn the flag on",
			subnet: "subnet-orphan",
			tables: []ec2RouteTable{
				{
					RouteTableID: "rtb-main-local",
					VpcID:        "vpc-local",
					Associations: []ec2RTAssociation{{Main: true}},
					Routes:       []ec2Route{{DestinationCidrBlock: "0.0.0.0/0", GatewayID: "igw-abc"}},
				},
				{
					RouteTableID: "rtb-main-foreign",
					VpcID:        "vpc-foreign",
					Associations: []ec2RTAssociation{{Main: true}},
					Routes:       []ec2Route{{DestinationCidrBlock: "0.0.0.0/0", NatGatewayID: "nat-xyz"}},
				},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := New(Config{Region: "us-east-1", SubnetID: tt.subnet, VPCID: "vpc-local"}, slog.Default())
			mock := &mockEC2{routeTables: tt.tables}
			p.SetEC2Client(mock)

			got, err := p.NodeRoutesViaNAT(context.Background())
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr = %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("NodeRoutesViaNAT = %v, want %v", got, tt.want)
			}
			if mock.routeTablesVPCFilter != "vpc-local" {
				t.Errorf("DescribeRouteTables vpc filter = %q, want vpc-local (region-wide listing regressed)",
					mock.routeTablesVPCFilter)
			}
		})
	}
}

// TestProvider_GetRateCard_FallbackMarked: per P4, a failed or unconfigured
// live-pricing fetch must not silently masquerade as live rates — the served
// default card carries Fallback plus its verification date and source label.
func TestProvider_GetRateCard_FallbackMarked(t *testing.T) {
	p := New(Config{Region: "us-east-1"}, slog.Default())

	card, err := p.GetRateCard(context.Background(), "us-east-1")
	if err != nil {
		t.Fatalf("GetRateCard: %v", err)
	}
	if !card.Fallback {
		t.Error("default card served without a pricing client must be marked Fallback (P4)")
	}
	if card.LastUpdated.IsZero() {
		t.Error("fallback card must be dated (P4)")
	}
	if card.Source == "" {
		t.Error("fallback card must carry a source label (P4)")
	}
}

// newFakeIMDS serves the given IMDS paths (e.g. "/latest/meta-data/mac")
// and 404s everything else.
func newFakeIMDS(t *testing.T, paths map[string]string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := paths[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// adversarialIMDSPaths models a multi-ENI node (EKS VPC-CNI custom
// networking) whose macs/ listing puts a secondary pod-ENI FIRST. The
// top-level meta-data/mac field is the only guaranteed primary-ENI signal;
// the old first-entry heuristic picked the pod ENI's subnet/VPC here.
func adversarialIMDSPaths() map[string]string {
	const (
		primaryMAC = "0a:11:22:33:44:55"
		podENIMAC  = "0e:de:ad:be:ef:00"
	)
	return map[string]string{
		"/latest/meta-data/mac":                                                  primaryMAC,
		"/latest/meta-data/network/interfaces/macs/":                             podENIMAC + "/\n" + primaryMAC + "/",
		"/latest/meta-data/network/interfaces/macs/" + primaryMAC + "/subnet-id": "subnet-primary",
		"/latest/meta-data/network/interfaces/macs/" + primaryMAC + "/vpc-id":    "vpc-local",
		"/latest/meta-data/network/interfaces/macs/" + podENIMAC + "/subnet-id":  "subnet-pod-eni",
		"/latest/meta-data/network/interfaces/macs/" + podENIMAC + "/vpc-id":     "vpc-pod-eni",
	}
}

// TestProvider_NodeSubnetID_PrimaryENI: the node's subnet must come from the
// primary ENI (top-level meta-data/mac), not the first macs/ listing entry —
// listing order is not guaranteed and the fake lists a pod ENI first.
func TestProvider_NodeSubnetID_PrimaryENI(t *testing.T) {
	srv := newFakeIMDS(t, adversarialIMDSPaths())
	p := New(Config{Region: "us-east-1"}, slog.Default())
	p.imdsBase = srv.URL

	subnetID, err := p.nodeSubnetID(context.Background())
	if err != nil {
		t.Fatalf("nodeSubnetID: %v", err)
	}
	if subnetID != "subnet-primary" {
		t.Errorf("nodeSubnetID = %q, want subnet-primary (secondary pod-ENI listed first must not win)", subnetID)
	}
}

// TestProvider_NodeVPCID_PrimaryENI: same guarantee for the VPC ID used by
// GetVPCPeerings' peer-side selection and NodeRoutesViaNAT's table scoping.
func TestProvider_NodeVPCID_PrimaryENI(t *testing.T) {
	srv := newFakeIMDS(t, adversarialIMDSPaths())
	p := New(Config{Region: "us-east-1"}, slog.Default())
	p.imdsBase = srv.URL

	vpcID, err := p.nodeVPCID(context.Background())
	if err != nil {
		t.Fatalf("nodeVPCID: %v", err)
	}
	if vpcID != "vpc-local" {
		t.Errorf("nodeVPCID = %q, want vpc-local", vpcID)
	}

	// The VPC of an instance is immutable, so a successful discovery is
	// cached: a second call must not need IMDS at all.
	srv.Close()
	vpcID, err = p.nodeVPCID(context.Background())
	if err != nil {
		t.Fatalf("nodeVPCID (cached): %v", err)
	}
	if vpcID != "vpc-local" {
		t.Errorf("cached nodeVPCID = %q, want vpc-local", vpcID)
	}
}

// TestProvider_GetVPCPeerings_IMDSDiscoveredVPC ties findings together
// end-to-end: with no configured VPCID, the local VPC comes from IMDS via
// the primary ENI, and an accepter-side peering reports the requester's
// CIDR — never the local VPC's own.
func TestProvider_GetVPCPeerings_IMDSDiscoveredVPC(t *testing.T) {
	srv := newFakeIMDS(t, adversarialIMDSPaths())
	p := New(Config{Region: "us-east-1"}, slog.Default())
	p.imdsBase = srv.URL
	p.SetEC2Client(&mockEC2{
		peerings: []ec2VpcPeering{{
			PeeringID:    "pcx-accepter-side",
			Status:       "active",
			RequesterVpc: ec2PeeringVpc{VpcID: "vpc-peer-1", CidrBlock: "172.16.0.0/16"},
			AccepterVpc:  ec2PeeringVpc{VpcID: "vpc-local", CidrBlock: "10.0.0.0/16"},
		}},
	})

	result, err := p.GetVPCPeerings(context.Background())
	if err != nil {
		t.Fatalf("GetVPCPeerings: %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 peering, got %d", len(result))
	}
	if want := netip.MustParsePrefix("172.16.0.0/16"); len(result[0].PeerCIDRs) != 1 || result[0].PeerCIDRs[0] != want {
		t.Errorf("PeerCIDRs = %v, want [%v]", result[0].PeerCIDRs, want)
	}
}

func TestProvider_Name(t *testing.T) {
	p := New(Config{Region: "us-east-1", Zone: "us-east-1a"}, slog.Default())
	if p.Name() != "aws" {
		t.Errorf("Name() = %q, want aws", p.Name())
	}
	if p.Region() != "us-east-1" {
		t.Errorf("Region() = %q, want us-east-1", p.Region())
	}
	if p.Zone() != "us-east-1a" {
		t.Errorf("Zone() = %q, want us-east-1a", p.Zone())
	}
}
