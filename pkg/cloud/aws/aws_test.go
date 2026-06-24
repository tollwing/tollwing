package aws

import (
	"context"
	"log/slog"
	"net/netip"
	"testing"
)

// mockEC2 implements ec2Client for testing.
type mockEC2 struct {
	subnets     []ec2Subnet
	natGateways []ec2NatGateway
	peerings    []ec2VpcPeering
	tgwAttach   []ec2TGWAttachment

	subnetsErr  error
	natErr      error
	peeringsErr error
	tgwErr      error
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

func TestProvider_GetVPCPeerings(t *testing.T) {
	p := New(Config{Region: "us-east-1"}, slog.Default())
	p.SetEC2Client(&mockEC2{
		peerings: []ec2VpcPeering{
			{
				PeeringID: "pcx-1",
				Status:    "active",
				AccepterVpc: ec2PeeringVpc{
					VpcID:     "vpc-peer-1",
					OwnerID:   "123456789",
					CidrBlock: "172.16.0.0/16",
					Region:    "us-west-2",
				},
			},
		},
	})

	result, err := p.GetVPCPeerings(context.Background())
	if err != nil {
		t.Fatalf("GetVPCPeerings: %v", err)
	}

	if len(result) != 1 {
		t.Fatalf("expected 1 peering, got %d", len(result))
	}

	if result[0].PeerVPCID != "vpc-peer-1" {
		t.Errorf("PeerVPCID = %q, want vpc-peer-1", result[0].PeerVPCID)
	}
	if result[0].PeerRegion != "us-west-2" {
		t.Errorf("PeerRegion = %q, want us-west-2", result[0].PeerRegion)
	}
	if len(result[0].PeerCIDRs) != 1 {
		t.Fatalf("expected 1 CIDR, got %d", len(result[0].PeerCIDRs))
	}
	if result[0].PeerCIDRs[0] != netip.MustParsePrefix("172.16.0.0/16") {
		t.Errorf("PeerCIDR = %v, want 172.16.0.0/16", result[0].PeerCIDRs[0])
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
