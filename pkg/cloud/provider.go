// Package cloud defines the cloud provider abstraction layer.
// Each provider (AWS, GCP, Azure) implements this interface to supply
// network topology, pricing, and billing data to the cost engine.
package cloud

import (
	"context"
	"net/netip"
	"time"

	"github.com/tollwing/tollwing/pkg/cost"
)

// Provider abstracts cloud-specific operations for network cost analysis.
type Provider interface {
	// Name returns the provider identifier ("aws", "gcp", "azure").
	Name() string

	// Identity
	Region() string
	Zone() string
	AccountID(ctx context.Context) (string, error)

	// Network Topology
	GetSubnetZoneMapping(ctx context.Context) (map[netip.Prefix]string, error)
	GetNATGateways(ctx context.Context) ([]NATGateway, error)
	GetVPCPeerings(ctx context.Context) ([]VPCPeering, error)
	GetTransitGateways(ctx context.Context) ([]TransitGateway, error)
	GetServiceCIDRs(ctx context.Context) (map[string][]netip.Prefix, error)

	// Pricing
	GetRateCard(ctx context.Context, region string) (*cost.RateCard, error)

	// Billing
	GetBillingData(ctx context.Context, start, end time.Time) (*cost.BillingData, error)
}

// NATGateway represents a NAT gateway with its ENI IPs.
type NATGateway struct {
	ID        string
	Name      string
	PrivateIP netip.Addr
	PublicIP  netip.Addr
	SubnetID  string
	VPCID     string
	Zone      string
}

// VPCPeering represents a VPC peering connection with its CIDR ranges.
type VPCPeering struct {
	ID            string
	PeerVPCID     string
	PeerAccountID string
	PeerRegion    string
	PeerCIDRs     []netip.Prefix
	Status        string
}

// TransitGateway represents a transit gateway attachment.
type TransitGateway struct {
	ID             string
	TransitGWID    string
	AttachmentType string // "vpc", "peering", "vpn"
	ResourceID     string
	CIDRs          []netip.Prefix
}

// ServiceCIDREntry represents a cloud service's IP ranges.
type ServiceCIDREntry struct {
	Service string
	Region  string
	Prefix  netip.Prefix
}
