// Package aws implements the cloud.Provider interface for Amazon Web Services.
// Uses the AWS SDK v2 for EC2, Pricing, and Cost Explorer API calls.
package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/tollwing/tollwing/pkg/cloud"
	"github.com/tollwing/tollwing/pkg/cost"
)

// Config controls the AWS provider.
type Config struct {
	Region string
	Zone   string
	// CURLocalPath points to a local directory containing CUR CSV/CSV.gz
	// files (typically mounted from an S3 sync or shared volume). When set,
	// GetBillingData reads and parses these files. When empty, GetBillingData
	// returns an empty BillingData.
	CURLocalPath string
}

// Provider implements cloud.Provider for AWS.
type Provider struct {
	cfg     Config
	log     *slog.Logger
	ec2     ec2Client
	pricing *PricingClient

	mu            sync.RWMutex
	serviceCIDRs  map[string][]netip.Prefix // cached ip-ranges.json
	lastCIDRFetch time.Time

	rateMu     sync.RWMutex
	rateCache  map[string]*cost.RateCard
	rateExpiry map[string]time.Time
}

// New creates an AWS provider. An optional ec2Client can be injected for testing.
func New(cfg Config, log *slog.Logger) *Provider {
	return &Provider{
		cfg:          cfg,
		log:          log,
		serviceCIDRs: make(map[string][]netip.Prefix),
		rateCache:    make(map[string]*cost.RateCard),
		rateExpiry:   make(map[string]time.Time),
	}
}

// SetPricingClient injects an AWS Price List client. When nil, GetRateCard
// returns the default rate card.
func (p *Provider) SetPricingClient(c *PricingClient) {
	p.pricing = c
}

// SetEC2Client sets the EC2 API client. Used by the agent to inject
// a real SDK client after initialization or a mock for testing.
func (p *Provider) SetEC2Client(c ec2Client) {
	p.ec2 = c
}

func (p *Provider) Name() string   { return "aws" }
func (p *Provider) Region() string { return p.cfg.Region }
func (p *Provider) Zone() string   { return p.cfg.Zone }

func (p *Provider) AccountID(ctx context.Context) (string, error) {
	// In production, use STS GetCallerIdentity.
	// For now, return from IMDS.
	body, err := imdsGet(ctx, "http://169.254.169.254/latest/dynamic/instance-identity/document")
	if err != nil {
		return "", err
	}
	var doc struct {
		AccountID string `json:"accountId"`
	}
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		return "", fmt.Errorf("parse identity doc: %w", err)
	}
	return doc.AccountID, nil
}

// ec2Client is an interface for EC2 API calls, enabling testing.
type ec2Client interface {
	DescribeSubnets(ctx context.Context) ([]ec2Subnet, error)
	DescribeNatGateways(ctx context.Context) ([]ec2NatGateway, error)
	DescribeVpcPeeringConnections(ctx context.Context) ([]ec2VpcPeering, error)
	DescribeTransitGatewayAttachments(ctx context.Context) ([]ec2TGWAttachment, error)
}

// ec2 response types used for parsing.
type ec2Subnet struct {
	SubnetID         string `json:"subnetId"`
	CidrBlock        string `json:"cidrBlock"`
	AvailabilityZone string `json:"availabilityZone"`
	VpcID            string `json:"vpcId"`
}

type ec2NatGateway struct {
	NatGatewayID string          `json:"natGatewayId"`
	SubnetID     string          `json:"subnetId"`
	VpcID        string          `json:"vpcId"`
	State        string          `json:"state"`
	Addresses    []ec2NatAddress `json:"natGatewayAddresses"`
}

type ec2NatAddress struct {
	PrivateIP string `json:"privateIp"`
	PublicIP  string `json:"publicIp"`
}

type ec2VpcPeering struct {
	PeeringID    string        `json:"vpcPeeringConnectionId"`
	Status       string        `json:"statusCode"`
	RequesterVpc ec2PeeringVpc `json:"requesterVpcInfo"`
	AccepterVpc  ec2PeeringVpc `json:"accepterVpcInfo"`
}

type ec2PeeringVpc struct {
	VpcID     string `json:"vpcId"`
	OwnerID   string `json:"ownerId"`
	CidrBlock string `json:"cidrBlock"`
	Region    string `json:"region"`
}

type ec2TGWAttachment struct {
	TransitGatewayAttachmentID string `json:"transitGatewayAttachmentId"`
	TransitGatewayID           string `json:"transitGatewayId"`
	ResourceType               string `json:"resourceType"`
	ResourceID                 string `json:"resourceId"`
	State                      string `json:"state"`
}

// GetSubnetZoneMapping returns subnet CIDR → AZ mappings using EC2 DescribeSubnets.
func (p *Provider) GetSubnetZoneMapping(ctx context.Context) (map[netip.Prefix]string, error) {
	if p.ec2 == nil {
		return nil, nil
	}

	subnets, err := p.ec2.DescribeSubnets(ctx)
	if err != nil {
		return nil, fmt.Errorf("describe subnets: %w", err)
	}

	result := make(map[netip.Prefix]string, len(subnets))
	for _, s := range subnets {
		prefix, err := netip.ParsePrefix(s.CidrBlock)
		if err != nil {
			p.log.Warn("invalid subnet CIDR", "subnet", s.SubnetID, "cidr", s.CidrBlock)
			continue
		}
		result[prefix] = s.AvailabilityZone
	}

	p.log.Info("fetched subnet-to-zone mapping", "subnets", len(result))
	return result, nil
}

// GetNATGateways discovers NAT gateway ENI IPs via EC2 DescribeNatGateways.
func (p *Provider) GetNATGateways(ctx context.Context) ([]cloud.NATGateway, error) {
	if p.ec2 == nil {
		return nil, nil
	}

	natGWs, err := p.ec2.DescribeNatGateways(ctx)
	if err != nil {
		return nil, fmt.Errorf("describe nat gateways: %w", err)
	}

	var result []cloud.NATGateway
	for _, ng := range natGWs {
		if ng.State != "available" {
			continue
		}
		for _, addr := range ng.Addresses {
			gw := cloud.NATGateway{
				ID:       ng.NatGatewayID,
				SubnetID: ng.SubnetID,
				VPCID:    ng.VpcID,
			}
			if addr.PrivateIP != "" {
				if a, err := netip.ParseAddr(addr.PrivateIP); err == nil {
					gw.PrivateIP = a
				}
			}
			if addr.PublicIP != "" {
				if a, err := netip.ParseAddr(addr.PublicIP); err == nil {
					gw.PublicIP = a
				}
			}
			result = append(result, gw)
		}
	}

	p.log.Info("fetched NAT gateways", "count", len(result))
	return result, nil
}

// GetVPCPeerings discovers VPC peering connections via EC2 DescribeVpcPeeringConnections.
func (p *Provider) GetVPCPeerings(ctx context.Context) ([]cloud.VPCPeering, error) {
	if p.ec2 == nil {
		return nil, nil
	}

	peerings, err := p.ec2.DescribeVpcPeeringConnections(ctx)
	if err != nil {
		return nil, fmt.Errorf("describe vpc peerings: %w", err)
	}

	var result []cloud.VPCPeering
	for _, pc := range peerings {
		peer := pc.AccepterVpc
		var cidrs []netip.Prefix
		if peer.CidrBlock != "" {
			if prefix, err := netip.ParsePrefix(peer.CidrBlock); err == nil {
				cidrs = append(cidrs, prefix)
			}
		}
		result = append(result, cloud.VPCPeering{
			ID:            pc.PeeringID,
			PeerVPCID:     peer.VpcID,
			PeerAccountID: peer.OwnerID,
			PeerRegion:    peer.Region,
			PeerCIDRs:     cidrs,
			Status:        pc.Status,
		})
	}

	p.log.Info("fetched VPC peerings", "count", len(result))
	return result, nil
}

// GetTransitGateways discovers transit gateway attachments via EC2 DescribeTransitGatewayAttachments.
func (p *Provider) GetTransitGateways(ctx context.Context) ([]cloud.TransitGateway, error) {
	if p.ec2 == nil {
		return nil, nil
	}

	attachments, err := p.ec2.DescribeTransitGatewayAttachments(ctx)
	if err != nil {
		return nil, fmt.Errorf("describe transit gateway attachments: %w", err)
	}

	var result []cloud.TransitGateway
	for _, a := range attachments {
		if a.State != "available" {
			continue
		}
		result = append(result, cloud.TransitGateway{
			ID:             a.TransitGatewayAttachmentID,
			TransitGWID:    a.TransitGatewayID,
			AttachmentType: a.ResourceType,
			ResourceID:     a.ResourceID,
		})
	}

	p.log.Info("fetched transit gateway attachments", "count", len(result))
	return result, nil
}

// GetServiceCIDRs fetches AWS service IP ranges from ip-ranges.json.
func (p *Provider) GetServiceCIDRs(ctx context.Context) (map[string][]netip.Prefix, error) {
	p.mu.RLock()
	if time.Since(p.lastCIDRFetch) < 6*time.Hour && len(p.serviceCIDRs) > 0 {
		result := p.serviceCIDRs
		p.mu.RUnlock()
		return result, nil
	}
	p.mu.RUnlock()

	cidrs, err := fetchIPRanges(ctx, p.cfg.Region)
	if err != nil {
		return nil, err
	}

	p.mu.Lock()
	p.serviceCIDRs = cidrs
	p.lastCIDRFetch = time.Now()
	p.mu.Unlock()

	p.log.Info("fetched AWS ip-ranges.json", "services", len(cidrs))
	return cidrs, nil
}

// GetRateCard returns a rate card from the AWS Price List API, cached for
// 6 hours. Falls back to DefaultAWSRateCard when no pricing client has been
// injected or the fetch fails.
func (p *Provider) GetRateCard(ctx context.Context, region string) (*cost.RateCard, error) {
	p.rateMu.RLock()
	if card, ok := p.rateCache[region]; ok {
		if exp, ok := p.rateExpiry[region]; ok && time.Now().Before(exp) {
			p.rateMu.RUnlock()
			return card, nil
		}
	}
	p.rateMu.RUnlock()

	if p.pricing == nil {
		return cost.DefaultAWSRateCard(region), nil
	}

	card, err := p.pricing.FetchRateCard(ctx, region)
	if err != nil {
		p.log.Warn("aws price list fetch failed, using defaults", "err", err, "region", region)
		return cost.DefaultAWSRateCard(region), nil
	}

	p.rateMu.Lock()
	p.rateCache[region] = card
	p.rateExpiry[region] = time.Now().Add(6 * time.Hour)
	p.rateMu.Unlock()

	return card, nil
}

// GetBillingData parses AWS Cost and Usage Report files from the configured
// local directory. Only network-related usage types are returned. When
// CURLocalPath is empty, returns an empty BillingData.
func (p *Provider) GetBillingData(ctx context.Context, start, end time.Time) (*cost.BillingData, error) {
	if p.cfg.CURLocalPath == "" {
		return &cost.BillingData{
			Provider: "aws",
			Period:   cost.BillingPeriod{Start: start, End: end},
		}, nil
	}
	return ParseCURDirectory(ctx, p.cfg.CURLocalPath, start, end)
}

// --- ip-ranges.json parsing ---

// ipRangesDoc is the top-level structure of AWS ip-ranges.json.
type ipRangesDoc struct {
	Prefixes     []ipPrefix   `json:"prefixes"`
	IPv6Prefixes []ipv6Prefix `json:"ipv6_prefixes"`
}

type ipPrefix struct {
	IPPrefix string `json:"ip_prefix"`
	Region   string `json:"region"`
	Service  string `json:"service"`
}

type ipv6Prefix struct {
	IPv6Prefix string `json:"ipv6_prefix"`
	Region     string `json:"region"`
	Service    string `json:"service"`
}

const ipRangesURL = "https://ip-ranges.amazonaws.com/ip-ranges.json"

// fetchIPRanges downloads and parses AWS ip-ranges.json, filtering by region.
func fetchIPRanges(ctx context.Context, region string) (map[string][]netip.Prefix, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", ipRangesURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch ip-ranges.json: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("ip-ranges.json returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024)) // 10 MB limit
	if err != nil {
		return nil, fmt.Errorf("read ip-ranges.json: %w", err)
	}

	var doc ipRangesDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("parse ip-ranges.json: %w", err)
	}

	result := make(map[string][]netip.Prefix)
	for _, p := range doc.Prefixes {
		// Filter to relevant region or GLOBAL services.
		if region != "" && p.Region != region && p.Region != "GLOBAL" {
			continue
		}
		prefix, err := netip.ParsePrefix(p.IPPrefix)
		if err != nil {
			continue
		}
		svc := strings.ToLower(p.Service)
		result[svc] = append(result[svc], prefix)
	}

	return result, nil
}

func imdsGet(ctx context.Context, url string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(body)), nil
}
