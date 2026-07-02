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
	// SubnetID is this node's subnet. When empty it is discovered from
	// IMDS via the primary ENI's MAC (meta-data/mac →
	// network/interfaces/macs/<mac>/subnet-id). Used by NodeRoutesViaNAT
	// for route-based NAT detection (DEC-015).
	SubnetID string
	// VPCID is this node's VPC. When empty it is discovered from IMDS via
	// the primary ENI's MAC (network/interfaces/macs/<mac>/vpc-id). Used
	// to pick the remote side of each peering connection and to scope
	// route-table lookups to this node's VPC.
	VPCID string
	// CURLocalPath points to a local directory containing CUR CSV/CSV.gz
	// files (typically mounted from an S3 sync or shared volume). When set,
	// GetBillingData reads and parses these files. When empty, GetBillingData
	// returns an empty BillingData.
	CURLocalPath string
}

// imdsDefaultBase is the link-local instance metadata service endpoint.
const imdsDefaultBase = "http://169.254.169.254"

// Provider implements cloud.Provider for AWS.
type Provider struct {
	cfg     Config
	log     *slog.Logger
	ec2     ec2Client
	pricing *PricingClient

	// imdsBase is the IMDS endpoint; overridden in tests with a fake server.
	imdsBase string

	mu            sync.RWMutex
	serviceCIDRs  map[string][]netip.Prefix // cached ip-ranges.json
	lastCIDRFetch time.Time

	// vpcMu guards the cached local VPC ID. An instance cannot change VPC,
	// so a successful discovery is cached for the provider's lifetime.
	vpcMu       sync.Mutex
	cachedVPCID string

	rateMu     sync.RWMutex
	rateCache  map[string]*cost.RateCard
	rateExpiry map[string]time.Time
}

// New creates an AWS provider. An optional ec2Client can be injected for testing.
func New(cfg Config, log *slog.Logger) *Provider {
	return &Provider{
		cfg:          cfg,
		log:          log,
		imdsBase:     imdsDefaultBase,
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
	body, err := imdsGet(ctx, p.imdsBase+"/latest/dynamic/instance-identity/document")
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
	// DescribeRouteTables lists route tables. A non-empty vpcID applies a
	// server-side vpc-id filter: another VPC's tables (in particular its
	// main table) must never decide this node's routing.
	DescribeRouteTables(ctx context.Context, vpcID string) ([]ec2RouteTable, error)
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

type ec2RouteTable struct {
	RouteTableID string             `json:"routeTableId"`
	VpcID        string             `json:"vpcId"`
	Associations []ec2RTAssociation `json:"associations"`
	Routes       []ec2Route         `json:"routes"`
}

type ec2RTAssociation struct {
	SubnetID string `json:"subnetId"`
	Main     bool   `json:"main"`
}

type ec2Route struct {
	DestinationCidrBlock string `json:"destinationCidrBlock"`
	GatewayID            string `json:"gatewayId"`
	NatGatewayID         string `json:"natGatewayId"`
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
//
// Per P5, the reported peer is the side of the connection that is NOT this
// node's VPC. A peering connection is symmetric — this VPC can be the
// requester OR the accepter — and always reporting the accepter registered
// the LOCAL VPC's own CIDR as a "peer" on accepter-side peerings, repricing
// every non-cluster RFC 1918 flow inside the local VPC as vpc_peering while
// the real peer's CIDR was never registered at all.
func (p *Provider) GetVPCPeerings(ctx context.Context) ([]cloud.VPCPeering, error) {
	if p.ec2 == nil {
		return nil, nil
	}

	localVPC, err := p.nodeVPCID(ctx)
	if err != nil {
		return nil, fmt.Errorf("resolve local vpc for peering sides: %w", err)
	}

	peerings, err := p.ec2.DescribeVpcPeeringConnections(ctx)
	if err != nil {
		return nil, fmt.Errorf("describe vpc peerings: %w", err)
	}

	var result []cloud.VPCPeering
	for _, pc := range peerings {
		var peer ec2PeeringVpc
		switch localVPC {
		case pc.RequesterVpc.VpcID:
			peer = pc.AccepterVpc
		case pc.AccepterVpc.VpcID:
			peer = pc.RequesterVpc
		default:
			// Neither side is this node's VPC: a peering visible via
			// cross-account/foreign API visibility. Its CIDRs say nothing
			// about traffic this node can send over a peering.
			p.log.Warn("vpc peering does not involve the local VPC, skipping",
				"peering", pc.PeeringID,
				"requester_vpc", pc.RequesterVpc.VpcID,
				"accepter_vpc", pc.AccepterVpc.VpcID,
				"local_vpc", localVPC)
			continue
		}
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

	p.log.Info("fetched VPC peerings", "count", len(result), "local_vpc", localVPC)
	return result, nil
}

// LocalVPCCIDRs returns the CIDR blocks of the subnets in this node's VPC.
// The topology refresher uses them as a belt-and-braces guard: a "peering"
// CIDR overlapping the local VPC's own address space is never a real peer
// (AWS refuses to peer VPCs with overlapping CIDRs) and must not enter the
// classifier's peering prefix set.
func (p *Provider) LocalVPCCIDRs(ctx context.Context) ([]netip.Prefix, error) {
	if p.ec2 == nil {
		return nil, nil
	}

	vpcID, err := p.nodeVPCID(ctx)
	if err != nil {
		return nil, fmt.Errorf("resolve local vpc: %w", err)
	}

	subnets, err := p.ec2.DescribeSubnets(ctx)
	if err != nil {
		return nil, fmt.Errorf("describe subnets: %w", err)
	}

	var result []netip.Prefix
	for _, s := range subnets {
		if s.VpcID != vpcID {
			continue
		}
		prefix, err := netip.ParsePrefix(s.CidrBlock)
		if err != nil {
			p.log.Warn("invalid subnet CIDR", "subnet", s.SubnetID, "cidr", s.CidrBlock)
			continue
		}
		result = append(result, prefix)
	}
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

// NodeRoutesViaNAT reports whether this node's subnet default-routes
// (0.0.0.0/0) through a NAT gateway (DEC-015). Internet-bound flows from such
// subnets incur NAT data-processing charges even though the flow destination
// stays the internet IP, so IP-based NAT detection can never see them —
// route knowledge is the only honest attribution.
func (p *Provider) NodeRoutesViaNAT(ctx context.Context) (bool, error) {
	if p.ec2 == nil {
		return false, fmt.Errorf("nat route detection: no EC2 client configured")
	}

	subnetID, err := p.nodeSubnetID(ctx)
	if err != nil {
		return false, fmt.Errorf("resolve node subnet: %w", err)
	}
	vpcID, err := p.nodeVPCID(ctx)
	if err != nil {
		return false, fmt.Errorf("resolve node vpc: %w", err)
	}

	// Scope the lookup to this node's VPC. Unfiltered, the main-table
	// fallback below picked up whichever VPC's main table the API returned
	// last, so a DIFFERENT VPC's default route decided this node's NAT flag
	// — flipping with API ordering.
	tables, err := p.ec2.DescribeRouteTables(ctx, vpcID)
	if err != nil {
		return false, fmt.Errorf("describe route tables: %w", err)
	}

	// Prefer the route table explicitly associated with the subnet; fall
	// back to this VPC's main route table (AWS semantics for subnets with
	// no explicit association).
	var mainTable *ec2RouteTable
	for i := range tables {
		rt := &tables[i]
		// Defense in depth against clients that ignore the vpc-id filter:
		// never let another VPC's tables into the decision.
		if rt.VpcID != "" && rt.VpcID != vpcID {
			continue
		}
		for _, assoc := range rt.Associations {
			if assoc.SubnetID == subnetID {
				return routeTableDefaultsToNAT(rt), nil
			}
			if assoc.Main {
				mainTable = rt
			}
		}
	}
	if mainTable != nil {
		return routeTableDefaultsToNAT(mainTable), nil
	}
	return false, nil
}

// routeTableDefaultsToNAT reports whether a route table's default route
// (0.0.0.0/0) targets a NAT gateway.
func routeTableDefaultsToNAT(rt *ec2RouteTable) bool {
	for _, r := range rt.Routes {
		if r.DestinationCidrBlock == "0.0.0.0/0" {
			return r.NatGatewayID != ""
		}
	}
	return false
}

// primaryMAC returns the primary ENI's MAC from the top-level IMDS
// meta-data/mac field. That field is guaranteed to be the primary interface;
// the network/interfaces/macs/ listing is NOT ordered, and on multi-ENI
// nodes (EKS VPC-CNI custom networking) taking its first entry could pick a
// secondary pod-ENI and evaluate the wrong subnet's route table.
func (p *Provider) primaryMAC(ctx context.Context) (string, error) {
	mac, err := imdsGet(ctx, p.imdsBase+"/latest/meta-data/mac")
	if err != nil {
		return "", fmt.Errorf("imds primary mac: %w", err)
	}
	if mac == "" {
		return "", fmt.Errorf("imds returned an empty primary mac")
	}
	return mac, nil
}

// nodeSubnetID returns the node's subnet: the configured override, or IMDS
// discovery via the primary interface's MAC.
func (p *Provider) nodeSubnetID(ctx context.Context) (string, error) {
	if p.cfg.SubnetID != "" {
		return p.cfg.SubnetID, nil
	}

	mac, err := p.primaryMAC(ctx)
	if err != nil {
		return "", err
	}

	subnetID, err := imdsGet(ctx, p.imdsBase+"/latest/meta-data/network/interfaces/macs/"+mac+"/subnet-id")
	if err != nil {
		return "", fmt.Errorf("imds subnet-id for mac %s: %w", mac, err)
	}
	return subnetID, nil
}

// nodeVPCID returns the node's VPC: the configured override, or IMDS
// discovery via the primary interface's MAC. A successful discovery is
// cached — an instance cannot move between VPCs.
func (p *Provider) nodeVPCID(ctx context.Context) (string, error) {
	if p.cfg.VPCID != "" {
		return p.cfg.VPCID, nil
	}

	p.vpcMu.Lock()
	defer p.vpcMu.Unlock()
	if p.cachedVPCID != "" {
		return p.cachedVPCID, nil
	}

	mac, err := p.primaryMAC(ctx)
	if err != nil {
		return "", err
	}

	vpcID, err := imdsGet(ctx, p.imdsBase+"/latest/meta-data/network/interfaces/macs/"+mac+"/vpc-id")
	if err != nil {
		return "", fmt.Errorf("imds vpc-id for mac %s: %w", mac, err)
	}
	if vpcID == "" {
		return "", fmt.Errorf("imds returned an empty vpc-id for mac %s", mac)
	}
	p.cachedVPCID = vpcID
	return vpcID, nil
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
// 6 hours. When no pricing client is injected or the fetch fails, the dated
// default card is returned with Fallback set — per P4, live rates must never
// be silently reverted to defaults; callers can surface the staleness
// (Source + LastUpdated identify the substitute). Fallback cards are not
// cached, so the next refresh retries the live API.
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
		card := cost.DefaultAWSRateCard(region)
		card.Fallback = true
		return card, nil
	}

	card, err := p.pricing.FetchRateCard(ctx, region)
	if err != nil {
		p.log.Warn("aws price list fetch failed, serving dated default card marked as fallback",
			"err", err, "region", region)
		fb := cost.DefaultAWSRateCard(region)
		fb.Fallback = true
		return fb, nil
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
