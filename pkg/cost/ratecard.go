// Package cost implements the cost calculation engine with tiered pricing
// and rate card management for cloud network traffic.
package cost

import (
	"math"
	"sync"
	"time"

	"github.com/tollwing/tollwing/pkg/classifier"
)

// MeteredDirection states which direction(s) of a flow's bytes are billable
// at the observing node for a given traffic type (DEC-014). Providers do not
// bill every byte in both directions: AWS charges cross-AZ traffic in each
// direction, but internet egress and cross-region transfer bill the egress
// side only. Blanket Tx+Rx metering double-charged Rx-heavy egress flows.
type MeteredDirection uint8

const (
	// MeterTxRx bills both directions at the observing node (e.g. AWS
	// cross-AZ: $0.01/GB out at the sender plus $0.01/GB in at the
	// receiver — each node's agent meters its own in+out, so the fleet
	// sum reproduces the bill without double counting).
	MeterTxRx MeteredDirection = iota
	// MeterTx bills the transmit direction only (internet egress,
	// cross-region: ingress is free on all three providers).
	MeterTx
	// MeterRx bills the receive direction only. No current rate uses it;
	// it exists so the table can express any provider semantics.
	MeterRx
	// MeterNone bills neither direction.
	MeterNone
)

// RateCard holds pricing data for a specific cloud provider and region.
type RateCard struct {
	Provider   string // "aws", "gcp", "azure"
	Region     string // e.g., "us-east-1"
	Rates      map[classifier.TrafficType]TieredRate
	NATGateway NATGatewayRate
	TransitGW  TransitGWRate

	// Directions is the per-traffic-type metered-direction table (DEC-014).
	// Traffic types missing from the table meter both directions.
	Directions map[classifier.TrafficType]MeteredDirection

	// LastUpdated dates the rates (P4: every displayed dollar is
	// bytes × dated-rate). Default cards carry the date the hardcoded
	// list prices were last verified against the provider's pricing
	// pages, NOT time.Now() — a stale default must look stale.
	LastUpdated time.Time

	// Source names where the rates came from (e.g. "aws-price-list-api",
	// "defaults (list prices verified 2026-07-02)").
	Source string

	// Fallback is true when these rates substitute for a live pricing
	// fetch that failed or was never configured. Per P4, callers must be
	// able to surface that displayed dollars come from dated defaults
	// rather than the provider's live price sheet.
	Fallback bool
}

// MeteredBytes returns the bytes of a flow that are billable at the observing
// node for the given traffic type, per the card's metered-direction table
// (DEC-014). Types absent from the table meter both directions.
func (c *RateCard) MeteredBytes(tt classifier.TrafficType, txBytes, rxBytes uint64) uint64 {
	switch c.Directions[tt] {
	case MeterTx:
		return txBytes
	case MeterRx:
		return rxBytes
	case MeterNone:
		return 0
	default: // MeterTxRx
		return txBytes + rxBytes
	}
}

// TieredRate represents tiered pricing with sorted thresholds.
type TieredRate struct {
	Tiers []Tier // sorted by UpToGB ascending
}

// MarginalRate returns the per-GB price of the first paid tier — the rate a
// marginal metered gigabyte costs once any monthly free allowance is used up.
// Per DEC-014 this is the default (distributed-honest) price: a fleet of
// per-node engines cannot know the account's true tier position, so each
// prices at the post-free-tier list rate instead of granting itself the free
// tier N times.
func (r TieredRate) MarginalRate() float64 {
	for _, t := range r.Tiers {
		if t.PerGB > 0 {
			return t.PerGB
		}
	}
	return 0
}

// Tier represents a single pricing tier.
type Tier struct {
	UpToGB float64 // cumulative GB threshold; math.Inf(1) for the last tier
	PerGB  float64 // price per GB in USD
}

// NATGatewayRate represents NAT gateway pricing (fixed + per-GB).
// PerHourUSD is deliberately never folded into per-flow cost — a fixed hourly
// charge is not traceable to a flow's bytes × rate (P4) and splitting it over
// flows would be a guess (P5). It surfaces through billing reconciliation's
// unaccounted bucket instead. See DEC-015.
type NATGatewayRate struct {
	PerHourUSD float64
	PerGBUSD   float64
}

// TransitGWRate represents transit gateway pricing. PerAttachmentHourUSD is
// excluded from per-flow cost for the same reason as NATGatewayRate.PerHourUSD
// (DEC-015).
type TransitGWRate struct {
	PerAttachmentHourUSD float64
	PerGBUSD             float64
}

// RateCardStore manages rate cards for multiple provider/region combinations.
type RateCardStore struct {
	mu    sync.RWMutex
	cards map[string]*RateCard // key: "provider:region"
}

// NewRateCardStore creates an empty rate card store.
func NewRateCardStore() *RateCardStore {
	return &RateCardStore{
		cards: make(map[string]*RateCard),
	}
}

// Set stores or updates a rate card.
func (s *RateCardStore) Set(card *RateCard) {
	s.mu.Lock()
	s.cards[card.Provider+":"+card.Region] = card
	s.mu.Unlock()
}

// Get retrieves a rate card for a provider and region.
func (s *RateCardStore) Get(provider, region string) *RateCard {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cards[provider+":"+region]
}

// defaultRatesAsOf is the date the hardcoded list prices below were last
// verified against the providers' published pricing pages. Per P4 a rate
// without a date is untraceable; the default cards stamp LastUpdated with
// this date, not time.Now(). Source URLs are recorded in DEC-014.
var defaultRatesAsOf = time.Date(2026, time.July, 2, 0, 0, 0, 0, time.UTC)

// defaultRatesSource labels the default cards for staleness reporting (P4).
const defaultRatesSource = "defaults (list prices verified 2026-07-02, DEC-014)"

// DefaultMeteredDirections returns the metered-direction table for a
// provider's default rate card (DEC-014). Exported so the live pricing
// clients (pkg/cloud/{aws,gcp,azure}) inherit the same direction semantics —
// the provider APIs publish prices, not billing directions.
func DefaultMeteredDirections(provider string) map[classifier.TrafficType]MeteredDirection {
	switch provider {
	case "gcp":
		return map[classifier.TrafficType]MeteredDirection{
			classifier.SameZone: MeterTxRx, // $0 either way
			// GCP bills egress to the sending project only; the peer's
			// egress (our Rx) is billed to the peer VM, whose own agent
			// meters it.
			classifier.CrossAZ:        MeterTx,
			classifier.CrossRegion:    MeterTx,
			classifier.InternetEgress: MeterTx,
			classifier.VPCPeering:     MeterTx,
			// PSC consumer data processing is charged both inbound and
			// outbound.
			classifier.VPCEndpoint: MeterTxRx,
			// Cloud NAT data processing applies to both directions.
			classifier.NATGatewayEgress:   MeterTxRx,
			classifier.TransitGateway:     MeterTx,
			classifier.CloudServicePublic: MeterTx,
		}
	case "azure":
		return map[classifier.TrafficType]MeteredDirection{
			classifier.SameZone:       MeterTxRx, // $0 either way
			classifier.CrossAZ:        MeterTxRx, // $0 — inter-AZ charges retired
			classifier.CrossRegion:    MeterTx,   // billed on egress from the source region
			classifier.InternetEgress: MeterTx,   // ingress is free
			// VNet peering bills ingress AND egress at both ends.
			classifier.VPCPeering: MeterTxRx,
			// Private Link data processing is billed inbound and outbound.
			classifier.VPCEndpoint: MeterTxRx,
			// NAT Gateway data processing covers outbound and return data.
			classifier.NATGatewayEgress:   MeterTxRx,
			classifier.TransitGateway:     MeterTx,
			classifier.CloudServicePublic: MeterTx,
		}
	default: // "aws"
		return map[classifier.TrafficType]MeteredDirection{
			classifier.SameZone: MeterTxRx, // $0 either way
			// Cross-AZ is $0.01/GB "in each direction": this node pays
			// for its Tx (out) and its Rx (in); the peer node's agent
			// meters the same wire bytes from its side.
			classifier.CrossAZ:        MeterTxRx,
			classifier.CrossRegion:    MeterTx, // inter-region DTO bills the sending side
			classifier.InternetEgress: MeterTx, // data transfer IN from the internet is free
			// Intra-region peering bills each direction like cross-AZ.
			classifier.VPCPeering: MeterTxRx,
			// PrivateLink interface endpoints bill data processed in
			// both directions.
			classifier.VPCEndpoint: MeterTxRx,
			// NAT data processing applies to every GB through the
			// gateway regardless of direction.
			classifier.NATGatewayEgress: MeterTxRx,
			// TGW data processing bills data sent INTO the TGW from this
			// VPC's attachment; the Rx bytes were billed to the sender's
			// attachment.
			classifier.TransitGateway:     MeterTx,
			classifier.CloudServicePublic: MeterTx,
		}
	}
}

// DefaultAWSRateCard returns the default AWS rate card for a given region.
// List prices for us-east-1, verified against the AWS pricing pages on
// defaultRatesAsOf (sources in DEC-014); overridden by the AWS Price List API
// when a pricing client is wired.
func DefaultAWSRateCard(region string) *RateCard {
	return &RateCard{
		Provider: "aws",
		Region:   region,
		Rates: map[classifier.TrafficType]TieredRate{
			classifier.SameZone: {Tiers: []Tier{{UpToGB: math.Inf(1), PerGB: 0}}},
			// $0.01/GB in each direction across AZs in the same region.
			classifier.CrossAZ: {Tiers: []Tier{{UpToGB: math.Inf(1), PerGB: 0.01}}},
			// us-east-1 → other regions: $0.02/GB (egress side only).
			classifier.CrossRegion: {Tiers: []Tier{{UpToGB: math.Inf(1), PerGB: 0.02}}},
			classifier.InternetEgress: {Tiers: []Tier{
				// First 100 GB/month free — aggregated ACROSS the whole
				// account (all services, all regions) since Dec 2021.
				// Only the single-meter pricing mode may grant it
				// (DEC-014); the default marginal mode prices at the
				// first paid tier.
				{UpToGB: 100, PerGB: 0},
				{UpToGB: 10 * 1024, PerGB: 0.09},   // up to 10 TB/mo
				{UpToGB: 50 * 1024, PerGB: 0.085},  // next 40 TB (10–50 TB)
				{UpToGB: 150 * 1024, PerGB: 0.07},  // next 100 TB (50–150 TB)
				{UpToGB: math.Inf(1), PerGB: 0.05}, // 150 TB+
			}},
			// Intra-region peering: $0.01/GB each direction (same-AZ
			// peering is free, but the peer's AZ is not observable here —
			// the cross-AZ rate is the documented conservative choice,
			// DEC-014).
			classifier.VPCPeering: {Tiers: []Tier{{UpToGB: math.Inf(1), PerGB: 0.01}}},
			// PrivateLink interface endpoint data processing (first 1 PB).
			classifier.VPCEndpoint:        {Tiers: []Tier{{UpToGB: math.Inf(1), PerGB: 0.01}}},
			classifier.CloudServicePublic: {Tiers: []Tier{{UpToGB: math.Inf(1), PerGB: 0}}},
		},
		NATGateway: NATGatewayRate{
			PerHourUSD: 0.045, // per gateway-hour; not per-flow (DEC-015)
			PerGBUSD:   0.045, // data processing, both directions
		},
		TransitGW: TransitGWRate{
			PerAttachmentHourUSD: 0.05, // not per-flow (DEC-015)
			PerGBUSD:             0.02, // data processing on bytes sent into the TGW
		},
		Directions:  DefaultMeteredDirections("aws"),
		LastUpdated: defaultRatesAsOf,
		Source:      defaultRatesSource,
	}
}

// DefaultGCPRateCard returns the default GCP rate card. List prices for
// us-central1 (Premium Tier, North American destinations), verified against
// the GCP network pricing pages on defaultRatesAsOf (sources in DEC-014).
func DefaultGCPRateCard(region string) *RateCard {
	return &RateCard{
		Provider: "gcp",
		Region:   region,
		Rates: map[classifier.TrafficType]TieredRate{
			classifier.SameZone: {Tiers: []Tier{{UpToGB: math.Inf(1), PerGB: 0}}},
			// Inter-zone traffic within a region is $0.01/GiB, billed to
			// the sending project — NOT free (the old $0 constant here
			// under-reported every GKE cross-zone byte).
			classifier.CrossAZ: {Tiers: []Tier{{UpToGB: math.Inf(1), PerGB: 0.01}}},
			// Inter-region within North America: $0.02/GiB.
			classifier.CrossRegion: {Tiers: []Tier{{UpToGB: math.Inf(1), PerGB: 0.02}}},
			classifier.InternetEgress: {Tiers: []Tier{
				// Premium Tier to worldwide destinations. GCP's 1 GiB/mo
				// "Always Free" allowance is an account-level program,
				// not a rate tier — modelling it per-engine would grant
				// it N times (DEC-014), so it is deliberately absent.
				{UpToGB: 1024, PerGB: 0.12},        // 0–1 TiB/mo
				{UpToGB: 10 * 1024, PerGB: 0.11},   // 1–10 TiB
				{UpToGB: math.Inf(1), PerGB: 0.08}, // 10 TiB+
			}},
			// VPC Network Peering bills at standard inter-zone/inter-region
			// rates; cross-zone same-region is the common case.
			classifier.VPCPeering: {Tiers: []Tier{{UpToGB: math.Inf(1), PerGB: 0.01}}},
			// Private Service Connect consumer data processing.
			classifier.VPCEndpoint:        {Tiers: []Tier{{UpToGB: math.Inf(1), PerGB: 0.01}}},
			classifier.CloudServicePublic: {Tiers: []Tier{{UpToGB: math.Inf(1), PerGB: 0}}},
		},
		NATGateway: NATGatewayRate{
			// Cloud NAT: $0.0014/VM-hour capped at $0.044/hour per
			// gateway; hourly is not per-flow (DEC-015).
			PerHourUSD: 0.044,
			PerGBUSD:   0.045, // data processing, both directions
		},
		TransitGW: TransitGWRate{
			// GCP has no transit gateway equivalent priced here (NCC is
			// not modelled); the provider returns no TGW attachments.
			PerAttachmentHourUSD: 0,
			PerGBUSD:             0,
		},
		Directions:  DefaultMeteredDirections("gcp"),
		LastUpdated: defaultRatesAsOf,
		Source:      defaultRatesSource,
	}
}

// DefaultAzureRateCard returns the default Azure rate card. List prices for
// eastus (bandwidth Zone 1), verified against the Azure pricing pages on
// defaultRatesAsOf (sources in DEC-014).
func DefaultAzureRateCard(region string) *RateCard {
	return &RateCard{
		Provider: "azure",
		Region:   region,
		Rates: map[classifier.TrafficType]TieredRate{
			classifier.SameZone: {Tiers: []Tier{{UpToGB: math.Inf(1), PerGB: 0}}},
			// Azure retired inter-availability-zone data transfer charges
			// (announced May 2024; the planned $0.01/GB was cancelled).
			// The old $0.01 constant here over-billed every cross-AZ byte.
			classifier.CrossAZ: {Tiers: []Tier{{UpToGB: math.Inf(1), PerGB: 0}}},
			// Between regions within North America: $0.02/GB (egress side).
			classifier.CrossRegion: {Tiers: []Tier{{UpToGB: math.Inf(1), PerGB: 0.02}}},
			classifier.InternetEgress: {Tiers: []Tier{
				// First 100 GB/month free, account-aggregated — single-
				// meter mode only (DEC-014). The old 5 GB constant was
				// stale.
				{UpToGB: 100, PerGB: 0},
				{UpToGB: 10 * 1024, PerGB: 0.087},  // up to 10 TB/mo
				{UpToGB: 50 * 1024, PerGB: 0.083},  // next 40 TB
				{UpToGB: 150 * 1024, PerGB: 0.07},  // next 100 TB
				{UpToGB: math.Inf(1), PerGB: 0.05}, // 150 TB+
			}},
			// Intra-region VNet peering: $0.01/GB charged on BOTH ingress
			// and egress at each end (the old $0 under-reported it).
			classifier.VPCPeering: {Tiers: []Tier{{UpToGB: math.Inf(1), PerGB: 0.01}}},
			// Private Link data processing (first tier).
			classifier.VPCEndpoint:        {Tiers: []Tier{{UpToGB: math.Inf(1), PerGB: 0.01}}},
			classifier.CloudServicePublic: {Tiers: []Tier{{UpToGB: math.Inf(1), PerGB: 0}}},
		},
		NATGateway: NATGatewayRate{
			PerHourUSD: 0.045, // per resource-hour; not per-flow (DEC-015)
			PerGBUSD:   0.045, // data processed, both directions
		},
		TransitGW: TransitGWRate{
			// Azure vWAN hubs are not modelled; the provider returns no
			// TGW attachments.
			PerAttachmentHourUSD: 0,
			PerGBUSD:             0,
		},
		Directions:  DefaultMeteredDirections("azure"),
		LastUpdated: defaultRatesAsOf,
		Source:      defaultRatesSource,
	}
}
