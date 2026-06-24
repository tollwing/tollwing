// Package cost implements the cost calculation engine with tiered pricing
// and rate card management for cloud network traffic.
package cost

import (
	"math"
	"sync"
	"time"

	"github.com/tollwing/tollwing/pkg/classifier"
)

// RateCard holds pricing data for a specific cloud provider and region.
type RateCard struct {
	Provider    string // "aws", "gcp", "azure"
	Region      string // e.g., "us-east-1"
	Rates       map[classifier.TrafficType]TieredRate
	NATGateway  NATGatewayRate
	TransitGW   TransitGWRate
	LastUpdated time.Time
}

// TieredRate represents tiered pricing with sorted thresholds.
type TieredRate struct {
	Tiers []Tier // sorted by UpToGB ascending
}

// Tier represents a single pricing tier.
type Tier struct {
	UpToGB float64 // cumulative GB threshold; math.Inf(1) for the last tier
	PerGB  float64 // price per GB in USD
}

// NATGatewayRate represents NAT gateway pricing (fixed + per-GB).
type NATGatewayRate struct {
	PerHourUSD float64
	PerGBUSD   float64
}

// TransitGWRate represents transit gateway pricing.
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

// DefaultAWSRateCard returns the default AWS rate card for a given region.
// These are approximate list prices and should be updated from the AWS Price List API.
func DefaultAWSRateCard(region string) *RateCard {
	return &RateCard{
		Provider: "aws",
		Region:   region,
		Rates: map[classifier.TrafficType]TieredRate{
			classifier.SameZone:    {Tiers: []Tier{{UpToGB: math.Inf(1), PerGB: 0}}},
			classifier.CrossAZ:     {Tiers: []Tier{{UpToGB: math.Inf(1), PerGB: 0.01}}},
			classifier.CrossRegion: {Tiers: []Tier{{UpToGB: math.Inf(1), PerGB: 0.02}}},
			classifier.InternetEgress: {Tiers: []Tier{
				{UpToGB: 1, PerGB: 0},              // first 1 GB/month free
				{UpToGB: 10 * 1024, PerGB: 0.09},   // up to 10 TB
				{UpToGB: 40 * 1024, PerGB: 0.085},  // 10-40 TB
				{UpToGB: 150 * 1024, PerGB: 0.07},  // 40-150 TB
				{UpToGB: math.Inf(1), PerGB: 0.05}, // 150 TB+
			}},
			classifier.VPCPeering:         {Tiers: []Tier{{UpToGB: math.Inf(1), PerGB: 0.01}}},
			classifier.VPCEndpoint:        {Tiers: []Tier{{UpToGB: math.Inf(1), PerGB: 0.01}}},
			classifier.CloudServicePublic: {Tiers: []Tier{{UpToGB: math.Inf(1), PerGB: 0}}},
		},
		NATGateway: NATGatewayRate{
			PerHourUSD: 0.045,
			PerGBUSD:   0.045,
		},
		TransitGW: TransitGWRate{
			PerAttachmentHourUSD: 0.05,
			PerGBUSD:             0.02,
		},
		LastUpdated: time.Now(),
	}
}

// DefaultGCPRateCard returns the default GCP rate card.
func DefaultGCPRateCard(region string) *RateCard {
	return &RateCard{
		Provider: "gcp",
		Region:   region,
		Rates: map[classifier.TrafficType]TieredRate{
			classifier.SameZone:    {Tiers: []Tier{{UpToGB: math.Inf(1), PerGB: 0}}},
			classifier.CrossAZ:     {Tiers: []Tier{{UpToGB: math.Inf(1), PerGB: 0}}}, // free intra-region on GCP
			classifier.CrossRegion: {Tiers: []Tier{{UpToGB: math.Inf(1), PerGB: 0.01}}},
			classifier.InternetEgress: {Tiers: []Tier{
				{UpToGB: 1, PerGB: 0},
				{UpToGB: 10 * 1024, PerGB: 0.085},
				{UpToGB: math.Inf(1), PerGB: 0.05},
			}},
			classifier.VPCPeering:         {Tiers: []Tier{{UpToGB: math.Inf(1), PerGB: 0}}},
			classifier.VPCEndpoint:        {Tiers: []Tier{{UpToGB: math.Inf(1), PerGB: 0}}},
			classifier.CloudServicePublic: {Tiers: []Tier{{UpToGB: math.Inf(1), PerGB: 0}}},
		},
		NATGateway: NATGatewayRate{
			PerHourUSD: 0,
			PerGBUSD:   0.045,
		},
		TransitGW: TransitGWRate{
			PerAttachmentHourUSD: 0,
			PerGBUSD:             0,
		},
		LastUpdated: time.Now(),
	}
}

// DefaultAzureRateCard returns the default Azure rate card.
func DefaultAzureRateCard(region string) *RateCard {
	return &RateCard{
		Provider: "azure",
		Region:   region,
		Rates: map[classifier.TrafficType]TieredRate{
			classifier.SameZone:    {Tiers: []Tier{{UpToGB: math.Inf(1), PerGB: 0}}},
			classifier.CrossAZ:     {Tiers: []Tier{{UpToGB: math.Inf(1), PerGB: 0.01}}},
			classifier.CrossRegion: {Tiers: []Tier{{UpToGB: math.Inf(1), PerGB: 0.02}}},
			classifier.InternetEgress: {Tiers: []Tier{
				{UpToGB: 5, PerGB: 0},
				{UpToGB: 10 * 1024, PerGB: 0.087},
				{UpToGB: 40 * 1024, PerGB: 0.083},
				{UpToGB: 150 * 1024, PerGB: 0.07},
				{UpToGB: math.Inf(1), PerGB: 0.05},
			}},
			classifier.VPCPeering:         {Tiers: []Tier{{UpToGB: math.Inf(1), PerGB: 0}}},
			classifier.VPCEndpoint:        {Tiers: []Tier{{UpToGB: math.Inf(1), PerGB: 0.01}}},
			classifier.CloudServicePublic: {Tiers: []Tier{{UpToGB: math.Inf(1), PerGB: 0}}},
		},
		NATGateway: NATGatewayRate{
			PerHourUSD: 0.045,
			PerGBUSD:   0.045,
		},
		TransitGW: TransitGWRate{
			PerAttachmentHourUSD: 0.05,
			PerGBUSD:             0.02,
		},
		LastUpdated: time.Now(),
	}
}
