package cost

import (
	"math"
	"testing"

	"github.com/tollwing/tollwing/pkg/classifier"
)

const gb = 1024 * 1024 * 1024 // 1 GB in bytes

// Expected dollars in these tests are derived by hand from the providers'
// published price sheets (verified 2026-07-02, sources in DEC-014) — NOT from
// the rate-card constants — so a wrong constant in ratecard.go fails here.

func TestTieredCost_FlatRate(t *testing.T) {
	tiers := []Tier{{UpToGB: math.Inf(1), PerGB: 0.01}}

	cost := tieredCost(tiers, 0, 100)
	expected := 100 * 0.01
	if !approxEqual(cost, expected) {
		t.Errorf("flat rate cost = %f, want %f", cost, expected)
	}
}

func TestTieredCost_MultiTier(t *testing.T) {
	tiers := []Tier{
		{UpToGB: 1, PerGB: 0},        // first 1 GB free
		{UpToGB: 10240, PerGB: 0.09}, // up to 10 TB
		{UpToGB: math.Inf(1), PerGB: 0.05},
	}

	// 0.5 GB — all in free tier.
	cost := tieredCost(tiers, 0, 0.5)
	if !approxEqual(cost, 0) {
		t.Errorf("0.5 GB cost = %f, want 0", cost)
	}

	// 5 GB — 1 free + 4 at $0.09.
	cost = tieredCost(tiers, 0, 5)
	expected := 4 * 0.09
	if !approxEqual(cost, expected) {
		t.Errorf("5 GB cost = %f, want %f", cost, expected)
	}

	// Cumulative: already used 5 GB, now add 10 more (5→15 GB).
	cost = tieredCost(tiers, 5, 15)
	expected = 10 * 0.09
	if !approxEqual(cost, expected) {
		t.Errorf("5→15 GB cost = %f, want %f", cost, expected)
	}
}

func TestTieredCost_CrossTierBoundary(t *testing.T) {
	tiers := []Tier{
		{UpToGB: 10, PerGB: 0.10},
		{UpToGB: math.Inf(1), PerGB: 0.05},
	}

	// 15 GB from 0: 10 at $0.10 + 5 at $0.05.
	cost := tieredCost(tiers, 0, 15)
	expected := 10*0.10 + 5*0.05
	if !approxEqual(cost, expected) {
		t.Errorf("cross-tier cost = %f, want %f", cost, expected)
	}
}

func TestEngine_SameZoneFree(t *testing.T) {
	store := NewRateCardStore()
	store.Set(DefaultAWSRateCard("us-east-1"))
	engine := NewEngine(store)

	results := engine.Calculate("aws", "us-east-1", []FlowRecord{{
		TrafficType: classifier.SameZone,
		TxBytes:     10 * gb,
		RxBytes:     5 * gb,
	}})

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].CostUSD != 0 {
		t.Errorf("same-zone cost = %f, want 0", results[0].CostUSD)
	}
}

// TestEngine_MeteredDirections pins the per-traffic-type metered-direction
// semantics (DEC-014). The pre-fix engine billed Tx+Rx at the per-GB rate for
// every type, which charged ingress at egress rates — the regression this
// table would have caught.
func TestEngine_MeteredDirections(t *testing.T) {
	tests := []struct {
		name     string
		provider string
		region   string
		card     *RateCard
		tt       classifier.TrafficType
		txGB     uint64
		rxGB     uint64
		wantUSD  float64
	}{
		// AWS cross-AZ: $0.01/GB in EACH direction at this node → Tx+Rx.
		{"aws/cross-az Tx only", "aws", "us-east-1", DefaultAWSRateCard("us-east-1"), classifier.CrossAZ, 1, 0, 0.01},
		{"aws/cross-az both directions", "aws", "us-east-1", DefaultAWSRateCard("us-east-1"), classifier.CrossAZ, 1, 1, 0.02},
		// AWS internet egress: ingress is free — 10 GB of Rx must cost $0.
		{"aws/internet-egress Rx not billed", "aws", "us-east-1", DefaultAWSRateCard("us-east-1"), classifier.InternetEgress, 0, 10, 0},
		{"aws/internet-egress Tx at marginal rate", "aws", "us-east-1", DefaultAWSRateCard("us-east-1"), classifier.InternetEgress, 1, 1, 0.09},
		// AWS cross-region: only the egress side bills ($0.02/GB from us-east-1).
		{"aws/cross-region Rx not billed", "aws", "us-east-1", DefaultAWSRateCard("us-east-1"), classifier.CrossRegion, 1, 1, 0.02},
		// AWS TGW: data processing bills bytes sent INTO the TGW ($0.02/GB, Tx).
		{"aws/transit-gateway Tx only", "aws", "us-east-1", DefaultAWSRateCard("us-east-1"), classifier.TransitGateway, 1, 1, 0.02},
		// AWS peering: $0.01/GB each direction, like cross-AZ.
		{"aws/vpc-peering both directions", "aws", "us-east-1", DefaultAWSRateCard("us-east-1"), classifier.VPCPeering, 1, 1, 0.02},
		// AWS PrivateLink endpoints: $0.01/GB processed in both directions.
		{"aws/vpc-endpoint both directions", "aws", "us-east-1", DefaultAWSRateCard("us-east-1"), classifier.VPCEndpoint, 1, 1, 0.02},
		// GCP inter-zone: $0.01/GiB billed to the sender only (Tx).
		{"gcp/cross-az Tx only", "gcp", "us-central1", DefaultGCPRateCard("us-central1"), classifier.CrossAZ, 1, 1, 0.01},
		// Azure cross-AZ: charges retired — $0 in any direction.
		{"azure/cross-az free", "azure", "eastus", DefaultAzureRateCard("eastus"), classifier.CrossAZ, 10, 10, 0},
		// Azure VNet peering: $0.01/GB inbound AND outbound.
		{"azure/vnet-peering both directions", "azure", "eastus", DefaultAzureRateCard("eastus"), classifier.VPCPeering, 1, 1, 0.02},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store := NewRateCardStore()
			store.Set(tc.card)
			engine := NewEngine(store)

			results := engine.Calculate(tc.provider, tc.region, []FlowRecord{{
				TrafficType: tc.tt,
				TxBytes:     tc.txGB * gb,
				RxBytes:     tc.rxGB * gb,
			}})

			if !approxEqual(results[0].CostUSD, tc.wantUSD) {
				t.Errorf("cost = %f, want %f", results[0].CostUSD, tc.wantUSD)
			}
		})
	}
}

func TestEngine_CrossAZ(t *testing.T) {
	store := NewRateCardStore()
	store.Set(DefaultAWSRateCard("us-east-1"))
	engine := NewEngine(store)

	results := engine.Calculate("aws", "us-east-1", []FlowRecord{{
		TrafficType: classifier.CrossAZ,
		TxBytes:     1 * gb,
		RxBytes:     0,
	}})

	expected := 1.0 * 0.01
	if !approxEqual(results[0].CostUSD, expected) {
		t.Errorf("cross-az cost = %f, want %f", results[0].CostUSD, expected)
	}
}

// TestEngine_NATGateway: per DEC-015, NAT-classified flows are internet-bound
// and pay the NAT data-processing charge on Tx+Rx plus the internet-egress
// charge on Tx. 10 GB out: 10×$0.045 + 10×$0.09 = $1.35 — the $0.45 the old
// engine reported dropped the DTO leg entirely.
func TestEngine_NATGateway(t *testing.T) {
	store := NewRateCardStore()
	store.Set(DefaultAWSRateCard("us-east-1"))
	engine := NewEngine(store)

	results := engine.Calculate("aws", "us-east-1", []FlowRecord{{
		TrafficType: classifier.NATGatewayEgress,
		TxBytes:     10 * gb,
		RxBytes:     0,
	}})

	expected := 10.0*0.045 + 10.0*0.09
	if !approxEqual(results[0].CostUSD, expected) {
		t.Errorf("NAT gateway cost = %f, want %f", results[0].CostUSD, expected)
	}
}

func TestEngine_NoRateCard(t *testing.T) {
	store := NewRateCardStore()
	engine := NewEngine(store)

	results := engine.Calculate("aws", "us-east-1", []FlowRecord{{
		TrafficType: classifier.InternetEgress,
		TxBytes:     1 * gb,
	}})

	if results[0].CostUSD != 0 {
		t.Errorf("no rate card: cost = %f, want 0", results[0].CostUSD)
	}
}

// TestEngine_GCPCrossAZCharged replaces the old TestEngine_GCPCrossAZFree,
// which locked in a $0 constant. GCP charges $0.01/GiB for inter-zone traffic
// within a region (sender-billed); 100 GiB out = $1.00 by the provider sheet.
func TestEngine_GCPCrossAZCharged(t *testing.T) {
	store := NewRateCardStore()
	store.Set(DefaultGCPRateCard("us-central1"))
	engine := NewEngine(store)

	results := engine.Calculate("gcp", "us-central1", []FlowRecord{{
		TrafficType: classifier.CrossAZ,
		TxBytes:     100 * gb,
		RxBytes:     0,
	}})

	expected := 100.0 * 0.01
	if !approxEqual(results[0].CostUSD, expected) {
		t.Errorf("GCP cross-az 100 GiB = %f, want %f ($0.01/GiB inter-zone)", results[0].CostUSD, expected)
	}
}

// TestEngine_AzureCrossAZFree: Azure retired inter-AZ data transfer charges;
// the old $0.01 constant over-billed every cross-AZ byte.
func TestEngine_AzureCrossAZFree(t *testing.T) {
	store := NewRateCardStore()
	store.Set(DefaultAzureRateCard("eastus"))
	engine := NewEngine(store)

	results := engine.Calculate("azure", "eastus", []FlowRecord{{
		TrafficType: classifier.CrossAZ,
		TxBytes:     100 * gb,
		RxBytes:     0,
	}})

	if results[0].CostUSD != 0 {
		t.Errorf("Azure cross-az should be free (charges retired), got %f", results[0].CostUSD)
	}
}

// TestEngine_InternetEgressMarginal: in the default distributed mode every
// metered GB prices at the post-free-tier list rate ($0.09/GB in us-east-1) —
// no per-process free-tier grant (DEC-014).
func TestEngine_InternetEgressMarginal(t *testing.T) {
	store := NewRateCardStore()
	store.Set(DefaultAWSRateCard("us-east-1"))
	engine := NewEngine(store)

	results := engine.Calculate("aws", "us-east-1", []FlowRecord{{
		TrafficType: classifier.InternetEgress,
		TxBytes:     5 * gb,
		RxBytes:     0,
	}})

	expected := 5.0 * 0.09
	if !approxEqual(results[0].CostUSD, expected) {
		t.Errorf("internet egress 5 GB (marginal) = %f, want %f", results[0].CostUSD, expected)
	}
}

// TestEngine_InternetEgressSingleMeter exercises the explicit single-meter
// mode with the corrected AWS free tier: 100 GB/month free (account-
// aggregated, since Dec 2021 — the old card granted only 1 GB), then $0.09/GB.
// 150 GB from a fresh meter = 50 × $0.09 = $4.50.
func TestEngine_InternetEgressSingleMeter(t *testing.T) {
	store := NewRateCardStore()
	store.Set(DefaultAWSRateCard("us-east-1"))
	engine := NewEngineWithConfig(store, EngineConfig{Mode: PricingModeSingleMeter})

	results := engine.Calculate("aws", "us-east-1", []FlowRecord{{
		TrafficType: classifier.InternetEgress,
		TxBytes:     150 * gb,
		RxBytes:     0,
	}})

	expected := 50.0 * 0.09
	if !approxEqual(results[0].CostUSD, expected) {
		t.Errorf("internet egress 150 GB (single-meter) = %f, want %f", results[0].CostUSD, expected)
	}
}

// TestEngine_MarginalModeHasNoTierState: two engines (two fleet nodes) each
// pricing 1 GB of egress must each report $0.09 — the pre-DEC-014 engine let
// every node grant itself the free tier, under-reporting fleet-wide dollars.
func TestEngine_MarginalModeHasNoTierState(t *testing.T) {
	flow := []FlowRecord{{TrafficType: classifier.InternetEgress, TxBytes: 1 * gb}}

	for _, name := range []string{"node-a", "node-b"} {
		store := NewRateCardStore()
		store.Set(DefaultAWSRateCard("us-east-1"))
		engine := NewEngine(store)

		results := engine.Calculate("aws", "us-east-1", flow)
		if !approxEqual(results[0].CostUSD, 0.09) {
			t.Errorf("%s: 1 GB egress = %f, want 0.09 (no per-node free tier)", name, results[0].CostUSD)
		}
	}
}

// TestEngine_AWSInternetEgressTierBoundaries pins the corrected tier
// boundaries against the AWS sheet: the $0.085 band covers the NEXT 40 TB
// (10–50 TB cumulative), not 10–40 TB as the old card had it.
func TestEngine_AWSInternetEgressTierBoundaries(t *testing.T) {
	tiers := DefaultAWSRateCard("us-east-1").Rates[classifier.InternetEgress].Tiers

	// Provider-sheet derivation for 60 TB in one month:
	//   100 GB free + 10,140 GB (to 10 TB) × 0.09 + 40 TB × 0.085 + 10 TB × 0.07
	const tb = 1024.0
	want := 0.0 +
		(10*tb-100)*0.09 + // free tier ends at 100 GB, $0.09 band to 10 TB
		40*tb*0.085 + // 10–50 TB
		10*tb*0.07 // 50–60 TB falls in the 50–150 TB band

	got := tieredCost(tiers, 0, 60*tb)
	if !approxEqual(got, want) {
		t.Errorf("60 TB egress = %f, want %f (tier boundary at 50 TB, not 40 TB)", got, want)
	}
}

func TestEngine_MultiBatch(t *testing.T) {
	store := NewRateCardStore()
	store.Set(DefaultAWSRateCard("us-east-1"))
	engine := NewEngine(store)

	results := engine.Calculate("aws", "us-east-1", []FlowRecord{
		{TrafficType: classifier.SameZone, TxBytes: 1 * gb},
		{TrafficType: classifier.CrossAZ, TxBytes: 2 * gb},
		{TrafficType: classifier.CrossRegion, TxBytes: 3 * gb},
	})

	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}
	if results[0].CostUSD != 0 {
		t.Error("same-zone should be free")
	}
	if !approxEqual(results[1].CostUSD, 2.0*0.01) {
		t.Errorf("cross-az = %f, want %f", results[1].CostUSD, 2.0*0.01)
	}
	if !approxEqual(results[2].CostUSD, 3.0*0.02) {
		t.Errorf("cross-region = %f, want %f", results[2].CostUSD, 3.0*0.02)
	}
}

func TestRateCardStore_SetGet(t *testing.T) {
	store := NewRateCardStore()

	card := DefaultAWSRateCard("us-east-1")
	store.Set(card)

	got := store.Get("aws", "us-east-1")
	if got == nil {
		t.Fatal("expected rate card, got nil")
	}
	if got.Provider != "aws" || got.Region != "us-east-1" {
		t.Errorf("got provider=%s region=%s", got.Provider, got.Region)
	}

	if store.Get("gcp", "us-central1") != nil {
		t.Error("expected nil for missing rate card")
	}
}

// TestRateCard_Dated: per P4 every default card must carry the verification
// date of its rates and a source label — a rate without a date is untraceable.
func TestRateCard_Dated(t *testing.T) {
	for _, card := range []*RateCard{
		DefaultAWSRateCard("us-east-1"),
		DefaultGCPRateCard("us-central1"),
		DefaultAzureRateCard("eastus"),
	} {
		if card.LastUpdated.IsZero() {
			t.Errorf("%s: default card has no rate date (P4)", card.Provider)
		}
		if !card.LastUpdated.Equal(defaultRatesAsOf) {
			t.Errorf("%s: LastUpdated = %v, want the pinned verification date %v", card.Provider, card.LastUpdated, defaultRatesAsOf)
		}
		if card.Source == "" {
			t.Errorf("%s: default card has no source label (P4)", card.Provider)
		}
		if card.Directions == nil {
			t.Errorf("%s: default card has no metered-direction table (DEC-014)", card.Provider)
		}
	}
}

func approxEqual(a, b float64) bool {
	return math.Abs(a-b) < 0.0001
}
