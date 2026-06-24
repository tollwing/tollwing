package cost

import (
	"math"
	"testing"

	"github.com/tollwing/tollwing/pkg/classifier"
)

const gb = 1024 * 1024 * 1024 // 1 GB in bytes

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

func TestEngine_NATGateway(t *testing.T) {
	store := NewRateCardStore()
	store.Set(DefaultAWSRateCard("us-east-1"))
	engine := NewEngine(store)

	results := engine.Calculate("aws", "us-east-1", []FlowRecord{{
		TrafficType: classifier.NATGatewayEgress,
		TxBytes:     10 * gb,
		RxBytes:     0,
	}})

	expected := 10.0 * 0.045
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

func TestEngine_GCPCrossAZFree(t *testing.T) {
	store := NewRateCardStore()
	store.Set(DefaultGCPRateCard("us-central1"))
	engine := NewEngine(store)

	results := engine.Calculate("gcp", "us-central1", []FlowRecord{{
		TrafficType: classifier.CrossAZ,
		TxBytes:     100 * gb,
		RxBytes:     0,
	}})

	if results[0].CostUSD != 0 {
		t.Errorf("GCP cross-az should be free, got %f", results[0].CostUSD)
	}
}

func TestEngine_InternetEgressTiered(t *testing.T) {
	store := NewRateCardStore()
	store.Set(DefaultAWSRateCard("us-east-1"))
	engine := NewEngine(store)

	// Send 5 GB — first 1 GB free, remaining 4 GB at $0.09.
	results := engine.Calculate("aws", "us-east-1", []FlowRecord{{
		TrafficType: classifier.InternetEgress,
		TxBytes:     5 * gb,
		RxBytes:     0,
	}})

	expected := 4.0 * 0.09
	if !approxEqual(results[0].CostUSD, expected) {
		t.Errorf("internet egress 5 GB cost = %f, want %f", results[0].CostUSD, expected)
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

func approxEqual(a, b float64) bool {
	return math.Abs(a-b) < 0.0001
}
