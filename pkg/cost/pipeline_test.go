package cost

import (
	"math"
	"testing"
	"time"

	"github.com/tollwing/tollwing/pkg/classifier"
)

// TestPipeline_ClassifierToCost verifies the full classification → cost pipeline.
// This is the integration test that ensures the classifier's traffic types
// map correctly to the cost engine's rate cards and produce expected USD values.
// Expected ranges are hand-derived from the AWS price sheet (verified
// 2026-07-02, DEC-014) — not from the rate-card constants.
func TestPipeline_ClassifierToCost(t *testing.T) {
	resolver := classifier.NewZoneResolver(nil)

	// Simulate AWS us-east-1 environment. Default engine mode: marginal
	// pricing (DEC-014) — egress prices at the post-free-tier list rate.
	store := NewRateCardStore()
	store.Set(DefaultAWSRateCard("us-east-1"))
	engine := NewEngine(store)

	// Test all traffic types produce reasonable costs. Flows are Tx-only,
	// so metered-direction differences don't blur the expected values.
	tests := []struct {
		name     string
		tt       classifier.TrafficType
		txGB     float64
		wantFree bool
		wantMin  float64 // minimum expected cost (0 if free)
		wantMax  float64 // maximum expected cost
	}{
		{"SameZone/free", classifier.SameZone, 100, true, 0, 0},
		{"CrossAZ/1GB", classifier.CrossAZ, 1, false, 0.009, 0.011},
		{"CrossRegion/1GB", classifier.CrossRegion, 1, false, 0.019, 0.021},
		// 5 GB at the marginal $0.09/GB rate — no per-node free tier (DEC-014).
		{"InternetEgress/5GB", classifier.InternetEgress, 5, false, 0.44, 0.46},
		// NAT processing $0.045 + internet DTO $0.09 on the Tx leg (DEC-015).
		{"NATGateway/1GB", classifier.NATGatewayEgress, 1, false, 0.134, 0.136},
		{"VPCPeering/1GB", classifier.VPCPeering, 1, false, 0.009, 0.011},
		{"TransitGateway/1GB", classifier.TransitGateway, 1, false, 0.019, 0.021},
		{"VPCEndpoint/1GB", classifier.VPCEndpoint, 1, false, 0.009, 0.011},
		{"CloudServicePublic/free", classifier.CloudServicePublic, 100, true, 0, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			txBytes := uint64(tt.txGB * 1024 * 1024 * 1024)
			results := engine.Calculate("aws", "us-east-1", []FlowRecord{{
				TrafficType: tt.tt,
				TxBytes:     txBytes,
				RxBytes:     0,
			}})

			cost := results[0].CostUSD
			if tt.wantFree && cost != 0 {
				t.Errorf("expected free, got $%.6f", cost)
			}
			if !tt.wantFree {
				if cost < tt.wantMin || cost > tt.wantMax {
					t.Errorf("cost $%.6f not in range [$%.4f, $%.4f]", cost, tt.wantMin, tt.wantMax)
				}
			}
		})
	}

	// Verify resolver is functional (won't actually resolve without IMDS, but shouldn't panic).
	_ = resolver.LocalZone()
}

// TestPipeline_MultiProvider verifies per-provider cross-AZ truth (provider
// sheets, 2026-07-02): AWS bills $0.01/GB per direction, GCP bills the sender
// $0.01/GiB, and Azure retired inter-AZ charges entirely. The old test locked
// in "GCP free, Azure ≈ AWS" — both wrong.
func TestPipeline_MultiProvider(t *testing.T) {
	store := NewRateCardStore()
	store.Set(DefaultAWSRateCard("us-east-1"))
	store.Set(DefaultGCPRateCard("us-central1"))
	store.Set(DefaultAzureRateCard("eastus"))
	engine := NewEngine(store)

	flow := []FlowRecord{{
		TrafficType: classifier.CrossAZ,
		TxBytes:     10 * gb,
		RxBytes:     0,
	}}

	awsCost := engine.Calculate("aws", "us-east-1", flow)[0].CostUSD
	gcpCost := engine.Calculate("gcp", "us-central1", flow)[0].CostUSD
	azureCost := engine.Calculate("azure", "eastus", flow)[0].CostUSD

	// AWS: 10 GB out × $0.01 (the Rx side of this flow is 0).
	if !approxEqual(awsCost, 0.10) {
		t.Errorf("AWS cross-AZ 10 GB = $%.6f, want $0.10", awsCost)
	}
	// GCP: inter-zone egress is $0.01/GiB, sender-billed — NOT free.
	if !approxEqual(gcpCost, 0.10) {
		t.Errorf("GCP cross-AZ 10 GiB = $%.6f, want $0.10 (inter-zone is charged)", gcpCost)
	}
	// Azure: inter-AZ data transfer charges were retired — must be $0.
	if azureCost != 0 {
		t.Errorf("Azure cross-AZ = $%.6f, want $0 (inter-AZ charges retired)", azureCost)
	}
}

// TestPipeline_SingleMeterCumulative verifies that the explicit single-meter
// mode (DEC-014, Enterprise server) tracks cumulative usage across Calculate
// calls: the 100 GB account free tier is granted exactly once.
func TestPipeline_SingleMeterCumulative(t *testing.T) {
	store := NewRateCardStore()
	store.Set(DefaultAWSRateCard("us-east-1"))
	engine := NewEngineWithConfig(store, EngineConfig{Mode: PricingModeSingleMeter})

	// Batch 1: 100 GB internet egress — exactly the monthly free tier.
	r1 := engine.Calculate("aws", "us-east-1", []FlowRecord{{
		TrafficType: classifier.InternetEgress,
		TxBytes:     100 * gb,
	}})
	if r1[0].CostUSD != 0 {
		t.Errorf("batch 1: first 100 GB should be free, got $%.6f", r1[0].CostUSD)
	}

	// Batch 2: 1 GB more (now past the free tier, $0.09/GB).
	r2 := engine.Calculate("aws", "us-east-1", []FlowRecord{{
		TrafficType: classifier.InternetEgress,
		TxBytes:     1 * gb,
	}})
	if math.Abs(r2[0].CostUSD-0.09) > 0.001 {
		t.Errorf("batch 2: 101st GB should cost $0.09, got $%.6f", r2[0].CostUSD)
	}

	// Batch 3: 8 GB more (101→109 GB, all in the $0.09/GB band).
	r3 := engine.Calculate("aws", "us-east-1", []FlowRecord{{
		TrafficType: classifier.InternetEgress,
		TxBytes:     8 * gb,
	}})
	expected := 8.0 * 0.09
	if math.Abs(r3[0].CostUSD-expected) > 0.001 {
		t.Errorf("batch 3: 8 GB should cost $%.2f, got $%.6f", expected, r3[0].CostUSD)
	}
}

// TestPipeline_MarginalIsStateless: in the default mode, repeated batches
// price identically — there is no hidden per-process tier position to reset
// or to drift after a restart (DEC-014).
func TestPipeline_MarginalIsStateless(t *testing.T) {
	store := NewRateCardStore()
	store.Set(DefaultAWSRateCard("us-east-1"))
	engine := NewEngine(store)

	flow := []FlowRecord{{TrafficType: classifier.InternetEgress, TxBytes: 1 * gb}}
	first := engine.Calculate("aws", "us-east-1", flow)[0].CostUSD
	second := engine.Calculate("aws", "us-east-1", flow)[0].CostUSD

	if !approxEqual(first, 0.09) || !approxEqual(second, 0.09) {
		t.Errorf("marginal mode: batches = $%.6f, $%.6f — want $0.09 each (stateless)", first, second)
	}
}

// TestPipeline_FlowRecordMetadata verifies that metadata is preserved through Calculate.
func TestPipeline_FlowRecordMetadata(t *testing.T) {
	store := NewRateCardStore()
	store.Set(DefaultAWSRateCard("us-east-1"))
	engine := NewEngine(store)

	flow := FlowRecord{
		Timestamp:    time.Now(),
		Cluster:      "prod-1",
		Node:         "node-abc",
		SrcNamespace: "payments",
		SrcPod:       "api-server-xyz",
		DstService:   "stripe.com",
		TrafficType:  classifier.InternetEgress,
		TxBytes:      5 * gb,
	}

	results := engine.Calculate("aws", "us-east-1", []FlowRecord{flow})
	r := results[0]

	if r.Cluster != "prod-1" {
		t.Errorf("Cluster = %q, want prod-1", r.Cluster)
	}
	if r.SrcNamespace != "payments" {
		t.Errorf("SrcNamespace = %q, want payments", r.SrcNamespace)
	}
	if r.SrcPod != "api-server-xyz" {
		t.Errorf("SrcPod = %q, want api-server-xyz", r.SrcPod)
	}
	if r.CostUSD <= 0 {
		t.Error("expected non-zero cost for internet egress")
	}
}
