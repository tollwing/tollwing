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
func TestPipeline_ClassifierToCost(t *testing.T) {
	resolver := classifier.NewZoneResolver(nil)

	// Simulate AWS us-east-1 environment.
	store := NewRateCardStore()
	store.Set(DefaultAWSRateCard("us-east-1"))
	engine := NewEngine(store)

	// Test all traffic types produce reasonable costs.
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
		{"InternetEgress/5GB", classifier.InternetEgress, 5, false, 0.35, 0.37}, // 1 free + 4*0.09
		{"NATGateway/1GB", classifier.NATGatewayEgress, 1, false, 0.044, 0.046},
		{"VPCPeering/1GB", classifier.VPCPeering, 1, false, 0.009, 0.011},
		{"TransitGateway/1GB", classifier.TransitGateway, 1, false, 0.019, 0.021},
		{"VPCEndpoint/1GB", classifier.VPCEndpoint, 1, false, 0.009, 0.011},
		{"CloudServicePublic/free", classifier.CloudServicePublic, 100, true, 0, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset for each test to avoid tiered pricing interference.
			engine.ResetBillingPeriod()

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

// TestPipeline_MultiProvider verifies costs differ across AWS/GCP/Azure.
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

	// AWS: $0.01/GB cross-AZ.
	engine.ResetBillingPeriod()
	awsResults := engine.Calculate("aws", "us-east-1", flow)
	awsCost := awsResults[0].CostUSD

	// GCP: free intra-region.
	engine.ResetBillingPeriod()
	gcpResults := engine.Calculate("gcp", "us-central1", flow)
	gcpCost := gcpResults[0].CostUSD

	// Azure: $0.01/GB cross-AZ.
	engine.ResetBillingPeriod()
	azureResults := engine.Calculate("azure", "eastus", flow)
	azureCost := azureResults[0].CostUSD

	if gcpCost != 0 {
		t.Errorf("GCP cross-AZ should be free, got $%.6f", gcpCost)
	}
	if awsCost == 0 {
		t.Error("AWS cross-AZ should not be free")
	}
	if azureCost == 0 {
		t.Error("Azure cross-AZ should not be free")
	}
	if math.Abs(awsCost-azureCost) > 0.01 {
		t.Errorf("AWS ($%.4f) and Azure ($%.4f) cross-AZ should be similar", awsCost, azureCost)
	}
}

// TestPipeline_CumulativeTracking verifies that cumulative billing works across
// multiple Calculate calls (simulating multiple poll ticks).
func TestPipeline_CumulativeTracking(t *testing.T) {
	store := NewRateCardStore()
	store.Set(DefaultAWSRateCard("us-east-1"))
	engine := NewEngine(store)

	// Batch 1: 1 GB internet egress (free tier).
	r1 := engine.Calculate("aws", "us-east-1", []FlowRecord{{
		TrafficType: classifier.InternetEgress,
		TxBytes:     1 * gb,
	}})
	if r1[0].CostUSD != 0 {
		t.Errorf("batch 1: first 1 GB should be free, got $%.6f", r1[0].CostUSD)
	}

	// Batch 2: 1 GB more (now past free tier, should cost $0.09).
	r2 := engine.Calculate("aws", "us-east-1", []FlowRecord{{
		TrafficType: classifier.InternetEgress,
		TxBytes:     1 * gb,
	}})
	if math.Abs(r2[0].CostUSD-0.09) > 0.01 {
		t.Errorf("batch 2: second 1 GB should cost ~$0.09, got $%.6f", r2[0].CostUSD)
	}

	// Batch 3: 8 GB more (2→10 GB, all at $0.09/GB tier).
	r3 := engine.Calculate("aws", "us-east-1", []FlowRecord{{
		TrafficType: classifier.InternetEgress,
		TxBytes:     8 * gb,
	}})
	expected := 8.0 * 0.09
	if math.Abs(r3[0].CostUSD-expected) > 0.01 {
		t.Errorf("batch 3: 8 GB should cost ~$%.2f, got $%.6f", expected, r3[0].CostUSD)
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
