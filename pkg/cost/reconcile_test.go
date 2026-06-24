package cost

import (
	"log/slog"
	"testing"
	"time"

	"github.com/tollwing/tollwing/pkg/classifier"
)

func TestReconcile_PerfectMatch(t *testing.T) {
	r := NewReconciler(ReconcilerConfig{}, slog.Default())

	measured := []CostResult{
		{FlowRecord: FlowRecord{TrafficType: classifier.CrossAZ, TxBytes: 1 * gb}, CostUSD: 0.01},
		{FlowRecord: FlowRecord{TrafficType: classifier.InternetEgress, TxBytes: 1 * gb}, CostUSD: 0.09},
	}

	billing := &BillingData{
		Period: BillingPeriod{Start: time.Now().Add(-24 * time.Hour), End: time.Now()},
		LineItems: []BillingLineItem{
			{UsageType: "DataTransfer-Regional-Bytes", CostUSD: 0.01},
			{UsageType: "DataTransfer-Out-Bytes", CostUSD: 0.09},
		},
	}

	report := r.Reconcile(measured, billing)

	if !approxEqual(report.AccuracyPct, 100) {
		t.Errorf("accuracy = %.1f%%, want 100%%", report.AccuracyPct)
	}
	if report.DriftAlert {
		t.Error("should not alert on perfect match")
	}
}

func TestReconcile_HighDrift(t *testing.T) {
	r := NewReconciler(ReconcilerConfig{DriftThresholdPct: 5.0}, slog.Default())

	measured := []CostResult{
		{FlowRecord: FlowRecord{TrafficType: classifier.CrossAZ}, CostUSD: 0.50},
	}

	billing := &BillingData{
		Period: BillingPeriod{Start: time.Now().Add(-24 * time.Hour), End: time.Now()},
		LineItems: []BillingLineItem{
			{UsageType: "DataTransfer-Regional-Bytes", CostUSD: 1.00},
		},
	}

	report := r.Reconcile(measured, billing)

	if !report.DriftAlert {
		t.Error("should alert on 50% drift")
	}
	if !approxEqual(report.DriftPct, 50.0) {
		t.Errorf("drift = %.1f%%, want 50%%", report.DriftPct)
	}
	if !approxEqual(report.UnaccountedUSD, 0.50) {
		t.Errorf("unaccounted = %.4f, want 0.50", report.UnaccountedUSD)
	}
}

func TestReconcile_CorrectionFactor(t *testing.T) {
	r := NewReconciler(ReconcilerConfig{}, slog.Default())

	measured := []CostResult{
		{FlowRecord: FlowRecord{TrafficType: classifier.InternetEgress}, CostUSD: 0.80},
	}

	billing := &BillingData{
		Period: BillingPeriod{Start: time.Now().Add(-24 * time.Hour), End: time.Now()},
		LineItems: []BillingLineItem{
			{UsageType: "DataTransfer-Out-Bytes", CostUSD: 1.00},
		},
	}

	report := r.Reconcile(measured, billing)

	// Correction factor should be 1.00 / 0.80 = 1.25
	if !approxEqual(report.CorrectionFactor, 1.25) {
		t.Errorf("correction factor = %f, want 1.25", report.CorrectionFactor)
	}
}

func TestReconcile_NoBilling(t *testing.T) {
	r := NewReconciler(ReconcilerConfig{}, slog.Default())

	measured := []CostResult{
		{FlowRecord: FlowRecord{TrafficType: classifier.CrossAZ}, CostUSD: 0.10},
	}

	billing := &BillingData{
		Period: BillingPeriod{Start: time.Now().Add(-24 * time.Hour), End: time.Now()},
	}

	report := r.Reconcile(measured, billing)

	if report.AccuracyPct != 0 {
		t.Errorf("accuracy = %.1f%%, want 0%% (no billing data)", report.AccuracyPct)
	}
}

func TestReconcile_EmptyBoth(t *testing.T) {
	r := NewReconciler(ReconcilerConfig{}, slog.Default())

	report := r.Reconcile(nil, &BillingData{
		Period: BillingPeriod{Start: time.Now().Add(-24 * time.Hour), End: time.Now()},
	})

	if report.AccuracyPct != 100 {
		t.Errorf("accuracy = %.1f%%, want 100%% (both empty)", report.AccuracyPct)
	}
	if report.DriftAlert {
		t.Error("should not alert when both empty")
	}
}

func TestReconcile_DriftAlertPayload(t *testing.T) {
	r := NewReconciler(ReconcilerConfig{DriftThresholdPct: 5.0}, slog.Default())

	measured := []CostResult{
		{FlowRecord: FlowRecord{TrafficType: classifier.InternetEgress}, CostUSD: 0.50},
	}

	billing := &BillingData{
		Period: BillingPeriod{Start: time.Now().Add(-24 * time.Hour), End: time.Now()},
		LineItems: []BillingLineItem{
			{UsageType: "DataTransfer-Out-Bytes", CostUSD: 1.00},
		},
	}

	report := r.Reconcile(measured, billing)
	payload := report.DriftAlertPayload()

	if payload["alert_type"] != "billing_drift" {
		t.Errorf("alert_type = %v, want billing_drift", payload["alert_type"])
	}
	if payload["severity"] != "warning" {
		t.Errorf("severity = %v, want warning", payload["severity"])
	}
}

func TestMapUsageType(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"DataTransfer-Regional-Bytes", "cross_az"},
		{"DataTransfer-Out-Bytes", "internet_egress"},
		{"DataTransfer-In-Bytes", "internet_ingress"},
		{"NatGateway-Bytes", "nat_gateway"},
		{"TransitGateway-Bytes", "transit_gateway"},
		{"VPCPeering-Bytes", "vpc_peering"},
		{"SomethingElse", "unknown"},
	}

	for _, tt := range tests {
		got := mapUsageType(tt.input)
		if got != tt.want {
			t.Errorf("mapUsageType(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
