package sim

import (
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/tollwing/tollwing/pkg/classifier"
	"github.com/tollwing/tollwing/pkg/cost"
)

func measuredCost(tt classifier.TrafficType, usd float64) cost.CostResult {
	return cost.CostResult{FlowRecord: cost.FlowRecord{TrafficType: tt}, CostUSD: usd}
}

func billItem(usageType string, usd float64) cost.BillingLineItem {
	return cost.BillingLineItem{UsageType: usageType, CostUSD: usd, Service: "AmazonEC2"}
}

func reconciler() *cost.Reconciler {
	return cost.NewReconciler(cost.ReconcilerConfig{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

// TestReconcile_PerfectMatch: a synthetic AWS CUR whose data-transfer line items
// match the eBPF-measured per-type costs reconciles to 100% accuracy, zero drift,
// no alert — measured == billed when the agent sees all the byte-metered cost (P4).
func TestReconcile_PerfectMatch(t *testing.T) {
	measured := []cost.CostResult{
		measuredCost(classifier.CrossAZ, 2.00),
		measuredCost(classifier.InternetEgress, 4.50),
		measuredCost(classifier.NATGatewayEgress, 2.25),
	}
	bill := &cost.BillingData{
		Provider: "aws",
		Period:   cost.BillingPeriod{Start: time.Unix(0, 0), End: time.Unix(1, 0)},
		LineItems: []cost.BillingLineItem{
			billItem("USE2-DataTransfer-Regional-Bytes", 2.00), // → cross_az
			billItem("USE2-DataTransfer-Out-Bytes", 4.50),      // → internet_egress
			billItem("USE2-NatGateway-Bytes", 2.25),            // → nat_gateway
		},
	}
	rep := reconciler().Reconcile(measured, bill)

	if !almostEqual(rep.MeasuredCost, 8.75) {
		t.Errorf("measured: $%.4f want $8.75", rep.MeasuredCost)
	}
	if !almostEqual(rep.BilledCost, 8.75) {
		t.Errorf("billed: $%.4f want $8.75", rep.BilledCost)
	}
	if !almostEqual(rep.AccuracyPct, 100) {
		t.Errorf("accuracy: %.2f%% want 100", rep.AccuracyPct)
	}
	if !almostEqual(rep.UnaccountedUSD, 0) {
		t.Errorf("unaccounted: $%.4f want $0", rep.UnaccountedUSD)
	}
	if rep.DriftAlert {
		t.Errorf("unexpected drift alert at 0%% drift")
	}
}

// TestReconcile_NATHoursUnaccounted: NAT-gateway *hours* are a fixed charge the
// byte-counting agent structurally cannot measure. The reconciler must surface
// exactly that fixed cost as "unaccounted" and raise a drift alert — the honest
// "unmeasured bucket" (P4), proven without a cloud account via a synthetic CUR.
func TestReconcile_NATHoursUnaccounted(t *testing.T) {
	const natHours = 33.48
	measured := []cost.CostResult{
		measuredCost(classifier.CrossAZ, 2.00),
		measuredCost(classifier.InternetEgress, 4.50),
		measuredCost(classifier.NATGatewayEgress, 2.25),
	}
	bill := &cost.BillingData{
		Provider: "aws",
		LineItems: []cost.BillingLineItem{
			billItem("USE2-DataTransfer-Regional-Bytes", 2.00),
			billItem("USE2-DataTransfer-Out-Bytes", 4.50),
			billItem("USE2-NatGateway-Bytes", 2.25),
			billItem("USE2-NatGateway-Hours", natHours), // fixed; the agent can't measure hours
		},
	}
	rep := reconciler().Reconcile(measured, bill)

	if !almostEqual(rep.MeasuredCost, 8.75) {
		t.Errorf("measured: $%.4f want $8.75", rep.MeasuredCost)
	}
	if !almostEqual(rep.BilledCost, 8.75+natHours) {
		t.Errorf("billed: $%.4f want $%.4f", rep.BilledCost, 8.75+natHours)
	}
	if !almostEqual(rep.UnaccountedUSD, natHours) {
		t.Errorf("unaccounted: $%.4f want $%.2f (the NAT-hours the agent can't measure)", rep.UnaccountedUSD, natHours)
	}
	if !rep.DriftAlert {
		t.Errorf("expected a drift alert (%.1f%% drift) for the unmeasured NAT-hours", rep.DriftPct)
	}
	t.Logf("reconcile: measured $%.2f vs billed $%.2f → unaccounted $%.2f (NAT-hours), drift %.1f%%, alert=%v ✓",
		rep.MeasuredCost, rep.BilledCost, rep.UnaccountedUSD, rep.DriftPct, rep.DriftAlert)
}
