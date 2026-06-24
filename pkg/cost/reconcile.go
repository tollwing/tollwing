package cost

import (
	"fmt"
	"log/slog"
	"math"
	"time"

	"github.com/tollwing/tollwing/pkg/classifier"
)

// ReconciliationReport compares eBPF-measured costs with cloud billing data.
type ReconciliationReport struct {
	Period           BillingPeriod
	MeasuredCost     float64 // total cost from eBPF measurements
	BilledCost       float64 // total cost from cloud billing
	AccuracyPct      float64 // measured / billed * 100
	DriftPct         float64 // absolute drift percentage
	DriftAlert       bool    // true if drift exceeds threshold
	ByType           []TypeReconciliation
	UnaccountedUSD   float64 // billed - measured (positive = missed traffic)
	CorrectionFactor float64 // factor to apply to future estimates
}

// TypeReconciliation breaks down reconciliation by traffic type.
type TypeReconciliation struct {
	UsageType    string
	MeasuredCost float64
	BilledCost   float64
	DriftPct     float64
}

// ReconcilerConfig controls the reconciliation engine.
type ReconcilerConfig struct {
	// DriftThresholdPct triggers an alert when exceeded. Default: 5.0.
	DriftThresholdPct float64
}

func (c *ReconcilerConfig) setDefaults() {
	if c.DriftThresholdPct == 0 {
		c.DriftThresholdPct = 5.0
	}
}

// Reconciler compares eBPF measurements against cloud billing.
type Reconciler struct {
	cfg ReconcilerConfig
	log *slog.Logger
}

// NewReconciler creates a billing reconciliation engine.
func NewReconciler(cfg ReconcilerConfig, log *slog.Logger) *Reconciler {
	cfg.setDefaults()
	return &Reconciler{cfg: cfg, log: log}
}

// Reconcile compares measured costs against billing data and produces a report.
func (r *Reconciler) Reconcile(measured []CostResult, billing *BillingData) *ReconciliationReport {
	report := &ReconciliationReport{
		Period: billing.Period,
	}

	// Aggregate measured costs by usage type.
	measuredByType := make(map[string]float64)
	for _, m := range measured {
		key := m.TrafficType.String()
		measuredByType[key] += m.CostUSD
		report.MeasuredCost += m.CostUSD
	}

	// Aggregate billed costs by usage type.
	billedByType := make(map[string]float64)
	for _, li := range billing.LineItems {
		key := mapUsageType(li.UsageType)
		billedByType[key] += li.CostUSD
		report.BilledCost += li.CostUSD
	}

	// Per-type reconciliation.
	allTypes := mergeKeys(measuredByType, billedByType)
	for _, t := range allTypes {
		m := measuredByType[t]
		b := billedByType[t]
		drift := 0.0
		if b > 0 {
			drift = math.Abs(m-b) / b * 100
		}
		report.ByType = append(report.ByType, TypeReconciliation{
			UsageType:    t,
			MeasuredCost: m,
			BilledCost:   b,
			DriftPct:     drift,
		})
	}

	// Overall accuracy and drift.
	if report.BilledCost > 0 {
		report.AccuracyPct = (report.MeasuredCost / report.BilledCost) * 100
		report.DriftPct = math.Abs(report.MeasuredCost-report.BilledCost) / report.BilledCost * 100
		report.CorrectionFactor = report.BilledCost / report.MeasuredCost
	} else if report.MeasuredCost > 0 {
		report.AccuracyPct = 0
		report.DriftPct = 100
		report.CorrectionFactor = 1.0
	} else {
		report.AccuracyPct = 100
		report.CorrectionFactor = 1.0
	}

	report.UnaccountedUSD = report.BilledCost - report.MeasuredCost
	report.DriftAlert = report.DriftPct > r.cfg.DriftThresholdPct

	if report.DriftAlert {
		r.log.Warn("billing drift exceeds threshold",
			"drift_pct", fmt.Sprintf("%.1f%%", report.DriftPct),
			"threshold_pct", fmt.Sprintf("%.1f%%", r.cfg.DriftThresholdPct),
			"measured_usd", fmt.Sprintf("%.4f", report.MeasuredCost),
			"billed_usd", fmt.Sprintf("%.4f", report.BilledCost),
			"unaccounted_usd", fmt.Sprintf("%.4f", report.UnaccountedUSD),
		)
	} else {
		r.log.Info("billing reconciliation",
			"accuracy_pct", fmt.Sprintf("%.1f%%", report.AccuracyPct),
			"drift_pct", fmt.Sprintf("%.1f%%", report.DriftPct),
			"measured_usd", fmt.Sprintf("%.4f", report.MeasuredCost),
			"billed_usd", fmt.Sprintf("%.4f", report.BilledCost),
		)
	}

	return report
}

// mapUsageType maps AWS CUR usage types to our canonical traffic-type wire
// strings. Per P6 the names derive from classifier.TrafficType.String() so the
// billed-side keys line up with the measured-side keys (which come from the
// same method at Reconcile time) and cannot drift apart.
func mapUsageType(usageType string) string {
	switch {
	case contains(usageType, "DataTransfer-Regional"):
		return classifier.CrossAZ.String()
	case contains(usageType, "DataTransfer-Out"):
		return classifier.InternetEgress.String()
	case contains(usageType, "DataTransfer-In"):
		return "internet_ingress" // AWS bills ingress separately; no TrafficType for it
	case contains(usageType, "NatGateway"):
		return classifier.NATGatewayEgress.String()
	case contains(usageType, "TransitGateway"):
		return classifier.TransitGateway.String()
	case contains(usageType, "VPCPeering"):
		return classifier.VPCPeering.String()
	default:
		return classifier.Unknown.String()
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && searchString(s, sub)
}

func searchString(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func mergeKeys(a, b map[string]float64) []string {
	seen := make(map[string]bool)
	var keys []string
	for k := range a {
		if !seen[k] {
			keys = append(keys, k)
			seen[k] = true
		}
	}
	for k := range b {
		if !seen[k] {
			keys = append(keys, k)
			seen[k] = true
		}
	}
	return keys
}

// DriftAlertPayload generates alert details for drift notifications.
func (r *ReconciliationReport) DriftAlertPayload() map[string]interface{} {
	payload := map[string]interface{}{
		"alert_type":      "billing_drift",
		"severity":        "warning",
		"accuracy_pct":    r.AccuracyPct,
		"drift_pct":       r.DriftPct,
		"measured_usd":    r.MeasuredCost,
		"billed_usd":      r.BilledCost,
		"unaccounted_usd": r.UnaccountedUSD,
		"period_start":    r.Period.Start.Format(time.RFC3339),
		"period_end":      r.Period.End.Format(time.RFC3339),
	}

	// Find type with highest drift.
	var worstType string
	var worstDrift float64
	for _, t := range r.ByType {
		if t.DriftPct > worstDrift {
			worstDrift = t.DriftPct
			worstType = t.UsageType
		}
	}
	if worstType != "" {
		payload["worst_drift_type"] = worstType
		payload["worst_drift_pct"] = worstDrift
	}

	return payload
}
