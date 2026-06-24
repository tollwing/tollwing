package sim

import (
	"math"
	"testing"
	"testing/quick"

	"github.com/tollwing/tollwing/pkg/classifier"
	"github.com/tollwing/tollwing/pkg/cost"
	"github.com/tollwing/tollwing/test/sim/scenario"
)

// buildCrossAZ builds a one-edge cross_az scenario with the given byte counts.
func buildCrossAZ(tx, rx uint64) *scenario.Scenario {
	return &scenario.Scenario{
		Name:     "prop-cross-az",
		Provider: "aws",
		Region:   "us-east-1",
		Zones: map[string]scenario.Zone{
			"us-east-1a": {Region: "us-east-1"},
			"us-east-1b": {Region: "us-east-1"},
		},
		Services: map[string]scenario.Service{
			"a": {Zone: "us-east-1a"},
			"b": {Zone: "us-east-1b"},
		},
		Traffic: []scenario.Edge{{From: "a", To: "b", TxBytes: tx, RxBytes: rx}},
	}
}

// TestProperty_ProductEqualsOracle: for arbitrary byte counts, the real product
// and the independent oracle agree on classification and cost. This is the core
// DEC-008 invariant, fuzzed via stdlib testing/quick (no third-party dep, P9).
func TestProperty_ProductEqualsOracle(t *testing.T) {
	f := func(tx, rx uint32) bool {
		s := buildCrossAZ(uint64(tx), uint64(rx))
		o := Oracle(s)[0]
		p := Measure(s)[0]
		return o.Type == p.Type && almostEqual(o.CostUSD, p.CostUSD)
	}
	if err := quick.Check(f, &quick.Config{MaxCount: 2000}); err != nil {
		t.Error(err)
	}
}

// TestProperty_TraceableToBytesXRate: every cross_az dollar the product reports
// equals measured bytes × the dated rate-card rate — P4, honest and traceable.
// The rate and the type are pulled from the product's own sources (no hardcoded
// number or enum string, P6).
func TestProperty_TraceableToBytesXRate(t *testing.T) {
	card := cost.DefaultAWSRateCard("us-east-1")
	rate := card.Rates[classifier.CrossAZ].Tiers[0].PerGB
	f := func(tx, rx uint32) bool {
		s := buildCrossAZ(uint64(tx), uint64(rx))
		p := Measure(s)[0]
		want := (float64(uint64(tx)+uint64(rx)) / (1 << 30)) * rate
		return p.Type == classifier.CrossAZ && math.Abs(p.CostUSD-want) < 1e-12
	}
	if err := quick.Check(f, &quick.Config{MaxCount: 2000}); err != nil {
		t.Error(err)
	}
}
