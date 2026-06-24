package sim

import (
	"path/filepath"
	"testing"

	"github.com/tollwing/tollwing/test/sim/scenario"
)

// TestScenarios_OracleEqualsProduct is the L0 core of the suite: for every
// scenario, the independent Oracle, the real product (Measure), and the
// scenario's pinned ground truth must all agree on classification and cost
// (DEC-008). Exact dollars, not "200 OK".
func TestScenarios_OracleEqualsProduct(t *testing.T) {
	paths, err := filepath.Glob("scenarios/*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatal("no scenarios found under scenarios/")
	}

	for _, p := range paths {
		t.Run(filepath.Base(p), func(t *testing.T) {
			s, err := scenario.Load(p)
			if err != nil {
				t.Fatalf("load: %v", err)
			}

			oracle := Oracle(s)
			product := Measure(s)
			if len(oracle) != len(product) {
				t.Fatalf("edge count mismatch: oracle=%d product=%d", len(oracle), len(product))
			}

			expect := map[string]scenario.EdgeExpect{}
			for _, e := range s.Expect.Edges {
				expect[e.From+"→"+e.To] = e
			}

			for i := range oracle {
				o, pr := oracle[i], product[i]
				key := o.From + "→" + o.To

				// (oracle ⇔ product): the real product must agree with the
				// independent re-derivation, on both class and cost.
				if o.Type != pr.Type {
					t.Errorf("%s: type mismatch: oracle=%s product=%s", key, o.Type, pr.Type)
				}
				if !almostEqual(o.CostUSD, pr.CostUSD) {
					t.Errorf("%s: cost mismatch: oracle=$%.6f product=$%.6f", key, o.CostUSD, pr.CostUSD)
				}

				// (⇔ scenario): both must match the human-pinned ground truth.
				e, ok := expect[key]
				if !ok {
					t.Errorf("%s: no expectation declared for this edge", key)
					continue
				}
				if e.Type != "" && e.Type != pr.Type.String() {
					t.Errorf("%s: type: scenario expected %q, product produced %q", key, e.Type, pr.Type)
				}
				if e.CostUSD != nil && !almostEqual(*e.CostUSD, pr.CostUSD) {
					t.Errorf("%s: cost: scenario expected $%.6f, product produced $%.6f", key, *e.CostUSD, pr.CostUSD)
				}
				if !t.Failed() {
					t.Logf("%s: %s = $%.6f ✓ (oracle == product == scenario)", key, pr.Type, pr.CostUSD)
				}
			}
		})
	}
}

func almostEqual(a, b float64) bool {
	const eps = 1e-9
	if d := a - b; d < 0 {
		return -d < eps
	} else {
		return d < eps
	}
}
