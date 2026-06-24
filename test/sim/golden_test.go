package sim

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/tollwing/tollwing/test/sim/scenario"
)

var update = flag.Bool("update", false, "update golden files")

// TestGolden_ClassificationCost replays every scenario through the real
// classification + cost path and snapshots {scenario, edge, traffic_type, bytes,
// cost} to a canonical JSON golden file. A diff means classification or cost
// output changed — the P4 traceability snapshot as code (the DeepFlow
// pcap-replay pattern). Enum strings derive from TrafficType.String() (P6), so
// they cannot silently drift in the golden.
//
// Regenerate intentionally with:  go test ./test/sim/... -run Golden -update
func TestGolden_ClassificationCost(t *testing.T) {
	type row struct {
		Scenario    string  `json:"scenario"`
		From        string  `json:"from"`
		To          string  `json:"to"`
		TrafficType string  `json:"traffic_type"`
		Bytes       uint64  `json:"bytes"`
		CostUSD     float64 `json:"cost_usd"`
	}

	paths, _ := filepath.Glob("scenarios/*.yaml")
	if len(paths) == 0 {
		t.Fatal("no scenarios found")
	}
	var rows []row
	for _, p := range paths {
		s, err := scenario.Load(p)
		if err != nil {
			t.Fatalf("load %s: %v", p, err)
		}
		for _, m := range measure(s) {
			rows = append(rows, row{
				Scenario:    s.Name,
				From:        m.edge.From,
				To:          m.edge.To,
				TrafficType: m.tt.String(),
				Bytes:       m.tx + m.rx,
				CostUSD:     m.cost,
			})
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Scenario != rows[j].Scenario {
			return rows[i].Scenario < rows[j].Scenario
		}
		if rows[i].From != rows[j].From {
			return rows[i].From < rows[j].From
		}
		return rows[i].To < rows[j].To
	})

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(rows); err != nil {
		t.Fatal(err)
	}
	got := buf.Bytes()

	golden := filepath.Join("testdata", "classification-cost.golden.json")
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(golden, got, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("updated %s (%d rows)", golden, len(rows))
		return
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read golden (run `go test ./test/sim/... -run Golden -update` to create): %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("classification/cost snapshot changed (run -update to accept the new output):\n--- got ---\n%s", got)
	}
}
