package scan

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"strings"
)

// WriteJSON emits the report as indented JSON.
func (r Report) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// WriteText renders a human-readable report in the same voice as `make demo`.
func (r Report) WriteText(w io.Writer) error {
	var b strings.Builder

	windowLabel := formatHours(r.WindowHours)
	fmt.Fprintf(&b, "\n  ┌────────────────────────────────────────────────────────────────────────┐\n")
	fmt.Fprintf(&b, "  │  Tollwing · network-cost scan · last %-35s │\n", windowLabel)
	fmt.Fprintf(&b, "  └────────────────────────────────────────────────────────────────────────┘\n\n")

	fmt.Fprintf(&b, "  Measured from the agent's tollwing_* metrics (bytes × dated rate, never\n")
	fmt.Fprintf(&b, "  estimated). Monthly figures are a linear projection of the last %s.\n\n", windowLabel)

	// Headline.
	fmt.Fprintf(&b, "  NETWORK DATA-TRANSFER COST\n")
	fmt.Fprintf(&b, "  ──────────────────────────────────────────────────────────────────────────\n")
	fmt.Fprintf(&b, "     last %-10s   $%s\n", windowLabel, money(r.TotalUSD))
	fmt.Fprintf(&b, "     projected/mo    $%s\n", money(r.MonthlyUSD))
	if r.MonthlyUSD > 0 {
		pct := r.AddressableUSD / r.MonthlyUSD * 100
		fmt.Fprintf(&b, "     addressable/mo  $%s   (%.0f%%, has a known low-effort fix)\n", money(r.AddressableUSD), pct)
	}
	fmt.Fprintln(&b)

	// Breakdown by billing path.
	if len(r.ByPath) > 0 {
		fmt.Fprintf(&b, "  BY AWS BILLING PATH  (projected monthly)\n")
		fmt.Fprintf(&b, "  ──────────────────────────────────────────────────────────────────────────\n")
		fmt.Fprintf(&b, "     %-22s %12s   %6s   %s\n", "billing path", "$/mo", "share", "")
		fmt.Fprintf(&b, "     ─────────────────────────────────────────────────────────────────────\n")
		for _, p := range r.ByPath {
			marker := ""
			if p.Addressable {
				marker = "◀ addressable"
			}
			fmt.Fprintf(&b, "     %-22s %12s   %5.0f%%   %s\n", p.Path, "$"+money(p.MonthlyUSD), p.Pct, marker)
		}
		fmt.Fprintln(&b)
	}

	// Top cost-driving pods.
	if len(r.TopPods) > 0 {
		fmt.Fprintf(&b, "  TOP COST-DRIVING PODS  (projected monthly)\n")
		fmt.Fprintf(&b, "  ──────────────────────────────────────────────────────────────────────────\n")
		for _, p := range r.TopPods {
			fmt.Fprintf(&b, "     %12s   %s/%s\n", "$"+money(p.MonthlyUSD), p.Namespace, p.Pod)
		}
		fmt.Fprintln(&b)
	}

	// Recommendations.
	if len(r.Recommendations) > 0 {
		fmt.Fprintf(&b, "  WHERE TO LOOK FIRST\n")
		fmt.Fprintf(&b, "  ──────────────────────────────────────────────────────────────────────────\n")
		for _, rec := range r.Recommendations {
			fmt.Fprintf(&b, "   • %s  (up to $%s/mo)\n", rec.Path, money(rec.MonthlyUSD))
			fmt.Fprintf(&b, "     %s\n", wrap(rec.Action, 68, "     "))
		}
		fmt.Fprintln(&b)
	}

	fmt.Fprintf(&b, "  ──────────────────────────────────────────────────────────────────────────\n")
	fmt.Fprintf(&b, "  Per-pod, per-service, per-connection detail and cost-savings reports are\n")
	fmt.Fprintf(&b, "  Tollwing Enterprise. This scan uses only the free agent's metrics.\n")

	_, err := io.WriteString(w, b.String())
	return err
}

// money formats a USD amount with thousands separators and 2 decimals.
// Non-finite input (which ingest already filters, but guard anyway) renders as
// "n/a" rather than crashing the report.
func money(v float64) string {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return "n/a"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	s := fmt.Sprintf("%.2f", v)
	dot := strings.IndexByte(s, '.')
	intPart, frac := s[:dot], s[dot:]
	var out strings.Builder
	n := len(intPart)
	for i, c := range intPart {
		if i > 0 && (n-i)%3 == 0 {
			out.WriteByte(',')
		}
		out.WriteRune(c)
	}
	res := out.String() + frac
	if neg {
		res = "-" + res
	}
	return res
}

// formatHours renders a window as a compact "24h" / "7d" style label.
func formatHours(h float64) string {
	if h <= 0 {
		return "window"
	}
	if h >= 24 && float64(int(h))/24 == h/24 && int(h)%24 == 0 {
		return fmt.Sprintf("%dd", int(h)/24)
	}
	if h == float64(int(h)) {
		return fmt.Sprintf("%dh", int(h))
	}
	return fmt.Sprintf("%.1fh", h)
}

// wrap soft-wraps s at width columns, indenting continuation lines with indent.
func wrap(s string, width int, indent string) string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return ""
	}
	var b strings.Builder
	lineLen := 0
	for i, word := range words {
		if i > 0 {
			if lineLen+1+len(word) > width {
				b.WriteString("\n" + indent)
				lineLen = 0
			} else {
				b.WriteByte(' ')
				lineLen++
			}
		}
		b.WriteString(word)
		lineLen += len(word)
	}
	return b.String()
}
