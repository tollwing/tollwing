package scan

import (
	"context"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tollwing/tollwing/pkg/classifier"
)

func TestAnalyze_ProjectionAndAddressable(t *testing.T) {
	// 24h window → monthly factor is exactly 30.
	byPath := map[string]float64{
		classifier.CrossAZ.String():          10.0, // addressable
		classifier.NATGatewayEgress.String(): 5.0,  // addressable
		classifier.InternetEgress.String():   4.0,  // not addressable
		classifier.SameZone.String():         0.0,  // free — dropped from breakdown
	}
	rep := Analyze(byPath, nil, 24*time.Hour)

	if got, want := rep.TotalUSD, 19.0; got != want {
		t.Fatalf("TotalUSD = %v, want %v", got, want)
	}
	if got, want := rep.MonthlyUSD, 19.0*30; got != want {
		t.Errorf("MonthlyUSD = %v, want %v", got, want)
	}
	// Addressable = (cross_az + nat_gateway) projected = (10+5)*30.
	if got, want := rep.AddressableUSD, 15.0*30; got != want {
		t.Errorf("AddressableUSD = %v, want %v", got, want)
	}
	// Zero-spend same_zone must not appear in the breakdown.
	if len(rep.ByPath) != 3 {
		t.Fatalf("ByPath has %d entries, want 3 (zero-spend dropped): %+v", len(rep.ByPath), rep.ByPath)
	}
	// Sorted descending by window USD: cross_az, nat_gateway, internet_egress.
	if rep.ByPath[0].Path != classifier.CrossAZ.String() || rep.ByPath[2].Path != classifier.InternetEgress.String() {
		t.Errorf("ByPath order wrong: %s, %s, %s", rep.ByPath[0].Path, rep.ByPath[1].Path, rep.ByPath[2].Path)
	}
	// Share of total for cross_az = 10/19.
	if got, want := rep.ByPath[0].Pct, 10.0/19.0*100; got != want {
		t.Errorf("cross_az Pct = %v, want %v", got, want)
	}
	if !rep.ByPath[0].Addressable || rep.ByPath[2].Addressable {
		t.Errorf("addressability flags wrong: %+v", rep.ByPath)
	}
	// Two recommendations (cross_az, nat_gateway), biggest first.
	if len(rep.Recommendations) != 2 || rep.Recommendations[0].Path != classifier.CrossAZ.String() {
		t.Fatalf("recommendations = %+v", rep.Recommendations)
	}
	if got, want := rep.Recommendations[0].MonthlyUSD, 10.0*30; got != want {
		t.Errorf("rec[0].MonthlyUSD = %v, want %v", got, want)
	}
}

func TestAnalyze_TopPodsSortAndCap(t *testing.T) {
	pods := []PodCost{
		{Namespace: "a", Pod: "low", USD: 1.0},
		{Namespace: "b", Pod: "high", USD: 9.0},
		{Namespace: "a", Pod: "zero", USD: 0.0}, // dropped
		{Namespace: "c", Pod: "mid", USD: 5.0},
	}
	rep := AnalyzeTopN(map[string]float64{classifier.CrossAZ.String(): 1}, pods, 24*time.Hour, 2)

	if len(rep.TopPods) != 2 {
		t.Fatalf("TopPods len = %d, want 2 (capped, zero dropped): %+v", len(rep.TopPods), rep.TopPods)
	}
	if rep.TopPods[0].Pod != "high" || rep.TopPods[1].Pod != "mid" {
		t.Errorf("top pods order wrong: %+v", rep.TopPods)
	}
	// Monthly projection per pod = USD * 30 over a 24h window.
	if got, want := rep.TopPods[0].MonthlyUSD, 9.0*30; got != want {
		t.Errorf("top pod MonthlyUSD = %v, want %v", got, want)
	}
}

func TestAnalyze_NonPositiveWindowDoesNotDivideByZero(t *testing.T) {
	rep := Analyze(map[string]float64{classifier.CrossAZ.String(): 12.0}, nil, 0)
	// Factor falls back to 1: monthly == window total, no NaN/Inf.
	if rep.MonthlyUSD != 12.0 {
		t.Errorf("MonthlyUSD with zero window = %v, want 12.0 (factor 1 fallback)", rep.MonthlyUSD)
	}
}

func TestAnalyze_EmptyIsZeroValued(t *testing.T) {
	rep := Analyze(map[string]float64{}, nil, 24*time.Hour)
	if rep.TotalUSD != 0 || len(rep.ByPath) != 0 || len(rep.Recommendations) != 0 {
		t.Errorf("empty scan not zero-valued: %+v", rep)
	}
}

func TestParseWindow(t *testing.T) {
	tests := []struct {
		in       string
		wantDur  time.Duration
		wantProm string
		wantErr  bool
	}{
		{"24h", 24 * time.Hour, "24h", false},
		{"7d", 7 * 24 * time.Hour, "7d", false},
		{"90m", 90 * time.Minute, "90m", false},
		{"1h30m", 90 * time.Minute, "1h30m", false},
		{"", 0, "", true},
		{"0h", 0, "", true},
		{"-5h", 0, "", true},
		{"0d", 0, "", true},
		{"banana", 0, "", true},
	}
	for _, tt := range tests {
		d, prom, err := ParseWindow(tt.in)
		if (err != nil) != tt.wantErr {
			t.Errorf("ParseWindow(%q) err = %v, wantErr %v", tt.in, err, tt.wantErr)
			continue
		}
		if tt.wantErr {
			continue
		}
		if d != tt.wantDur || prom != tt.wantProm {
			t.Errorf("ParseWindow(%q) = (%v, %q), want (%v, %q)", tt.in, d, prom, tt.wantDur, tt.wantProm)
		}
	}
}

func TestPromSource_FetchSumsAcrossInstances(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("query")
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(q, "traffic_type"):
			// Two nodes each contribute cross_az; the query is a sum, but
			// prove we also sum client-side if the label survives.
			w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[
				{"metric":{"traffic_type":"cross_az"},"value":[1710000000,"20.5"]},
				{"metric":{"traffic_type":"nat_gateway"},"value":[1710000000,"7.25"]},
				{"metric":{},"value":[1710000000,"99"]}
			]}}`))
		case strings.Contains(q, "pod"):
			w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[
				{"metric":{"namespace":"shop","pod":"cart-1"},"value":[1710000000,"12.0"]},
				{"metric":{"namespace":"shop","pod":"checkout-1"},"value":[1710000000,"8.0"]}
			]}}`))
		}
	}))
	defer srv.Close()

	byPath, pods, err := PromSource{BaseURL: srv.URL}.Fetch(context.Background(), "24h")
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if got, want := byPath["cross_az"], 20.5; got != want {
		t.Errorf("cross_az = %v, want %v", got, want)
	}
	if got, want := byPath["nat_gateway"], 7.25; got != want {
		t.Errorf("nat_gateway = %v, want %v", got, want)
	}
	// The label-less series (malformed for this metric) must be dropped, not
	// bucketed under "".
	if _, ok := byPath[""]; ok {
		t.Errorf("empty-label series leaked into byPath: %+v", byPath)
	}
	if len(pods) != 2 || pods[0].Namespace != "shop" {
		t.Fatalf("pods = %+v", pods)
	}
}

func TestPromSource_PrometheusError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"status":"error","error":"parse error: bad query"}`))
	}))
	defer srv.Close()

	_, _, err := PromSource{BaseURL: srv.URL}.Fetch(context.Background(), "24h")
	if err == nil || !strings.Contains(err.Error(), "bad query") {
		t.Errorf("expected prometheus error surfaced, got %v", err)
	}
}

func TestPromSource_EmptyResultIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[]}}`))
	}))
	defer srv.Close()

	_, _, err := PromSource{BaseURL: srv.URL}.Fetch(context.Background(), "24h")
	if err == nil || !strings.Contains(err.Error(), "no tollwing_") {
		t.Errorf("expected a no-metrics error, got %v", err)
	}
}

func TestReport_TextMentionsHeadlineDollars(t *testing.T) {
	byPath := map[string]float64{classifier.CrossAZ.String(): 10.0}
	rep := Analyze(byPath, []PodCost{{Namespace: "n", Pod: "p", USD: 10}}, 24*time.Hour)
	var b strings.Builder
	if err := rep.WriteText(&b); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	// Monthly projection of $10/24h = $300/mo; must appear formatted.
	if !strings.Contains(out, "$300.00") {
		t.Errorf("text report missing projected monthly $300.00:\n%s", out)
	}
	if !strings.Contains(out, "cross_az") {
		t.Errorf("text report missing cross_az path")
	}
}

func TestAnalyze_VPCEndpointIsNotAddressable(t *testing.T) {
	// vpc_endpoint is the cheap path other fixes land on; its spend must NOT
	// count as addressable or generate a savings recommendation (DEC-021, P5).
	byPath := map[string]float64{
		classifier.VPCEndpoint.String(): 200.0,
		classifier.CrossAZ.String():     10.0,
	}
	rep := Analyze(byPath, nil, 24*time.Hour)
	if got, want := rep.AddressableUSD, 10.0*30; got != want {
		t.Errorf("AddressableUSD = %v, want %v (only cross_az; vpc_endpoint excluded)", got, want)
	}
	for _, p := range rep.ByPath {
		if p.Path == classifier.VPCEndpoint.String() && p.Addressable {
			t.Errorf("vpc_endpoint flagged addressable")
		}
	}
	for _, rec := range rep.Recommendations {
		if rec.Path == classifier.VPCEndpoint.String() {
			t.Errorf("vpc_endpoint got a recommendation: %+v", rec)
		}
	}
}

func TestPromSource_DropsInvalidSamples(t *testing.T) {
	// increase() over a counter reset can emit NaN/+Inf/negative samples,
	// strings. They must be dropped at ingest, not summed or crash the report.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("query")
		if strings.Contains(q, "traffic_type") {
			w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[
				{"metric":{"traffic_type":"cross_az"},"value":[1710000000,"10.0"]},
				{"metric":{"traffic_type":"nat_gateway"},"value":[1710000000,"NaN"]},
				{"metric":{"traffic_type":"internet_egress"},"value":[1710000000,"+Inf"]},
				{"metric":{"traffic_type":"vpc_peering"},"value":[1710000000,"-3.5"]}
			]}}`))
			return
		}
		w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[
			{"metric":{"namespace":"n","pod":"p"},"value":[1710000000,"5.0"]}
		]}}`))
	}))
	defer srv.Close()

	byPath, pods, err := PromSource{BaseURL: srv.URL}.Fetch(context.Background(), "24h")
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if _, ok := byPath["nat_gateway"]; ok {
		t.Errorf("NaN nat_gateway sample not dropped: %+v", byPath)
	}
	if _, ok := byPath["internet_egress"]; ok {
		t.Errorf("+Inf internet_egress sample not dropped: %+v", byPath)
	}
	if _, ok := byPath["vpc_peering"]; ok {
		t.Errorf("negative vpc_peering sample not dropped: %+v", byPath)
	}
	// The finite report must render without panicking, and totals stay finite.
	rep := Analyze(byPath, pods, 24*time.Hour)
	var b strings.Builder
	if err := rep.WriteText(&b); err != nil {
		t.Fatalf("WriteText: %v", err)
	}
	if rep.MonthlyUSD != 10.0*30 {
		t.Errorf("MonthlyUSD = %v, want %v (only the finite cross_az sample)", rep.MonthlyUSD, 10.0*30)
	}
}

func TestMoney_NonFiniteIsNotAPanic(t *testing.T) {
	// Defense in depth: even if a non-finite value reaches money(), it renders
	// "n/a" instead of the slice-out-of-range panic it used to.
	for _, v := range []float64{math.NaN(), math.Inf(1), math.Inf(-1)} {
		if got := money(v); got != "n/a" {
			t.Errorf("money(%v) = %q, want \"n/a\"", v, got)
		}
	}
}

func TestMoney(t *testing.T) {
	for _, tt := range []struct {
		in   float64
		want string
	}{
		{0, "0.00"},
		{5.5, "5.50"},
		{1234.5, "1,234.50"},
		{1234567.89, "1,234,567.89"},
		{-42.1, "-42.10"},
	} {
		if got := money(tt.in); got != tt.want {
			t.Errorf("money(%v) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
