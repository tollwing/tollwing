package terraform

import (
	"math"
	"testing"
)

func TestEstimate_NATGatewayCreate(t *testing.T) {
	changes := []NetworkChange{
		{Address: "aws_nat_gateway.main", Type: "nat_gateway", Action: "create"},
	}
	traffic := &TrafficData{MonthlyNATEgressGB: 500}

	result := Estimate(changes, traffic)

	if result.AnalyzedResources != 1 {
		t.Errorf("AnalyzedResources = %d, want 1", result.AnalyzedResources)
	}

	want := 500 * DefaultRates.NATGatewayPerGB
	if !approxEqual(result.TotalDeltaUSD, want) {
		t.Errorf("TotalDeltaUSD = %.2f, want %.2f", result.TotalDeltaUSD, want)
	}

	if result.Changes[0].Confidence != "medium" {
		t.Errorf("Confidence = %q, want %q", result.Changes[0].Confidence, "medium")
	}
}

func TestEstimate_NATGatewayDelete(t *testing.T) {
	changes := []NetworkChange{
		{Address: "aws_nat_gateway.old", Type: "nat_gateway", Action: "delete"},
	}
	traffic := &TrafficData{MonthlyNATEgressGB: 200}

	result := Estimate(changes, traffic)

	want := -(200 * DefaultRates.NATGatewayPerGB)
	if !approxEqual(result.TotalDeltaUSD, want) {
		t.Errorf("TotalDeltaUSD = %.2f, want %.2f", result.TotalDeltaUSD, want)
	}
}

func TestEstimate_NATGatewayDefaultTraffic(t *testing.T) {
	changes := []NetworkChange{
		{Address: "aws_nat_gateway.main", Type: "nat_gateway", Action: "create"},
	}

	result := Estimate(changes, nil)

	// Default: 100 GB
	want := 100 * DefaultRates.NATGatewayPerGB
	if !approxEqual(result.TotalDeltaUSD, want) {
		t.Errorf("TotalDeltaUSD = %.2f, want %.2f", result.TotalDeltaUSD, want)
	}
}

func TestEstimate_VPCEndpointCreate(t *testing.T) {
	changes := []NetworkChange{
		{Address: "aws_vpc_endpoint.s3", Type: "vpc_endpoint", Action: "create", ServiceName: "com.amazonaws.us-east-1.s3"},
	}
	traffic := &TrafficData{MonthlyNATEgressGB: 1000}

	result := Estimate(changes, traffic)

	// Savings = (NAT rate - endpoint rate) * GB
	savings := 1000 * (DefaultRates.NATGatewayPerGB - DefaultRates.VPCEndpointPerGB)
	if !approxEqual(result.TotalDeltaUSD, -savings) {
		t.Errorf("TotalDeltaUSD = %.2f, want %.2f", result.TotalDeltaUSD, -savings)
	}

	if result.Changes[0].Confidence != "high" {
		t.Errorf("Confidence = %q, want %q", result.Changes[0].Confidence, "high")
	}
}

func TestEstimate_VPCEndpointDelete(t *testing.T) {
	changes := []NetworkChange{
		{Address: "aws_vpc_endpoint.s3", Type: "vpc_endpoint", Action: "delete"},
	}
	traffic := &TrafficData{MonthlyNATEgressGB: 1000}

	result := Estimate(changes, traffic)

	cost := 1000 * (DefaultRates.NATGatewayPerGB - DefaultRates.VPCEndpointPerGB)
	if !approxEqual(result.TotalDeltaUSD, cost) {
		t.Errorf("TotalDeltaUSD = %.2f, want %.2f", result.TotalDeltaUSD, cost)
	}
}

func TestEstimate_VPCPeeringCreate(t *testing.T) {
	changes := []NetworkChange{
		{Address: "aws_vpc_peering_connection.peer", Type: "vpc_peering", Action: "create"},
	}
	traffic := &TrafficData{MonthlyPeeringGB: 300}

	result := Estimate(changes, traffic)

	want := 300 * DefaultRates.PeeringPerGB
	if !approxEqual(result.TotalDeltaUSD, want) {
		t.Errorf("TotalDeltaUSD = %.2f, want %.2f", result.TotalDeltaUSD, want)
	}
}

func TestEstimate_VPCPeeringDelete(t *testing.T) {
	changes := []NetworkChange{
		{Address: "aws_vpc_peering_connection.peer", Type: "vpc_peering", Action: "delete"},
	}
	traffic := &TrafficData{MonthlyPeeringGB: 300}

	result := Estimate(changes, traffic)

	want := -(300 * DefaultRates.PeeringPerGB)
	if !approxEqual(result.TotalDeltaUSD, want) {
		t.Errorf("TotalDeltaUSD = %.2f, want %.2f", result.TotalDeltaUSD, want)
	}
}

func TestEstimate_TransitGatewayCreate(t *testing.T) {
	changes := []NetworkChange{
		{Address: "aws_ec2_transit_gateway.main", Type: "transit_gateway", Action: "create"},
	}
	traffic := &TrafficData{MonthlyTransitGWGB: 500}

	result := Estimate(changes, traffic)

	want := 500 * DefaultRates.TransitGWPerGB
	if !approxEqual(result.TotalDeltaUSD, want) {
		t.Errorf("TotalDeltaUSD = %.2f, want %.2f", result.TotalDeltaUSD, want)
	}
}

func TestEstimate_TransitGatewayDelete(t *testing.T) {
	changes := []NetworkChange{
		{Address: "aws_ec2_transit_gateway.main", Type: "transit_gateway", Action: "delete"},
	}
	traffic := &TrafficData{MonthlyTransitGWGB: 500}

	result := Estimate(changes, traffic)

	want := -(500 * DefaultRates.TransitGWPerGB)
	if !approxEqual(result.TotalDeltaUSD, want) {
		t.Errorf("TotalDeltaUSD = %.2f, want %.2f", result.TotalDeltaUSD, want)
	}
}

func TestEstimate_SubnetCreate(t *testing.T) {
	changes := []NetworkChange{
		{Address: "aws_subnet.main", Type: "subnet", Action: "create", CIDR: "10.0.1.0/24", Zone: "us-east-1a"},
	}

	result := Estimate(changes, nil)

	// Subnet changes have no direct cost delta.
	if result.TotalDeltaUSD != 0 {
		t.Errorf("TotalDeltaUSD = %.2f, want 0", result.TotalDeltaUSD)
	}
	if result.Changes[0].Confidence != "low" {
		t.Errorf("Confidence = %q, want %q", result.Changes[0].Confidence, "low")
	}
}

func TestEstimate_UnknownType(t *testing.T) {
	changes := []NetworkChange{
		{Address: "aws_route.main", Type: "route", Action: "create"},
	}

	result := Estimate(changes, nil)

	if result.TotalDeltaUSD != 0 {
		t.Errorf("TotalDeltaUSD = %.2f, want 0", result.TotalDeltaUSD)
	}
	if result.Changes[0].Confidence != "low" {
		t.Errorf("Confidence = %q, want %q", result.Changes[0].Confidence, "low")
	}
}

func TestEstimate_MultipleChanges(t *testing.T) {
	changes := []NetworkChange{
		{Address: "aws_nat_gateway.new", Type: "nat_gateway", Action: "create"},
		{Address: "aws_vpc_endpoint.s3", Type: "vpc_endpoint", Action: "create"},
		{Address: "aws_vpc_peering_connection.peer", Type: "vpc_peering", Action: "create"},
	}
	traffic := &TrafficData{
		MonthlyNATEgressGB: 200,
		MonthlyPeeringGB:   100,
	}

	result := Estimate(changes, traffic)

	if result.AnalyzedResources != 3 {
		t.Errorf("AnalyzedResources = %d, want 3", result.AnalyzedResources)
	}
	if result.NetworkChanges != 3 {
		t.Errorf("NetworkChanges = %d, want 3", result.NetworkChanges)
	}

	natCost := 200 * DefaultRates.NATGatewayPerGB
	endpointSavings := 200 * (DefaultRates.NATGatewayPerGB - DefaultRates.VPCEndpointPerGB)
	peeringCost := 100 * DefaultRates.PeeringPerGB

	wantTotal := natCost - endpointSavings + peeringCost
	if !approxEqual(result.TotalDeltaUSD, wantTotal) {
		t.Errorf("TotalDeltaUSD = %.2f, want %.2f", result.TotalDeltaUSD, wantTotal)
	}
}

func TestEstimate_AffectedServices(t *testing.T) {
	changes := []NetworkChange{
		{Address: "aws_nat_gateway.main", Type: "nat_gateway", Action: "create"},
	}
	traffic := &TrafficData{
		MonthlyNATEgressGB: 100,
		AffectedServices: map[string][]string{
			"aws_nat_gateway.main": {"api-server", "worker"},
		},
	}

	result := Estimate(changes, traffic)

	svcs := result.Changes[0].AffectedServices
	if len(svcs) != 2 {
		t.Fatalf("got %d affected services, want 2", len(svcs))
	}
}

func TestEstimate_NATGatewayUpdate(t *testing.T) {
	changes := []NetworkChange{
		{Address: "aws_nat_gateway.main", Type: "nat_gateway", Action: "update"},
	}

	result := Estimate(changes, nil)

	if result.TotalDeltaUSD != 0 {
		t.Errorf("TotalDeltaUSD = %.2f, want 0 for update", result.TotalDeltaUSD)
	}
	if result.Changes[0].Confidence != "low" {
		t.Errorf("Confidence = %q, want %q", result.Changes[0].Confidence, "low")
	}
}

func TestEstimate_Empty(t *testing.T) {
	result := Estimate(nil, nil)

	if result.TotalDeltaUSD != 0 {
		t.Errorf("TotalDeltaUSD = %.2f, want 0", result.TotalDeltaUSD)
	}
	if result.AnalyzedResources != 0 {
		t.Errorf("AnalyzedResources = %d, want 0", result.AnalyzedResources)
	}
}

func approxEqual(a, b float64) bool {
	return math.Abs(a-b) < 0.01
}
