package terraform

import (
	"fmt"
)

// CostImpact is the estimated cost impact of a Terraform change.
type CostImpact struct {
	Change            NetworkChange `json:"change"`
	EstimatedDeltaUSD float64       `json:"estimated_delta_usd"`
	Explanation       string        `json:"explanation"`
	AffectedServices  []string      `json:"affected_services,omitempty"`
	Confidence        string        `json:"confidence"` // high, medium, low
}

// EstimateResult is the full cost estimation for a Terraform plan.
type EstimateResult struct {
	Changes           []CostImpact `json:"changes"`
	TotalDeltaUSD     float64      `json:"total_delta_usd"`
	MonthlyImpactUSD  float64      `json:"monthly_impact_usd"`
	AnalyzedResources int          `json:"analyzed_resources"`
	NetworkChanges    int          `json:"network_changes"`
}

// TrafficData represents current traffic patterns for cost estimation.
type TrafficData struct {
	// MonthlyEgressGB is the total monthly egress through NAT gateways.
	MonthlyNATEgressGB float64
	// MonthlyPeeringGB is the total monthly peering traffic.
	MonthlyPeeringGB float64
	// MonthlyTransitGWGB is the total monthly transit gateway traffic.
	MonthlyTransitGWGB float64
	// AffectedServices maps resource addresses to affected service names.
	AffectedServices map[string][]string
}

// DefaultRates for cost estimation when no rate card is available.
var DefaultRates = struct {
	NATGatewayPerGB  float64
	VPCEndpointPerGB float64
	PeeringPerGB     float64
	TransitGWPerGB   float64
	CrossAZPerGB     float64
}{
	NATGatewayPerGB:  0.045,
	VPCEndpointPerGB: 0.01,
	PeeringPerGB:     0.01,
	TransitGWPerGB:   0.02,
	CrossAZPerGB:     0.01,
}

// Estimate cross-references Terraform changes with traffic data to estimate cost impact.
func Estimate(changes []NetworkChange, traffic *TrafficData) EstimateResult {
	if traffic == nil {
		traffic = &TrafficData{}
	}

	var impacts []CostImpact
	var totalDelta float64

	for _, change := range changes {
		impact := estimateChange(change, traffic)
		impacts = append(impacts, impact)
		totalDelta += impact.EstimatedDeltaUSD
	}

	return EstimateResult{
		Changes:           impacts,
		TotalDeltaUSD:     totalDelta,
		MonthlyImpactUSD:  totalDelta,
		AnalyzedResources: len(changes),
		NetworkChanges:    len(changes),
	}
}

func estimateChange(change NetworkChange, traffic *TrafficData) CostImpact {
	impact := CostImpact{
		Change:     change,
		Confidence: "medium",
	}

	// change.Type is a Terraform resource category from parser.go's
	// networkResourceTypes table — a Terraform-domain token, not a
	// classifier.TrafficType, even where the names coincide (DEC-007).
	switch change.Type {
	case "nat_gateway": // not a classifier.TrafficType (DEC-007)
		impact = estimateNATGateway(change, traffic)
	case "vpc_endpoint": // not a classifier.TrafficType (DEC-007)
		impact = estimateVPCEndpoint(change, traffic)
	case "vpc_peering": // not a classifier.TrafficType (DEC-007)
		impact = estimateVPCPeering(change, traffic)
	case "transit_gateway", "transit_gateway_attachment": // not a classifier.TrafficType (DEC-007)
		impact = estimateTransitGW(change, traffic)
	case "subnet":
		impact = estimateSubnet(change, traffic)
	default:
		impact.Explanation = "No cost model for this resource type"
		impact.Confidence = "low"
	}

	impact.Change = change
	if traffic.AffectedServices != nil {
		if svcs, ok := traffic.AffectedServices[change.Address]; ok {
			impact.AffectedServices = svcs
		}
	}
	return impact
}

func estimateNATGateway(change NetworkChange, traffic *TrafficData) CostImpact {
	monthlyGB := traffic.MonthlyNATEgressGB
	if monthlyGB == 0 {
		monthlyGB = 100 // conservative estimate
	}

	monthlyCost := monthlyGB * DefaultRates.NATGatewayPerGB

	switch change.Action {
	case "create":
		return CostImpact{
			EstimatedDeltaUSD: monthlyCost,
			Explanation:       fmt.Sprintf("New NAT gateway: ~%.0f GB/month × $%.3f/GB = $%.2f/month data processing + hourly charges", monthlyGB, DefaultRates.NATGatewayPerGB, monthlyCost),
			Confidence:        "medium",
		}
	case "delete":
		return CostImpact{
			EstimatedDeltaUSD: -monthlyCost,
			Explanation:       fmt.Sprintf("Removing NAT gateway saves ~$%.2f/month in data processing charges", monthlyCost),
			Confidence:        "medium",
		}
	default:
		return CostImpact{
			Explanation: "NAT gateway modification — cost impact depends on traffic routing changes",
			Confidence:  "low",
		}
	}
}

func estimateVPCEndpoint(change NetworkChange, traffic *TrafficData) CostImpact {
	monthlyGB := traffic.MonthlyNATEgressGB
	if monthlyGB == 0 {
		monthlyGB = 100
	}

	switch change.Action {
	case "create":
		// VPC endpoint replaces NAT gateway for specific service traffic.
		savings := monthlyGB * (DefaultRates.NATGatewayPerGB - DefaultRates.VPCEndpointPerGB)
		return CostImpact{
			EstimatedDeltaUSD: -savings,
			Explanation:       fmt.Sprintf("VPC endpoint for %s: saves $%.3f/GB vs NAT gateway, ~$%.2f/month savings", change.ServiceName, DefaultRates.NATGatewayPerGB-DefaultRates.VPCEndpointPerGB, savings),
			Confidence:        "high",
		}
	case "delete":
		cost := monthlyGB * (DefaultRates.NATGatewayPerGB - DefaultRates.VPCEndpointPerGB)
		return CostImpact{
			EstimatedDeltaUSD: cost,
			Explanation:       fmt.Sprintf("Removing VPC endpoint: traffic falls back to NAT gateway, ~$%.2f/month increase", cost),
			Confidence:        "high",
		}
	default:
		return CostImpact{Explanation: "VPC endpoint update", Confidence: "low"}
	}
}

func estimateVPCPeering(change NetworkChange, traffic *TrafficData) CostImpact {
	monthlyGB := traffic.MonthlyPeeringGB
	if monthlyGB == 0 {
		monthlyGB = 50
	}

	switch change.Action {
	case "create":
		cost := monthlyGB * DefaultRates.PeeringPerGB
		return CostImpact{
			EstimatedDeltaUSD: cost,
			Explanation:       fmt.Sprintf("New VPC peering: ~%.0f GB/month × $%.3f/GB = $%.2f/month", monthlyGB, DefaultRates.PeeringPerGB, cost),
			Confidence:        "medium",
		}
	case "delete":
		cost := monthlyGB * DefaultRates.PeeringPerGB
		return CostImpact{
			EstimatedDeltaUSD: -cost,
			Explanation:       fmt.Sprintf("Removing VPC peering saves ~$%.2f/month", cost),
			Confidence:        "medium",
		}
	default:
		return CostImpact{Explanation: "VPC peering update", Confidence: "low"}
	}
}

func estimateTransitGW(change NetworkChange, traffic *TrafficData) CostImpact {
	monthlyGB := traffic.MonthlyTransitGWGB
	if monthlyGB == 0 {
		monthlyGB = 100
	}

	switch change.Action {
	case "create":
		cost := monthlyGB * DefaultRates.TransitGWPerGB
		return CostImpact{
			EstimatedDeltaUSD: cost,
			Explanation:       fmt.Sprintf("New transit gateway attachment: ~%.0f GB/month × $%.3f/GB = $%.2f/month + hourly charges", monthlyGB, DefaultRates.TransitGWPerGB, cost),
			Confidence:        "medium",
		}
	case "delete":
		cost := monthlyGB * DefaultRates.TransitGWPerGB
		return CostImpact{
			EstimatedDeltaUSD: -cost,
			Explanation:       fmt.Sprintf("Removing transit gateway saves ~$%.2f/month", cost),
			Confidence:        "medium",
		}
	default:
		return CostImpact{Explanation: "Transit gateway modification", Confidence: "low"}
	}
}

func estimateSubnet(change NetworkChange, traffic *TrafficData) CostImpact {
	switch change.Action {
	case "create":
		return CostImpact{
			Explanation: fmt.Sprintf("New subnet %s in %s — cost depends on workload placement and cross-AZ traffic patterns", change.CIDR, change.Zone),
			Confidence:  "low",
		}
	case "delete":
		return CostImpact{
			Explanation: fmt.Sprintf("Removing subnet %s — workloads must relocate, may change cross-AZ costs", change.CIDR),
			Confidence:  "low",
		}
	default:
		return CostImpact{Explanation: "Subnet modification", Confidence: "low"}
	}
}
