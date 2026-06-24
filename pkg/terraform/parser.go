// Package terraform parses Terraform plan JSON output and identifies
// resource changes that affect network topology and cost.
package terraform

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// Plan represents a parsed Terraform plan.
type Plan struct {
	ResourceChanges []ResourceChange           `json:"resource_changes"`
	Variables       map[string]json.RawMessage `json:"variables"`
}

// ResourceChange represents a single resource change in the plan.
type ResourceChange struct {
	Address      string `json:"address"`
	Type         string `json:"type"`
	Name         string `json:"name"`
	ProviderName string `json:"provider_name"`
	Change       Change `json:"change"`
}

// Change holds the before/after state of a resource.
type Change struct {
	Actions []string               `json:"actions"`
	Before  map[string]interface{} `json:"before"`
	After   map[string]interface{} `json:"after"`
}

// NetworkChange is a parsed network-relevant change from a Terraform plan.
type NetworkChange struct {
	Address     string `json:"address"`
	Type        string `json:"type"`   // subnet, nat_gateway, vpc_endpoint, etc.
	Action      string `json:"action"` // create, delete, update
	Description string `json:"description"`
	// Parsed details.
	CIDR        string `json:"cidr,omitempty"`
	Zone        string `json:"zone,omitempty"`
	ServiceName string `json:"service_name,omitempty"`
	Region      string `json:"region,omitempty"`
}

// networkResourceTypes maps Terraform resource types to our network-resource
// categories. These category values are Terraform-domain tokens; several
// coincide with classifier.TrafficType wire strings (nat_gateway, vpc_endpoint,
// vpc_peering, transit_gateway) but are NOT TrafficType values — a scoped,
// intentional P6 exception (DEC-007).
var networkResourceTypes = map[string]string{
	// AWS
	"aws_subnet":                             "subnet",
	"aws_nat_gateway":                        "nat_gateway",     // not a classifier.TrafficType (DEC-007)
	"aws_vpc_endpoint":                       "vpc_endpoint",    // not a classifier.TrafficType (DEC-007)
	"aws_vpc_peering_connection":             "vpc_peering",     // not a classifier.TrafficType (DEC-007)
	"aws_ec2_transit_gateway":                "transit_gateway", // not a classifier.TrafficType (DEC-007)
	"aws_ec2_transit_gateway_vpc_attachment": "transit_gateway_attachment",
	"aws_route":                              "route",
	"aws_route_table":                        "route_table",
	// GCP
	"google_compute_subnetwork":      "subnet",
	"google_compute_router_nat":      "nat_gateway", // not a classifier.TrafficType (DEC-007)
	"google_compute_network_peering": "vpc_peering", // not a classifier.TrafficType (DEC-007)
	// Azure
	"azurerm_subnet":                  "subnet",
	"azurerm_nat_gateway":             "nat_gateway", // not a classifier.TrafficType (DEC-007)
	"azurerm_virtual_network_peering": "vpc_peering", // not a classifier.TrafficType (DEC-007)
}

// ParsePlan parses a Terraform JSON plan from a reader.
func ParsePlan(r io.Reader) (*Plan, error) {
	var plan Plan
	if err := json.NewDecoder(r).Decode(&plan); err != nil {
		return nil, fmt.Errorf("decode terraform plan: %w", err)
	}
	return &plan, nil
}

// ExtractNetworkChanges identifies resource changes that affect network topology.
func ExtractNetworkChanges(plan *Plan) []NetworkChange {
	var changes []NetworkChange

	for _, rc := range plan.ResourceChanges {
		category, ok := networkResourceTypes[rc.Type]
		if !ok {
			continue
		}

		for _, action := range rc.Change.Actions {
			if action == "no-op" || action == "read" {
				continue
			}

			nc := NetworkChange{
				Address: rc.Address,
				Type:    category,
				Action:  action,
			}

			// Extract details from after state (for create/update) or before (for delete).
			state := rc.Change.After
			if action == "delete" {
				state = rc.Change.Before
			}

			if state != nil {
				nc.extractDetails(rc.Type, state)
			}

			nc.Description = describeChange(nc)
			changes = append(changes, nc)
		}
	}

	return changes
}

func (nc *NetworkChange) extractDetails(resourceType string, state map[string]interface{}) {
	switch {
	case strings.Contains(resourceType, "subnet"):
		if cidr, ok := state["cidr_block"].(string); ok {
			nc.CIDR = cidr
		}
		if cidr, ok := state["ip_cidr_range"].(string); ok {
			nc.CIDR = cidr // GCP
		}
		if cidr, ok := state["address_prefix"].(string); ok {
			nc.CIDR = cidr // Azure
		}
		if az, ok := state["availability_zone"].(string); ok {
			nc.Zone = az
		}
		if region, ok := state["region"].(string); ok {
			nc.Region = region
		}

	case strings.Contains(resourceType, "nat_gateway"): // not a classifier.TrafficType (DEC-007)
		if subnet, ok := state["subnet_id"].(string); ok {
			nc.ServiceName = "NAT Gateway (subnet: " + subnet + ")"
		}

	case strings.Contains(resourceType, "vpc_endpoint"): // not a classifier.TrafficType (DEC-007)
		if svc, ok := state["service_name"].(string); ok {
			nc.ServiceName = svc
		}

	case strings.Contains(resourceType, "peering"):
		if peer, ok := state["peer_vpc_id"].(string); ok {
			nc.ServiceName = "VPC Peering to " + peer
		}
		if peer, ok := state["peer_virtual_network_id"].(string); ok {
			nc.ServiceName = "VNet Peering to " + peer
		}
	}
}

func describeChange(nc NetworkChange) string {
	verb := "Modify"
	switch nc.Action {
	case "create":
		verb = "Create"
	case "delete":
		verb = "Delete"
	case "update":
		verb = "Update"
	}

	detail := nc.Type
	if nc.CIDR != "" {
		detail += " " + nc.CIDR
	}
	if nc.Zone != "" {
		detail += " in " + nc.Zone
	}
	if nc.ServiceName != "" {
		detail += " (" + nc.ServiceName + ")"
	}

	return fmt.Sprintf("%s %s: %s", verb, nc.Address, detail)
}
