package terraform

import (
	"strings"
	"testing"
)

func TestParsePlan(t *testing.T) {
	planJSON := `{
		"resource_changes": [
			{
				"address": "aws_nat_gateway.main",
				"type": "aws_nat_gateway",
				"name": "main",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"change": {
					"actions": ["create"],
					"before": null,
					"after": {
						"subnet_id": "subnet-abc123"
					}
				}
			},
			{
				"address": "aws_instance.web",
				"type": "aws_instance",
				"name": "web",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"change": {
					"actions": ["create"],
					"before": null,
					"after": {}
				}
			}
		]
	}`

	plan, err := ParsePlan(strings.NewReader(planJSON))
	if err != nil {
		t.Fatalf("ParsePlan: %v", err)
	}

	if len(plan.ResourceChanges) != 2 {
		t.Fatalf("got %d resource changes, want 2", len(plan.ResourceChanges))
	}

	rc := plan.ResourceChanges[0]
	if rc.Address != "aws_nat_gateway.main" {
		t.Errorf("address = %q, want %q", rc.Address, "aws_nat_gateway.main")
	}
	if rc.Type != "aws_nat_gateway" {
		t.Errorf("type = %q, want %q", rc.Type, "aws_nat_gateway")
	}
	if rc.Change.Actions[0] != "create" {
		t.Errorf("action = %q, want %q", rc.Change.Actions[0], "create")
	}
}

func TestParsePlanInvalid(t *testing.T) {
	_, err := ParsePlan(strings.NewReader("not json"))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestExtractNetworkChanges(t *testing.T) {
	plan := &Plan{
		ResourceChanges: []ResourceChange{
			{
				Address: "aws_nat_gateway.main",
				Type:    "aws_nat_gateway",
				Name:    "main",
				Change: Change{
					Actions: []string{"create"},
					After: map[string]interface{}{
						"subnet_id": "subnet-abc123",
					},
				},
			},
			{
				Address: "aws_subnet.private",
				Type:    "aws_subnet",
				Name:    "private",
				Change: Change{
					Actions: []string{"create"},
					After: map[string]interface{}{
						"cidr_block":        "10.0.1.0/24",
						"availability_zone": "us-east-1a",
					},
				},
			},
			{
				Address: "aws_vpc_endpoint.s3",
				Type:    "aws_vpc_endpoint",
				Name:    "s3",
				Change: Change{
					Actions: []string{"create"},
					After: map[string]interface{}{
						"service_name": "com.amazonaws.us-east-1.s3",
					},
				},
			},
			{
				Address: "aws_instance.web",
				Type:    "aws_instance",
				Name:    "web",
				Change: Change{
					Actions: []string{"create"},
					After:   map[string]interface{}{},
				},
			},
			{
				Address: "aws_subnet.ignored",
				Type:    "aws_subnet",
				Name:    "ignored",
				Change: Change{
					Actions: []string{"no-op"},
					Before: map[string]interface{}{
						"cidr_block": "10.0.2.0/24",
					},
					After: map[string]interface{}{
						"cidr_block": "10.0.2.0/24",
					},
				},
			},
		},
	}

	changes := ExtractNetworkChanges(plan)

	if len(changes) != 3 {
		t.Fatalf("got %d changes, want 3", len(changes))
	}

	// NAT gateway
	if changes[0].Type != "nat_gateway" {
		t.Errorf("changes[0].Type = %q, want %q", changes[0].Type, "nat_gateway")
	}
	if changes[0].Action != "create" {
		t.Errorf("changes[0].Action = %q, want %q", changes[0].Action, "create")
	}
	if !strings.Contains(changes[0].ServiceName, "subnet-abc123") {
		t.Errorf("changes[0].ServiceName = %q, want to contain subnet ID", changes[0].ServiceName)
	}

	// Subnet
	if changes[1].Type != "subnet" {
		t.Errorf("changes[1].Type = %q, want %q", changes[1].Type, "subnet")
	}
	if changes[1].CIDR != "10.0.1.0/24" {
		t.Errorf("changes[1].CIDR = %q, want %q", changes[1].CIDR, "10.0.1.0/24")
	}
	if changes[1].Zone != "us-east-1a" {
		t.Errorf("changes[1].Zone = %q, want %q", changes[1].Zone, "us-east-1a")
	}

	// VPC endpoint
	if changes[2].Type != "vpc_endpoint" {
		t.Errorf("changes[2].Type = %q, want %q", changes[2].Type, "vpc_endpoint")
	}
	if changes[2].ServiceName != "com.amazonaws.us-east-1.s3" {
		t.Errorf("changes[2].ServiceName = %q", changes[2].ServiceName)
	}
}

func TestExtractNetworkChanges_Delete(t *testing.T) {
	plan := &Plan{
		ResourceChanges: []ResourceChange{
			{
				Address: "aws_nat_gateway.old",
				Type:    "aws_nat_gateway",
				Name:    "old",
				Change: Change{
					Actions: []string{"delete"},
					Before: map[string]interface{}{
						"subnet_id": "subnet-old",
					},
					After: nil,
				},
			},
		},
	}

	changes := ExtractNetworkChanges(plan)
	if len(changes) != 1 {
		t.Fatalf("got %d changes, want 1", len(changes))
	}
	if changes[0].Action != "delete" {
		t.Errorf("action = %q, want %q", changes[0].Action, "delete")
	}
	if !strings.Contains(changes[0].ServiceName, "subnet-old") {
		t.Errorf("service name should contain subnet ID: %q", changes[0].ServiceName)
	}
}

func TestExtractNetworkChanges_GCP(t *testing.T) {
	plan := &Plan{
		ResourceChanges: []ResourceChange{
			{
				Address: "google_compute_subnetwork.main",
				Type:    "google_compute_subnetwork",
				Name:    "main",
				Change: Change{
					Actions: []string{"create"},
					After: map[string]interface{}{
						"ip_cidr_range": "10.128.0.0/20",
						"region":        "us-central1",
					},
				},
			},
			{
				Address: "google_compute_router_nat.nat",
				Type:    "google_compute_router_nat",
				Name:    "nat",
				Change: Change{
					Actions: []string{"create"},
					After:   map[string]interface{}{},
				},
			},
		},
	}

	changes := ExtractNetworkChanges(plan)
	if len(changes) != 2 {
		t.Fatalf("got %d changes, want 2", len(changes))
	}
	if changes[0].CIDR != "10.128.0.0/20" {
		t.Errorf("CIDR = %q, want %q", changes[0].CIDR, "10.128.0.0/20")
	}
	if changes[0].Region != "us-central1" {
		t.Errorf("Region = %q, want %q", changes[0].Region, "us-central1")
	}
}

func TestExtractNetworkChanges_Azure(t *testing.T) {
	plan := &Plan{
		ResourceChanges: []ResourceChange{
			{
				Address: "azurerm_subnet.internal",
				Type:    "azurerm_subnet",
				Name:    "internal",
				Change: Change{
					Actions: []string{"create"},
					After: map[string]interface{}{
						"address_prefix": "10.0.1.0/24",
					},
				},
			},
			{
				Address: "azurerm_virtual_network_peering.hub",
				Type:    "azurerm_virtual_network_peering",
				Name:    "hub",
				Change: Change{
					Actions: []string{"create"},
					After: map[string]interface{}{
						"peer_virtual_network_id": "/subscriptions/xxx/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/hub-vnet",
					},
				},
			},
		},
	}

	changes := ExtractNetworkChanges(plan)
	if len(changes) != 2 {
		t.Fatalf("got %d changes, want 2", len(changes))
	}
	if changes[0].CIDR != "10.0.1.0/24" {
		t.Errorf("CIDR = %q, want %q", changes[0].CIDR, "10.0.1.0/24")
	}
	if !strings.Contains(changes[1].ServiceName, "hub-vnet") {
		t.Errorf("ServiceName = %q, want to contain hub-vnet", changes[1].ServiceName)
	}
}

func TestExtractNetworkChanges_VPCPeering(t *testing.T) {
	plan := &Plan{
		ResourceChanges: []ResourceChange{
			{
				Address: "aws_vpc_peering_connection.peer",
				Type:    "aws_vpc_peering_connection",
				Name:    "peer",
				Change: Change{
					Actions: []string{"create"},
					After: map[string]interface{}{
						"peer_vpc_id": "vpc-abc123",
					},
				},
			},
		},
	}

	changes := ExtractNetworkChanges(plan)
	if len(changes) != 1 {
		t.Fatalf("got %d changes, want 1", len(changes))
	}
	if changes[0].Type != "vpc_peering" {
		t.Errorf("type = %q, want %q", changes[0].Type, "vpc_peering")
	}
	if !strings.Contains(changes[0].ServiceName, "vpc-abc123") {
		t.Errorf("ServiceName = %q, want to contain vpc-abc123", changes[0].ServiceName)
	}
}

func TestExtractNetworkChanges_TransitGateway(t *testing.T) {
	plan := &Plan{
		ResourceChanges: []ResourceChange{
			{
				Address: "aws_ec2_transit_gateway.main",
				Type:    "aws_ec2_transit_gateway",
				Name:    "main",
				Change: Change{
					Actions: []string{"create"},
					After:   map[string]interface{}{},
				},
			},
			{
				Address: "aws_ec2_transit_gateway_vpc_attachment.vpc1",
				Type:    "aws_ec2_transit_gateway_vpc_attachment",
				Name:    "vpc1",
				Change: Change{
					Actions: []string{"create"},
					After:   map[string]interface{}{},
				},
			},
		},
	}

	changes := ExtractNetworkChanges(plan)
	if len(changes) != 2 {
		t.Fatalf("got %d changes, want 2", len(changes))
	}
	if changes[0].Type != "transit_gateway" {
		t.Errorf("changes[0].Type = %q, want %q", changes[0].Type, "transit_gateway")
	}
	if changes[1].Type != "transit_gateway_attachment" {
		t.Errorf("changes[1].Type = %q, want %q", changes[1].Type, "transit_gateway_attachment")
	}
}

func TestExtractNetworkChanges_ReadNoOp(t *testing.T) {
	plan := &Plan{
		ResourceChanges: []ResourceChange{
			{
				Address: "aws_subnet.data",
				Type:    "aws_subnet",
				Name:    "data",
				Change: Change{
					Actions: []string{"read"},
					After:   map[string]interface{}{},
				},
			},
		},
	}

	changes := ExtractNetworkChanges(plan)
	if len(changes) != 0 {
		t.Fatalf("got %d changes, want 0 for read action", len(changes))
	}
}

func TestDescribeChange(t *testing.T) {
	tests := []struct {
		name string
		nc   NetworkChange
		want string
	}{
		{
			name: "create subnet",
			nc: NetworkChange{
				Address: "aws_subnet.main",
				Type:    "subnet",
				Action:  "create",
				CIDR:    "10.0.1.0/24",
				Zone:    "us-east-1a",
			},
			want: "Create aws_subnet.main: subnet 10.0.1.0/24 in us-east-1a",
		},
		{
			name: "delete nat gateway",
			nc: NetworkChange{
				Address:     "aws_nat_gateway.old",
				Type:        "nat_gateway",
				Action:      "delete",
				ServiceName: "NAT Gateway (subnet: subnet-old)",
			},
			want: "Delete aws_nat_gateway.old: nat_gateway (NAT Gateway (subnet: subnet-old))",
		},
		{
			name: "update route",
			nc: NetworkChange{
				Address: "aws_route.main",
				Type:    "route",
				Action:  "update",
			},
			want: "Update aws_route.main: route",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := describeChange(tt.nc)
			if got != tt.want {
				t.Errorf("describeChange() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParsePlan_FullJSON(t *testing.T) {
	// Test with a more complete terraform plan JSON structure.
	planJSON := `{
		"format_version": "1.2",
		"terraform_version": "1.5.0",
		"variables": {
			"region": {"value": "us-east-1"}
		},
		"resource_changes": [
			{
				"address": "aws_vpc_endpoint.s3",
				"type": "aws_vpc_endpoint",
				"name": "s3",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"change": {
					"actions": ["create"],
					"before": null,
					"after": {
						"service_name": "com.amazonaws.us-east-1.s3",
						"vpc_endpoint_type": "Gateway"
					}
				}
			}
		]
	}`

	plan, err := ParsePlan(strings.NewReader(planJSON))
	if err != nil {
		t.Fatalf("ParsePlan: %v", err)
	}
	if len(plan.Variables) != 1 {
		t.Errorf("got %d variables, want 1", len(plan.Variables))
	}
}

func TestExtractNetworkChanges_Empty(t *testing.T) {
	plan := &Plan{}
	changes := ExtractNetworkChanges(plan)
	if len(changes) != 0 {
		t.Fatalf("got %d changes, want 0 for empty plan", len(changes))
	}
}
