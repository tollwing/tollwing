package aws

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// SDKClient implements ec2Client using the AWS SDK v2.
type SDKClient struct {
	client *ec2.Client
	log    *slog.Logger
}

// NewSDKClient creates a real EC2 client using default AWS credentials.
// It loads credentials from the standard chain (env vars, shared config,
// IMDS, etc.) and targets the specified region.
func NewSDKClient(ctx context.Context, region string, log *slog.Logger) (*SDKClient, error) {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("load aws config: %w", err)
	}

	return &SDKClient{
		client: ec2.NewFromConfig(cfg),
		log:    log,
	}, nil
}

func (c *SDKClient) DescribeSubnets(ctx context.Context) ([]ec2Subnet, error) {
	var subnets []ec2Subnet
	paginator := ec2.NewDescribeSubnetsPaginator(c.client, &ec2.DescribeSubnetsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("ec2 DescribeSubnets: %w", err)
		}
		for _, s := range page.Subnets {
			subnets = append(subnets, ec2Subnet{
				SubnetID:         deref(s.SubnetId),
				CidrBlock:        deref(s.CidrBlock),
				AvailabilityZone: deref(s.AvailabilityZone),
				VpcID:            deref(s.VpcId),
			})
		}
	}
	return subnets, nil
}

func (c *SDKClient) DescribeNatGateways(ctx context.Context) ([]ec2NatGateway, error) {
	var gateways []ec2NatGateway
	paginator := ec2.NewDescribeNatGatewaysPaginator(c.client, &ec2.DescribeNatGatewaysInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("ec2 DescribeNatGateways: %w", err)
		}
		for _, ng := range page.NatGateways {
			gw := ec2NatGateway{
				NatGatewayID: deref(ng.NatGatewayId),
				SubnetID:     deref(ng.SubnetId),
				VpcID:        deref(ng.VpcId),
				State:        string(ng.State),
			}
			for _, addr := range ng.NatGatewayAddresses {
				gw.Addresses = append(gw.Addresses, ec2NatAddress{
					PrivateIP: deref(addr.PrivateIp),
					PublicIP:  deref(addr.PublicIp),
				})
			}
			gateways = append(gateways, gw)
		}
	}
	return gateways, nil
}

func (c *SDKClient) DescribeVpcPeeringConnections(ctx context.Context) ([]ec2VpcPeering, error) {
	var peerings []ec2VpcPeering
	paginator := ec2.NewDescribeVpcPeeringConnectionsPaginator(c.client, &ec2.DescribeVpcPeeringConnectionsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("ec2 DescribeVpcPeeringConnections: %w", err)
		}
		for _, pc := range page.VpcPeeringConnections {
			p := ec2VpcPeering{
				PeeringID: deref(pc.VpcPeeringConnectionId),
			}
			if pc.Status != nil {
				p.Status = string(pc.Status.Code)
			}
			if pc.RequesterVpcInfo != nil {
				p.RequesterVpc = ec2PeeringVpc{
					VpcID:     deref(pc.RequesterVpcInfo.VpcId),
					OwnerID:   deref(pc.RequesterVpcInfo.OwnerId),
					CidrBlock: deref(pc.RequesterVpcInfo.CidrBlock),
					Region:    deref(pc.RequesterVpcInfo.Region),
				}
			}
			if pc.AccepterVpcInfo != nil {
				p.AccepterVpc = ec2PeeringVpc{
					VpcID:     deref(pc.AccepterVpcInfo.VpcId),
					OwnerID:   deref(pc.AccepterVpcInfo.OwnerId),
					CidrBlock: deref(pc.AccepterVpcInfo.CidrBlock),
					Region:    deref(pc.AccepterVpcInfo.Region),
				}
			}
			peerings = append(peerings, p)
		}
	}
	return peerings, nil
}

func (c *SDKClient) DescribeTransitGatewayAttachments(ctx context.Context) ([]ec2TGWAttachment, error) {
	var attachments []ec2TGWAttachment
	paginator := ec2.NewDescribeTransitGatewayAttachmentsPaginator(c.client, &ec2.DescribeTransitGatewayAttachmentsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("ec2 DescribeTransitGatewayAttachments: %w", err)
		}
		for _, a := range page.TransitGatewayAttachments {
			attachments = append(attachments, ec2TGWAttachment{
				TransitGatewayAttachmentID: deref(a.TransitGatewayAttachmentId),
				TransitGatewayID:           deref(a.TransitGatewayId),
				ResourceType:               string(a.ResourceType),
				ResourceID:                 deref(a.ResourceId),
				State:                      string(a.State),
			})
		}
	}
	return attachments, nil
}

// DescribeRouteTables lists route tables, server-side filtered to vpcID when
// non-empty: route-based NAT detection (DEC-015) must only ever see this
// node's VPC — another VPC's main table must not decide this node's NAT flag.
func (c *SDKClient) DescribeRouteTables(ctx context.Context, vpcID string) ([]ec2RouteTable, error) {
	input := &ec2.DescribeRouteTablesInput{}
	if vpcID != "" {
		input.Filters = []types.Filter{{
			Name:   aws.String("vpc-id"),
			Values: []string{vpcID},
		}}
	}

	var tables []ec2RouteTable
	paginator := ec2.NewDescribeRouteTablesPaginator(c.client, input)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("ec2 DescribeRouteTables: %w", err)
		}
		for _, rt := range page.RouteTables {
			table := ec2RouteTable{
				RouteTableID: deref(rt.RouteTableId),
				VpcID:        deref(rt.VpcId),
			}
			for _, assoc := range rt.Associations {
				a := ec2RTAssociation{SubnetID: deref(assoc.SubnetId)}
				if assoc.Main != nil {
					a.Main = *assoc.Main
				}
				table.Associations = append(table.Associations, a)
			}
			for _, r := range rt.Routes {
				table.Routes = append(table.Routes, ec2Route{
					DestinationCidrBlock: deref(r.DestinationCidrBlock),
					GatewayID:            deref(r.GatewayId),
					NatGatewayID:         deref(r.NatGatewayId),
				})
			}
			tables = append(tables, table)
		}
	}
	return tables, nil
}

// deref safely dereferences a string pointer, returning "" for nil.
func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
