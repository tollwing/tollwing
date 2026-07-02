package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/pricing"
	pricingtypes "github.com/aws/aws-sdk-go-v2/service/pricing/types"

	"github.com/tollwing/tollwing/pkg/classifier"
	"github.com/tollwing/tollwing/pkg/cost"
)

// AWS Price List API is only available in us-east-1 and ap-south-1.
const pricingAPIRegion = "us-east-1"

// PricingClient fetches live AWS Price List data.
type PricingClient struct {
	api *pricing.Client
	log *slog.Logger
}

// NewPricingClient creates an AWS Price List API client. It uses the default
// AWS credential chain (env vars, shared config, IRSA, etc).
func NewPricingClient(ctx context.Context, log *slog.Logger) (*PricingClient, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(pricingAPIRegion))
	if err != nil {
		return nil, fmt.Errorf("load aws config for pricing: %w", err)
	}
	return &PricingClient{
		api: pricing.NewFromConfig(cfg),
		log: log,
	}, nil
}

// FetchRateCard builds a RateCard for the given AWS region using live
// Price List API data. Overlays live prices onto the default rate card.
func (c *PricingClient) FetchRateCard(ctx context.Context, region string) (*cost.RateCard, error) {
	card := cost.DefaultAWSRateCard(region)

	location, err := regionToLocation(region)
	if err != nil {
		return card, err
	}

	// Fetch AWSDataTransfer pricing for bandwidth between regions and out.
	dtItems, err := c.getProducts(ctx, "AWSDataTransfer", map[string]string{
		"fromLocation": location,
	})
	if err != nil {
		return card, fmt.Errorf("fetch data transfer prices: %w", err)
	}
	applyAWSDataTransferPrices(card, dtItems, region)

	// Fetch NAT Gateway pricing (part of AmazonEC2).
	natItems, err := c.getProducts(ctx, "AmazonEC2", map[string]string{
		"location":      location,
		"productFamily": "NAT Gateway",
	})
	if err != nil {
		c.log.Warn("fetch NAT gateway prices failed", "err", err)
	} else {
		applyAWSNATGatewayPrices(card, natItems)
	}

	// Live prices: re-date and re-label the card (P4 — every rate is dated
	// and sourced; the default card's date covers only the defaults it
	// started from).
	card.LastUpdated = time.Now()
	card.Source = "aws-price-list-api"
	card.Fallback = false
	return card, nil
}

// getProducts calls GetProducts with the given filters and returns parsed
// price list items. Paginates through results.
func (c *PricingClient) getProducts(ctx context.Context, serviceCode string, filters map[string]string) ([]priceListItem, error) {
	var f []pricingtypes.Filter
	for k, v := range filters {
		f = append(f, pricingtypes.Filter{
			Type:  pricingtypes.FilterTypeTermMatch,
			Field: aws.String(k),
			Value: aws.String(v),
		})
	}

	var items []priceListItem
	paginator := pricing.NewGetProductsPaginator(c.api, &pricing.GetProductsInput{
		ServiceCode: aws.String(serviceCode),
		Filters:     f,
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return items, err
		}
		for _, raw := range page.PriceList {
			var item priceListItem
			if err := json.Unmarshal([]byte(raw), &item); err != nil {
				continue
			}
			items = append(items, item)
		}
	}
	return items, nil
}

// priceListItem models the subset of AWS Price List JSON fields we use.
type priceListItem struct {
	Product struct {
		Attributes map[string]string `json:"attributes"`
	} `json:"product"`
	Terms struct {
		OnDemand map[string]priceTerm `json:"OnDemand"`
	} `json:"terms"`
}

type priceTerm struct {
	PriceDimensions map[string]priceDimension `json:"priceDimensions"`
}

type priceDimension struct {
	Unit         string            `json:"unit"`
	BeginRange   string            `json:"beginRange"`
	EndRange     string            `json:"endRange"`
	Description  string            `json:"description"`
	PricePerUnit map[string]string `json:"pricePerUnit"`
}

func (d priceDimension) USDPrice() float64 {
	if v, ok := d.PricePerUnit["USD"]; ok {
		f, _ := strconv.ParseFloat(v, 64)
		return f
	}
	return 0
}

// applyAWSDataTransferPrices maps AWSDataTransfer price list items onto the rate card.
func applyAWSDataTransferPrices(card *cost.RateCard, items []priceListItem, region string) {
	// Collect internet egress tiers across all matching items.
	var egressTiers []cost.Tier
	crossRegionBest := math.Inf(1)
	crossAZBest := math.Inf(1)
	peeringBest := math.Inf(1)

	for _, it := range items {
		attrs := it.Product.Attributes
		ttype := strings.ToLower(attrs["transferType"])
		toLocation := attrs["toLocation"]
		toLocationType := attrs["toLocationType"]

		for _, term := range it.Terms.OnDemand {
			for _, dim := range term.PriceDimensions {
				// Skip zero rows unless they're tier thresholds.
				price := dim.USDPrice()
				unit := strings.ToLower(dim.Unit)
				if !strings.Contains(unit, "gb") {
					continue
				}

				switch {
				case strings.Contains(ttype, "internetout") || toLocationType == "AWS Edge Location":
					begin, _ := strconv.ParseFloat(dim.BeginRange, 64)
					end, _ := strconv.ParseFloat(dim.EndRange, 64)
					upTo := math.Inf(1)
					if dim.EndRange != "" && dim.EndRange != "Inf" {
						upTo = end
					}
					_ = begin
					egressTiers = append(egressTiers, cost.Tier{UpToGB: upTo, PerGB: price})

				case strings.Contains(ttype, "interregion") || strings.Contains(ttype, "inter-region"):
					if price > 0 && price < crossRegionBest {
						crossRegionBest = price
					}

				case strings.Contains(ttype, "intraregion") || strings.Contains(ttype, "intra-region"):
					// Cross-AZ intra-region.
					if price > 0 && price < crossAZBest {
						crossAZBest = price
					}

				case strings.Contains(ttype, "vpcpeering") || strings.Contains(strings.ToLower(attrs["productFamily"]), "peering"):
					if price > 0 && price < peeringBest {
						peeringBest = price
					}
				}
				_ = toLocation
			}
		}
	}

	if len(egressTiers) > 0 {
		// Sort ascending by UpToGB so cost.Calculate walks them in order.
		sortTiersAsc(egressTiers)
		card.Rates[classifier.InternetEgress] = cost.TieredRate{Tiers: egressTiers}
	}
	if !math.IsInf(crossRegionBest, 1) {
		card.Rates[classifier.CrossRegion] = cost.TieredRate{
			Tiers: []cost.Tier{{UpToGB: math.Inf(1), PerGB: crossRegionBest}},
		}
	}
	if !math.IsInf(crossAZBest, 1) {
		card.Rates[classifier.CrossAZ] = cost.TieredRate{
			Tiers: []cost.Tier{{UpToGB: math.Inf(1), PerGB: crossAZBest}},
		}
	}
	if !math.IsInf(peeringBest, 1) {
		card.Rates[classifier.VPCPeering] = cost.TieredRate{
			Tiers: []cost.Tier{{UpToGB: math.Inf(1), PerGB: peeringBest}},
		}
	}
}

// applyAWSNATGatewayPrices extracts NAT gateway per-hour and per-GB rates.
func applyAWSNATGatewayPrices(card *cost.RateCard, items []priceListItem) {
	for _, it := range items {
		for _, term := range it.Terms.OnDemand {
			for _, dim := range term.PriceDimensions {
				unit := strings.ToLower(dim.Unit)
				price := dim.USDPrice()
				if price <= 0 {
					continue
				}
				switch {
				case strings.Contains(unit, "hrs") || strings.Contains(unit, "hour"):
					card.NATGateway.PerHourUSD = price
				case strings.Contains(unit, "gb"):
					card.NATGateway.PerGBUSD = price
				}
			}
		}
	}
}

func sortTiersAsc(tiers []cost.Tier) {
	for i := 1; i < len(tiers); i++ {
		for j := i; j > 0 && tiers[j-1].UpToGB > tiers[j].UpToGB; j-- {
			tiers[j-1], tiers[j] = tiers[j], tiers[j-1]
		}
	}
}

// regionToLocation maps AWS region codes to Price List API location names.
// The Price List API uses human-readable location names as filter values.
func regionToLocation(region string) (string, error) {
	m := map[string]string{
		"us-east-1":      "US East (N. Virginia)",
		"us-east-2":      "US East (Ohio)",
		"us-west-1":      "US West (N. California)",
		"us-west-2":      "US West (Oregon)",
		"eu-west-1":      "EU (Ireland)",
		"eu-west-2":      "EU (London)",
		"eu-west-3":      "EU (Paris)",
		"eu-central-1":   "EU (Frankfurt)",
		"eu-north-1":     "EU (Stockholm)",
		"eu-south-1":     "EU (Milan)",
		"ap-northeast-1": "Asia Pacific (Tokyo)",
		"ap-northeast-2": "Asia Pacific (Seoul)",
		"ap-northeast-3": "Asia Pacific (Osaka)",
		"ap-southeast-1": "Asia Pacific (Singapore)",
		"ap-southeast-2": "Asia Pacific (Sydney)",
		"ap-south-1":     "Asia Pacific (Mumbai)",
		"ap-east-1":      "Asia Pacific (Hong Kong)",
		"sa-east-1":      "South America (Sao Paulo)",
		"ca-central-1":   "Canada (Central)",
		"af-south-1":     "Africa (Cape Town)",
		"me-south-1":     "Middle East (Bahrain)",
	}
	if loc, ok := m[region]; ok {
		return loc, nil
	}
	return "", fmt.Errorf("unknown AWS region: %s", region)
}
