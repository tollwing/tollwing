package cost

import (
	"math"
	"sync"
	"time"

	"github.com/tollwing/tollwing/pkg/classifier"
)

// FlowRecord represents a classified flow with metadata for cost calculation.
type FlowRecord struct {
	Timestamp    time.Time
	Cluster      string
	Node         string
	SrcNamespace string
	SrcPod       string
	SrcProcess   string
	SrcZone      string
	SrcService   string
	DstNamespace string
	DstPod       string
	DstService   string
	DstZone      string
	TrafficType  classifier.TrafficType
	TxBytes      uint64
	RxBytes      uint64
	Connections  uint32

	// ResolvedDomain — when non-empty, the destination IP was resolved
	// from a DNS query for this domain. Set by the agent's enricher
	// from the DNS tracker. Powers the "DNS cascade attribution"
	// reports: a pod queries s3.amazonaws.com, gets back an IP,
	// hammers it with N bytes — those N bytes are attributed back
	// to s3.amazonaws.com so operators can see "your S3 traffic
	// costs $4.8K/month" without manually correlating IPs.
	//
	// Empty when:
	//   - no DNS lookup was observed for the dst IP
	//   - the cache entry expired (TTL exceeded MinTTL window)
	//   - DNS tracking is disabled
	ResolvedDomain string

	// CloudService — when non-empty, the resolved domain mapped to a
	// known cloud service (e.g. "S3", "DynamoDB", "Azure Blob").
	// Coarser than ResolvedDomain but more useful for executive
	// dashboards. Populated alongside ResolvedDomain by the enricher.
	CloudService string
}

// CostResult is the output of cost calculation for a flow record.
type CostResult struct {
	FlowRecord
	CostUSD float64
}

// Engine calculates costs for classified network flows.
type Engine struct {
	store *RateCardStore

	// Cumulative byte counters per traffic type for tiered pricing.
	// Key: "provider:region:trafficType"
	mu              sync.Mutex
	cumulativeBytes map[string]float64
	resetTime       time.Time // start of current billing period
}

// NewEngine creates a cost calculation engine.
func NewEngine(store *RateCardStore) *Engine {
	return &Engine{
		store:           store,
		cumulativeBytes: make(map[string]float64),
		resetTime:       startOfMonth(time.Now()),
	}
}

// Calculate computes the cost for a batch of flow records.
func (e *Engine) Calculate(provider, region string, flows []FlowRecord) []CostResult {
	card := e.store.Get(provider, region)
	if card == nil {
		// No rate card — return zero costs.
		results := make([]CostResult, len(flows))
		for i, f := range flows {
			results[i] = CostResult{FlowRecord: f}
		}
		return results
	}

	results := make([]CostResult, len(flows))
	for i, f := range flows {
		cost := e.calculateFlow(card, f)
		results[i] = CostResult{
			FlowRecord: f,
			CostUSD:    cost,
		}
	}
	return results
}

// calculateFlow computes the cost for a single flow.
func (e *Engine) calculateFlow(card *RateCard, flow FlowRecord) float64 {
	totalBytes := float64(flow.TxBytes + flow.RxBytes)
	totalGB := totalBytes / (1024 * 1024 * 1024)

	switch flow.TrafficType {
	case classifier.NATGatewayEgress:
		return totalGB * card.NATGateway.PerGBUSD
	case classifier.TransitGateway:
		return totalGB * card.TransitGW.PerGBUSD
	default:
		rate, ok := card.Rates[flow.TrafficType]
		if !ok {
			return 0
		}
		return e.calculateTiered(card.Provider, card.Region, flow.TrafficType, rate, totalGB)
	}
}

// calculateTiered applies tiered pricing with cumulative tracking.
func (e *Engine) calculateTiered(provider, region string, tt classifier.TrafficType, rate TieredRate, gb float64) float64 {
	if len(rate.Tiers) == 0 {
		return 0
	}

	// Simple flat rate (single tier).
	if len(rate.Tiers) == 1 {
		return gb * rate.Tiers[0].PerGB
	}

	// Multi-tier: track cumulative usage for the billing period.
	key := provider + ":" + region + ":" + tt.String()

	e.mu.Lock()
	// Reset counters at month boundary.
	now := time.Now()
	if now.After(e.resetTime.AddDate(0, 1, 0)) {
		e.cumulativeBytes = make(map[string]float64)
		e.resetTime = startOfMonth(now)
	}

	prevGB := e.cumulativeBytes[key]
	e.cumulativeBytes[key] = prevGB + gb
	e.mu.Unlock()

	return tieredCost(rate.Tiers, prevGB, prevGB+gb)
}

// tieredCost calculates cost for GB consumed between prevGB and newGB
// across pricing tiers.
func tieredCost(tiers []Tier, prevGB, newGB float64) float64 {
	var cost float64
	remaining := newGB - prevGB

	for _, tier := range tiers {
		if remaining <= 0 {
			break
		}

		// How much capacity is in this tier above our previous usage?
		tierStart := 0.0
		if len(tiers) > 1 {
			// Find where previous tiers ended.
			for _, t := range tiers {
				if t.UpToGB >= tier.UpToGB {
					break
				}
				tierStart = t.UpToGB
			}
		}

		if prevGB >= tier.UpToGB {
			continue // already past this tier
		}

		usableStart := math.Max(prevGB, tierStart)
		usableEnd := math.Min(newGB, tier.UpToGB)
		gbInTier := usableEnd - usableStart

		if gbInTier > 0 {
			cost += gbInTier * tier.PerGB
			remaining -= gbInTier
		}
	}

	return cost
}

// ResetBillingPeriod resets cumulative counters (for testing or manual reset).
func (e *Engine) ResetBillingPeriod() {
	e.mu.Lock()
	e.cumulativeBytes = make(map[string]float64)
	e.resetTime = startOfMonth(time.Now())
	e.mu.Unlock()
}

func startOfMonth(t time.Time) time.Time {
	return time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, t.Location())
}
