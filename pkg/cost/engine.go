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

// PricingMode selects how multi-tier (free-allowance) rates are applied
// (DEC-014).
type PricingMode int

const (
	// PricingModeMarginal is the default: every metered GB is priced at
	// the marginal (post-free-tier) list rate. Per DEC-014 this is the
	// only honest option for a distributed fleet — per-process cumulative
	// tier state would grant the account-wide free tier once per engine
	// and reset the meter on every restart (P5: never guess the account's
	// tier position).
	PricingModeMarginal PricingMode = iota

	// PricingModeSingleMeter applies the full tier table with cumulative
	// in-memory tracking. Valid ONLY when exactly one engine meters the
	// whole account's traffic (the Enterprise server's aggregation path).
	// The meter is per-process and resets on restart — mid-month restarts
	// re-grant the free tier (DEC-014 records this limitation).
	PricingModeSingleMeter
)

// EngineConfig controls cost calculation.
type EngineConfig struct {
	// Mode selects the tier-handling strategy. The zero value is
	// PricingModeMarginal, the honest default for distributed agents
	// (DEC-014).
	Mode PricingMode
}

func (c *EngineConfig) setDefaults() {
	// PricingModeMarginal is the zero value — nothing to fill; the method
	// exists to keep the Config+setDefaults idiom and a place for future
	// fields.
}

// Engine calculates costs for classified network flows.
type Engine struct {
	store *RateCardStore
	cfg   EngineConfig

	// Cumulative byte counters per traffic type for tiered pricing.
	// Only maintained in PricingModeSingleMeter (DEC-014).
	// Key: "provider:region:trafficType"
	mu              sync.Mutex
	cumulativeBytes map[string]float64
	resetTime       time.Time // start of current billing period
}

// NewEngine creates a cost calculation engine in the default
// PricingModeMarginal (DEC-014).
func NewEngine(store *RateCardStore) *Engine {
	return NewEngineWithConfig(store, EngineConfig{})
}

// NewEngineWithConfig creates a cost calculation engine with an explicit
// pricing mode. The Enterprise server's single aggregation engine opts into
// PricingModeSingleMeter here (DEC-014).
func NewEngineWithConfig(store *RateCardStore, cfg EngineConfig) *Engine {
	cfg.setDefaults()
	return &Engine{
		store:           store,
		cfg:             cfg,
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

// calculateFlow computes the cost for a single flow. Billable bytes are
// selected by the card's per-traffic-type metered-direction table (DEC-014);
// blanket Tx+Rx metering previously billed ingress at egress rates.
func (e *Engine) calculateFlow(card *RateCard, flow FlowRecord) float64 {
	meteredGB := bytesToGB(card.MeteredBytes(flow.TrafficType, flow.TxBytes, flow.RxBytes))

	switch flow.TrafficType {
	case classifier.NATGatewayEgress:
		// Per DEC-015: an internet-bound flow through a NAT gateway incurs
		// BOTH the NAT data-processing charge (on the metered directions)
		// and the internet-egress charge on the Tx leg — the bytes still
		// leave the cloud after the NAT. The NAT hourly charge is
		// deliberately not per-flow (P4: bytes × dated-rate only); it
		// surfaces in reconciliation's unaccounted bucket.
		cost := meteredGB * card.NATGateway.PerGBUSD
		if rate, ok := card.Rates[classifier.InternetEgress]; ok {
			cost += e.priceTiered(card.Provider, card.Region, classifier.InternetEgress, rate, bytesToGB(flow.TxBytes))
		}
		return cost
	case classifier.TransitGateway:
		// Per-attachment-hour is not per-flow (DEC-015).
		return meteredGB * card.TransitGW.PerGBUSD
	default:
		rate, ok := card.Rates[flow.TrafficType]
		if !ok {
			return 0
		}
		return e.priceTiered(card.Provider, card.Region, flow.TrafficType, rate, meteredGB)
	}
}

// priceTiered prices gb of a traffic type according to the engine's pricing
// mode (DEC-014).
func (e *Engine) priceTiered(provider, region string, tt classifier.TrafficType, rate TieredRate, gb float64) float64 {
	if len(rate.Tiers) == 0 {
		return 0
	}

	// Simple flat rate (single tier) — mode-independent.
	if len(rate.Tiers) == 1 {
		return gb * rate.Tiers[0].PerGB
	}

	// Per DEC-014: the default mode prices at the marginal post-free-tier
	// list rate — no per-process cumulative fiction.
	if e.cfg.Mode == PricingModeMarginal {
		return gb * rate.MarginalRate()
	}

	// Single-meter mode: track cumulative usage for the billing period.
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

// bytesToGB converts a byte count to the GiB-based "GB" unit the rate tables
// use throughout pkg/cost.
func bytesToGB(b uint64) float64 {
	return float64(b) / (1024 * 1024 * 1024)
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
