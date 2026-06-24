package cost

import (
	"context"
	"log/slog"
	"time"
)

// RateCardProvider can fetch a rate card for a given region.
// Implemented by cloud.Provider.GetRateCard.
type RateCardProvider interface {
	GetRateCard(ctx context.Context, region string) (*RateCard, error)
}

// RateCardRefresher periodically fetches live pricing from the cloud provider
// and updates the RateCardStore. Falls back to default rates on failure.
type RateCardRefresher struct {
	store    *RateCardStore
	provider RateCardProvider
	region   string
	interval time.Duration
	log      *slog.Logger
}

// NewRateCardRefresher creates a refresher that periodically updates the rate card.
func NewRateCardRefresher(
	store *RateCardStore,
	provider RateCardProvider,
	region string,
	log *slog.Logger,
) *RateCardRefresher {
	return &RateCardRefresher{
		store:    store,
		provider: provider,
		region:   region,
		interval: 6 * time.Hour, // refresh every 6 hours
		log:      log,
	}
}

// Start performs an initial fetch and then refreshes periodically.
// Non-blocking.
func (r *RateCardRefresher) Start(ctx context.Context) {
	r.refresh(ctx)
	go func() {
		ticker := time.NewTicker(r.interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				r.refresh(ctx)
			case <-ctx.Done():
				return
			}
		}
	}()
}

func (r *RateCardRefresher) refresh(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	card, err := r.provider.GetRateCard(ctx, r.region)
	if err != nil {
		r.log.Warn("rate card refresh failed, keeping existing rates", "err", err, "region", r.region)
		return
	}
	if card == nil {
		return
	}

	r.store.Set(card)
	r.log.Info("rate card refreshed",
		"provider", card.Provider,
		"region", card.Region,
		"rate_count", len(card.Rates),
	)
}
