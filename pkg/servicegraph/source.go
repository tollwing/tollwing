package servicegraph

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// EdgeSource provides aggregated edge rows for a lookback window. The default
// implementation (ClickHouseEdgeSource) issues one aggregate query; tests use
// an in-memory fake.
type EdgeSource interface {
	Edges(ctx context.Context, window time.Duration) ([]EdgeRow, error)
}

// Build constructs a graph snapshot from a set of rows. It is the seam shared
// by the live snapshotter and tests.
func Build(rows []EdgeRow, snapshotAt time.Time, window time.Duration) *ServiceGraph {
	g := New()
	g.SnapshotAt = snapshotAt
	g.Window = window
	for _, r := range rows {
		g.AddEdgeRow(r)
	}
	return g
}

// ClickHouseEdgeSource rolls the flows table up into service-pair edges with a
// single aggregate query. The result set is tiny (services × services ×
// traffic types), so this is cheap to run on the snapshot cadence.
//
// NOTE: src_service / dst_service / src_zone / dst_zone are populated by the
// agent's enrichment path (the pre-DNAT service-intent resolution). Until that
// lands, src_service is empty and this query returns no internal edges — the
// graph builds from real data once enrichment ships. The graph logic and its
// queries are exercised independently via in-memory rows in tests.
type ClickHouseEdgeSource struct {
	DB      *sql.DB
	Cluster string // optional filter; empty = all clusters
}

const edgeQuery = `SELECT
	cluster,
	src_namespace,
	src_service,
	dst_namespace,
	dst_service,
	cloud_service,
	domain,
	src_zone,
	dst_zone,
	traffic_type,
	sum(tx_bytes + rx_bytes) AS bytes,
	sum(connections)         AS conns,
	sum(cost_usd)            AS cost
FROM flows
WHERE timestamp >= ?
  AND src_service != ''
  AND (dst_service != '' OR cloud_service != '' OR domain != '')
  %s
GROUP BY cluster, src_namespace, src_service, dst_namespace, dst_service,
         cloud_service, domain, src_zone, dst_zone, traffic_type`

// Edges runs the rollup query and maps each row to an EdgeRow.
func (c *ClickHouseEdgeSource) Edges(ctx context.Context, window time.Duration) ([]EdgeRow, error) {
	if c.DB == nil {
		return nil, errors.New("servicegraph: ClickHouse DB handle is nil")
	}

	clusterFilter := ""
	args := []any{time.Now().Add(-window)}
	if c.Cluster != "" {
		clusterFilter = "AND cluster = ?"
		args = append(args, c.Cluster)
	}

	rows, err := c.DB.QueryContext(ctx, fmt.Sprintf(edgeQuery, clusterFilter), args...)
	if err != nil {
		return nil, fmt.Errorf("query flows: %w", err)
	}
	defer rows.Close()

	var out []EdgeRow
	for rows.Next() {
		var (
			cluster, srcNS, srcSvc, dstNS, dstSvc  string
			cloudSvc, domain, srcZone, dstZone, tt string
			bytes, conns                           uint64
			cost                                   float64
		)
		if err := rows.Scan(
			&cluster, &srcNS, &srcSvc, &dstNS, &dstSvc,
			&cloudSvc, &domain, &srcZone, &dstZone, &tt,
			&bytes, &conns, &cost,
		); err != nil {
			return nil, fmt.Errorf("scan: %w", err)
		}
		out = append(out, EdgeRow{
			Src:         NodeID{Cluster: cluster, Namespace: srcNS, Name: srcSvc, Kind: KindService},
			Dst:         dstNode(cluster, dstNS, dstSvc, cloudSvc, domain),
			SrcZone:     srcZone,
			DstZone:     dstZone,
			TrafficType: tt,
			Bytes:       bytes,
			Connections: conns,
			Cost:        cost,
		})
	}
	return out, rows.Err()
}

// dstNode builds the destination node id, preferring an in-cluster service
// (the pre-DNAT ClusterIP intent), then a recognised cloud service, then the
// raw DNS domain.
func dstNode(cluster, dstNS, dstSvc, cloudSvc, domain string) NodeID {
	switch {
	case dstSvc != "":
		return NodeID{Cluster: cluster, Namespace: dstNS, Name: dstSvc, Kind: KindService}
	case cloudSvc != "":
		return NodeID{Cluster: cluster, Name: cloudSvc, Kind: KindExternal}
	default:
		return NodeID{Cluster: cluster, Name: domain, Kind: KindExternal}
	}
}
