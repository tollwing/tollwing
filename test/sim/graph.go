package sim

import (
	"github.com/tollwing/tollwing/pkg/servicegraph"
	"github.com/tollwing/tollwing/test/sim/scenario"
)

// ServiceNode returns the servicegraph NodeID for an in-cluster service.
func ServiceNode(s *scenario.Scenario, name string) servicegraph.NodeID {
	return servicegraph.NodeID{
		Cluster:   "sim",
		Namespace: s.Services[name].Namespace,
		Name:      name,
		Kind:      servicegraph.KindService,
	}
}

// GraphEdges converts a scenario's traffic into servicegraph EdgeRows via the
// REAL product classification + cost (the producer's enrichment output), so the
// real pkg/servicegraph builds its graph from real edges. Used by the
// transitive-attribution proof.
func GraphEdges(s *scenario.Scenario) []servicegraph.EdgeRow {
	ms := measure(s)
	rows := make([]servicegraph.EdgeRow, 0, len(ms))
	for _, m := range ms {
		dst := servicegraph.NodeID{Name: m.edge.To, Kind: servicegraph.KindExternal}
		dstZone := ""
		if svc, ok := s.Services[m.edge.To]; ok {
			dst = servicegraph.NodeID{Cluster: "sim", Namespace: svc.Namespace, Name: m.edge.To, Kind: servicegraph.KindService}
			dstZone = svc.Zone
		}
		conns := m.edge.Requests
		if conns == 0 {
			conns = 1
		}
		rows = append(rows, servicegraph.EdgeRow{
			Src:         ServiceNode(s, m.edge.From),
			Dst:         dst,
			SrcZone:     s.Services[m.edge.From].Zone,
			DstZone:     dstZone,
			TrafficType: m.tt.String(),
			Bytes:       m.tx + m.rx,
			Connections: conns,
			Cost:        m.cost,
		})
	}
	return rows
}
