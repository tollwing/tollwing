//go:build linux

package ebpf

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

// AgentConfig mirrors struct agent_config in maps.h.
// Field order, sizes, and padding must be identical.
type AgentConfig struct {
	Enabled       uint8
	TrackUDP      uint8
	SampleRate    uint8
	Reserved      [5]uint8
	AggregationNs uint64
}

// OriginalDst mirrors struct original_dst in maps.h.
type OriginalDst struct {
	IP       uint32 // network byte order (IPv4), 0 for IPv6
	Port     uint16 // host byte order
	Family   uint8  // AF_INET=2, AF_INET6=10
	Pad      uint8
	PID      uint32
	CgroupID uint64
	Comm     [16]byte
	IP6      [16]byte // IPv6 address (for AF_INET6)
}

// Addr returns the original destination as a netip.AddrPort.
func (o *OriginalDst) Addr() netip.AddrPort {
	return ipPort(o.IP, o.Port)
}

// ConnInfo mirrors struct conn_info in maps.h.
type ConnInfo struct {
	SrcIP           uint32
	DstIP           uint32
	OriginalDstIP   uint32
	SrcPort         uint16
	DstPort         uint16
	OriginalDstPort uint16
	Family          uint8
	Protocol        uint8
	PID             uint32
	CgroupID        uint64
	StartNs         uint64
	TxBytes         uint64
	RxBytes         uint64
	RetransmitBytes uint64
	RetransmitCount uint32
	Direction       uint8
	State           uint8
	Pad             [2]uint8
	SrcIP6          [16]byte
	DstIP6          [16]byte
	OriginalDstIP6  [16]byte
}

// FlowKey mirrors struct flow_key in maps.h.
// Key for the flow_aggregates PERCPU_HASH map.
type FlowKey struct {
	SrcIP     uint32
	DstIP     uint32
	SrcPort   uint16
	DstPort   uint16
	PID       uint32
	Protocol  uint8
	Direction uint8
	Pad       uint16
}

// FlowMetrics mirrors struct flow_metrics in maps.h.
// Value for the flow_aggregates PERCPU_HASH map (per-CPU).
type FlowMetrics struct {
	TxBytes         uint64
	RxBytes         uint64
	ConnCount       uint64
	LastUpdatedNs   uint64
	RetransmitBytes uint64
	RetransmitCount uint64
}

// EventType matches enum event_type in maps.h.
type EventType uint8

const (
	EventConnect   EventType = 1
	EventEstablish EventType = 2
	EventClose     EventType = 3
)

func (t EventType) String() string {
	switch t {
	case EventConnect:
		return "connect"
	case EventEstablish:
		return "establish"
	case EventClose:
		return "close"
	default:
		return fmt.Sprintf("unknown(%d)", t)
	}
}

// ConnectEvent mirrors struct connect_event in maps.h.
type ConnectEvent struct {
	Type            uint8
	Protocol        uint8
	Pad             uint16
	PID             uint32
	Cookie          uint64
	CgroupID        uint64
	OriginalDstIP   uint32 // network byte order
	OriginalDstPort uint16 // host byte order
	Pad2            uint16
	TimestampNs     uint64
	Comm            [16]byte
}

func (e *ConnectEvent) ProcessName() string { return nullStr(e.Comm[:]) }

func (e *ConnectEvent) DstAddr() netip.AddrPort {
	return ipPort(e.OriginalDstIP, e.OriginalDstPort)
}

// EstablishEvent mirrors struct establish_event in maps.h.
// Contains both post-DNAT (actual) and pre-DNAT (original) addresses.
type EstablishEvent struct {
	Type            uint8
	Direction       uint8 // 0=outgoing, 1=incoming
	Protocol        uint8
	Pad             uint8
	PID             uint32
	Cookie          uint64
	CgroupID        uint64
	SrcIP           uint32
	DstIP           uint32 // post-DNAT (actual backend pod IP)
	SrcPort         uint16
	DstPort         uint16 // post-DNAT (actual backend port)
	OriginalDstIP   uint32 // pre-DNAT (ClusterIP), 0 if no DNAT
	OriginalDstPort uint16 // pre-DNAT port, 0 if no DNAT
	Pad2            uint16
	TimestampNs     uint64
	Comm            [16]byte
}

func (e *EstablishEvent) ProcessName() string { return nullStr(e.Comm[:]) }

func (e *EstablishEvent) ActualDstAddr() netip.AddrPort {
	return ipPort(e.DstIP, e.DstPort)
}

func (e *EstablishEvent) OriginalDstAddr() netip.AddrPort {
	if e.OriginalDstIP == 0 {
		return netip.AddrPort{}
	}
	return ipPort(e.OriginalDstIP, e.OriginalDstPort)
}

func (e *EstablishEvent) SrcAddr() netip.AddrPort {
	return ipPort(e.SrcIP, e.SrcPort)
}

func (e *EstablishEvent) IsOutgoing() bool { return e.Direction == 0 }

func (e *EstablishEvent) WasDNATed() bool { return e.OriginalDstIP != 0 }

// CloseEvent mirrors struct close_event in maps.h.
type CloseEvent struct {
	Type            uint8
	Direction       uint8
	Protocol        uint8
	Pad             uint8
	PID             uint32
	Cookie          uint64
	SrcIP           uint32
	DstIP           uint32
	SrcPort         uint16
	DstPort         uint16
	OriginalDstIP   uint32
	OriginalDstPort uint16
	Pad2            uint16
	TxBytes         uint64
	RxBytes         uint64
	RetransmitBytes uint64
	RetransmitCount uint32
	Pad3            uint32
	DurationNs      uint64
	TimestampNs     uint64
}

func (e *CloseEvent) ActualDstAddr() netip.AddrPort {
	return ipPort(e.DstIP, e.DstPort)
}

func (e *CloseEvent) OriginalDstAddr() netip.AddrPort {
	if e.OriginalDstIP == 0 {
		return netip.AddrPort{}
	}
	return ipPort(e.OriginalDstIP, e.OriginalDstPort)
}

// CgroupCostBPF mirrors struct cgroup_cost in maps.h (BPF_MAP_TYPE_CGRP_STORAGE).
type CgroupCostBPF struct {
	TxBytes         uint64
	RxBytes         uint64
	RetransmitBytes uint64
	ConnCount       uint64
}

// SkCostMeta mirrors struct sk_cost_meta in maps.h (BPF_MAP_TYPE_SK_STORAGE).
type SkCostMeta struct {
	FK              FlowKey
	TxBytes         uint64
	RxBytes         uint64
	RetransmitBytes uint64
	CgroupID        uint64
	StartNs         uint64
}

// QuicFlowKey mirrors struct quic_flow_key in maps.h.
type QuicFlowKey struct {
	SrcIP   uint32
	DstIP   uint32
	SrcPort uint16
	DstPort uint16
}

// QuicFlowMetrics mirrors struct quic_flow_metrics in maps.h.
type QuicFlowMetrics struct {
	TxBytes      uint64
	RxBytes      uint64
	PktCount     uint64
	LastSeenNs   uint64
	QuicVersion  uint32
	IsLongHeader uint8
	Pad          [3]uint8
}

// SidecarInfo mirrors struct sidecar_info in maps.h.
type SidecarInfo struct {
	IsSidecarInternal uint8
	Pad               [3]uint8
	AppPID            uint32
	AppCgroupID       uint64
}

// helpers

func nullStr(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// AddrFromU32 converts a uint32 IPv4 field — as read from a BPF map or ringbuf
// event — into a netip.Addr. The kernel writes these fields in network byte
// order (e.g. skops->local_ip4, ctx->user_ip4, stored without ntohl) and the Go
// struct is decoded native-endian (binary.Read in pkg/poller and the iterator,
// an unsafe cast in the ringbuf reader), so the four address bytes must be
// recovered with the SAME native endianness to round-trip the on-wire byte
// sequence on any host. A big-endian decode here reverses the octets — that was
// the cross-AZ misclassification bug (DEC-009). This is the single canonical
// BPF-field IP decoder for the linux side; pkg/classifier and pkg/enricher
// carry intentional cross-platform mirrors that cite it.
func AddrFromU32(v uint32) netip.Addr {
	var b [4]byte
	binary.NativeEndian.PutUint32(b[:], v)
	return netip.AddrFrom4(b)
}

func ipPort(ip uint32, port uint16) netip.AddrPort {
	return netip.AddrPortFrom(AddrFromU32(ip), port)
}

// FormatIPPort formats a BPF IP field (network-order bytes, native-endian
// decoded — see AddrFromU32) and a host-order port as "ip:port".
func FormatIPPort(ip uint32, port uint16) string {
	return ipPort(ip, port).String()
}
