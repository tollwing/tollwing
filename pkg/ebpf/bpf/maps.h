#pragma once

#include <bpf/bpf_helpers.h>

// ============================================================================
// Agent configuration — pushed from userspace on startup and config reload.
// Must match agentConfig in Go exactly (field order, sizes, padding).
// ============================================================================

struct agent_config {
	__u8  enabled;
	__u8  track_udp;          // also hook UDP connects (for DNS cost attribution)
	__u8  sample_rate;        // 1 = every conn, N = 1/N sampling
	__u8  reserved[5];
	__u64 aggregation_ns;     // flow flush interval (default: 5s)
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct agent_config);
} agent_config SEC(".maps");

// ============================================================================
// Pre-DNAT resolution — populated by cgroup/connect4, consumed by sock_ops.
// Short-lived entries: deleted after sock_ops correlates them.
// ============================================================================

struct original_dst {
	__u32 ip;                 // original destination IPv4 (network byte order), 0 for IPv6
	__u16 port;               // original destination port (host byte order)
	__u8  family;             // AF_INET=2, AF_INET6=10
	__u8  pad;
	__u32 pid;                // PID captured in cgroup/connect context
	__u64 cgroupid;           // cgroup ID captured in cgroup/connect context
	char  comm[16];           // process name
	__u8  ip6[16];            // original destination IPv6 (for AF_INET6)
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, __u64);       // socket cookie
	__type(value, struct original_dst);
} cookie_to_original_dst SEC(".maps");

// ============================================================================
// Connection table — full lifecycle tracking per socket cookie.
// Updated on establish, read on byte count, deleted on close.
// ============================================================================

struct conn_info {
	__u32 src_ip;
	__u32 dst_ip;
	__u32 original_dst_ip;    // pre-DNAT (ClusterIP), 0 if no DNAT
	__u16 src_port;
	__u16 dst_port;
	__u16 original_dst_port;  // pre-DNAT port
	__u8  family;             // AF_INET=2, AF_INET6=10
	__u8  protocol;           // IPPROTO_TCP=6, IPPROTO_UDP=17
	__u32 pid;
	__u64 cgroupid;
	__u64 start_ns;
	__u64 tx_bytes;
	__u64 rx_bytes;
	__u64 retransmit_bytes;   // cumulative retransmitted bytes
	__u32 retransmit_count;   // number of retransmissions
	__u8  direction;          // 0=outgoing, 1=incoming
	__u8  state;              // TCP state
	__u8  pad[2];
	__u8  src_ip6[16];        // IPv6 source (for AF_INET6)
	__u8  dst_ip6[16];        // IPv6 destination (for AF_INET6)
	__u8  original_dst_ip6[16]; // IPv6 pre-DNAT destination
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 524288); // 512K connections
	__type(key, __u64);          // socket cookie
	__type(value, struct conn_info);
} connections SEC(".maps");

// ============================================================================
// Ring buffer — connection lifecycle events to userspace.
// Using ringbuf over perf: no per-CPU alloc, lower overhead, reserve/commit.
// ============================================================================

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 22); // 4MB
} events SEC(".maps");

// ============================================================================
// In-kernel flow aggregation — reduces perf event volume by 100-1000x.
// Kprobes (tcp_sendmsg, tcp_cleanup_rbuf) increment these counters instead
// of updating the connections map directly for byte counting.
// The poller batch-reads and resets this map on each tick.
// ============================================================================

struct flow_key {
	__u32 src_ip;
	__u32 dst_ip;
	__u16 src_port;
	__u16 dst_port;
	__u32 pid;
	__u8  protocol;
	__u8  direction;
	__u16 pad;
};

struct flow_metrics {
	__u64 tx_bytes;
	__u64 rx_bytes;
	__u64 conn_count;
	__u64 last_updated_ns;
	__u64 retransmit_bytes;   // cumulative retransmitted bytes
	__u64 retransmit_count;   // number of retransmissions
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 131072); // 128K unique flows per CPU
	__type(key, struct flow_key);
	__type(value, struct flow_metrics);
} flow_aggregates SEC(".maps");

// ============================================================================
// NAT mapping cache — populated by fentry/nf_conntrack_confirm (optional).
// Used to enhance DNAT resolution when cgroup/connect4 + sock_ops
// two-phase correlation is insufficient (e.g., hairpin NAT, external LB).
// ============================================================================

struct nat_mapping {
	__u32 pre_dnat_ip;
	__u16 pre_dnat_port;
	__u32 post_dnat_ip;
	__u16 post_dnat_port;
	__u64 timestamp_ns;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 131072); // 128K NAT mappings
	__type(key, __u64);          // hash(src_ip, src_port, dst_ip, dst_port)
	__type(value, struct nat_mapping);
} nat_mappings SEC(".maps");

// ============================================================================
// Per-cgroup cost accumulation (kernel 6.3+, BPF_MAP_TYPE_CGRP_STORAGE).
//
// Accumulates bytes directly per cgroup, providing native per-container/pod
// byte accounting without the flow → PID → cgroup → pod userspace lookup.
// Optional: coexists with flow_aggregates path.
// ============================================================================

struct cgroup_cost {
	__u64 tx_bytes;
	__u64 rx_bytes;
	__u64 retransmit_bytes;
	__u64 conn_count;
};

#ifdef BPF_MAP_TYPE_CGRP_STORAGE
struct {
	__uint(type, BPF_MAP_TYPE_CGRP_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);  // cgroup fd (unused in BPF side, kernel manages)
	__type(value, struct cgroup_cost);
} cgroup_cost_storage SEC(".maps");
#endif

// ============================================================================
// Per-socket metadata for BPF iterators (kernel 6.4+).
//
// Stores per-socket cost metadata, populated from sock_ops on establish.
// Read via SEC("iter/bpf_sk_storage_map") for consistent state snapshots.
// ============================================================================

struct sk_cost_meta {
	struct flow_key fk;
	__u64 tx_bytes;
	__u64 rx_bytes;
	__u64 retransmit_bytes;
	__u64 cgroupid;
	__u64 start_ns;
};

struct {
	__uint(type, BPF_MAP_TYPE_SK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);  // socket fd (unused in BPF side, kernel manages)
	__type(value, struct sk_cost_meta);
} sk_cost_storage SEC(".maps");

// ============================================================================
// QUIC flow tracking (kernel 6.6+ for bpf_dynptr, fallback to manual parsing).
//
// Tracks QUIC (UDP) flows by 4-tuple with byte accumulation.
// ============================================================================

struct quic_flow_key {
	__u32 src_ip;
	__u32 dst_ip;
	__u16 src_port;
	__u16 dst_port;
};

struct quic_flow_metrics {
	__u64 tx_bytes;
	__u64 rx_bytes;
	__u64 pkt_count;
	__u64 last_seen_ns;
	__u32 quic_version;
	__u8  is_long_header;  // last seen header type
	__u8  pad[3];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 65536); // 64K QUIC flows
	__type(key, struct quic_flow_key);
	__type(value, struct quic_flow_metrics);
} quic_flows SEC(".maps");

// ============================================================================
// Sidecar de-duplication — marks loopback and known sidecar sockets.
// ============================================================================

struct sidecar_info {
	__u8  is_sidecar_internal;   // 1 = loopback/sidecar, skip byte counting
	__u8  pad[3];
	__u32 app_pid;               // correlated application PID (if known)
	__u64 app_cgroupid;          // correlated application cgroup (if known)
};

struct {
	__uint(type, BPF_MAP_TYPE_SK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct sidecar_info);
} sidecar_storage SEC(".maps");

// ============================================================================
// Event types emitted to the ring buffer.
// ============================================================================

enum event_type {
	EVENT_CONNECT   = 1,  // cgroup/connect4: pre-DNAT capture
	EVENT_ESTABLISH = 2,  // sock_ops: post-DNAT established
	EVENT_CLOSE     = 3,  // sock_ops/state_cb: connection closed
};

struct connect_event {
	__u8  type;               // EVENT_CONNECT
	__u8  protocol;           // IPPROTO_TCP or IPPROTO_UDP
	__u16 pad;
	__u32 pid;
	__u64 cookie;
	__u64 cgroupid;
	__u32 original_dst_ip;    // pre-DNAT destination IP
	__u16 original_dst_port;  // pre-DNAT destination port
	__u16 pad2;
	__u64 timestamp_ns;
	char  comm[16];           // process name
};

// Emitted by sock_ops on ACTIVE_ESTABLISHED / PASSIVE_ESTABLISHED.
// Contains the post-DNAT (actual) destination AND the correlated pre-DNAT
// original from cgroup/connect4. This completes the two-phase capture.
struct establish_event {
	__u8  type;               // EVENT_ESTABLISH
	__u8  direction;          // 0=outgoing (active), 1=incoming (passive)
	__u8  protocol;
	__u8  pad;
	__u32 pid;
	__u64 cookie;
	__u64 cgroupid;
	__u32 src_ip;             // local IP
	__u32 dst_ip;             // post-DNAT remote IP (actual backend pod)
	__u16 src_port;
	__u16 dst_port;           // post-DNAT remote port
	__u32 original_dst_ip;    // pre-DNAT IP (ClusterIP), 0 if no DNAT
	__u16 original_dst_port;  // pre-DNAT port, 0 if no DNAT
	__u16 pad2;
	__u64 timestamp_ns;
	char  comm[16];
};

// Emitted by sock_ops on TCP state change to CLOSE / CLOSE_WAIT / FIN_WAIT.
// Final byte counters and connection duration.
struct close_event {
	__u8  type;               // EVENT_CLOSE
	__u8  direction;
	__u8  protocol;
	__u8  pad;
	__u32 pid;
	__u64 cookie;
	__u32 src_ip;
	__u32 dst_ip;
	__u16 src_port;
	__u16 dst_port;
	__u32 original_dst_ip;
	__u16 original_dst_port;
	__u16 pad2;
	__u64 tx_bytes;
	__u64 rx_bytes;
	__u64 retransmit_bytes;   // cumulative retransmitted bytes
	__u32 retransmit_count;   // number of retransmissions
	__u32 pad3;
	__u64 duration_ns;        // elapsed since establish
	__u64 timestamp_ns;
};
