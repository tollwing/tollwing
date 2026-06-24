// tollwing — eBPF programs for cloud network cost attribution.
//
// Hook strategy (layered, with graceful degradation):
//   1. cgroup/connect4  — pre-DNAT destination capture (the key differentiator)
//   2. sock_ops         — connection lifecycle (establish, close)
//   3. kprobe/tcp_sendmsg + tcp_cleanup_rbuf — byte counting
//   4. fentry/nf_conntrack_confirm — NAT mapping resolution              [TODO]
//
// CO-RE: compiles against vmlinux headers for kernel portability.
// Kernel requirement: 5.8+ for cgroup/sock_ops BPF programs + ringbuf.

#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

// TCP states we care about for connection close detection.
// These match the kernel's TCP_* enum values.
#define TCP_CLOSE        7
#define TCP_CLOSE_WAIT   8
#define TCP_FIN_WAIT1   11
#define TCP_FIN_WAIT2   12

#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif

#include "maps.h"

// ============================================================================
// Sidecar detection: known sidecar proxy ports.
// ============================================================================

static __always_inline bool is_sidecar_port(__u16 port)
{
	switch (port) {
	case 15001: // Envoy outbound
	case 15006: // Envoy inbound
	case 15090: // Envoy stats
	case 15021: // Envoy health
	case 4143:  // Linkerd outbound
	case 4191:  // Linkerd admin
		return true;
	default:
		return false;
	}
}

// ============================================================================
// Helper: update per-cgroup cost accumulator (kernel 6.3+).
// Uses bpf_cgrp_storage_get() — nop if map doesn't exist on older kernels.
// ============================================================================

#ifdef BPF_MAP_TYPE_CGRP_STORAGE
static __always_inline void update_cgroup_cost_tx(struct bpf_sock_ops *skops, __u64 bytes)
{
	struct cgroup *cgrp = BPF_CORE_READ(skops, sk, sk_cgrp_data.cgroup);
	if (!cgrp)
		return;
	struct cgroup_cost *cost = bpf_cgrp_storage_get(&cgroup_cost_storage, cgrp, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (cost)
		__sync_fetch_and_add(&cost->tx_bytes, bytes);
}

static __always_inline void update_cgroup_cost_rx(struct bpf_sock_ops *skops, __u64 bytes)
{
	struct cgroup *cgrp = BPF_CORE_READ(skops, sk, sk_cgrp_data.cgroup);
	if (!cgrp)
		return;
	struct cgroup_cost *cost = bpf_cgrp_storage_get(&cgroup_cost_storage, cgrp, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (cost)
		__sync_fetch_and_add(&cost->rx_bytes, bytes);
}

static __always_inline void cgroup_cost_new_conn(struct bpf_sock_ops *skops)
{
	struct bpf_sock *sk = skops->sk;
	if (!sk)
		return;
	struct cgroup *cgrp = BPF_CORE_READ(sk, sk_cgrp_data.cgroup);
	if (!cgrp)
		return;
	struct cgroup_cost *cost = bpf_cgrp_storage_get(&cgroup_cost_storage, cgrp, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (cost)
		__sync_fetch_and_add(&cost->conn_count, 1);
}
#else
__attribute__((unused))
static __always_inline void update_cgroup_cost_tx(struct bpf_sock_ops *skops, __u64 bytes) {}
__attribute__((unused))
static __always_inline void update_cgroup_cost_rx(struct bpf_sock_ops *skops, __u64 bytes) {}
__attribute__((unused))
static __always_inline void cgroup_cost_new_conn(struct bpf_sock_ops *skops) {}
#endif

// ============================================================================
// Helper: populate sk_cost_storage on connection establish (for BPF iterators).
// ============================================================================

static __always_inline void populate_sk_cost_meta(struct bpf_sock_ops *skops,
                                                  struct conn_info *conn)
{
	struct bpf_sock *sk = skops->sk;
	if (!sk)
		return;

	struct sk_cost_meta *meta;
	meta = bpf_sk_storage_get(&sk_cost_storage, sk, 0,
	                          BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!meta)
		return;

	meta->fk.src_ip    = conn->src_ip;
	meta->fk.dst_ip    = conn->dst_ip;
	meta->fk.src_port  = conn->src_port;
	meta->fk.dst_port  = conn->dst_port;
	meta->fk.pid       = conn->pid;
	meta->fk.protocol  = conn->protocol;
	meta->fk.direction = conn->direction;
	meta->tx_bytes     = 0;
	meta->rx_bytes     = 0;
	meta->retransmit_bytes = 0;
	meta->cgroupid     = conn->cgroupid;
	meta->start_ns     = conn->start_ns;
}

// ============================================================================
// Helper: detect and mark sidecar sockets.
// ============================================================================

static __always_inline bool detect_sidecar(struct bpf_sock_ops *skops)
{
	__u32 local_ip  = skops->local_ip4;
	__u32 remote_ip = skops->remote_ip4;
	__u16 local_port = skops->local_port;
	__u16 remote_port = bpf_ntohl(skops->remote_port);

	// Detect loopback connections (both ends 127.0.0.1).
	bool is_loopback = (local_ip == bpf_htonl(0x7F000001) &&
	                    remote_ip == bpf_htonl(0x7F000001));

	// Detect known sidecar ports.
	bool sidecar_port = is_sidecar_port(local_port) || is_sidecar_port(remote_port);

	if (is_loopback || sidecar_port) {
		struct bpf_sock *sk = skops->sk;
		if (!sk)
			return false;
		struct sidecar_info info = {};
		info.is_sidecar_internal = 1;
		bpf_sk_storage_get(&sidecar_storage, sk, &info,
		                   BPF_LOCAL_STORAGE_GET_F_CREATE);
		return true;
	}
	return false;
}

// ============================================================================
// Helper: check if socket is marked as sidecar-internal.
// ============================================================================

static __always_inline bool is_sidecar_socket_cookie(__u64 cookie,
                                                     struct conn_info *conn)
{
	// We check by examining the conn_info for loopback addresses.
	if (!conn)
		return false;
	__u32 lo = bpf_htonl(0x7F000001);
	if (conn->src_ip == lo && conn->dst_ip == lo)
		return true;
	if (is_sidecar_port(conn->src_port) || is_sidecar_port(conn->dst_port))
		return true;
	return false;
}

// ============================================================================
// Helper: read config with fast-path bailout.
// ============================================================================

static __always_inline struct agent_config *get_config(void)
{
	__u32 key = 0;
	struct agent_config *cfg = bpf_map_lookup_elem(&agent_config, &key);
	if (!cfg || !cfg->enabled)
		return 0;
	return cfg;
}

// should_sample returns true if this connection should be tracked.
// sample_rate=0 or 1 means track everything. N>1 means track 1/N connections.
static __always_inline bool should_sample(__u8 sample_rate)
{
	if (sample_rate <= 1)
		return true;
	return (bpf_get_prandom_u32() % sample_rate) == 0;
}

// ============================================================================
// Hook 1: cgroup/connect4 — pre-DNAT destination capture.
//
// Fires BEFORE kube-proxy DNAT. Captures the original ClusterIP:port.
// The cookie stored here is correlated by sock_ops when the connection
// is established post-DNAT.
//
// Return: 1 = allow, 0 = reject. We ALWAYS return 1 (observer only).
// ============================================================================

SEC("cgroup/connect4")
int tollwing_connect4(struct bpf_sock_addr *ctx)
{
	struct agent_config *cfg = get_config();
	if (!cfg)
		return 1;

	__u8 proto = ctx->protocol;
	if (proto != IPPROTO_TCP && !(proto == IPPROTO_UDP && cfg->track_udp))
		return 1;

	// Sampling: skip this connection if not selected.
	if (!should_sample(cfg->sample_rate))
		return 1;

	__u64 cookie = bpf_get_socket_cookie(ctx);

	// user_ip4: original dest IP (network byte order).
	// user_port: __be16 in a __u32. bpf_ntohl gives host-order in upper 16 bits.
	struct original_dst dst = {};
	dst.ip       = ctx->user_ip4;
	dst.port     = bpf_ntohl(ctx->user_port) >> 16;
	dst.pid      = bpf_get_current_pid_tgid() >> 32;
	dst.cgroupid = bpf_get_current_cgroup_id();
	bpf_get_current_comm(&dst.comm, sizeof(dst.comm));

	bpf_map_update_elem(&cookie_to_original_dst, &cookie, &dst, BPF_ANY);

	// For UDP: create a connections entry directly since there's no sock_ops
	// establish phase. This enables udp_sendmsg/udp_recvmsg byte counting.
	if (proto == IPPROTO_UDP) {
		struct conn_info conn = {};
		conn.dst_ip            = ctx->user_ip4;
		conn.original_dst_ip   = ctx->user_ip4;
		conn.dst_port          = dst.port;
		conn.original_dst_port = dst.port;
		conn.pid               = dst.pid;
		conn.cgroupid          = dst.cgroupid;
		conn.start_ns          = bpf_ktime_get_ns();
		conn.protocol          = IPPROTO_UDP;
		conn.direction         = 0; // outgoing
		conn.state             = 1;
		bpf_map_update_elem(&connections, &cookie, &conn, BPF_NOEXIST);
	}

	struct connect_event *evt;
	evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
	if (!evt)
		return 1;

	evt->type               = EVENT_CONNECT;
	evt->protocol           = proto;
	evt->pid                = bpf_get_current_pid_tgid() >> 32;
	evt->cookie             = cookie;
	evt->cgroupid           = bpf_get_current_cgroup_id();
	evt->original_dst_ip    = ctx->user_ip4;
	evt->original_dst_port  = dst.port;
	evt->timestamp_ns       = bpf_ktime_get_ns();
	bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

	bpf_ringbuf_submit(evt, 0);

	return 1;
}

// ============================================================================
// Hook 1b: cgroup/connect6 — pre-DNAT destination capture for IPv6.
//
// Mirrors cgroup/connect4 but for AF_INET6 connections.
// ============================================================================

SEC("cgroup/connect6")
int tollwing_connect6(struct bpf_sock_addr *ctx)
{
	struct agent_config *cfg = get_config();
	if (!cfg)
		return 1;

	__u8 proto = ctx->protocol;
	if (proto != IPPROTO_TCP && !(proto == IPPROTO_UDP && cfg->track_udp))
		return 1;

	if (!should_sample(cfg->sample_rate))
		return 1;

	__u64 cookie = bpf_get_socket_cookie(ctx);

	struct original_dst dst = {};
	dst.family   = AF_INET6;
	dst.port     = bpf_ntohl(ctx->user_port) >> 16;
	dst.pid      = bpf_get_current_pid_tgid() >> 32;
	dst.cgroupid = bpf_get_current_cgroup_id();
	bpf_get_current_comm(&dst.comm, sizeof(dst.comm));
	// user_ip6 is accessed as 4 individual __u32 fields.
	*(__u32 *)&dst.ip6[0]  = ctx->user_ip6[0];
	*(__u32 *)&dst.ip6[4]  = ctx->user_ip6[1];
	*(__u32 *)&dst.ip6[8]  = ctx->user_ip6[2];
	*(__u32 *)&dst.ip6[12] = ctx->user_ip6[3];

	bpf_map_update_elem(&cookie_to_original_dst, &cookie, &dst, BPF_ANY);

	struct connect_event *evt;
	evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
	if (!evt)
		return 1;

	evt->type               = EVENT_CONNECT;
	evt->protocol           = proto;
	evt->pid                = dst.pid;
	evt->cookie             = cookie;
	evt->cgroupid           = dst.cgroupid;
	evt->original_dst_port  = dst.port;
	evt->timestamp_ns       = bpf_ktime_get_ns();
	bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

	bpf_ringbuf_submit(evt, 0);

	return 1;
}

// ============================================================================
// Hook 2: sock_ops — connection lifecycle (establish + close).
//
// ACTIVE_ESTABLISHED_CB: outgoing connection completed (post-DNAT).
//   - Correlate with cookie_to_original_dst to get pre-DNAT ClusterIP.
//   - Populate the full conn_info in the connections map.
//   - Emit establish_event with both pre-DNAT and post-DNAT addresses.
//
// PASSIVE_ESTABLISHED_CB: incoming connection accepted.
//   - No pre-DNAT lookup needed (we're the server side).
//   - Still track in connections map for byte counting.
//
// STATE_CB: TCP state transitions.
//   - Detect close states (CLOSE, CLOSE_WAIT, FIN_WAIT) for final tallying.
//   - Emit close_event and remove from connections map.
// ============================================================================

static __always_inline void handle_established(struct bpf_sock_ops *skops,
                                               __u8 direction)
{
	__u64 cookie = bpf_get_socket_cookie(skops);
	__u64 now    = bpf_ktime_get_ns();

	// remote_port is __be32 in sock_ops — convert to host-order __u16.
	__u16 dst_port = bpf_ntohl(skops->remote_port);

	// ---- Two-phase correlation ----
	// Look up pre-DNAT destination stored by cgroup/connect4.
	// For active (outgoing) connections, the cookie should match.
	// For passive (incoming), there's no pre-DNAT entry — that's expected.
	// PID and cgroup ID are captured in cgroup/connect4 context where
	// bpf_get_current_pid_tgid is reliably available.
	__u32 orig_ip   = 0;
	__u16 orig_port = 0;
	__u32 pid       = 0;
	__u64 cgroupid  = 0;
	char  comm[16]  = {};

	if (direction == 0) { // outgoing
		struct original_dst *orig;
		orig = bpf_map_lookup_elem(&cookie_to_original_dst, &cookie);
		if (orig) {
			orig_ip   = orig->ip;
			orig_port = orig->port;
			pid       = orig->pid;
			cgroupid  = orig->cgroupid;
			__builtin_memcpy(comm, orig->comm, sizeof(comm));
			// Delete — this was a short-lived correlation entry.
			bpf_map_delete_elem(&cookie_to_original_dst, &cookie);
		}
	}

	// ---- Populate full connection info ----
	struct conn_info conn = {};
	conn.family             = skops->family;
	conn.src_ip             = skops->local_ip4;
	conn.dst_ip             = skops->remote_ip4;
	conn.original_dst_ip    = orig_ip;
	conn.src_port           = skops->local_port;
	conn.dst_port           = dst_port;
	conn.original_dst_port  = orig_port;
	conn.pid                = pid;
	conn.cgroupid           = cgroupid;
	conn.start_ns           = now;
	conn.tx_bytes           = 0;
	conn.rx_bytes           = 0;
	conn.protocol           = IPPROTO_TCP;
	conn.direction          = direction;
	conn.state              = 1; // ESTABLISHED

	// Populate IPv6 addresses if applicable.
	if (skops->family == AF_INET6) {
		// sock_ops context fields must be accessed individually (no memcpy).
		*(__u32 *)&conn.src_ip6[0]  = skops->local_ip6[0];
		*(__u32 *)&conn.src_ip6[4]  = skops->local_ip6[1];
		*(__u32 *)&conn.src_ip6[8]  = skops->local_ip6[2];
		*(__u32 *)&conn.src_ip6[12] = skops->local_ip6[3];
		*(__u32 *)&conn.dst_ip6[0]  = skops->remote_ip6[0];
		*(__u32 *)&conn.dst_ip6[4]  = skops->remote_ip6[1];
		*(__u32 *)&conn.dst_ip6[8]  = skops->remote_ip6[2];
		*(__u32 *)&conn.dst_ip6[12] = skops->remote_ip6[3];
	}

	bpf_map_update_elem(&connections, &cookie, &conn, BPF_ANY);

	// ---- Per-cgroup cost: increment conn_count (kernel 6.3+) ----
	cgroup_cost_new_conn(skops);

	// ---- Populate sk_cost_storage for BPF iterators (kernel 6.4+) ----
	populate_sk_cost_meta(skops, &conn);

	// ---- Detect and mark sidecar sockets ----
	detect_sidecar(skops);

	// ---- Seed flow_aggregates with conn_count=1, zero bytes ----
	{
		struct flow_key fk = {};
		fk.src_ip    = conn.src_ip;
		fk.dst_ip    = conn.dst_ip;
		fk.src_port  = conn.src_port;
		fk.dst_port  = dst_port;
		fk.pid       = pid;
		fk.protocol  = IPPROTO_TCP;
		fk.direction = direction;

		struct flow_metrics *existing = bpf_map_lookup_elem(&flow_aggregates, &fk);
		if (existing) {
			__sync_fetch_and_add(&existing->conn_count, 1);
			existing->last_updated_ns = now;
		} else {
			struct flow_metrics fm = {};
			fm.conn_count = 1;
			fm.last_updated_ns = now;
			bpf_map_update_elem(&flow_aggregates, &fk, &fm, BPF_NOEXIST);
		}
	}

	// ---- Emit establish event ----
	struct establish_event *evt;
	evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
	if (!evt)
		return;

	evt->type               = EVENT_ESTABLISH;
	evt->direction          = direction;
	evt->protocol           = IPPROTO_TCP;
	evt->pid                = pid;
	evt->cookie             = cookie;
	evt->cgroupid           = conn.cgroupid;
	evt->src_ip             = skops->local_ip4;
	evt->dst_ip             = skops->remote_ip4;
	evt->src_port           = skops->local_port;
	evt->dst_port           = dst_port;
	evt->original_dst_ip    = orig_ip;
	evt->original_dst_port  = orig_port;
	evt->timestamp_ns       = now;
	__builtin_memcpy(evt->comm, comm, sizeof(evt->comm));

	bpf_ringbuf_submit(evt, 0);
}

static __always_inline void handle_state_change(struct bpf_sock_ops *skops)
{
	// args[0] = old state, args[1] = new state
	int new_state = skops->args[1];

	// Only fire on terminal states.
	if (new_state != TCP_CLOSE &&
	    new_state != TCP_CLOSE_WAIT &&
	    new_state != TCP_FIN_WAIT1 &&
	    new_state != TCP_FIN_WAIT2)
		return;

	__u64 cookie = bpf_get_socket_cookie(skops);

	// Look up the connection to get accumulated byte counters.
	struct conn_info *conn = bpf_map_lookup_elem(&connections, &cookie);
	if (!conn)
		return;

	__u64 now = bpf_ktime_get_ns();

	// ---- Emit close event ----
	struct close_event *evt;
	evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
	if (!evt)
		goto cleanup;

	evt->type               = EVENT_CLOSE;
	evt->direction          = conn->direction;
	evt->protocol           = conn->protocol;
	evt->pid                = conn->pid;
	evt->cookie             = cookie;
	evt->src_ip             = conn->src_ip;
	evt->dst_ip             = conn->dst_ip;
	evt->src_port           = conn->src_port;
	evt->dst_port           = conn->dst_port;
	evt->original_dst_ip    = conn->original_dst_ip;
	evt->original_dst_port  = conn->original_dst_port;
	evt->tx_bytes           = conn->tx_bytes;
	evt->rx_bytes           = conn->rx_bytes;
	evt->retransmit_bytes   = conn->retransmit_bytes;
	evt->retransmit_count   = conn->retransmit_count;
	evt->duration_ns        = now - conn->start_ns;
	evt->timestamp_ns       = now;

	bpf_ringbuf_submit(evt, 0);

cleanup:
	bpf_map_delete_elem(&connections, &cookie);
}

SEC("sockops")
int tollwing_sockops(struct bpf_sock_ops *skops)
{
	struct agent_config *cfg = get_config();
	if (!cfg)
		return 1;

	// Only track IPv4/IPv6 TCP.
	if (skops->family != AF_INET && skops->family != AF_INET6)
		return 1;

	switch (skops->op) {
	case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
		// For outgoing: if cgroup/connect4 sampled this out, there will be
		// no cookie_to_original_dst entry. We still proceed here because
		// handle_established checks for the entry and handles its absence.
		// However, if sample_rate > 1 and no pre-DNAT entry exists, the
		// connection was likely sampled out — skip it entirely.
		{
			__u64 ck = bpf_get_socket_cookie(skops);
			struct original_dst *orig = bpf_map_lookup_elem(&cookie_to_original_dst, &ck);
			if (!orig && cfg->sample_rate > 1)
				break; // sampled out in cgroup/connect4
		}
		handle_established(skops, 0); // outgoing
		break;
	case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
		// For incoming connections: apply sampling here since they don't go
		// through cgroup/connect4.
		if (!should_sample(cfg->sample_rate))
			break;
		handle_established(skops, 1); // incoming
		break;
	case BPF_SOCK_OPS_STATE_CB:
		handle_state_change(skops);
		break;
	}

	return 1;
}

// ============================================================================
// Hook 3: kprobe/tcp_sendmsg — egress byte counting.
//
// Fires on every tcp_sendmsg() call. Looks up the socket cookie in the
// connections map and atomically increments tx_bytes.
//
// This is the hot path — must be as lean as possible. No ring buffer
// events here; byte counters are read by userspace on the poll interval
// and reported in the close_event.
//
// int tcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)
// ============================================================================

// Helper: build flow_key from a connection and update flow_aggregates.
static __always_inline void update_flow_aggregate(struct conn_info *conn,
                                                  __u64 tx_delta,
                                                  __u64 rx_delta)
{
	struct flow_key key = {};
	key.src_ip    = conn->src_ip;
	key.dst_ip    = conn->dst_ip;
	key.src_port  = conn->src_port;
	key.dst_port  = conn->dst_port;
	key.pid       = conn->pid;
	key.protocol  = conn->protocol;
	key.direction = conn->direction;

	struct flow_metrics *val = bpf_map_lookup_elem(&flow_aggregates, &key);
	if (val) {
		val->tx_bytes += tx_delta;
		val->rx_bytes += rx_delta;
		val->last_updated_ns = bpf_ktime_get_ns();
	} else {
		struct flow_metrics new_val = {};
		new_val.tx_bytes = tx_delta;
		new_val.rx_bytes = rx_delta;
		new_val.conn_count = 1;
		new_val.last_updated_ns = bpf_ktime_get_ns();
		bpf_map_update_elem(&flow_aggregates, &key, &new_val, BPF_NOEXIST);
	}
}

SEC("kprobe/tcp_sendmsg")
int tollwing_tcp_sendmsg(struct pt_regs *ctx)
{
	if (!get_config())
		return 0;

	int size = (int)PT_REGS_PARM3(ctx);

	if (size <= 0)
		return 0;

	__u64 cookie = bpf_get_socket_cookie(ctx);

	struct conn_info *conn = bpf_map_lookup_elem(&connections, &cookie);
	if (!conn)
		return 0;

	// Skip sidecar-internal traffic to avoid double counting.
	if (is_sidecar_socket_cookie(cookie, conn))
		return 0;

	// Update per-connection counters (for close_event final tally).
	__sync_fetch_and_add(&conn->tx_bytes, (__u64)size);

	// Update flow_aggregates for efficient batch polling.
	update_flow_aggregate(conn, (__u64)size, 0);

	return 0;
}

// ============================================================================
// Hook 4: kprobe/tcp_cleanup_rbuf — ingress byte counting.
//
// Fires when the application reads data from the TCP receive buffer.
// The 'copied' parameter is the number of bytes consumed.
//
// void tcp_cleanup_rbuf(struct sock *sk, int copied)
// ============================================================================

SEC("kprobe/tcp_cleanup_rbuf")
int tollwing_tcp_cleanup_rbuf(struct pt_regs *ctx)
{
	if (!get_config())
		return 0;

	int copied = (int)PT_REGS_PARM2(ctx);

	if (copied <= 0)
		return 0;

	__u64 cookie = bpf_get_socket_cookie(ctx);

	struct conn_info *conn = bpf_map_lookup_elem(&connections, &cookie);
	if (!conn)
		return 0;

	// Skip sidecar-internal traffic to avoid double counting.
	if (is_sidecar_socket_cookie(cookie, conn))
		return 0;

	// Update per-connection counters (for close_event final tally).
	__sync_fetch_and_add(&conn->rx_bytes, (__u64)copied);

	// Update flow_aggregates for efficient batch polling.
	update_flow_aggregate(conn, 0, (__u64)copied);

	return 0;
}

// ============================================================================
// Hook 3b: fentry/tcp_sendmsg — egress byte counting (preferred over kprobe).
//
// fentry has reliable bpf_get_socket_cookie support via struct sock *.
// Used when the kernel supports fentry (5.5+) since kprobe context may not
// expose bpf_get_socket_cookie on all kernels.
//
// int tcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)
// ============================================================================

SEC("fentry/tcp_sendmsg")
int BPF_PROG(tollwing_tcp_sendmsg_fentry, struct sock *sk, struct msghdr *msg, size_t size)
{
	if (!get_config())
		return 0;

	if ((int)size <= 0)
		return 0;

	__u64 cookie = bpf_get_socket_cookie(sk);

	struct conn_info *conn = bpf_map_lookup_elem(&connections, &cookie);
	if (!conn)
		return 0;

	if (is_sidecar_socket_cookie(cookie, conn))
		return 0;

	__sync_fetch_and_add(&conn->tx_bytes, (__u64)size);
	update_flow_aggregate(conn, (__u64)size, 0);

	return 0;
}

// ============================================================================
// Hook 4b: fentry/tcp_cleanup_rbuf — ingress byte counting (preferred over kprobe).
//
// void tcp_cleanup_rbuf(struct sock *sk, int copied)
// ============================================================================

SEC("fentry/tcp_cleanup_rbuf")
int BPF_PROG(tollwing_tcp_cleanup_rbuf_fentry, struct sock *sk, int copied)
{
	if (!get_config())
		return 0;

	if (copied <= 0)
		return 0;

	__u64 cookie = bpf_get_socket_cookie(sk);

	struct conn_info *conn = bpf_map_lookup_elem(&connections, &cookie);
	if (!conn)
		return 0;

	if (is_sidecar_socket_cookie(cookie, conn))
		return 0;

	__sync_fetch_and_add(&conn->rx_bytes, (__u64)copied);
	update_flow_aggregate(conn, 0, (__u64)copied);

	return 0;
}

// ============================================================================
// Hook 3c/4c: fentry/udp_sendmsg — UDP egress byte counting.
//
// int udp_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)
// ============================================================================

SEC("fentry/udp_sendmsg")
int BPF_PROG(tollwing_udp_sendmsg, struct sock *sk, struct msghdr *msg, size_t len)
{
	if (!get_config())
		return 0;

	if ((int)len <= 0)
		return 0;

	__u64 cookie = bpf_get_socket_cookie(sk);

	struct conn_info *conn = bpf_map_lookup_elem(&connections, &cookie);
	if (!conn || conn->protocol != IPPROTO_UDP)
		return 0;

	__sync_fetch_and_add(&conn->tx_bytes, (__u64)len);
	update_flow_aggregate(conn, (__u64)len, 0);

	return 0;
}

// ============================================================================
// Hook 5: fentry/tcp_retransmit_skb — retransmission byte counting.
//
// Fires on every TCP retransmission. Increments retransmit_bytes and
// retransmit_count in both the connections map and flow_aggregates.
//
// void tcp_retransmit_skb(struct sock *sk, struct sk_buff *skb, int segs)
// ============================================================================

SEC("fentry/tcp_retransmit_skb")
int BPF_PROG(tollwing_tcp_retransmit, struct sock *sk, struct sk_buff *skb, int segs)
{
	if (!get_config())
		return 0;

	__u32 skb_len = BPF_CORE_READ(skb, len);
	if (skb_len == 0)
		return 0;

	__u64 cookie = bpf_get_socket_cookie(sk);

	struct conn_info *conn = bpf_map_lookup_elem(&connections, &cookie);
	if (!conn)
		return 0;

	// Update per-connection retransmit counters.
	__sync_fetch_and_add(&conn->retransmit_bytes, (__u64)skb_len);
	__sync_fetch_and_add(&conn->retransmit_count, 1);

	// Update flow_aggregates retransmit counters.
	struct flow_key key = {};
	key.src_ip    = conn->src_ip;
	key.dst_ip    = conn->dst_ip;
	key.src_port  = conn->src_port;
	key.dst_port  = conn->dst_port;
	key.pid       = conn->pid;
	key.protocol  = conn->protocol;
	key.direction = conn->direction;

	struct flow_metrics *val = bpf_map_lookup_elem(&flow_aggregates, &key);
	if (val) {
		__sync_fetch_and_add(&val->retransmit_bytes, (__u64)skb_len);
		__sync_fetch_and_add(&val->retransmit_count, 1);
		val->last_updated_ns = bpf_ktime_get_ns();
	}

	return 0;
}

// ============================================================================
// Hook 6: fentry/tcp_send_loss_probe — TLP (speculative retransmit) tracking.
//
// Tail Loss Probes are speculative retransmits sent when the retransmit
// timer hasn't fired yet. They're still wasted bytes.
//
// void tcp_send_loss_probe(struct sock *sk)
// ============================================================================

SEC("fentry/tcp_send_loss_probe")
int BPF_PROG(tollwing_tcp_loss_probe, struct sock *sk)
{
	if (!get_config())
		return 0;

	__u64 cookie = bpf_get_socket_cookie(sk);

	struct conn_info *conn = bpf_map_lookup_elem(&connections, &cookie);
	if (!conn)
		return 0;

	// TLP sends a single MSS-sized probe. We estimate the size from the
	// TCP MSS cached in the socket.
	struct tcp_sock *tp = (struct tcp_sock *)sk;
	__u32 mss = BPF_CORE_READ(tp, mss_cache);
	if (mss == 0)
		mss = 1460; // default MSS

	__sync_fetch_and_add(&conn->retransmit_bytes, (__u64)mss);
	__sync_fetch_and_add(&conn->retransmit_count, 1);

	// Update flow_aggregates.
	struct flow_key key = {};
	key.src_ip    = conn->src_ip;
	key.dst_ip    = conn->dst_ip;
	key.src_port  = conn->src_port;
	key.dst_port  = conn->dst_port;
	key.pid       = conn->pid;
	key.protocol  = conn->protocol;
	key.direction = conn->direction;

	struct flow_metrics *val = bpf_map_lookup_elem(&flow_aggregates, &key);
	if (val) {
		__sync_fetch_and_add(&val->retransmit_bytes, (__u64)mss);
		__sync_fetch_and_add(&val->retransmit_count, 1);
		val->last_updated_ns = bpf_ktime_get_ns();
	}

	return 0;
}

// ============================================================================
// Hook 7 (optional): fentry/nf_conntrack_confirm — NAT mapping resolution.
//
// Requires kernel 5.11+ with fentry/fexit support and CONFIG_NF_CONNTRACK.
// Captures conntrack NAT translations for enhanced DNAT resolution beyond
// the cgroup/connect4 + sock_ops two-phase correlation.
//
// If unavailable, the agent gracefully degrades to the two-phase method.
//
// int nf_conntrack_confirm(struct sk_buff *skb)
// ============================================================================

// Common conntrack NAT resolution logic — shared between fentry and kprobe variants.
static __always_inline int conntrack_confirm_common(struct sk_buff *skb)
{
	struct agent_config *cfg = get_config();
	if (!cfg)
		return 0;

	// Read the nf_conntrack entry from the skb.
	// skb->_nfct holds a pointer to struct nf_conn (low bits are status flags).
	unsigned long nfct_val;
	nfct_val = BPF_CORE_READ(skb, _nfct);
	if (!nfct_val)
		return 0;

	// Mask off the low 3 bits (nfct status flags) to get the nf_conn pointer.
	struct nf_conn *ct = (struct nf_conn *)(nfct_val & ~7UL);
	if (!ct)
		return 0;

	// Read the original tuple (pre-NAT).
	struct nf_conntrack_tuple orig;
	bpf_probe_read_kernel(&orig, sizeof(orig),
		&ct->tuplehash[0].tuple);

	// Read the reply tuple (post-NAT, reversed direction).
	struct nf_conntrack_tuple reply;
	bpf_probe_read_kernel(&reply, sizeof(reply),
		&ct->tuplehash[1].tuple);

	// Only track IPv4 TCP (IPv6 NAT is rare in Kubernetes).
	if (orig.src.l3num != AF_INET)
		return 0;

	__u32 orig_dst_ip   = orig.dst.u3.ip;
	__u16 orig_dst_port = bpf_ntohs(orig.dst.u.tcp.port);
	__u32 reply_src_ip  = reply.src.u3.ip;
	__u16 reply_src_port = bpf_ntohs(reply.src.u.tcp.port);

	// If original destination differs from reply source, NAT occurred.
	if (orig_dst_ip == reply_src_ip && orig_dst_port == reply_src_port)
		return 0; // no NAT

	// Build a hash key from the original tuple.
	__u64 key = ((__u64)orig.src.u3.ip << 32) ^
		    ((__u64)orig.dst.u3.ip << 16) ^
		    ((__u64)bpf_ntohs(orig.src.u.tcp.port) << 8) ^
		    (__u64)orig_dst_port;

	struct nat_mapping mapping = {};
	mapping.pre_dnat_ip   = orig_dst_ip;
	mapping.pre_dnat_port = orig_dst_port;
	mapping.post_dnat_ip  = reply_src_ip;
	mapping.post_dnat_port = reply_src_port;
	mapping.timestamp_ns  = bpf_ktime_get_ns();

	bpf_map_update_elem(&nat_mappings, &key, &mapping, BPF_ANY);

	return 0;
}

SEC("fentry/nf_conntrack_confirm")
int BPF_PROG(tollwing_conntrack_confirm, struct sk_buff *skb)
{
	return conntrack_confirm_common(skb);
}

// kprobe fallback — attaches to __nf_conntrack_confirm (module-local symbol).
// Used when fentry on module functions is unavailable.
SEC("kprobe/__nf_conntrack_confirm")
int BPF_KPROBE(tollwing_conntrack_confirm_kprobe, struct sk_buff *skb)
{
	return conntrack_confirm_common(skb);
}

// ============================================================================
// Additional program modules — included as part of the same compilation unit
// so they share vmlinux.h, maps.h, and the GPL license.
// ============================================================================

#include "conntrack_kfunc.bpf.c"
#include "dns.bpf.c"
#include "iter.bpf.c"
#include "quic.bpf.c"

char LICENSE[] SEC("license") = "GPL";
