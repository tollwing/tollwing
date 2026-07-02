// tollwing — eBPF programs for cloud network cost attribution.
//
// Hook strategy (layered, with graceful degradation):
//   1. cgroup/connect4  — pre-DNAT destination capture (the key differentiator)
//   2. sock_ops         — connection lifecycle (establish, close)
//   3. kprobe/tcp_sendmsg + tcp_cleanup_rbuf — byte counting
//   4. cgroup/sock_release — connection-table cleanup (UDP has no close CB)
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

// The TCP state that ends byte accounting. Matches the kernel's TCP_* enum.
// Only TCP_CLOSE is terminal for us: half-close states (CLOSE_WAIT,
// FIN_WAIT*) still carry legal application data — see handle_state_change.
#define TCP_CLOSE        7

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

// Per DEC-016, the per-cgroup CGRP_STORAGE cost helpers and the
// sk_cost_storage iterator feed were removed. The CGRP_STORAGE block was
// guarded by `#ifdef BPF_MAP_TYPE_CGRP_STORAGE` — an enum from vmlinux.h,
// never a macro — so it compiled out of EVERY build while userspace logged
// "map not available" as if the kernel lacked support.

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
	if (!evt) {
		count_drop(DROP_SLOT_EVENTS_RINGBUF);
		return 1;
	}

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
	if (!evt) {
		count_drop(DROP_SLOT_EVENTS_RINGBUF);
		return 1;
	}

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
//   - Detect the fully-closed state (TCP_CLOSE) for final tallying.
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

	// ---- Arm the STATE_CB callback for this socket ----
	// The kernel delivers BPF_SOCK_OPS_STATE_CB only to sockets that opt in
	// via this per-socket flag; without it handle_state_change never runs
	// and the TCP_CLOSE cleanup below it is dead code (the entry then lives
	// until sock_release/LRU and the close_event is never emitted). OR into
	// the existing flags so a future flag user isn't clobbered. The helper
	// (4.16+) and the flag enum (from the vendored vmlinux headers) both
	// predate our 5.8 kernel floor, so no runtime guard is needed — and a
	// preprocessor guard would be wrong anyway: the flag is an enum, never
	// a macro, so `#ifdef` silently compiles it out (the DEC-016 lesson).
	bpf_sock_ops_cb_flags_set(skops,
	                          skops->bpf_sock_ops_cb_flags |
	                          BPF_SOCK_OPS_STATE_CB_FLAG);

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
			if (bpf_map_update_elem(&flow_aggregates, &fk, &fm, BPF_NOEXIST))
				count_drop(DROP_SLOT_FLOW_AGGREGATES);
		}
	}

	// ---- Emit establish event ----
	struct establish_event *evt;
	evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
	if (!evt) {
		count_drop(DROP_SLOT_EVENTS_RINGBUF);
		return;
	}

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

	// Only fire on the fully-closed state. Half-close states (CLOSE_WAIT,
	// FIN_WAIT*) were previously treated as terminal, which deleted the
	// connection entry while the application could still legally send or
	// receive (e.g. a server draining its response after the client's FIN)
	// — those bytes went uncounted. Every socket reaches TCP_CLOSE via
	// tcp_set_state()/tcp_done() on all paths (including TIME_WAIT, resets,
	// and timeouts), so deferring loses nothing. Per P5, count until the
	// connection is actually done.
	if (new_state != TCP_CLOSE)
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
	if (!evt) {
		count_drop(DROP_SLOT_EVENTS_RINGBUF);
		goto cleanup;
	}

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
		// A failed insert (map full, or lost race with another CPU) means
		// this delta is silently gone — count it so tollwing_map_update_
		// drops_total tells the truth instead of reading 0 forever (P4).
		if (bpf_map_update_elem(&flow_aggregates, &key, &new_val, BPF_NOEXIST))
			count_drop(DROP_SLOT_FLOW_AGGREGATES);
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
// Hook 7: cgroup/sock_release — connection-table cleanup (kernel 5.9+).
//
// UDP sockets get a `connections` entry in cgroup/connect4 (and a
// cookie_to_original_dst entry) but never pass through the sock_ops
// STATE_CB close path, so those entries used to live until LRU eviction —
// and enough UDP churn evicted LIVE TCP entries, silently ending their
// byte counting. Per P2 (bounded agent state), delete both entries when
// the socket is destroyed.
//
// TCP entries are deliberately NOT deleted here. The kernel runs
// INET_SOCK_RELEASE when the fd closes, BEFORE the TCP state machine
// finishes (FIN_WAIT/LAST_ACK/TIME_WAIT come after), so deleting TCP here
// would preempt the STATE_CB TCP_CLOSE path for every gracefully closed
// connection — ending byte/retransmit accounting early and suppressing
// the close_event (the post-close undercount this hook must not recreate,
// P5). TCP cleanup belongs to handle_state_change at TCP_CLOSE; a TCP
// socket that somehow never reaches TCP_CLOSE (e.g. the cb-flags helper
// failed at establish) leaves one stale entry that the LRU_HASH
// `connections` map evicts under pressure — bounded state per P2, so the
// belt-and-braces delete is not worth re-breaking graceful closes for.
//
// Deliberately not gated on agent_config.enabled: cleanup must keep
// running for entries created before a runtime disable.
// ============================================================================

SEC("cgroup/sock_release")
int tollwing_sock_release(struct bpf_sock *ctx)
{
	__u64 cookie = bpf_get_socket_cookie(ctx);
	if (ctx->protocol != IPPROTO_TCP)
		bpf_map_delete_elem(&connections, &cookie);
	// The pre-DNAT correlation entry is safe to drop for every protocol:
	// for TCP it is consumed (and deleted) at ESTABLISHED_CB, so by
	// release time it only lingers for connections that never established.
	bpf_map_delete_elem(&cookie_to_original_dst, &cookie);
	return 1;
}

// Per DEC-016, the conntrack NAT-resolution programs
// (fentry/nf_conntrack_confirm, kprobe/__nf_conntrack_confirm, and the
// SEC("netfilter") kfunc variant in conntrack_kfunc.bpf.c) were removed:
// per-packet work feeding the nat_mappings map that no userspace code ever
// read, with two writers using incompatible key schemes. Pre-DNAT intent
// comes from the two-phase capture (DEC-003).

// ============================================================================
// Additional program modules — included as part of the same compilation unit
// so they share vmlinux.h, maps.h, and the GPL license.
// ============================================================================

#include "dns.bpf.c"
#include "quic.bpf.c"

char LICENSE[] SEC("license") = "GPL";
