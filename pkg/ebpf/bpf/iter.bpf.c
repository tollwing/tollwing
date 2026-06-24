// iter.bpf.c — BPF iterator for consistent per-socket cost state dumps.
//
// Uses SEC("iter/bpf_sk_storage_map") to iterate all entries in the
// sk_cost_storage map in a single consistent pass.
//
// This eliminates race conditions from iterating BPF hash maps while
// entries are added/deleted. Complementary to the ring buffer path:
//   - Ring buffer: real-time events (connect/close)
//   - Iterator: periodic (10-30s) aggregated state snapshots
//
// Kernel requirement: 5.15+ for BPF iterators, 6.4+ for sk_storage iterators.

// Included from tollwing.bpf.c — do not compile standalone.
// vmlinux.h, bpf helpers, and maps.h are already included.

// ============================================================================
// Output format: each iteration emits a fixed-size record to the iter fd.
//
// Userspace reads the fd to get all entries in one pass.
// ============================================================================

struct iter_output {
	struct flow_key fk;
	__u64 tx_bytes;
	__u64 rx_bytes;
	__u64 retransmit_bytes;
	__u64 cgroupid;
	__u64 start_ns;
	__u64 snapshot_ns;   // timestamp of this snapshot
};

// ============================================================================
// SEC("iter/bpf_sk_storage_map") — iterates sk_cost_storage entries.
//
// The BPF runtime calls this once per entry in the sk_cost_storage map.
// ctx->sk is the socket, ctx->value is the struct sk_cost_meta pointer.
//
// We read the current socket byte counters and emit an iter_output record.
// ============================================================================

SEC("iter/bpf_sk_storage_map")
int tollwing_sk_iter(struct bpf_iter__bpf_sk_storage_map *ctx)
{
	struct sock *sk = ctx->sk;
	struct sk_cost_meta *meta = ctx->value;

	if (!sk || !meta)
		return 0;

	struct iter_output out = {};

	// Copy flow key from stored metadata.
	out.fk = meta->fk;
	out.cgroupid = meta->cgroupid;
	out.start_ns = meta->start_ns;
	out.snapshot_ns = bpf_ktime_get_ns();

	// Read current byte counters from the socket's conn_info in the
	// connections map (via socket cookie lookup).
	__u64 cookie = bpf_get_socket_cookie(sk);
	struct conn_info *conn = bpf_map_lookup_elem(&connections, &cookie);
	if (conn) {
		out.tx_bytes = conn->tx_bytes;
		out.rx_bytes = conn->rx_bytes;
		out.retransmit_bytes = conn->retransmit_bytes;
	} else {
		// Connection may have been cleaned up. Use last known values
		// from the sk_cost_meta.
		out.tx_bytes = meta->tx_bytes;
		out.rx_bytes = meta->rx_bytes;
		out.retransmit_bytes = meta->retransmit_bytes;
	}

	// Also update the meta with latest values for future reads.
	if (conn) {
		meta->tx_bytes = conn->tx_bytes;
		meta->rx_bytes = conn->rx_bytes;
		meta->retransmit_bytes = conn->retransmit_bytes;
	}

	// Emit the record to the iter fd.
	bpf_seq_write(ctx->meta->seq, &out, sizeof(out));

	return 0;
}

// LICENSE defined in tollwing.bpf.c
