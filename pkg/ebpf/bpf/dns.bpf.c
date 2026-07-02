// dns.bpf.c — Minimal eBPF DNS response capture for IP-to-domain resolution.
//
// Hook: fentry/udp_recvmsg
// Captures raw DNS response packets and sends them to userspace via ring
// buffer. All DNS parsing happens in Go — this avoids BPF verifier
// complexity with variable-offset packet parsing.

// Included from tollwing.bpf.c — do not compile standalone.

#ifndef AF_INET6
#define AF_INET6 10
#endif

#define DNS_PORT     53
#define DNS_RAW_MAX  512

struct dns_raw_event {
	__u16 len;
	__u16 pad;
	__u8  data[DNS_RAW_MAX];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} dns_events SEC(".maps");

SEC("fentry/udp_recvmsg")
int BPF_PROG(tollwing_dns_recvmsg, struct sock *sk)
{
	__u16 src_port = BPF_CORE_READ(sk, __sk_common.skc_dport);
	if (bpf_ntohs(src_port) != DNS_PORT)
		return 0;

	__u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
	if (family != AF_INET && family != AF_INET6)
		return 0;

	struct sk_buff *skb = BPF_CORE_READ(sk, sk_receive_queue.next);
	// An empty sk_receive_queue is a circular list whose head points to
	// itself: `next` is then the embedded list head inside struct sock —
	// NOT an skb and NOT NULL. At fentry time (before the datagram is
	// consumed) an empty queue is common; dereferencing the sentinel as an
	// skb read garbage `data`/`len` fields. Guard against it explicitly.
	if (!skb || (void *)skb == (void *)&sk->sk_receive_queue)
		return 0;

	unsigned char *data = BPF_CORE_READ(skb, data);
	__u32 dlen = BPF_CORE_READ(skb, len);
	if (!data || dlen < 12 || dlen > DNS_RAW_MAX)
		return 0;

	struct dns_raw_event *evt;
	evt = bpf_ringbuf_reserve(&dns_events, sizeof(*evt), 0);
	if (!evt) {
		count_drop(DROP_SLOT_DNS_RINGBUF);
		return 0;
	}

	__builtin_memset(evt, 0, sizeof(*evt));

	// Clamp instead of masking: `dlen & (DNS_RAW_MAX - 1)` mapped a
	// full-size 512-byte payload to a 0-byte copy while evt->len still
	// claimed 512. The range check above already bounds dlen to
	// [12, DNS_RAW_MAX]; the explicit clamp keeps the verifier's bound
	// obvious and survives future edits to the check.
	__u32 copy_len = dlen;
	if (copy_len > DNS_RAW_MAX)
		copy_len = DNS_RAW_MAX;
	evt->len = (__u16)copy_len;

	if (bpf_probe_read_kernel(evt->data, copy_len, data) < 0) {
		bpf_ringbuf_discard(evt, 0);
		return 0;
	}

	bpf_ringbuf_submit(evt, 0);
	return 0;
}

// ============================================================================
// fexit/udp_recvmsg — UDP ingress byte counting.
//
// Fires after udp_recvmsg returns. The return value is the number of
// bytes received (or negative on error).
//
// int udp_recvmsg(struct sock *sk, struct msghdr *msg, size_t len,
//                 int flags, int *addr_len)
// ============================================================================

SEC("fexit/udp_recvmsg")
int BPF_PROG(tollwing_udp_recvmsg_exit, struct sock *sk, struct msghdr *msg,
             size_t len, int flags, int *addr_len, int ret)
{
	if (ret <= 0)
		return 0;

	struct agent_config *cfg;
	__u32 key = 0;
	cfg = bpf_map_lookup_elem(&agent_config, &key);
	if (!cfg || !cfg->enabled)
		return 0;

	__u64 cookie = bpf_get_socket_cookie(sk);

	struct conn_info *conn = bpf_map_lookup_elem(&connections, &cookie);
	if (!conn || conn->protocol != IPPROTO_UDP)
		return 0;

	__sync_fetch_and_add(&conn->rx_bytes, (__u64)ret);

	// Update flow_aggregates.
	struct flow_key fk = {};
	fk.src_ip    = conn->src_ip;
	fk.dst_ip    = conn->dst_ip;
	fk.src_port  = conn->src_port;
	fk.dst_port  = conn->dst_port;
	fk.pid       = conn->pid;
	fk.protocol  = conn->protocol;
	fk.direction = conn->direction;

	struct flow_metrics *val = bpf_map_lookup_elem(&flow_aggregates, &fk);
	if (val) {
		__sync_fetch_and_add(&val->rx_bytes, (__u64)ret);
		val->last_updated_ns = bpf_ktime_get_ns();
	}

	return 0;
}

// LICENSE defined in tollwing.bpf.c
