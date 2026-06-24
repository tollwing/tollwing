// conntrack_kfunc.bpf.c — Conntrack kfunc-based NAT resolution (kernel 6.4+).
//
// Uses BPF_PROG_TYPE_NETFILTER with bpf_ct_lookup kfuncs to resolve conntrack
// entries directly, replacing the fentry/nf_conntrack_confirm approach.
//
// Advantages over fentry:
//   - Direct access to conntrack byte/packet counters
//   - Full NAT translation info (pre-DNAT + post-DNAT tuples) in one call
//   - Type-safe kfunc interface instead of raw pointer chasing
//
// Degradation: kfunc → fentry → two-phase only
//
// Kernel requirement: 6.4+ for BPF_PROG_TYPE_NETFILTER + CT kfuncs.

// Included from tollwing.bpf.c — do not compile standalone.
// vmlinux.h, bpf helpers, AF_INET, IPPROTO_TCP, and maps.h are already included.

// ---- Netfilter verdicts (kernel 6.4+ for BPF_PROG_TYPE_NETFILTER) ----
#ifndef NF_ACCEPT
#define NF_ACCEPT 1
#define NF_DROP   0
#endif

// ---- struct bpf_nf_ctx: context passed to SEC("netfilter") programs (kernel 6.4+) ----
#ifndef BPF_NF_CTX_DEFINED
#define BPF_NF_CTX_DEFINED
struct bpf_nf_ctx {
	const struct nf_hook_state *state;
	struct sk_buff *skb;
};
#endif

// ---- struct bpf_ct_opts: options for conntrack kfunc calls (kernel 6.4+) ----
#ifndef BPF_CT_OPTS_DEFINED
#define BPF_CT_OPTS_DEFINED
struct bpf_ct_opts {
	s32 netns_id;
	s32 error;
	u8  l4proto;
	u8  dir;
	u8  reserved[2];
};
#endif

// ============================================================================
// Conntrack kfunc declarations (kernel 6.4+).
//
// These are kernel-provided BPF kfuncs for conntrack operations.
// The compiler resolves them at load time via BTF.
// ============================================================================

struct nf_conn;

// bpf_skb_ct_lookup — look up conntrack entry for a given skb.
// Returns a locked nf_conn pointer (must be released via bpf_ct_release).
extern struct nf_conn *bpf_skb_ct_lookup(struct __sk_buff *skb_ctx,
					 struct bpf_ct_opts *bpf_tuple,
					 u32 tuple__sz,
					 struct bpf_ct_opts *opts,
					 u32 opts__sz) __ksym;

// bpf_ct_release — release a conntrack reference obtained from bpf_skb_ct_lookup.
extern void bpf_ct_release(struct nf_conn *ct) __ksym;

// bpf_ct_opts for kfunc calls.
struct bpf_ct_opts___local {
	s32 netns_id;
	s32 error;
	u8  l4proto;
	u8  dir;
	u8  reserved[2];
};

// ============================================================================
// SEC("netfilter") — NF_INET_LOCAL_OUT hook point.
//
// Fires on locally originated packets. Looks up the conntrack entry via
// kfunc and stores the NAT mapping in our nat_mappings map.
//
// This replaces fentry/nf_conntrack_confirm when available.
// ============================================================================

SEC("netfilter")
int tollwing_conntrack_kfunc(struct bpf_nf_ctx *ctx)
{
	struct agent_config *cfg;
	__u32 key = 0;
	cfg = bpf_map_lookup_elem(&agent_config, &key);
	if (!cfg || !cfg->enabled)
		return NF_ACCEPT;

	struct sk_buff *skb = ctx->skb;
	if (!skb)
		return NF_ACCEPT;

	// Only process IPv4.
	__u16 protocol = BPF_CORE_READ(skb, protocol);
	if (protocol != bpf_htons(0x0800)) // ETH_P_IP
		return NF_ACCEPT;

	// Parse IP header for basic 4-tuple.
	unsigned char *head = BPF_CORE_READ(skb, head);
	__u16 net_hdr_off = BPF_CORE_READ(skb, network_header);
	if (!head)
		return NF_ACCEPT;

	struct iphdr iph;
	if (bpf_probe_read_kernel(&iph, sizeof(iph), head + net_hdr_off) < 0)
		return NF_ACCEPT;

	if (iph.protocol != IPPROTO_TCP)
		return NF_ACCEPT;

	// Parse TCP header for ports.
	__u16 trans_hdr_off = BPF_CORE_READ(skb, transport_header);
	struct tcphdr th;
	if (bpf_probe_read_kernel(&th, sizeof(th), head + trans_hdr_off) < 0)
		return NF_ACCEPT;

	__u32 src_ip = iph.saddr;
	__u32 dst_ip __attribute__((unused)) = iph.daddr;
	__u16 src_port = bpf_ntohs(th.source);
	__u16 dst_port = bpf_ntohs(th.dest);

	// Check if there's already a NAT mapping for this flow.
	__u64 hash_key = ((__u64)src_ip << 32) |
			 ((__u64)src_port << 16) |
			 (__u64)dst_port;

	struct nat_mapping *existing = bpf_map_lookup_elem(&nat_mappings, &hash_key);
	if (existing) {
		// Already have a mapping, update timestamp.
		existing->timestamp_ns = bpf_ktime_get_ns();
		return NF_ACCEPT;
	}

	// Try conntrack lookup via the skb's existing nfct pointer.
	// The skb->_nfct field is set by conntrack before we see it.
	unsigned long nfct_val = BPF_CORE_READ(skb, _nfct);
	if (!nfct_val)
		return NF_ACCEPT;

	struct nf_conn *ct = (struct nf_conn *)(nfct_val & ~7UL);
	if (!ct)
		return NF_ACCEPT;

	// Read original and reply tuples.
	struct nf_conntrack_tuple orig, reply;
	bpf_probe_read_kernel(&orig, sizeof(orig), &ct->tuplehash[0].tuple);
	bpf_probe_read_kernel(&reply, sizeof(reply), &ct->tuplehash[1].tuple);

	if (orig.src.l3num != AF_INET)
		return NF_ACCEPT;

	__u32 orig_dst_ip    = orig.dst.u3.ip;
	__u16 orig_dst_port  = bpf_ntohs(orig.dst.u.tcp.port);
	__u32 reply_src_ip   = reply.src.u3.ip;
	__u16 reply_src_port = bpf_ntohs(reply.src.u.tcp.port);

	// If original destination == reply source, no NAT occurred.
	if (orig_dst_ip == reply_src_ip && orig_dst_port == reply_src_port)
		return NF_ACCEPT;

	// Store NAT mapping.
	struct nat_mapping mapping = {};
	mapping.pre_dnat_ip    = orig_dst_ip;
	mapping.pre_dnat_port  = orig_dst_port;
	mapping.post_dnat_ip   = reply_src_ip;
	mapping.post_dnat_port = reply_src_port;
	mapping.timestamp_ns   = bpf_ktime_get_ns();

	bpf_map_update_elem(&nat_mappings, &hash_key, &mapping, BPF_ANY);

	return NF_ACCEPT;
}

// LICENSE defined in tollwing.bpf.c
