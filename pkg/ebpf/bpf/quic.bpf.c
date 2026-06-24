// quic.bpf.c — TC egress program for QUIC/HTTP3 flow tracking.
//
// Parses UDP packets on TC egress for QUIC headers:
//   - Long header: first byte & 0xC0 == 0xC0, version in bytes 1-4
//   - Short header: first byte & 0x40 == 0x40
//
// Tracks QUIC flows by 4-tuple (src IP, dst IP, src port, dst port).
// Connection IDs are NOT used for tracking since they rotate.
//
// Accumulates bytes per flow in the quic_flows PERCPU_HASH map.
//
// Attachment: TCX (kernel 6.6+) or legacy tc filter (fallback).

// Included from tollwing.bpf.c — do not compile standalone.
// vmlinux.h, bpf helpers, and maps.h are already included.

#ifndef TC_ACT_OK
#define TC_ACT_OK 0
#endif

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

#ifndef ETH_P_IPV6
#define ETH_P_IPV6 0x86DD
#endif

// QUIC version constants.
#define QUIC_VERSION_1     0x00000001  // QUICv1 (RFC 9000)
#define QUIC_VERSION_2     0x6b3343cf  // QUICv2 (RFC 9369)
#define QUIC_VERSION_DRAFT 0xff000000  // Draft versions (mask for top byte 0xff)

// QUIC header detection masks.
#define QUIC_LONG_HEADER_MASK  0xC0
#define QUIC_SHORT_HEADER_MASK 0x40
#define QUIC_FIXED_BIT         0x40

// Fixed header sizes for verifier-friendly bounds checks.
#define ETH_HLEN       14
#define IP_MIN_HLEN    20
#define IP6_HLEN       40
#define UDP_HLEN       8

// ============================================================================
// Helper: check if a UDP payload looks like QUIC.
// Returns 1 for long header, 2 for short header, 0 for non-QUIC.
// ============================================================================

static __always_inline int detect_quic(__u8 first_byte)
{
	if (!(first_byte & QUIC_FIXED_BIT))
		return 0;

	if ((first_byte & QUIC_LONG_HEADER_MASK) == QUIC_LONG_HEADER_MASK)
		return 1; // long header

	if ((first_byte & QUIC_SHORT_HEADER_MASK) == QUIC_SHORT_HEADER_MASK)
		return 2; // short header

	return 0;
}

// ============================================================================
// SEC("tc") — TC egress classifier for QUIC packet detection.
//
// Parses: Ethernet → IPv4 → UDP → QUIC header.
// Accumulates bytes per QUIC 4-tuple in quic_flows map.
//
// Returns TC_ACT_OK (pass-through, never drops packets).
// ============================================================================

SEC("tc")
int tollwing_quic_egress(struct __sk_buff *skb)
{
	void *data     = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	// ---- Bounds check: need at least ETH + IP(min) + UDP + 1 byte QUIC ----
	if (data + ETH_HLEN + IP_MIN_HLEN + UDP_HLEN + 1 > data_end)
		return TC_ACT_OK;

	// ---- Parse Ethernet header ----
	__u16 eth_proto = *(__u16 *)(data + 12); // h_proto at offset 12

	__u32 saddr = 0, daddr = 0;
	__u16 udp_offset;

	if (eth_proto == bpf_htons(ETH_P_IP)) {
		// ---- Parse IPv4 header ----
		__u8 *ip_start = data + ETH_HLEN;
		__u8 ver_ihl = *ip_start;
		__u8 ihl = ver_ihl & 0x0F;
		if (ihl < 5 || ihl > 15)
			return TC_ACT_OK;

		__u8 protocol = *(ip_start + 9);
		if (protocol != IPPROTO_UDP)
			return TC_ACT_OK;

		__u16 ip_hdr_len = (__u16)ihl << 2;
		udp_offset = ETH_HLEN + ip_hdr_len;
		if (data + udp_offset + UDP_HLEN + 1 > data_end)
			return TC_ACT_OK;

		saddr = *(__u32 *)(ip_start + 12);
		daddr = *(__u32 *)(ip_start + 16);
	} else if (eth_proto == bpf_htons(ETH_P_IPV6)) {
		// ---- Parse IPv6 header (fixed 40 bytes) ----
		if (data + ETH_HLEN + IP6_HLEN + UDP_HLEN + 1 > data_end)
			return TC_ACT_OK;

		__u8 *ip6_start = data + ETH_HLEN;
		__u8 next_header = *(ip6_start + 6);
		if (next_header != IPPROTO_UDP)
			return TC_ACT_OK;

		// IPv6 addresses are truncated to the first 4 bytes for the flow
		// key. This is a known limitation: IPv6 addresses sharing the
		// same /32 prefix will collide. Full IPv6 tracking would require
		// a larger key struct (32 bytes per address) which significantly
		// increases per-CPU memory usage in the PERCPU_HASH map. IPv6
		// QUIC flows are rare in Kubernetes; this trade-off is acceptable
		// for now. When full IPv6 is needed, extend quic_flow_key to
		// include struct in6_addr for both src and dst.
		saddr = *(__u32 *)(ip6_start + 8);  // src_addr[0:4]
		daddr = *(__u32 *)(ip6_start + 24); // dst_addr[0:4]
		udp_offset = ETH_HLEN + IP6_HLEN;
	} else {
		return TC_ACT_OK;
	}

	// ---- Parse UDP header ----
	if (data + udp_offset + UDP_HLEN + 1 > data_end)
		return TC_ACT_OK;
	__u8 *udp_start = data + udp_offset;
	__u16 src_port = bpf_ntohs(*(__u16 *)(udp_start));
	__u16 dst_port = bpf_ntohs(*(__u16 *)(udp_start + 2));
	__u16 udp_len  = bpf_ntohs(*(__u16 *)(udp_start + 4));

	if (udp_len < UDP_HLEN + 1) // need at least 1 byte of QUIC payload
		return TC_ACT_OK;

	// ---- Check QUIC first byte ----
	__u8 *quic_start = udp_start + UDP_HLEN;
	// Already bounds-checked above (data + udp_offset + UDP_HLEN + 1 <= data_end).
	__u8 first_byte = *quic_start;
	int header_type = detect_quic(first_byte);
	if (header_type == 0)
		return TC_ACT_OK;

	// ---- Extract QUIC version (long header only, bytes 1-4) ----
	__u32 quic_version = 0;
	if (header_type == 1) {
		// Need 5 more bytes from QUIC start (1 byte header + 4 bytes version).
		if ((void *)(quic_start + 5) > data_end)
			return TC_ACT_OK;
		quic_version = ((__u32)quic_start[1] << 24) |
		               ((__u32)quic_start[2] << 16) |
		               ((__u32)quic_start[3] << 8)  |
		               (__u32)quic_start[4];
		if (quic_version != QUIC_VERSION_1 &&
		    quic_version != QUIC_VERSION_2 &&
		    (quic_version & 0xff000000) != QUIC_VERSION_DRAFT) {
			quic_version = 0;
		}
	}

	// ---- Track by 4-tuple ----
	struct quic_flow_key key = {};
	key.src_ip   = saddr;
	key.dst_ip   = daddr;
	key.src_port = src_port;
	key.dst_port = dst_port;

	__u64 pkt_bytes = (__u64)(data_end - data);
	__u64 now = bpf_ktime_get_ns();

	struct quic_flow_metrics *val = bpf_map_lookup_elem(&quic_flows, &key);
	if (val) {
		__sync_fetch_and_add(&val->tx_bytes, pkt_bytes);
		__sync_fetch_and_add(&val->pkt_count, 1);
		val->last_seen_ns = now;
		if (quic_version != 0)
			val->quic_version = quic_version;
		val->is_long_header = (header_type == 1) ? 1 : 0;
	} else {
		struct quic_flow_metrics new_val = {};
		new_val.tx_bytes = pkt_bytes;
		new_val.pkt_count = 1;
		new_val.last_seen_ns = now;
		new_val.quic_version = quic_version;
		new_val.is_long_header = (header_type == 1) ? 1 : 0;
		bpf_map_update_elem(&quic_flows, &key, &new_val, BPF_NOEXIST);
	}

	return TC_ACT_OK;
}

// LICENSE defined in tollwing.bpf.c
