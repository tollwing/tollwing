// Package enricher provides flow data enrichment utilities.
package enricher

import (
	"encoding/binary"
	"net/netip"
)

// KnownSidecarProxies lists process names that are known sidecar proxies.
var KnownSidecarProxies = map[string]bool{
	"envoy":          true,
	"linkerd-proxy":  true,
	"linkerd2-proxy": true,
	"istio-proxy":    true,
}

// KnownSidecarPorts lists ports used by sidecar proxies.
var KnownSidecarPorts = map[uint16]string{
	15001: "envoy-outbound",
	15006: "envoy-inbound",
	15090: "envoy-stats",
	15021: "envoy-health",
	4143:  "linkerd-outbound",
	4191:  "linkerd-admin",
}

// IsSidecarPort checks if a port is a known sidecar proxy port.
func IsSidecarPort(port uint16) bool {
	_, ok := KnownSidecarPorts[port]
	return ok
}

// IsLoopback reports whether both endpoints are loopback (127/8) — the
// sidecar-internal / same-host case. srcIP and dstIP are BPF IP fields:
// network-order bytes decoded native-endian, recovered the same way as
// pkg/ebpf.AddrFromU32 (duplicated because pkg/enricher is cross-platform and
// cannot import the linux-only pkg/ebpf). The previous version compared the raw
// uint32 against the big-endian constant 0x7f000001, which never matched the
// native-endian-loaded value on little-endian hosts — see DEC-009.
func IsLoopback(srcIP, dstIP uint32) bool {
	return addrFromU32(srcIP).IsLoopback() && addrFromU32(dstIP).IsLoopback()
}

// addrFromU32 mirrors pkg/ebpf.AddrFromU32; see DEC-009.
func addrFromU32(v uint32) netip.Addr {
	var b [4]byte
	binary.NativeEndian.PutUint32(b[:], v)
	return netip.AddrFrom4(b)
}
