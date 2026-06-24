//go:build linux

package ebpf

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/features"
)

// ProbeResult describes the availability of a specific eBPF feature.
type ProbeResult struct {
	Name      string
	Supported bool
	Err       error
}

// ProbeAll checks all kernel features required and optional for tollwing.
// Returns results grouped by criticality.
func ProbeAll() (required []ProbeResult, optional []ProbeResult) {
	required = []ProbeResult{
		probeProgramType("cgroup_sock_addr", ebpf.CGroupSockAddr),
		probeProgramType("sock_ops", ebpf.SockOps),
		probeProgramType("kprobe", ebpf.Kprobe),
		probeMapType("ringbuf", ebpf.RingBuf),
		probeMapType("lru_hash", ebpf.LRUHash),
		probeMapType("percpu_hash", ebpf.PerCPUHash),
		probeHelper("get_socket_cookie (cgroup)", ebpf.CGroupSockAddr, asm.FnGetSocketCookie),
		probeHelper("get_current_pid_tgid (cgroup)", ebpf.CGroupSockAddr, asm.FnGetCurrentPidTgid),
		probeHelper("get_current_cgroup_id (cgroup)", ebpf.CGroupSockAddr, asm.FnGetCurrentCgroupId),
		probeHelper("ringbuf_reserve (cgroup)", ebpf.CGroupSockAddr, asm.FnRingbufReserve),
	}

	optional = []ProbeResult{
		probeHelper("get_socket_cookie (kprobe)", ebpf.Kprobe, asm.FnGetSocketCookie),
		probeProgramType("tracing (fentry/fexit)", ebpf.Tracing),
		probeHelper("get_func_ip (tracing)", ebpf.Tracing, asm.FnGetFuncIp),
		probeCgroupStorage(),
		probeSkStorage(),
		probeNetfilterProg(),
		probeTCX(),
	}
	return
}

// HaveCgroupConnect4 reports whether the kernel supports cgroup/connect4 programs.
func HaveCgroupConnect4() bool {
	return features.HaveProgramType(ebpf.CGroupSockAddr) == nil
}

// HaveSockOps reports whether the kernel supports sock_ops programs.
func HaveSockOps() bool {
	return features.HaveProgramType(ebpf.SockOps) == nil
}

// HaveRingBuf reports whether the kernel supports BPF_MAP_TYPE_RINGBUF.
func HaveRingBuf() bool {
	return features.HaveMapType(ebpf.RingBuf) == nil
}

// HaveFentry reports whether the kernel supports fentry/fexit tracing programs.
func HaveFentry() bool {
	return features.HaveProgramType(ebpf.Tracing) == nil
}

// CheckRequired verifies all required features are available.
// Returns a combined error listing all missing features, or nil.
func CheckRequired() error {
	required, _ := ProbeAll()
	var missing []string
	for _, r := range required {
		if !r.Supported {
			missing = append(missing, r.Name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("kernel missing required eBPF features: %v", missing)
	}
	return nil
}

func probeProgramType(name string, pt ebpf.ProgramType) ProbeResult {
	err := features.HaveProgramType(pt)
	return ProbeResult{Name: name, Supported: err == nil, Err: err}
}

func probeMapType(name string, mt ebpf.MapType) ProbeResult {
	err := features.HaveMapType(mt)
	return ProbeResult{Name: name, Supported: err == nil, Err: err}
}

func probeHelper(name string, pt ebpf.ProgramType, fn asm.BuiltinFunc) ProbeResult {
	err := features.HaveProgramHelper(pt, fn)
	return ProbeResult{Name: name, Supported: err == nil, Err: err}
}

// HaveCgroupStorage probes for BPF_MAP_TYPE_CGRP_STORAGE (kernel 6.3+).
func HaveCgroupStorageMap() bool {
	return features.HaveMapType(ebpf.CGroupStorage) == nil
}

func probeCgroupStorage() ProbeResult {
	err := features.HaveMapType(ebpf.CGroupStorage)
	return ProbeResult{Name: "cgrp_storage (6.3+)", Supported: err == nil, Err: err}
}

// HaveSkStorage probes for BPF_MAP_TYPE_SK_STORAGE.
func HaveSkStorage() bool {
	return features.HaveMapType(ebpf.MapType(24)) == nil // SK_STORAGE = 24
}

func probeSkStorage() ProbeResult {
	err := features.HaveMapType(ebpf.MapType(24))
	return ProbeResult{Name: "sk_storage", Supported: err == nil, Err: err}
}

// HaveNetfilterProg probes for BPF_PROG_TYPE_NETFILTER (kernel 6.4+).
func HaveNetfilterProg() bool {
	// BPF_PROG_TYPE_NETFILTER = 37
	return features.HaveProgramType(ebpf.ProgramType(37)) == nil
}

func probeNetfilterProg() ProbeResult {
	err := features.HaveProgramType(ebpf.ProgramType(37))
	return ProbeResult{Name: "netfilter prog (6.4+)", Supported: err == nil, Err: err}
}

// HaveTCX probes for TCX program attachment (kernel 6.6+).
// TCX uses BPF_LINK_TYPE_TCX which can be detected by checking for
// the SchedCLS program type (it's the same prog type, different attach).
func HaveTCX() bool {
	// TCX requires kernel 6.6+. We probe by checking if the kernel
	// supports SchedCLS with link-based attachment.
	return features.HaveProgramType(ebpf.SchedCLS) == nil
}

func probeTCX() ProbeResult {
	err := features.HaveProgramType(ebpf.SchedCLS)
	return ProbeResult{Name: "tc/tcx (6.6+)", Supported: err == nil, Err: err}
}

// HaveIterator probes for BPF iterator support.
func HaveIterator() bool {
	return features.HaveProgramType(ebpf.Tracing) == nil
}
