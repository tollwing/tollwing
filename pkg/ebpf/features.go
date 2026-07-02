//go:build linux

package ebpf

import (
	"errors"
	"fmt"
	"sync"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/link"
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
		probeSkStorage(),
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

// Per DEC-016, HaveCgroupStorageMap was removed with the CGRP_STORAGE
// subsystem. It also probed the wrong map type: ebpf.CGroupStorage is
// BPF_MAP_TYPE_CGROUP_STORAGE (type 19, kernel 4.19), not
// BPF_MAP_TYPE_CGRP_STORAGE (type 32, kernel 6.3).

// HaveSkStorage probes for BPF_MAP_TYPE_SK_STORAGE.
func HaveSkStorage() bool {
	return features.HaveMapType(ebpf.MapType(24)) == nil // SK_STORAGE = 24
}

func probeSkStorage() ProbeResult {
	err := features.HaveMapType(ebpf.MapType(24))
	return ProbeResult{Name: "sk_storage", Supported: err == nil, Err: err}
}

// HaveTCX reports whether the kernel supports TCX link attachment (6.6+).
//
// Probing SchedCLS alone is NOT evidence of TCX: that program type exists
// since kernel 4.1, so the old probe reported "TCX supported" everywhere and
// the QUIC attach then failed at runtime on <6.6 kernels. Instead, attempt a
// real TCX link create against an interface index that cannot exist: a
// TCX-capable kernel parses the link type and fails looking up the device
// (ENODEV), while a pre-6.6 kernel rejects the link/attach type itself.
func HaveTCX() bool {
	return haveTCX()
}

var haveTCX = sync.OnceValue(func() bool {
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type:    ebpf.SchedCLS,
		License: "MIT",
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
	})
	if err != nil {
		return false
	}
	defer prog.Close()

	lnk, err := link.AttachTCX(link.TCXOptions{
		Program:   prog,
		Attach:    ebpf.AttachTCXEgress,
		Interface: int(^uint32(0)), // deliberately nonexistent ifindex
	})
	if err == nil {
		// Cannot happen with a bogus ifindex; be safe anyway.
		lnk.Close()
		return true
	}
	return errors.Is(err, syscall.ENODEV)
})

func probeTCX() ProbeResult {
	supported := HaveTCX()
	var err error
	if !supported {
		err = errors.New("TCX link create not supported")
	}
	return ProbeResult{Name: "tcx link (6.6+)", Supported: supported, Err: err}
}
