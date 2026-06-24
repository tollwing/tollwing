// vmlinux.h — architecture-specific kernel type definitions for CO-RE.
// Generated via: bpftool btf dump file /sys/kernel/btf/vmlinux format c

#if defined(__TARGET_ARCH_x86)
#include "../../../vmlinux/x86.h"
#elif defined(__TARGET_ARCH_arm64)
#include "../../../vmlinux/arm.h"
#else
#error "Unsupported target architecture — define __TARGET_ARCH_x86 or __TARGET_ARCH_arm64"
#endif
