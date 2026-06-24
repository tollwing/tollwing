# Third-party licenses

Tollwing itself is licensed under Apache-2.0 (see [`LICENSE`](LICENSE)). It
vendors a small number of third-party files required to compile the eBPF data
plane. Those files retain their own licenses, listed below.

---

## libbpf headers — `include/bpf/*.h`

`bpf_core_read.h`, `bpf_endian.h`, `bpf_helper_defs.h`, `bpf_helpers.h`,
`bpf_tracing.h`

These are unmodified headers from the [libbpf](https://github.com/libbpf/libbpf)
project (and originally the Linux kernel's `tools/lib/bpf`). They carry the SPDX
identifier `(LGPL-2.1 OR BSD-2-Clause)`. Tollwing uses them under the
**BSD-2-Clause** option, reproduced below. (`bpf_helper_defs.h` is a
machine-generated libbpf file under the same terms.)

```
Copyright (c) the libbpf Authors and contributors. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

---

## Kernel BTF type definitions — `vmlinux/x86.h`, `vmlinux/arm.h`

These are machine-generated C type declarations (struct/enum/typedef
definitions) produced from the Linux kernel's BTF debug information, e.g.:

```
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux/x86.h
```

They are derived from the Linux kernel, which is licensed
**GPL-2.0-only WITH Linux-syscall-note**. They contain only generated type
declarations (no kernel code) and are included so the BPF objects can be
compiled CO-RE without a kernel-headers checkout. To regenerate them from a
running kernel rather than using the vendored copies, run the command above.

See <https://www.kernel.org/doc/html/latest/process/license-rules.html>.
