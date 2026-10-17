<p align="center">
  <img src="assets/lkmhunter_header.png"
       alt="LKMHunter - Linux Kernel Rootkit Research"
       width="100%">
</p>

# LKMHunter

LKMHunter is a Python library and companion CLI for hunting rogue Linux kernel
modules. Kernel memory access, symbol resolution, KASLR relocation, baseline
images, and structure layouts live in one shared session. Scanners return
structured evidence instead of printing from library code.

The current kernel scanners target little-endian Linux x86-64:

- **Syscalls:** compare the live syscall table with a matching local kernel image.
- **Ftrace:** identify groups of functions sharing module-space dispatchers.
- **Module recovery:** find the module structure owning an address, including
  structures with erased names, then optionally dump its memory regions.

## Install

Requires Python 3.10 or newer:

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[test]'
```

Install `bpftool` for automatic live BTF layout discovery. A kernel image with
DWARF is an alternative; a full debug-symbol package is not required when usable
live BTF is present. Access to live memory usually requires root.

## Commands

```bash
sudo .venv/bin/lkmhunter scan syscalls
sudo .venv/bin/lkmhunter scan ftrace --min-group 3
sudo .venv/bin/lkmhunter module find 0xffffffffc0123456
sudo .venv/bin/lkmhunter module dump 0xffffffffc0123456 --out-dir dumps
```

Common options work before or after the subcommand:

```bash
sudo .venv/bin/lkmhunter scan syscalls --backend kcore \
  --vmlinux /path/to/vmlinux --system-map /path/to/System.map
sudo .venv/bin/lkmhunter scan ftrace --tracefs /sys/kernel/tracing --json
sudo .venv/bin/lkmhunter module find 0xffffffffc0123456 \
  --backend lkm_mem --max-back 32M --direction both --debug
```

`--backend auto` (default) opens `/proc/lkm/mem` when accessible, otherwise
`/proc/kcore`. The chosen backend is reported and remains fixed for the session.
An error or filtered read never silently switches sources. `--kcore`,
`--lkm-mem`, and `--kallsyms` override live paths.

Exit codes are **0** for a completed scan without suspicious findings, **1** for
a completed scan with suspicious findings, and **2** for a failed, unavailable,
or incomplete operation. JSON includes `status`, `findings`, `diagnostics`, and
`coverage`; partial results can still contain useful findings.

A successful module lookup reports an owner; finding a normal module is not
itself suspicious. A bounded search without an owner does not establish absence.
Dumping is explicit, refuses to overwrite files, and records zero-filled
unreadable ranges in its JSON manifest. A dump with gaps exits with code 2.

## Python API

```python
from lkmhunter import KernelSession, SyscallScanner, FtraceScanner, ModuleScanner

with KernelSession.open() as session:
    syscalls = SyscallScanner().scan(session)
    ftrace = FtraceScanner(min_group=3).scan(session)
    print(syscalls.to_dict())

    # An address from a finding can be investigated in the same session.
    owner = ModuleScanner().scan(session, address=0xffffffffc0123456)
```

`session.memory.read(address, size)` accepts runtime virtual addresses and
returns exactly the requested bytes or raises `MemoryReadError`. Scanners do not
translate ELF offsets, open devices, or calculate relocation themselves.
`dump_module(session, owner.findings[0], "dumps")` is a separate operation.
Library imports and session creation have no live-kernel side effects. Resources
are opened lazily and closed when the session exits; ftrace needs neither a
baseline nor memory access.

### Resource discovery

- Baselines are discovered in standard local debug/boot/module locations for
  the running release. If needed, an installed `extract-vmlinux` script extracts
  the local boot image into temporary storage. No downloads or module loading
  happen automatically.
- GNU build IDs, when available, must match. Kernel banners, baseline map
  anchors, and consistent KASLR anchors provide additional validation. Supply
  `--kernel-release` and `--live-notes` when analyzing alternate target files.
- Syscall count comes from ELF symbol size, BTF array metadata, or DWARF. If
  unavailable, `--syscall-count N` is required. Symbol names are used when
  available; numeric identifiers remain usable without syscall name tables.
  A baseline is required: an address-range heuristic does not replace comparison.
- Module layouts come from live BTF, then matching local DWARF. Both split
  `mem[]` and older core/init layouts are supported. Unsupported layouts are
  reported rather than replaced with hard-coded offsets.
- An explicit `--layout FILE.json` overrides discovery. The format is the JSON
  returned by `session.module_layout.to_dict()`; callers are responsible for
  supplying a layout for the correct kernel. Fields use byte offsets and sizes.
- Tracefs is discovered under `/sys/kernel/tracing` and
  `/sys/kernel/debug/tracing`. Unknown input lines mark the scan partial.

BTF describes types, not runtime addresses or trusted expected memory contents.
Restricted kallsyms and missing baselines can still limit individual techniques.
Ftrace grouping is a heuristic: legitimate instrumentation may also share a
callback. Live observations can race, and an infected kernel can manipulate
inputs and output; these tools report evidence, not proof of a clean system.

## Memory helper

The optional helper preserves the existing transfer ioctl ABI. Its read path
uses inline exception-protected loads, avoiding the named
`copy_from_kernel_nofault` function. Sparse module searches require the new
fault-contained-read capability; rebuild and reload older helpers first.

Build and load **inside the disposable test VM**:

```bash
make -C /lib/modules/$(uname -r)/build M="$PWD/modules/src" obj-m=lkm_mem.o modules
sudo insmod modules/src/lkm_mem.ko
```

The hunting API uses the helper read-only. The legacy `lkm_mem.LkmMem` adapter
retains explicit writes for existing experiments; arbitrary writes remain
unsafe. See [testbed/README.md](testbed/README.md) for the QEMU environment.

## Compatibility and other tools

`compare_syscalls.py`, `ftrace_hunt.py`, and `find_module.py` are import-safe CLI
wrappers. Old image/map arguments, `--path`, search controls, and `--out-dir`
remain accepted. `find_module.py` retains recovery followed by dumping. Their
results and exit codes follow the shared CLI. Install dependencies into the
Python environment used to invoke them.

The old prototype Python APIs (`kernel.py`, `syscalls.py`, and their unused
helpers) have been replaced by `lkmhunter`. `debugfs_hunt.py` and the `/sys` versus
`lsmod` shell orchestration remain separate in this migration. The filesystem
scanner's existing tests and output-filter bypass are preserved.

## Tests

```bash
.venv/bin/python -m pytest -q
# Inside a disposable VM, after installing the package and loading the helper:
python3 -m pytest -q --live-kernel
```

Default tests need no root or live kernel resources. They cover transport
selection, ELF boundaries and short reads, relocation, metadata extraction,
scanner evidence, CLI compatibility, and dump gaps. Compiler-based DWARF tests
skip when no C compiler is installed. The explicit integration test reads live
metadata and checks helper fault handling; it never loads rootkits or modules.

Recorded testbed results: [testbed/VALIDATION.md](testbed/VALIDATION.md).
