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

The syscall scanner checks both table pointers and decoded direct calls/jumps
to `__x64_sys_*` handlers inside `x64_sys_call`, when that dispatcher exists.
Changed transfers report their instruction address and expected/actual targets.
Dispatcher coverage is reported separately; unreadable code, missing symbol
sizes, or unsupported decoding produce a partial result. This checks direct
handler transfers, not all possible inline hooks. Other text changes from
kernel alternatives and tracing are outside this comparison.

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

## Copy baseline bytes to live memory

`copy LIVE_ADDRESS SIZE` writes through `/proc/lkm/mem` and verifies readback.
The source is the corresponding virtual address in matching `vmlinux`, computed
by subtracting the detected KASLR slide. The address is hexadecimal; sizes accept
decimal, `0x` notation, and K/M/G suffixes.

```bash
# Example from the Diamorphine testbed: restore one five-byte call instruction.
# Use the current scanner's site address, not an address from another boot.
sudo .venv/bin/lkmhunter copy 0xffffffff81350292 5 \
  --backup /var/tmp/call-before-copy.json
```

`--vmlinux /path/to/vmlinux`, `--lkm-mem /proc/lkm/mem`, and `--json` are
supported. Optional `--backup` creates a new private JSON file containing the
previous bytes and replacement bytes before starting writes; existing files
are never overwritten. This is a raw live write with no confirmation prompt or
CPU synchronization. A failure can leave memory partially modified.

The payload is copied verbatim: embedded absolute pointers are **not relocated**.
Use instruction ranges verified against the baseline. Copying whole functions
can overwrite legitimate runtime alternatives or tracing patches. Repairing
instructions does not unload a module or undo its other changes.

## Local GDB inspection

See the [GDB hunting walkthrough](docs/gdb-hunting.md) for syscall-pointer
investigation with Diamorphine and a recorded KoviD ftrace example, including
owner recovery, disassembly, and evidence export.

Run GDB **on the machine being inspected**. No SSH, TCP listener, QEMU debug
stub, or separate debugger machine is required:

```bash
sudo .venv/bin/lkmhunter gdb --backend lkm_mem --symbols kallsyms
```

The launcher starts local GDB and a local adapter connected through a subprocess
pipe. The adapter reads `/proc/lkm/mem` through the same `KernelSession` memory
interface as the scanners. GDB calls this a remote-protocol target internally;
both processes run locally. Install `gdb` and load the updated helper first.
`--backend auto` can also select kcore when the helper is unavailable.

Runtime symbols from `/proc/kallsyms` are converted into a temporary symbol-only
ELF, so these commands need no vmlinux:

```gdb
x/8gx &sys_call_table
x/10i _stext
info address sys_call_table
info symbol 0xffffffff81000000
```

Only nonzero kernel virtual addresses are imported. Visible module symbols are
qualified as `module__symbol` to avoid collisions with core names. Kallsyms
provides names and runtime addresses, not C types. Hidden symbols remain absent.

For typed expressions, use a matching vmlinux with DWARF:

```bash
sudo .venv/bin/lkmhunter gdb --backend lkm_mem \
  --vmlinux /usr/lib/debug/boot/vmlinux-$(uname -r)
```

```gdb
p init_task.pid
p init_task.comm
```

The default `--symbols auto` discovers a usable local vmlinux and validates and
relocates its symbols with the session's KASLR calculation. Otherwise it uses
kallsyms. Explicit `--symbols vmlinux`, `--symbols kallsyms`, and `--symbols none`
select a source or raw-address-only inspection. Invalid explicitly supplied
images are reported rather than silently replaced.

This is a **read-only live memory view**. The kernel keeps running. Writes,
breakpoints, stepping, and execution-control packets are rejected. Registers are
unavailable except `$pc`, which is an explicitly synthetic inspection address
anchored at `_stext` (or another available address), not a CPU's program counter.
Backtraces do not represent actual kernel execution, and reads are not atomic
snapshots. Code and stack caching are disabled in the generated session.

A reusable local session can be exported:

```bash
sudo .venv/bin/lkmhunter gdb --backend lkm_mem --symbols kallsyms \
  --export /var/tmp/lkmhunter-gdb
sudo gdb -nx -q -x /var/tmp/lkmhunter-gdb/session.gdb
```

Choose a fresh export directory; exports are private and are not overwritten.
Regenerate exported sessions after a reboot or KASLR change. `--batch` and
repeatable `--command 'GDB COMMAND'` options support scripted read-only checks.
GDB may warn that no executable was specified: the session loads symbols only.
Automatic debugger scripts and shared-library symbol loading are disabled.

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

The hunting API uses the helper read-only. `lkmhunter.memory.LkmWriter`
provides explicit writes for experiments; arbitrary writes remain
unsafe. See [testbed/README.md](testbed/README.md) for the QEMU environment.

## Other tools

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
scanner evidence, CLI behavior, and dump gaps. Compiler-based DWARF tests
skip when no C compiler is installed. The explicit integration test reads live
metadata and checks helper fault handling; it never loads rootkits or modules.

Recorded testbed results: [testbed/VALIDATION.md](testbed/VALIDATION.md).
