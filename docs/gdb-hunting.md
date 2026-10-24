# Investigating kernel hooks with local GDB

Run these commands on the inspected machine, with the updated memory helper
already loaded. Examples assume an installed checkout and x86-64 Linux.
They inspect an existing infection; they do not load or modify a rootkit.

This bridge follows live pointers and disassembles code. It cannot record calls,
stop CPUs, single-step, set breakpoints, or provide a real backtrace. `$pc` is
synthetic. The kernel keeps running, so repeat important reads and expect races.

## Start a session

Without kernel debug symbols:

```bash
sudo .venv/bin/lkmhunter gdb --backend lkm_mem --symbols kallsyms
```

For kernel structures and C types, use matching DWARF symbols:

```bash
sudo .venv/bin/lkmhunter gdb --backend lkm_mem --symbols vmlinux \
  --vmlinux /usr/lib/debug/boot/vmlinux-$(uname -r)
```

KASLR relocation is handled by the library. BTF used by the module scanner does
not by itself give GDB C types. With kallsyms, use casts, addresses, `x`, and
`info symbol`; typed examples below require DWARF.

## Diamorphine: follow a changed syscall pointer

The upstream [Diamorphine source](https://github.com/m0nad/Diamorphine/blob/master/diamorphine.c)
replaces syscall-table entries for `kill`, `getdents`, and `getdents64` on older
kernels. The supplied version instead patches direct transfers inside
`x64_sys_call` on newer x86 kernels. The syscall scanner checks both paths.
The table walkthrough below applies to table-hooking versions; on the loaded
7.3 sample the table matched and the dispatcher check found three redirects.

First compare the live table with the matching kernel baseline:

```bash
sudo .venv/bin/lkmhunter scan syscalls --backend lkm_mem
```

For `syscall_dispatch_hook` findings, use the reported `site` and `actual`
addresses directly in GDB (`x/5i SITE`, `x/24i ACTUAL`), then pass `actual` to
`module find`. If a modified instruction has no decoded direct target,
`actual` is null: inspect the recorded bytes and site instead.

Inside GDB, examine the native x86-64 slots (62, 78, 217):

```gdb
set $table = (unsigned long *)&sys_call_table
x/gx ($table + 62)
x/gx ($table + 78)
x/gx ($table + 217)
set $hook = $table[217]
p/x $hook
info symbol $hook
x/24i $hook
p/x (unsigned long)&__x64_sys_getdents64
```

On a clean matching kernel, slot 217 should agree with the expected entry
reported by the scanner. A different address is the starting point for an
investigation. A hidden module may produce `No symbol matches`; its bytes can
still be read. A nearby core symbol name is not proof of ownership either.

Copy the value printed for `$hook` into another local shell:

```bash
sudo .venv/bin/lkmhunter module find 0xREPLACE_WITH_HOOK --backend lkm_mem
sudo .venv/bin/lkmhunter module dump 0xREPLACE_WITH_HOOK \
  --backend lkm_mem --out-dir /var/tmp/suspect-module
```

Use the reported module regions to establish ownership. In the disassembly,
follow an actual call or jump destination using `info symbol ADDRESS` and
`x/20i ADDRESS`. An indirect call needs its operand resolved: inspect the
referenced memory slot, then disassemble the pointer stored there. Live CPU
register values are unavailable, so register-dependent targets cannot always
be resolved with this bridge.

## KoviD: follow an ftrace dispatcher into a hidden module

Run both scanners:

```bash
sudo .venv/bin/lkmhunter scan syscalls --backend lkm_mem
sudo .venv/bin/lkmhunter scan ftrace --json
```

In the recorded KoviD run on kernel `6.8.0-147-generic`, all 462 syscall entries
matched, but 22 functions shared dispatcher `0xffffffffc0a5be30`. Hooks included
`__x64_sys_read`, `__x64_sys_bpf`, and `vfs_statx`. These are historical addresses:
replace them with the current scan output after every reload or reboot.

In GDB:

```gdb
set $dispatcher = (unsigned long)0xffffffffc0a5be30
info symbol $dispatcher
x/40i $dispatcher
x/20i &__x64_sys_read
```

The syscall entry can remain legitimate while ftrace redirects execution.
The supplied KoviD source registers `fh_ftrace_thunk` as its callback; that
callback locates its enclosing hook object and replaces the saved instruction
pointer with the hook's replacement function. Disassembling the syscall entry
alone therefore does not establish whether it is hooked.

Recover the callback's owner in a local shell:

```bash
sudo .venv/bin/lkmhunter module find 0xffffffffc0a5be30 --backend lkm_mem
```

The recorded result recovered `kovid` at `0xffffffffc0a636c0`, with state
`UNFORMED`, despite absence from `/proc/modules` and `/sys/module`. With matching
kernel DWARF, inspect the current recovered address:

```gdb
set $mod = (struct module *)0xffffffffc0a636c0
p $mod->name
p $mod->state
p/x $mod->mkobj.mod
p/x $mod->list.next
p/x $mod->list.prev
ptype /o struct module
```

`mkobj.mod` should point back to the recovered structure. Inspect memory-region
fields according to `ptype`: kernels use different layouts, so do not copy
offsets from another release. Plausible stored list links do not establish actual
membership in the kernel's module list. The recorded recovery's hidden flag
was false despite the missing normal views; combine the evidence.

If module symbols remain visible in a **kallsyms-mode** session, try:

```gdb
info functions kovid__
info address kovid__fh_ftrace_thunk
x/40i &kovid__fh_ftrace_thunk
```

Hidden symbols may be absent entirely. Kernel vmlinux symbols do not supply
KoviD's private `struct ftrace_hook` type or its private globals. To inspect those
by name requires the exact module's debug ELF and runtime addresses for each
loaded section; loading a `.ko` at a guessed base gives misleading results.
The owner recovery and raw disassembly workflow does not require those symbols.

## Save evidence and leave

Enable logging before your inspection commands to preserve their output:

```gdb
set logging file /var/tmp/kernel-inspection.log
set logging overwrite off
set logging enabled on
```

To save a small range from the current callback (choose the size from the
recovered region bounds, and use a fresh output path):

```gdb
dump binary memory /var/tmp/dispatcher.bin $dispatcher ($dispatcher + 0x100)
set logging enabled off
detach
quit
```

These files are evidence from a running system, not a consistent kernel snapshot.
