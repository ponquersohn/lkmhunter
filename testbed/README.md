# lkmhunter testbed

A throwaway QEMU VM for exercising the hunter against **known** LKM rootkits,
with live kernel debugging. Nothing here touches your host kernel: rootkits are
built and loaded only inside the guest, and the guest resets to a pristine image
in seconds.

## Why a VM

`lkmhunter` works by comparing live kernel state against on-disk ground truth:

- `python3 -m lkmhunter scan syscalls` diffs the **running** syscall table (read from
  `/proc/kcore`, resolved via `/proc/kallsyms`) against the table in the
  **on-disk** `vmlinux` (extracted from `/boot/vmlinuz-*`) using
  `/boot/System.map-*`.
- `find_rootkits.sh` also diffs `/sys/module/*` against `lsmod` to spot modules
  that unlinked themselves from the module list but left `/sys` traces.
- `debugfs_hunt.py` walks the raw ext4 filesystem with `debugfs` and compares it
  to what the live VFS shows.

To test any of that you need a real, resettable kernel with real symbol
addresses and a real block device — exactly what this harness provides.

## Prerequisites (host)

Already present on this machine: `qemu-system-x86_64`, `qemu-img`, KVM access,
`gdb`. You also need a seed-ISO builder:

```bash
sudo apt-get install cloud-image-utils   # provides cloud-localds
# (genisoimage or xorriso also work as fallbacks)
```

## Quick start

```bash
cd testbed
./setup.sh                       # download image, build disk + cloud-init seed  (once)
./run.sh --daemon                # boot in background; console -> console.log
./ssh.sh 'cloud-init status --wait'   # wait for first-boot provisioning (+ one reboot)
./fetch-symbols.sh               # pull vmlinux out for gdb

./rootkits/fetch.sh              # clone Diamorphine (test payload)
./inject.sh                      # build + load it in the guest, then run the hunter
```

Expected: `lsmod` shows nothing, but the hunter reports the `/sys` leftover and
the hooked `kill` / `getdents` / `getdents64` syscalls.

## Everyday commands

| Command | What it does |
|---|---|
| `./run.sh` | Boot in foreground (console attached; `Ctrl-a x` quits, `Ctrl-a c` = QEMU monitor). |
| `./run.sh --daemon` | Boot in background, console to `console.log`. |
| `./stop.sh` | Graceful ACPI shutdown (`--force` to pull the plug, `--status` to check). |
| `./run.sh --snapshot` | Ephemeral boot — disk writes discarded on shutdown. |
| `./run.sh --freeze` | Boot with CPU halted (`-S`); connect gdb and `continue` to catch early boot. |
| `./ssh.sh ['cmd']` | Shell into the guest / run a command (as `hunter`; `GUEST_USER=root ./ssh.sh` for root). |
| `./params.sh` | Show kernel hardening/visibility knobs and their guest values. |
| `./params.sh preset relaxed\|default\|hardened` | Flip the whole policy at once. |
| `./params.sh set kptr_restrict 2` | Set one knob at runtime (`--persist` to survive reboot). |
| `./inject.sh` | Build + load a rootkit, then run `find_rootkits.sh`. |
| `./inject.sh --hunt-only` | Run the hunter without loading anything (clean baseline). |
| `./inject.sh --unload` | Best-effort unload (Diamorphine: magic signal 63 + rmmod). |
| `./gdb.sh` | Attach host gdb to the guest kernel with symbols. |
| `./reset.sh` | Roll the guest back to a pristine, clean-kernel image (VM must be off). |

## Remote kernel debugging

QEMU exposes a gdb stub on `localhost:$GDB_PORT` (default 1234). With the guest
running and `./fetch-symbols.sh` done:

```bash
./gdb.sh
(gdb) p &sys_call_table           # base of the live syscall table
(gdb) x/8a &sys_call_table        # first entries — compare to the on-disk vmlinux
(gdb) b __x64_sys_kill            # Diamorphine hooks kill(); break where it lands
(gdb) continue
```

Because the overlay disk and the symbol file come from the same kernel build,
addresses line up between gdb, `/proc/kallsyms`, and the hunter's analysis. This
is the ground truth you check the detector's findings against.

To debug the hunter's Python itself, it runs in the guest over the 9p share, so
you can `./ssh.sh` in and `python3 -m pdb -m lkmhunter scan syscalls ...` directly.

## How the pieces fit

```
host  testbed/            run.sh ── QEMU ──┐
      ├── (this repo) ────9p share────────►│  /opt/lkmhunter  (live, your edits)
      ├── rootkits/src/ ──(same share)─────│  built + insmod'd here
      ├── symbols/vmlinux ◄── fetch-symbols │  dbgsym from guest
      └── gdb.sh ──────────tcp:1234────────►│  QEMU gdb stub (kernel)
                           tcp:2222 ssh ───►│  :22
```

## Resetting between tests

A loaded rootkit may hide itself and resist `rmmod`, so don't trust in-guest
cleanup for a known-clean kernel. Either:

- `./run.sh --snapshot` for a test whose disk changes you want thrown away, or
- shut down and `./reset.sh` to recreate the overlay from the base image
  (cloud-init re-provisions on next boot).

For a faster reset that skips re-provisioning, take a QEMU internal snapshot of
the provisioned state once and restore it:

```bash
./ssh.sh 'sudo cloud-init status --wait'
echo 'savevm clean' | socat - unix:images/monitor.sock   # name a snapshot 'clean'
# later, from the monitor:  loadvm clean
```

## Tuning the target's policy

`./params.sh` flips the kernel knobs that change what a detector can see, so you
can confirm the hunter copes with a real hardened host, not just a loose one:

```bash
./params.sh                    # table of current values + boot-time state
./params.sh preset hardened    # kptr_restrict=2, ptrace_scope=3, ...
./inject.sh                    # ...then see if the hunter still finds the hook
./params.sh preset default     # back to stock Ubuntu
```

Runtime knobs apply immediately via `sysctl -w` (add `--persist` for a drop-in).
Boot-time settings (KASLR, lockdown) are shown read-only — change those via the
grub cmdline + reboot. Two knobs are one-way (`kexec_load_disabled`,
`modules_disabled`) and refuse to flip on without `--force`; `modules_disabled=1`
in particular breaks `insmod`, so `./reset.sh` afterward.

## Running as root vs sudo

The guest has a `hunter` user with passwordless sudo; root is key-login enabled
(`GUEST_USER=root ./ssh.sh`). There's no privilege difference — `sudo cmd` runs
as uid 0 just like a root shell does. The default path uses `hunter` + sudo
because that mirrors how `find_rootkits.sh` is invoked on a real host.

## Adding your own test rootkits

Edit `rootkits/fetch.sh` and add `name -> git-url` to the `ROOTKITS` map, then
`./inject.sh --rootkit name`. Anything with a standard kbuild `Makefile`
(`make` against `/lib/modules/$(uname -r)/build`) works unchanged.

## Safety

The rootkit sources are public, well-known detector-test payloads. They are only
ever compiled and loaded inside this disposable VM, which has no access to your
host beyond the shared repo directory. Never build or load them on a machine you
care about.

## Detecting files hidden by Singularity

The debugfs hunter can bypass this checkout's Singularity output filter:

```bash
./ssh.sh 'python3 /opt/lkmhunter/debugfs_hunt.py /dev/vda1 / --directory /root --bypass-output-filter'
```

The device must be the ext4 filesystem backing the mountpoint. `--directory`
selects a path inside that filesystem; omit it to scan from `/`. A 9p share
such as `/opt/lkmhunter` is not part of the ext4 scan.

The optional bypass requires root, Linux x86_64, `cc`, and permission to trace a
child with ptrace. It compiles `utils/debugfs_output.c` in a temporary directory,
then runs debugfs read-only. The helper routes debugfs stdout writes through a
writable fd 0, which this rootkit's write hook skips. The Python report uses the
same exclusion so matching paths survive piped SSH output. The temporary build
is removed afterward. This is specific to the inspected rootkit implementation;
it does not make an infected kernel trustworthy.

Without `--bypass-output-filter`, ordinary debugfs output collection is used.
Add `--debug` (or `-v`) for per-directory disk/VFS counts, pending work,
subprocess commands, elapsed times, captured stderr, and error tracebacks.
The bypass helper also reports its child PID, exit status, and number of
redirected writes. In bypass mode, diagnostics use the protected output path
alongside findings so matching names survive the rootkit's pipe filter;
otherwise logs go to stderr. Normal runs log progress every 100 directories.

The scanner reports missing directory entries as well as files, compares while
walking, and exits with an error if a directory cannot be scanned. Because the
filesystem is live, concurrent file changes can also produce discrepancies.

## Shared kernel hunting library

Install the package in the guest's Python environment before using the wrapper
scripts. New testbed provisioning includes `python3-pyelftools`,
`python3-pytest`, and `bpftool`; an existing guest can install those packages with
apt. See the repository README for virtual-environment installation instead.

```bash
./ssh.sh 'cd /opt/lkmhunter && python3 -m lkmhunter scan syscalls --json'
./ssh.sh 'cd /opt/lkmhunter && python3 -m lkmhunter scan ftrace --json'
./ssh.sh 'cd /opt/lkmhunter && python3 -m pytest -q --live-kernel'
```

For memory-filter tests, build only the helper against the guest headers:

```bash
./ssh.sh 'cd /opt/lkmhunter && make -C /lib/modules/$(uname -r)/build M=/opt/lkmhunter/modules/src obj-m=lkm_mem.o modules && insmod modules/src/lkm_mem.ko'
```

The helper is selected automatically when loaded. Its capability ioctl must
advertise fault-contained reads before sparse recovery is enabled. The existing
read/write transfer ABI is unchanged. Rebooting removes the loaded helper.

The explicit integration checks read symbols/layouts, compare syscall pointers,
parse ftrace observations, verify an invalid helper address returns an error,
and recover the loaded helper's owning structure. Run ordinary unit tests on a
clean kernel: rootkit file/read/output filters can tamper with test fixtures.

Validation scenarios are a clean guest, a syscall-table hook, a shared ftrace
dispatcher, and recovery/dumping when kcore is filtered. Reboot between infected
and clean runs. The default guest boots with `nokaslr`; also test with that
parameter removed and verify a nonzero `kaslr_offset` in syscall scan coverage.
Restore the original boot configuration after that test. Layout extraction uses
BTF automatically, including when no debug-symbol image is present; syscall
comparison still requires a matching baseline image.
