# Shared-library migration validation

Validated on 2026-10-17 in the existing Ubuntu QEMU testbed, kernel
`7.3.0-9-generic` (x86-64). Kernel modules were loaded only in the guest.

| Check | Result |
| --- | --- |
| Default unprivileged test suite | 37 passed; 2 explicit integration tests skipped |
| Guest suite with `--live-kernel`, KASLR enabled | 39 passed |
| Clean syscall comparison through kcore | 473 entries compared; no differences |
| Clean comparison with KASLR | 473 entries compared; discovered slide `0x12000000` |
| Controlled syscall-table change | Changed unused entry 134 temporarily; scanner found exactly that entry; restored pointer and confirmed clean comparison |
| Infected ftrace scan | Found a shared module-space dispatcher used by 114 functions |
| Infected kcore input | Filtered ELF header reported unavailable, never clean |
| Helper selection and syscall comparison | Automatically selected loaded helper; all 473 entries compared |
| Hidden module recovery | Recovered structure despite erased name and invalid list pointers |
| Recovery with KASLR and self-reference validation | Found owner at `0xffffffffc0f8be80` from dispatcher `0xffffffffc1012170`; complete region dump without gaps |
| Invalid helper address | Fault-contained read returned an error; guest stayed running |
| BTF discovery | Derived live module offsets without debug symbols or compilation |
| DWARF fallback | Compiled fixture verified sizes/offsets, array count, and layout discovery with unavailable kallsyms and matching build ID |
| Packaging | Built and installed wheel in a separate environment; imported package and ran CLI outside checkout |
| Static checks | Python compilation, shell syntax, and `git diff --check` passed |

The helper target built against both host `7.0.0-38-generic` headers and guest
`7.3.0-9-generic` headers. The unrelated combined module build still fails on
existing `modlist.c` missing-prototype warnings under `-Werror`; use the targeted
helper build documented in the README.

The original `nokaslr` boot configuration was restored after testing. The final
reboot was verified: `nokaslr` active, helper unloaded, and zero suspicious
ftrace groups. Recovery dumps from the final
infected run are retained in the guest under `/var/tmp/lkmhunter-kaslr-recovery`.

These are live observations from the tested builds, not a guarantee that the
same heuristics cover every kernel or rootkit. The integration test suite is
opt-in and read-only; controlled table modification and rootkit loading above
were separate manual testbed exercises.

## KoviD detection exercise

The supplied KoviD 4.0.1 source did not compile on the main guest's
`7.3.0-9-generic` kernel: after passing its existing compiler definitions through
Kbuild's current flag interface, compilation stopped at the removed `strncpy`
declaration. No source compatibility patch was applied.

KoviD built and loaded on `6.8.0-147-generic` in a separate, disposable QEMU
snapshot of the existing Ubuntu 24.04 image. The main testbed was kept clean.
Build-generated configuration changes were confined to a guest-local source
copy. The matching generated kernel header supplied the syscall count (462),
since the extracted baseline lacked ELF symbol sizes and DWARF. KASLR relocation
was discovered as `0x21400000`.

| Check | Result |
| --- | --- |
| Clean syscall comparison | 462 entries; no differences |
| Infected syscall comparison | 462 entries; no differences, consistent with ftrace hooks |
| Visibility after loading | Absent from `/proc/modules` and `/sys/module` |
| Ftrace detection | One module-space dispatcher shared by 22 functions |
| Owner recovery, kcore | Recovered `kovid`, state `UNFORMED` |
| Owner recovery, lkm_mem | Same owning structure recovered |
| Region dump | Text 32,768 bytes; data 45,056 bytes; rodata 8,192 bytes; no gaps |
| Scanner regression checks | 15 scanner tests passed, including both direct-call continuation formats |

This run exposed the kernel 6.8 `direct-->` ftrace continuation format. The
scanner now accepts it as well as `direct(jmp)-->`; the post-fix infected scan
completed with no unparsed lines. The original raw report retains its initial
partial status, and a separate post-fix result records the completed scan.

Recovery currently reports `hidden_from_module_list=false` for this sample:
its stored list links remain plausible. Ownership recovery succeeds, but the
standalone flag does not establish actual list membership. The absence from
both normal module views and the `UNFORMED` state are recorded separately.

Local artifacts are retained under `scratchpad/kovid-validation-20261017/`:
`summary.json`, `report.json`, `ftrace-after-parser-fix.json`, build logs, raw
ftrace observations, and `module-dump.tar`. These generated artifacts are
ignored by Git. The secondary snapshot VM was shut down after export, discarding
its guest changes.
