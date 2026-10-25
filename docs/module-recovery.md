# Recovering the lab KoviD unhide value

`lkmhunter recover kovid` reads the loaded module's AES state and decrypts a
snapshot offline. It performs no kernel writes, kernel function calls, unhide
requests, or unload actions. It needs root access to the configured memory
backend, `openssl`, and the **exact unstripped module ELF with DWARF** for the
loaded build. Matching kernel vmlinux is not required for this operation.

First find the live module-space callback with `lkmhunter scan ftrace`. Confirm
that it is KoviD's `fh_ftrace_thunk`; grouping alone is a heuristic. Then run:

```bash
lkmhunter recover kovid \
  --module-elf /path/to/exact-module.elf \
  --dispatcher 0xffffffffREPLACE_WITH_LIVE_CALLBACK \
  --backend kcore
```

Use a fresh address from this boot and module load. `--json` includes addresses,
module file SHA-256, ciphertext size, memory backend, and snapshot stability.
A successful extraction returns 0; unavailable inputs or recovery failures
return 2. This command does not use scanner finding exit-code semantics.

The implementation:

1. Uses the ELF symbol `fh_ftrace_thunk` and supplied callback to derive `.text`.
2. Uses at least two relocated AES-key references inside
   `kv_crypto_engine_init` to cross-check the live `.bss` base.
3. Resolves the static 32-byte AES key and `kvmgc_unhidekey` pointer from ELF
   symbols, and the object/member offsets from DWARF.
4. Reads the key, IV, and ciphertext twice, refusing inconsistent snapshots.
5. Decrypts with AES-256-CBC, without padding removal, and interprets the first
   eight plaintext bytes as the little-endian integer used by `_crypto_cb`.

Only the recovered unhide value is printed by default. Raw AES key bytes are
not included in the report or saved. The offline OpenSSL subprocess receives
its AES key through its `-K` argument, which may be visible to local process
inspection while it runs.

This is a KoviD-specific forensic helper for the workshop's non-obfuscated
x86-64 build. It expects the known symbol names, a 32-byte static AES key in
`.bss`, supported PC-relative or sign-extended absolute relocations, and DWARF
crypto structures. Stripped, obfuscated, optimized differently, or modified
builds can be unsupported. KoviD may hide filenames containing its name; the
workshop used an exact copy under a neutral `.elf` filename.

Repeated reads agreeing is a consistency check, not an atomic capture: CPUs
continue running. AES-CBC is unauthenticated, and neither the supplied ELF nor
the callback is independently proven to match the loaded module. Successful
decryption is therefore not proof of credential validity. The report sets
`credential_validated` to false; compare against the known lab value separately.
All memory reads still depend on the running kernel.

In the rehearsed guest, the command recovered `1978101720260042` from the live
snapshot, matching the independently known configured lab value. Addresses and
filenames from that run are not reusable defaults.
