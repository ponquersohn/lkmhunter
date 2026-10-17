#!/usr/bin/env bash
# Attach host gdb to the running VM's QEMU gdb stub, with kernel symbols loaded.
#   ./gdb.sh                 connect and load vmlinux symbols
#   ./gdb.sh <expr...>       pass extra args straight to gdb
#
# Handy once attached:
#   (gdb) p (void *)sys_call_table           # syscall table base
#   (gdb) x/16a &sys_call_table              # the entries; compare to on-disk
#   (gdb) b __x64_sys_kill                    # break where a hooked syscall lands
#   (gdb) info registers / bt / continue
set -euo pipefail
source "$(dirname "$0")/config.sh"

if [[ ! -f "$VMLINUX" ]]; then
  echo "[gdb] no symbol file at $VMLINUX — run ./fetch-symbols.sh first." >&2
  echo "[gdb] connecting anyway, raw addresses only."
  exec gdb -ex "target remote localhost:$GDB_PORT" "$@"
fi

exec gdb -q \
  -ex "set architecture i386:x86-64" \
  -ex "file $VMLINUX" \
  -ex "target remote localhost:$GDB_PORT" \
  -ex "echo \n[gdb] connected to $VM_NAME with symbols from $VMLINUX\n" \
  "$@"
