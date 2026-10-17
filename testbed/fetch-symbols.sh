#!/usr/bin/env bash
# Copy the guest's symbol-rich vmlinux to the host so gdb can resolve kernel
# symbols against the QEMU gdb stub. Needs the VM running and provisioned
# (the dbgsym package is installed by cloud-init on first boot).
set -euo pipefail
source "$(dirname "$0")/config.sh"
mkdir -p "$SYMBOLS_DIR"

KREL="$(ssh_guest 'uname -r')"
REMOTE="/usr/lib/debug/boot/vmlinux-$KREL"

echo "[symbols] guest kernel: $KREL"
if ssh_guest "test -f $REMOTE"; then
  echo "[symbols] copying $REMOTE -> $VMLINUX"
  scp_guest "$GUEST_USER@localhost:$REMOTE" "$VMLINUX"
  echo "[symbols] done. gdb will load $VMLINUX"
else
  echo "[symbols] $REMOTE not found in guest." >&2
  echo "          The dbgsym package may still be installing. Check with:" >&2
  echo "            ./ssh.sh 'cloud-init status --wait'" >&2
  echo "            ./ssh.sh 'ls /usr/lib/debug/boot/'" >&2
  echo "          Without it gdb still stops/steps, but with raw addresses only." >&2
  exit 1
fi
