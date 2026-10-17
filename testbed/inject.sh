#!/usr/bin/env bash
# Drive a full detection test inside the guest:
#   1. build the chosen rootkit against the guest's kernel headers
#   2. load it (it hides itself from lsmod, as real rootkits do)
#   3. run the hunter and show whether it catches the hook
#
#   ./inject.sh                       # build + load diamorphine, then hunt
#   ./inject.sh --rootkit diamorphine
#   ./inject.sh --hunt-only           # just run the hunter (no load)
#   ./inject.sh --unload              # best-effort unload (diamorphine: signal 63)
#
# Everything runs in the VM. To get back to a clean kernel, reset the guest
# (./reset.sh) rather than trusting a rootkit to cleanly remove itself.
set -euo pipefail
source "$(dirname "$0")/config.sh"

ROOTKIT=diamorphine HUNT_ONLY=0 UNLOAD=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --rootkit) ROOTKIT="$2"; shift 2 ;;
    --hunt-only) HUNT_ONLY=1; shift ;;
    --unload) UNLOAD=1; shift ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

RK_DIR="$GUEST_REPO/testbed/rootkits/src/$ROOTKIT"

if (( UNLOAD )); then
  echo "[inject] attempting unload of $ROOTKIT"
  # Diamorphine toggles visibility on SIGCONT-ish magic signal 63, then rmmod.
  ssh_guest "sudo kill -63 1 2>/dev/null; sudo rmmod $ROOTKIT 2>/dev/null; echo done"
  exit 0
fi

if (( ! HUNT_ONLY )); then
  echo "[inject] building $ROOTKIT in guest against $(ssh_guest 'uname -r')"
  ssh_guest "test -d '$RK_DIR' || { echo 'missing $RK_DIR — run rootkits/fetch.sh on the host first' >&2; exit 1; }"
  ssh_guest "cd '$RK_DIR' && make >/tmp/rk-build.log 2>&1 && echo built || { echo BUILD FAILED; tail -20 /tmp/rk-build.log; exit 1; }"

  KO="$(ssh_guest "ls '$RK_DIR'/*.ko 2>/dev/null | head -1")"
  echo "[inject] loading $KO"
  ssh_guest "sudo insmod '$KO' && echo loaded"
  echo "[inject] lsmod shows it? (a good rootkit hides, so expect nothing):"
  ssh_guest "lsmod | grep -i '$ROOTKIT' || echo '  (hidden from lsmod — as expected)'"
fi

echo
echo "===================== running lkmhunter ====================="
# find_rootkits.sh: /sys enumeration diff + syscall-table hook comparison.
ssh_guest "cd '$GUEST_REPO' && sudo bash find_rootkits.sh"
echo "============================================================="
echo
echo "[inject] done. Reset to a clean kernel with ./reset.sh when finished."
