#!/usr/bin/env bash
# Shut the testbed VM down.
#
#   ./stop.sh            graceful ACPI shutdown (like pressing the power button),
#                        waits for the guest to power off cleanly
#   ./stop.sh --force    pull the plug immediately (QEMU quit) — may corrupt the
#                        working disk; fine for a disposable overlay
#   ./stop.sh --status   just report whether the VM is running
#
# Works for VMs started with ./run.sh (foreground or --daemon): both expose the
# QEMU monitor on the unix socket this talks to.
set -euo pipefail
source "$(dirname "$0")/config.sh"

SOCK="$IMAGES_DIR/monitor.sock"

# Send a command to the QEMU monitor socket.
monitor() { printf '%s\n' "$1" | socat - "UNIX-CONNECT:$SOCK" >/dev/null 2>&1; }

# Is a testbed QEMU alive? Prefer the monitor socket; fall back to pgrep.
vm_pids() { pgrep -f "qemu-system-x86_64.*$VM_NAME" 2>/dev/null || true; }
vm_running() { [[ -S "$SOCK" ]] && monitor "" && return 0; [[ -n "$(vm_pids)" ]]; }

FORCE=0 STATUS=0
for a in "$@"; do
  case "$a" in
    --force)  FORCE=1 ;;
    --status) STATUS=1 ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "unknown arg: $a" >&2; exit 2 ;;
  esac
done

if (( STATUS )); then
  if vm_running; then echo "running (pids: $(vm_pids | tr '\n' ' '))"; else echo "stopped"; fi
  exit 0
fi

if ! vm_running; then
  echo "[stop] VM is not running."
  rm -f "$SOCK"
  exit 0
fi

if (( FORCE )); then
  echo "[stop] forcing QEMU to quit"
  monitor "quit" || kill $(vm_pids) 2>/dev/null || true
else
  echo "[stop] sending graceful ACPI power-down"
  monitor "system_powerdown"
  echo -n "[stop] waiting for clean shutdown"
  for _ in $(seq 1 30); do
    if ! vm_running; then echo " — done."; rm -f "$SOCK"; exit 0; fi
    echo -n "."; sleep 1
  done
  echo
  echo "[stop] still up after 30s (guest may be mid-boot or ignoring ACPI)."
  echo "       Re-run with --force to pull the plug."
  exit 1
fi

# Give a forced quit a moment, then confirm.
for _ in $(seq 1 5); do vm_running || break; sleep 1; done
if vm_running; then
  echo "[stop] QEMU still alive, sending SIGKILL"
  kill -9 $(vm_pids) 2>/dev/null || true
fi
rm -f "$SOCK"
echo "[stop] stopped."
