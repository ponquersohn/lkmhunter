#!/usr/bin/env bash
# Reset the guest to a pristine, provisioned state by recreating the working
# overlay from the base image. The VM must be shut down first.
#
# Note: this rolls back to the freshly-downloaded cloud image, so cloud-init
# re-provisions on the next ./run.sh (reinstalls headers/dbgsym). Fast and total
# — the right way to get a known-clean kernel between rootkit tests.
set -euo pipefail
source "$(dirname "$0")/config.sh"

if [[ -S "$IMAGES_DIR/monitor.sock" ]] && pgrep -f "$VM_NAME" >/dev/null 2>&1; then
  echo "[reset] VM looks like it is still running — shut it down first:" >&2
  echo "        ./stop.sh        (graceful)   or   ./stop.sh --force" >&2
  exit 1
fi

echo "[reset] recreating working overlay from base image"
rm -f "$DISK_IMAGE"
qemu-img create -f qcow2 -F qcow2 -b "$BASE_IMAGE" "$DISK_IMAGE" "$DISK_SIZE" >/dev/null
echo "[reset] done. Next ./run.sh boots clean and re-provisions via cloud-init."
