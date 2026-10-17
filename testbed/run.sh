#!/usr/bin/env bash
# Boot the testbed VM.
#
#   ./run.sh                 boot normally, repo shared in, gdb stub on :$GDB_PORT
#   ./run.sh --freeze        boot with the CPU frozen (-S): gdb must `continue`
#   ./run.sh --snapshot      ephemeral boot; all disk writes discarded on exit
#   ./run.sh --daemon        run in background, console -> console.log
#   ./run.sh --no-gdb        do not expose the gdb stub
#
# The repo at $REPO_DIR is shared into the guest at $GUEST_REPO over 9p, so your
# host edits are live inside the VM with no copy step.
set -euo pipefail
source "$(dirname "$0")/config.sh"

FREEZE=0 SNAPSHOT=0 DAEMON=0 GDB=1
for arg in "$@"; do
  case "$arg" in
    --freeze)   FREEZE=1 ;;
    --snapshot) SNAPSHOT=1 ;;
    --daemon)   DAEMON=1 ;;
    --no-gdb)   GDB=0 ;;
    -h|--help)  sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "unknown arg: $arg" >&2; exit 2 ;;
  esac
done

[[ -f "$DISK_IMAGE" ]] || { echo "No disk image. Run ./setup.sh first." >&2; exit 1; }

QEMU=(
  qemu-system-x86_64
  -name "$VM_NAME"
  -machine q35,accel=kvm
  -cpu host
  -smp "$VM_CPUS"
  -m "$VM_MEM"
  -nographic
  -drive "file=$DISK_IMAGE,if=virtio,format=qcow2"
  -drive "file=$SEED_IMAGE,if=virtio,format=raw"
  # user-mode NAT with an ssh forward; guest reaches the internet for apt/curl.
  -netdev "user,id=net0,hostfwd=tcp::${SSH_PORT}-:22"
  -device "virtio-net-pci,netdev=net0"
  # share the repo read-write over 9p (mounted at $GUEST_REPO by cloud-init).
  -virtfs "local,path=$REPO_DIR,mount_tag=$MOUNT_TAG,security_model=mapped-xattr,id=hostshare"
  # QEMU monitor on a unix socket so scripts can poke the VM if needed.
  -monitor "unix:$IMAGES_DIR/monitor.sock,server,nowait"
)

(( GDB ))     && QEMU+=( -gdb "tcp::${GDB_PORT}" )
(( FREEZE ))  && QEMU+=( -S )
(( SNAPSHOT ))&& QEMU+=( -snapshot )

echo "[run] $VM_NAME  cpus=$VM_CPUS mem=${VM_MEM}M"
echo "[run] ssh  -> localhost:$SSH_PORT   (./ssh.sh)"
(( GDB )) && echo "[run] gdb  -> localhost:$GDB_PORT    (./gdb.sh)"
(( SNAPSHOT )) && echo "[run] SNAPSHOT mode: disk writes are discarded on shutdown"
(( FREEZE ))   && echo "[run] CPU FROZEN: connect gdb and 'continue' to start"
echo "[run] console: Ctrl-a x to quit, Ctrl-a c for QEMU monitor"
echo

if (( DAEMON )); then
  "${QEMU[@]}" -serial "file:$TESTBED_DIR/console.log" &
  echo "[run] backgrounded (pid $!), console -> $TESTBED_DIR/console.log"
  echo "[run] stop it with: ./stop.sh   (status: ./stop.sh --status)"
else
  exec "${QEMU[@]}" -serial mon:stdio
fi
