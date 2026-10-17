# Shared configuration for the lkmhunter QEMU testbed.
# Sourced by every script in this directory. Override any value via the
# environment, e.g.  SSH_PORT=2300 ./run.sh

# --- Paths -------------------------------------------------------------------
# Resolve the testbed dir regardless of where a script is invoked from.
TESTBED_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$TESTBED_DIR/.." && pwd)"          # the lkmhunter checkout, shared into the guest
IMAGES_DIR="${IMAGES_DIR:-$TESTBED_DIR/images}"    # downloaded + working disk images (gitignored)
SYMBOLS_DIR="${SYMBOLS_DIR:-$TESTBED_DIR/symbols}" # vmlinux pulled out of the guest for host gdb

# --- Guest OS ----------------------------------------------------------------
# Ubuntu cloud image, picked by codename. Kernel shipped (as of 2026-10):
#   noble     24.04 LTS   kernel 6.8   (7.0 via HWE)
#   questing  25.10       kernel 6.17
#   resolute  26.04 LTS   kernel 7.0   (matches this host; LTS = most stable)
#   stonking  26.10       kernel 7.3   <- newest kernel (default)
# Override per-invocation, e.g.  CLOUD_RELEASE=resolute ./setup.sh
CLOUD_RELEASE="${CLOUD_RELEASE:-stonking}"
CLOUD_IMAGE_URL="${CLOUD_IMAGE_URL:-https://cloud-images.ubuntu.com/${CLOUD_RELEASE}/current/${CLOUD_RELEASE}-server-cloudimg-amd64.img}"
BASE_IMAGE="$IMAGES_DIR/${CLOUD_RELEASE}-base.img"  # pristine download, never booted directly
DISK_IMAGE="$IMAGES_DIR/${CLOUD_RELEASE}-disk.qcow2" # the working overlay we actually boot
SEED_IMAGE="$IMAGES_DIR/seed.img"                    # cloud-init NoCloud seed (user-data/meta-data)
DISK_SIZE="${DISK_SIZE:-20G}"

# --- VM resources ------------------------------------------------------------
VM_CPUS="${VM_CPUS:-4}"
VM_MEM="${VM_MEM:-4096}"      # MiB
VM_NAME="${VM_NAME:-lkmhunter-testbed}"

# --- Networking (QEMU user-mode NAT + host port forwards) --------------------
SSH_PORT="${SSH_PORT:-2222}" # host port -> guest :22

# --- Kernel debugging --------------------------------------------------------
GDB_PORT="${GDB_PORT:-1234}" # QEMU gdb stub (the -s shorthand is :1234)
VMLINUX="$SYMBOLS_DIR/vmlinux" # symbol file host gdb loads; populated by fetch-symbols.sh

# --- Guest-side account ------------------------------------------------------
GUEST_USER="${GUEST_USER:-hunter}"
GUEST_PASS="${GUEST_PASS:-hunter}"         # console login; ssh uses the key below
SSH_KEY="$TESTBED_DIR/id_testbed"          # auto-generated keypair (gitignored)
MOUNT_TAG="lkmhunter"                       # 9p tag; repo mounts at /opt/lkmhunter in guest
GUEST_REPO="/opt/lkmhunter"

# Convenience wrapper so every ssh/scp call shares the same options.
ssh_guest() {
  ssh -i "$SSH_KEY" -p "$SSH_PORT" \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o LogLevel=ERROR -o ConnectTimeout=5 \
    "$GUEST_USER@localhost" "$@"
}
scp_guest() {
  scp -i "$SSH_KEY" -P "$SSH_PORT" \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o LogLevel=ERROR "$@"
}
