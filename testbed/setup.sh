#!/usr/bin/env bash
# One-time (idempotent) setup for the lkmhunter QEMU testbed.
#
#   - downloads the Ubuntu cloud image
#   - builds a working qcow2 overlay sized up for kernel builds
#   - generates an SSH keypair for passwordless access
#   - builds a cloud-init seed that, on first boot, creates the test user and
#     installs toolchain + headers + dbgsym + debugfs and disables KASLR so the
#     dbgsym vmlinux lines up with the running kernel for gdb.
#
# Safe to re-run: existing artifacts are reused. Delete images/ to start clean.
set -euo pipefail
source "$(dirname "$0")/config.sh"

mkdir -p "$IMAGES_DIR" "$SYMBOLS_DIR"

# --- 1. SSH keypair ----------------------------------------------------------
if [[ ! -f "$SSH_KEY" ]]; then
  echo "[setup] generating testbed SSH keypair"
  ssh-keygen -t ed25519 -N '' -f "$SSH_KEY" -C "lkmhunter-testbed" >/dev/null
fi
PUBKEY="$(cat "$SSH_KEY.pub")"

# --- 2. Base cloud image -----------------------------------------------------
if [[ ! -f "$BASE_IMAGE" ]]; then
  echo "[setup] downloading $CLOUD_IMAGE_URL"
  curl -fL --progress-bar -o "$BASE_IMAGE.part" "$CLOUD_IMAGE_URL"
  mv "$BASE_IMAGE.part" "$BASE_IMAGE"
else
  echo "[setup] base image present: $BASE_IMAGE"
fi

# --- 3. Working overlay disk -------------------------------------------------
# A qcow2 backed by the pristine download: resets by deleting this one file.
if [[ ! -f "$DISK_IMAGE" ]]; then
  echo "[setup] creating working disk ($DISK_SIZE) backed by base image"
  qemu-img create -f qcow2 -F qcow2 -b "$BASE_IMAGE" "$DISK_IMAGE" "$DISK_SIZE" >/dev/null
else
  echo "[setup] working disk present: $DISK_IMAGE (delete it to reset the guest)"
fi

# --- 4. cloud-init seed ------------------------------------------------------
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

cat >"$WORK/meta-data" <<EOF
instance-id: $VM_NAME
local-hostname: $VM_NAME
EOF

cat >"$WORK/user-data" <<EOF
#cloud-config
users:
  - name: $GUEST_USER
    groups: [sudo]
    shell: /bin/bash
    sudo: ["ALL=(ALL) NOPASSWD:ALL"]
    lock_passwd: false
    ssh_authorized_keys:
      - $PUBKEY

chpasswd:
  expire: false
  users:
    - name: $GUEST_USER
      password: $GUEST_PASS
      type: text

# Allow key-based root login too (sshd default PermitRootLogin prohibit-password
# already permits it). disable_root:false stops cloud-init from planting the
# usual "please login as hunter" forced command in root's authorized_keys.
# Then:  GUEST_USER=root ./ssh.sh   logs in straight as root, no sudo needed.
disable_root: false

# NOTE: we deliberately do NOT relax kptr_restrict. Ubuntu's default (=1) already
# lets root (CAP_SYSLOG) read real addresses from /proc/kallsyms, and /proc/kcore
# needs root anyway — which is how the hunter runs (sudo). Keeping the stock
# default means the guest matches a real target, so the testbed can't mask a bug
# that only bites on a default-hardened host.
write_files:
  - path: /etc/modules-load.d/9p.conf
    content: |
      9p
      9pnet_virtio
  # Disable KASLR so the dbgsym vmlinux symbol addresses match the running
  # kernel — without this, host gdb resolves every symbol to the wrong address.
  - path: /etc/default/grub.d/99-nokaslr.cfg
    content: |
      GRUB_CMDLINE_LINUX_DEFAULT="\$GRUB_CMDLINE_LINUX_DEFAULT nokaslr"

# Mount the host repo over 9p at boot. nofail so a stray boot without the share
# does not wedge the VM.
mounts:
  - [ $MOUNT_TAG, $GUEST_REPO, 9p, "trans=virtio,version=9p2000.L,msize=262144,nofail,_netdev", "0", "0" ]

bootcmd:
  - mkdir -p $GUEST_REPO

package_update: true
packages:
  - build-essential
  - python3
  - python3-pip
  - python3-pyelftools   # shared lkmhunter library
  - python3-pytest       # opt-in integration tests
  - bpftool             # automatic BTF layout discovery
  - binutils            # objdump and kernel build diagnostics
  - e2fsprogs           # debugfs, used by debugfs_hunt.py
  - curl
  - gdb
  - kmod
  - linux-headers-generic

runcmd:
  - update-grub   # pick up the nokaslr snippet above before the reboot below
  # Install the testbed key for root so GUEST_USER=root ./ssh.sh works.
  - [ bash, -c, "install -d -m700 /root/.ssh && echo '$PUBKEY' > /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys" ]
  # Install matching kernel headers + debug symbols for the ACTUAL running kernel.
  - [ bash, -c, "apt-get install -y linux-headers-\$(uname -r) || true" ]
  # ddebs (debug symbol) repo, so host gdb can get a symbol-rich vmlinux.
  - [ bash, -c, "echo \\"deb http://ddebs.ubuntu.com $CLOUD_RELEASE main restricted universe multiverse\\" > /etc/apt/sources.list.d/ddebs.list" ]
  - [ bash, -c, "echo \\"deb http://ddebs.ubuntu.com $CLOUD_RELEASE-updates main restricted universe multiverse\\" >> /etc/apt/sources.list.d/ddebs.list" ]
  - [ bash, -c, "apt-get install -y ubuntu-dbgsym-keyring || apt-key adv --keyserver keyserver.ubuntu.com --recv-keys F2EDC64DC5AEE1F6B9C621F0C8CAB6595FDFF622 || true" ]
  - [ bash, -c, "apt-get update || true" ]
  - [ bash, -c, "apt-get install -y linux-image-\$(uname -r)-dbgsym || true" ]
  - [ bash, -c, "touch /var/lib/cloud/instance/lkmhunter-provisioned" ]

power_state:
  mode: reboot
  condition: true
EOF

echo "[setup] building cloud-init seed image"
if command -v cloud-localds >/dev/null 2>&1; then
  cloud-localds "$SEED_IMAGE" "$WORK/user-data" "$WORK/meta-data"
elif command -v genisoimage >/dev/null 2>&1; then
  genisoimage -output "$SEED_IMAGE" -volid cidata -joliet -rock \
    "$WORK/user-data" "$WORK/meta-data" >/dev/null 2>&1
elif command -v xorriso >/dev/null 2>&1; then
  xorriso -as mkisofs -output "$SEED_IMAGE" -volid cidata -joliet -rock \
    "$WORK/user-data" "$WORK/meta-data" >/dev/null 2>&1
else
  echo "[setup] ERROR: need one of cloud-localds / genisoimage / xorriso." >&2
  echo "        Install with: sudo apt-get install cloud-image-utils genisoimage" >&2
  exit 1
fi

echo
echo "[setup] done."
echo "  Next:  ./run.sh            # boot the VM (first boot provisions via cloud-init)"
echo "         ./ssh.sh            # shell into the guest once it is up"
echo "         ./fetch-symbols.sh  # pull vmlinux out for host gdb"
echo
echo "  First boot installs packages then reboots itself; give it a few minutes."
echo "  Watch progress with:  ./ssh.sh 'cloud-init status --wait'"
