#!/bin/bash
# Hunt for hidden kernel modules and hooked syscalls on the RUNNING kernel.
#
# Must run as root: it reads /proc/kcore and the (now 0600) /boot/vmlinuz. If
# not root it re-execs itself under sudo, so `bash find_rootkits.sh` works too.
#
#   bash find_rootkits.sh            # normal run
#   bash find_rootkits.sh --debug    # verbose library logging
set -u

if [ "$(id -u)" -ne 0 ]; then
    exec sudo bash "$0" "$@"
fi

# Run from the repo dir so the lkmhunter package resolves regardless of cwd.
cd "$(dirname "$0")" || exit 1

DEBUG=""
case "${1:-}" in
    -v|--debug) DEBUG="--debug" ;;
esac

workdir=/tmp
running_kernel=$(uname -r)

echo "The dumbest thing ever. Looking in sys and found:"
for module in $(comm -13 \
        <(lsmod | cut -d " " -f1 | tail -n +2 | sort) \
        <(find /sys/module/ -name holders -exec dirname {} \; | xargs -n 1 basename | sort)); do
    echo "Found module in sys: $module"
done

echo "Staring prework"
# Use mktemp rather than fixed /tmp paths: a stale, differently-owned
# /tmp/vmlinux is unwritable under fs.protected_regular (default on modern
# Ubuntu), even for root, and would be silently reused.
vmlinux_out="$(mktemp "$workdir/vmlinux.XXXXXX")"
fetched=""

# Prefer the kernel's own extract-vmlinux (ships with linux-headers): offline and
# not subject to GitHub rate limiting. Fall back to the upstream copy if absent.
extract="/lib/modules/$running_kernel/build/scripts/extract-vmlinux"
if [ ! -f "$extract" ]; then
    extract="$(mktemp "$workdir/extract-vmlinux.XXXXXX")"
    fetched=1
    curl --no-progress-meter \
        https://raw.githubusercontent.com/torvalds/linux/master/scripts/extract-vmlinux \
        > "$extract"
fi

sh "$extract" "/boot/vmlinuz-$running_kernel" > "$vmlinux_out"

echo "Comparing syscalls"
python3 -m lkmhunter scan syscalls $DEBUG \
    --vmlinux "$vmlinux_out" \
    --system-map "/boot/System.map-$running_kernel"
rc=$?   # 0 = clean, 1 = hooks found

rm -f "$vmlinux_out" 2>/dev/null
[ -n "$fetched" ] && rm -f "$extract" 2>/dev/null
exit $rc
