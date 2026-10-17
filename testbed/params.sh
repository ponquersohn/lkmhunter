#!/usr/bin/env bash
# Flip kernel hardening/visibility knobs in the guest, so you can see how the
# hunter behaves under different host policies (stock, relaxed, locked down).
#
#   ./params.sh                      show every knob + its current guest value
#   ./params.sh get                  same
#   ./params.sh set kptr_restrict 2  set one knob at runtime (sysctl -w)
#   ./params.sh set kptr_restrict 2 --persist   also write a sysctl.d drop-in
#   ./params.sh preset default       stock Ubuntu values
#   ./params.sh preset relaxed       loosened for debugging
#   ./params.sh preset hardened      locked down
#
# Everything runs in the guest over ssh (so: VM up, and not frozen by gdb).
set -euo pipefail
source "$(dirname "$0")/config.sh"

# short-name | sysctl path | allowed values | one-way? | description
KNOBS=(
  "kptr_restrict|kernel.kptr_restrict|0,1,2|no|Hide kernel ptrs in kallsyms/%pK (1=CAP_SYSLOG,2=nobody)"
  "dmesg_restrict|kernel.dmesg_restrict|0,1|no|Restrict dmesg to CAP_SYSLOG"
  "perf_event_paranoid|kernel.perf_event_paranoid|-1,0,1,2,3,4|no|perf access level (-1=wide open)"
  "ptrace_scope|kernel.yama.ptrace_scope|0,1,2,3|no|Yama ptrace restriction (0=classic)"
  "unprivileged_bpf|kernel.unprivileged_bpf_disabled|0,1,2|no|Block unprivileged BPF"
  "kexec_load_disabled|kernel.kexec_load_disabled|0,1|yes|Disable kexec (cannot be undone w/o reboot)"
  "modules_disabled|kernel.modules_disabled|0,1|yes|Freeze module loading (ONE-WAY; breaks insmod!)"
)

# Stock Ubuntu defaults (verified against a stock host).
declare -A P_DEFAULT=( [kptr_restrict]=1 [dmesg_restrict]=1 [perf_event_paranoid]=4
                       [ptrace_scope]=1 [unprivileged_bpf]=2 )
# Loosened — most visible to tooling; good for first-pass hunter development.
declare -A P_RELAXED=( [kptr_restrict]=0 [dmesg_restrict]=0 [perf_event_paranoid]=-1
                       [ptrace_scope]=0 [unprivileged_bpf]=0 )
# Locked down — the hardest realistic target the hunter should still cope with.
declare -A P_HARDENED=( [kptr_restrict]=2 [dmesg_restrict]=1 [perf_event_paranoid]=4
                        [ptrace_scope]=3 [unprivileged_bpf]=2 )

field() { echo "$1" | cut -d'|' -f"$2"; }           # pull a field from a KNOBS row
lookup() { for row in "${KNOBS[@]}"; do [[ "$(field "$row" 1)" == "$1" ]] && { echo "$row"; return; }; done; }

do_get() {
  printf '%-22s %-7s %-12s %s\n' "KNOB" "VALUE" "ALLOWED" "DESCRIPTION"
  printf '%-22s %-7s %-12s %s\n' "----" "-----" "-------" "-----------"
  # One ssh round-trip: read every sysctl at once.
  local paths vals
  paths="$(for row in "${KNOBS[@]}"; do field "$row" 2; done)"
  vals="$(ssh_guest "for p in $paths; do printf '%s=%s\n' \"\$p\" \"\$(sysctl -n \$p 2>/dev/null || echo NA)\"; done")"
  for row in "${KNOBS[@]}"; do
    local short sys allowed oneway desc cur
    short="$(field "$row" 1)"; sys="$(field "$row" 2)"; allowed="$(field "$row" 3)"
    oneway="$(field "$row" 4)"; desc="$(field "$row" 5)"
    cur="$(echo "$vals" | sed -n "s|^$sys=||p")"
    [[ "$oneway" == yes ]] && desc="$desc  [one-way]"
    printf '%-22s %-7s %-12s %s\n' "$short" "${cur:-NA}" "$allowed" "$desc"
  done
  echo "---- boot-time (set via grub cmdline + reboot, not here) ----"
  ssh_guest 'echo -n "KASLR:    "; grep -qw nokaslr /proc/cmdline && echo "OFF (nokaslr)" || echo "ON";
             echo -n "lockdown: "; cat /sys/kernel/security/lockdown 2>/dev/null || echo "securityfs absent"'
}

do_set() {
  local short="$1" val="$2" persist="${3:-}"
  local row; row="$(lookup "$short")"
  [[ -z "$row" ]] && { echo "unknown knob: $short (see ./params.sh get)" >&2; exit 2; }
  local sys allowed oneway; sys="$(field "$row" 2)"; allowed="$(field "$row" 3)"; oneway="$(field "$row" 4)"
  [[ ",$allowed," == *",$val,"* ]] || { echo "invalid value '$val' for $short (allowed: $allowed)" >&2; exit 2; }
  if [[ "$oneway" == yes && "$val" != 0 && "$FORCE" != 1 ]]; then
    echo "REFUSING: $short=$val is a one-way switch (needs a reboot to undo)." >&2
    [[ "$short" == modules_disabled ]] && echo "          modules_disabled=1 breaks insmod — the whole testbed. Reset after." >&2
    echo "          Re-run with --force if you really mean it." >&2
    exit 3
  fi
  echo "[params] set $sys = $val${persist:+ (persisted)}"
  ssh_guest "sudo sysctl -w $sys=$val"
  if [[ -n "$persist" ]]; then
    ssh_guest "echo '$sys = $val' | sudo tee /etc/sysctl.d/90-lkmhunter-params.conf >/dev/null && echo persisted to /etc/sysctl.d/90-lkmhunter-params.conf"
  fi
}

do_preset() {
  local name="$1"; local -n P
  case "$name" in
    default)  P=P_DEFAULT ;;
    relaxed)  P=P_RELAXED ;;
    hardened) P=P_HARDENED ;;
    *) echo "unknown preset: $name (default|relaxed|hardened)" >&2; exit 2 ;;
  esac
  echo "[params] applying preset '$name'"
  # Build one sysctl command so it is a single ssh round-trip.
  local cmd=""
  for short in "${!P[@]}"; do
    local sys; sys="$(field "$(lookup "$short")" 2)"
    cmd+="sudo sysctl -w $sys=${P[$short]}; "
  done
  ssh_guest "$cmd"
  echo "[params] done — current state:"
  do_get
}

FORCE=0
ARGS=()
for a in "$@"; do [[ "$a" == --force ]] && FORCE=1 || ARGS+=("$a"); done
set -- "${ARGS[@]:-}"

case "${1:-get}" in
  get|"") do_get ;;
  set)
    [[ $# -ge 3 ]] || { echo "usage: ./params.sh set <knob> <value> [--persist]" >&2; exit 2; }
    persist=""; [[ "${4:-}" == --persist ]] && persist=1
    do_set "$2" "$3" "$persist" ;;
  preset)
    [[ $# -ge 2 ]] || { echo "usage: ./params.sh preset <default|relaxed|hardened>" >&2; exit 2; }
    do_preset "$2" ;;
  -h|--help) sed -n '2,14p' "$0" ;;
  *) echo "unknown command: $1 (get|set|preset)" >&2; exit 2 ;;
esac
