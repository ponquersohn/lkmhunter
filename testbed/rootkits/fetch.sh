#!/usr/bin/env bash
# Fetch public, well-known LKM rootkit sources used as ground-truth test
# payloads for the hunter. These are cloned to src/ (gitignored) and are only
# ever built and loaded INSIDE the throwaway QEMU guest, never on the host.
#
#   ./fetch.sh            # fetch the default set
#   ./fetch.sh diamorphine
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p src

# name -> git URL. Add your own test payloads here.
declare -A ROOTKITS=(
  [diamorphine]="https://github.com/m0nad/Diamorphine"
)

want=("${@:-}")
[[ -z "${want[*]}" ]] && want=("${!ROOTKITS[@]}")

for name in "${want[@]}"; do
  url="${ROOTKITS[$name]:-}"
  if [[ -z "$url" ]]; then
    echo "[fetch] unknown rootkit '$name'. Known: ${!ROOTKITS[*]}" >&2
    continue
  fi
  if [[ -d "src/$name/.git" ]]; then
    echo "[fetch] $name present, pulling latest"
    git -C "src/$name" pull --ff-only --quiet || true
  else
    echo "[fetch] cloning $name from $url"
    git clone --depth 1 --quiet "$url" "src/$name"
  fi
done
echo "[fetch] done -> $(pwd)/src/  (shared into guest, built there by ../inject.sh)"
