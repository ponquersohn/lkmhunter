#!/usr/bin/env bash
set -euo pipefail

cd -- "$(dirname -- "${BASH_SOURCE[0]}")"

clone() {
    local url="$1" name="$2"
    if [[ -e "$name" ]]; then
        printf 'Skipping existing %s\n' "$name"
        return
    fi
    git clone -- "$url" "$name"
}

clone https://github.com/m0nad/Diamorphine Diamorphine
clone https://github.com/carloslack/KoviD.git KoviD
clone https://github.com/MatheuZSecurity/Singularity.git Singularity
