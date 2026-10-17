#!/usr/bin/env bash
# Shell into the guest, or run a command there.
#   ./ssh.sh                      interactive shell
#   ./ssh.sh 'uname -a'           run a command
#   ./ssh.sh 'cloud-init status --wait'   wait for first-boot provisioning
set -euo pipefail
source "$(dirname "$0")/config.sh"
ssh_guest "$@"
