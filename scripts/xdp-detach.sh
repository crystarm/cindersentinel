#!/usr/bin/env bash
set -euo pipefail

script_dir="$(
  cd "$(dirname "${BASH_SOURCE[0]}")" && pwd
)"
source "${script_dir}/common.sh"
need_root "$@"

ip netns exec "${NS_A}" ip link set dev "${IFACE_A}" xdpgeneric off 2>/dev/null || true
log_info "xdp detached: ${NS_A}/${IFACE_A}"
