#!/usr/bin/env bash
set -euo pipefail

script_dir="$(
  cd "$(dirname "${BASH_SOURCE[0]}")" && pwd
)"
source "${script_dir}/common.sh"
need_root "$@"

if [[ ! -f "${XDP_OBJ}" ]]; then
  die "Missing: ${XDP_OBJ}"
fi

ip netns exec "${NS_A}" ip link set dev "${IFACE_A}" xdpgeneric off 2>/dev/null || true
ip netns exec "${NS_A}" ip link set dev "${IFACE_A}" xdpgeneric obj "${XDP_OBJ}" sec xdp

ip netns exec "${NS_A}" ip -details link show dev "${IFACE_A}" | grep -i xdp || true
log_info "xdp attached (generic): ${NS_A}/${IFACE_A}"
