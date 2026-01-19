#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/common.sh"
need_root "$@"

if [[ ! -f "${XDP_OBJ}" ]]; then
  echo "Missing: ${XDP_OBJ}"
  exit 1
fi

ip netns exec "${NS_A}" ip link set dev "${IFACE_A}" xdpgeneric off 2>/dev/null || true
ip netns exec "${NS_A}" ip link set dev "${IFACE_A}" xdpgeneric obj "${XDP_OBJ}" sec xdp

ip netns exec "${NS_A}" ip -details link show dev "${IFACE_A}" | grep -i xdp || true
echo "xdp attached (generic): ${NS_A}/${IFACE_A}"
