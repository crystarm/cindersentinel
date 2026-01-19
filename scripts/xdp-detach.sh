#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/common.sh"
need_root "$@"

ip netns exec "${NS_A}" ip link set dev "${IFACE_A}" xdpgeneric off 2>/dev/null || true
echo "xdp detached: ${NS_A}/${IFACE_A}"
