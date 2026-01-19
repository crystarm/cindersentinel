#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/common.sh"
need_root "$@"

ip netns del "${NS_A}" 2>/dev/null || true
ip netns del "${NS_B}" 2>/dev/null || true
ip link del "${IFACE_A}" 2>/dev/null || true
echo "netns cleaned"
