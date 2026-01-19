#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/common.sh"
need_root "$@"

ip netns del "${NS_A}" 2>/dev/null || true
ip netns del "${NS_B}" 2>/dev/null || true
ip link del "${IFACE_A}" 2>/dev/null || true

ip netns add "${NS_A}"
ip netns add "${NS_B}"

ip link add "${IFACE_A}" type veth peer name "${IFACE_B}"
ip link set "${IFACE_A}" netns "${NS_A}"
ip link set "${IFACE_B}" netns "${NS_B}"

ip netns exec "${NS_A}" ip addr add "${IP_A}" dev "${IFACE_A}"
ip netns exec "${NS_B}" ip addr add "${IP_B}" dev "${IFACE_B}"

ip netns exec "${NS_A}" ip link set "${IFACE_A}" up
ip netns exec "${NS_B}" ip link set "${IFACE_B}" up
ip netns exec "${NS_A}" ip link set lo up
ip netns exec "${NS_B}" ip link set lo up

ip netns exec "${NS_A}" ping -c 1 "${IP_B_PLAIN}" >/dev/null
echo "netns ready: ${NS_A}:${IFACE_A} <-> ${NS_B}:${IFACE_B}"
