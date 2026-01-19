#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/common.sh"

SCRIPT_DIR="$(dirname "$0")"

"${SCRIPT_DIR}/build-host.sh"
"${SCRIPT_DIR}/build-bpf.sh"

sudo -E "${SCRIPT_DIR}/netns-up.sh"

if [[ ! -f "${TC_OBJ}" ]]; then
  echo "Missing: ${TC_OBJ}"
  exit 1
fi

sudo -E ip netns exec "${NS_A}" tc filter del dev "${IFACE_A}" ingress 2>/dev/null || true
sudo -E ip netns exec "${NS_A}" tc qdisc del dev "${IFACE_A}" clsact 2>/dev/null || true
sudo -E ip netns exec "${NS_A}" tc qdisc replace dev "${IFACE_A}" clsact >/dev/null 2>&1 || true

echo "running tc backend:"
echo "  ${HOST_BIN} --iface ${IFACE_A} --obj ${TC_OBJ}"
exec sudo -E ip netns exec "${NS_A}" "${HOST_BIN}" --iface "${IFACE_A}" --obj "${TC_OBJ}"
