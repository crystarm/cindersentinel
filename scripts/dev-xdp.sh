#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/common.sh"

"$(dirname "$0")/build-bpf.sh"

sudo -E "$(dirname "$0")/netns-up.sh"
sudo -E "$(dirname "$0")/xdp-attach.sh"

echo "generating traffic:"
sudo -E ip netns exec "${NS_A}" ping -c 3 "${IP_B_PLAIN}" || true

echo "counters (Ctrl+C to stop):"
exec sudo -E "$(dirname "$0")/watch-counters.sh"
