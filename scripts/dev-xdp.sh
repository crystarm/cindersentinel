#!/usr/bin/env bash
set -euo pipefail

script_dir="$(
  cd "$(dirname "${BASH_SOURCE[0]}")" && pwd
)"
source "${script_dir}/common.sh"

"${script_dir}/build-bpf.sh"
sudo -E "${script_dir}/netns-up.sh"
sudo -E "${script_dir}/xdp-detach.sh" || true

if [[ ! -f "${XDP_OBJ}" ]]; then
  die "Missing: ${XDP_OBJ}"
fi

sudo -E "${script_dir}/xdp-attach.sh"

log_info "ping:"
printf '  ip netns exec %s ping -c 2 %s\n' "${NS_A}" "${IP_B_PLAIN}"
sudo -E ip netns exec "${NS_A}" ping -c 2 "${IP_B_PLAIN}" || true

log_info "counters:"
exec sudo -E "${CLI_BIN}" embers --watch --interval-ms 500
