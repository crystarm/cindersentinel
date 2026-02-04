#!/usr/bin/env bash
set -euo pipefail

script_dir="$(
  cd "$(dirname "${BASH_SOURCE[0]}")" && pwd
)"
source "${script_dir}/common.sh"

"${script_dir}/build-host.sh"
"${script_dir}/build-bpf.sh"

sudo -E "${script_dir}/netns-up.sh"

if [[ ! -f "${TC_OBJ}" ]]; then
  die "Missing: ${TC_OBJ}"
fi

if [[ ! -x "${HOST_BIN}" ]]; then
  if [[ -f "${HOST_BIN}" ]]; then
    die "Not executable: ${HOST_BIN}"
  fi
  die "Missing: ${HOST_BIN}"
fi

log_info "running tc backend:"
printf '  %s --backend tc --iface %s --obj %s\n' "${HOST_BIN}" "${IFACE_A}" "${TC_OBJ}"
exec sudo -E ip netns exec "${NS_A}" "${HOST_BIN}" --backend tc --iface "${IFACE_A}" --obj "${TC_OBJ}"
