#!/usr/bin/env bash
set -euo pipefail

script_dir="$(
  cd "$(dirname "${BASH_SOURCE[0]}")" && pwd
)"
source "${script_dir}/common.sh"

${script_dir}/build-host.sh
"${script_dir}/build-bpf.sh"
sudo -E "${script_dir}/netns-up.sh"
sudo -E ip netns exec "${NS_A}" "${HOST_BIN}" --backend xdp --xdp-mode generic --iface "${IFACE_A}" --detach || true

if [[ ! -f "${XDP_OBJ}" ]]; then
  die "Missing: ${XDP_OBJ}"
fi

if [[ ! -x "${HOST_BIN}" ]]; then
  if [[ -f "${HOST_BIN}" ]]; then
    die "Not executable: ${HOST_BIN}"
  fi
  die "Missing: ${HOST_BIN}"
fi

log_info "running xdp backend (daemon, generic):"
pidfile="/tmp/cindersentineld-xdp.pid"
logfile="/tmp/cindersentineld-xdp.log"

sudo -E ip netns exec "${NS_A}" bash -c "rm -f '${pidfile}'; '${HOST_BIN}' --backend xdp --xdp-mode generic --iface '${IFACE_A}' --obj '${XDP_OBJ}' >'${logfile}' 2>&1 & echo \$! >'${pidfile}'"
daemon_pid="$(sudo -E cat "${pidfile}")"

cleanup()
{
  sudo -E kill "${daemon_pid}" 2>/dev/null || true
  sudo -E ip netns exec "${NS_A}" "${HOST_BIN}" --backend xdp --xdp-mode generic --iface "${IFACE_A}" --detach >/dev/null 2>&1 || true
  sudo -E rm -f "${pidfile}" >/dev/null 2>&1 || true
}
trap cleanup EXIT
sleep 0.2

log_info "ping:"
printf '  ip netns exec %s ping -c 2 %s\n' "${NS_A}" "${IP_B_PLAIN}"
sudo -E ip netns exec "${NS_A}" ping -c 2 "${IP_B_PLAIN}" || true

log_info "counters:"
sudo -E "${CLI_BIN}" embers --iface "${IFACE_A}" --backend xdp --watch --interval-ms 500
