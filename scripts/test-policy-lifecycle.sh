#!/usr/bin/env bash
set -euo pipefail

script_dir="$(
  cd "$(dirname "${BASH_SOURCE[0]}")" && pwd
)"
source "${script_dir}/common.sh"

need_root "$@"

usage()
{
  cat <<USAGE
Usage:
  ${script_dir}/step3-test.sh tc
  ${script_dir}/step3-test.sh xdp
  ${script_dir}/step3-test.sh both

Environment overrides:
  IFACE_A, NS_A, NS_B, HOST_BIN, CLI_BIN, TC_OBJ, XDP_OBJ
  PIN_BASE (default /sys/fs/bpf/cindersentinel)
  STATE_ROOT (default /var/lib/cindersentinel)
USAGE
}

PIN_BASE="${PIN_BASE:-/sys/fs/bpf/cindersentinel}"
STATE_ROOT="${STATE_ROOT:-/var/lib/cindersentinel}"

ensure_bpffs()
{
  PIN_BASE="/run/bpf/cindersentinel"

  mkdir -p /run/bpf
  if ! mountpoint -q /run/bpf; then
    mount -t bpf bpf /run/bpf || die "cannot mount bpffs at /run/bpf"
  fi
  mkdir -p "${PIN_BASE}"

  if ! sudo -E ip netns exec "${NS_A}" bash -c "mkdir -p /run/bpf; mountpoint -q /run/bpf || mount --bind /proc/1/root/run/bpf /run/bpf; mountpoint -q /run/bpf"; then
    die "bpffs not visible inside netns ${NS_A} at /run/bpf"
  fi
  if ! sudo -E ip netns exec "${NS_A}" mkdir -p "${PIN_BASE}"; then
    die "cannot create pin base inside netns ${NS_A}: ${PIN_BASE}"
  fi
}

tmpdir="$(mktemp -d)"
cleanup_tmp()
{
  rm -rf "${tmpdir}" >/dev/null 2>&1 || true
}
trap cleanup_tmp EXIT

get_active_hash()
{
  local active="${STATE_ROOT}/${IFACE_A}/active"
  if [[ ! -f "${active}" ]]; then
    die "state active not found: ${active}"
  fi
  local h
  h="$(grep -m1 '^sha256=' "${active}" | cut -d= -f2)"
  if [[ -z "${h}" ]]; then
    die "state active missing sha256"
  fi
  printf '%s\n' "${h}"
}

get_active_policy_path()
{
  local h
  h="$(get_active_hash)"
  local p="${STATE_ROOT}/${IFACE_A}/policies/${h}.cbor"
  if [[ ! -f "${p}" ]]; then
    die "policy blob not found: ${p}"
  fi
  printf '%s\n' "${p}"
}

ensure_bins()
{
  if [[ ! -x "${HOST_BIN}" ]]; then
    die "Missing host daemon: ${HOST_BIN}"
  fi
  if [[ ! -x "${CLI_BIN}" ]]; then
    die "Missing cli: ${CLI_BIN}"
  fi
}

ensure_objs()
{
  local obj="$1"
  if [[ ! -f "${obj}" ]]; then
    die "Missing BPF object: ${obj}"
  fi
}

start_daemon()
{
  local backend="$1"
  local obj="$2"
  local extra="$3"
  local pidfile="$4"
  local logfile="$5"

  sudo -E ip netns exec "${NS_A}" bash -c "rm -f '${pidfile}'; '${HOST_BIN}' --backend ${backend} --iface '${IFACE_A}' --pin-root '${PIN_BASE}' --obj '${obj}' ${extra} >'${logfile}' 2>&1 & echo \$! >'${pidfile}'"
  sudo -E cat "${pidfile}"
}

stop_daemon()
{
  local pid="$1"
  local backend="$2"
  local extra="$3"

  sudo -E kill "${pid}" 2>/dev/null || true
  sudo -E ip netns exec "${NS_A}" "${HOST_BIN}" --backend "${backend}" --iface "${IFACE_A}" ${extra} --detach >/dev/null 2>&1 || true
}

check_pins()
{
  local backend="$1"
  local root="${PIN_BASE}/${IFACE_A}/${backend}/maps"
  for m in cs_cnt cs_blk_icmp cs_blk_tcp cs_blk_udp; do
    if ! sudo -E ip netns exec "${NS_A}" test -e "${root}/${m}"; then
      die "Pinned map missing: ${root}/${m}"
    fi
  done
}

run_invoke_stepback()
{
  local backend="$1"

  sudo -E ip netns exec "${NS_A}" "${CLI_BIN}" etch icmp forbid --iface "${IFACE_A}" --backend "${backend}" --pin-base "${PIN_BASE}"
  sudo -E ip netns exec "${NS_A}" "${CLI_BIN}" etch tcp forbid 8080 --iface "${IFACE_A}" --backend "${backend}" --pin-base "${PIN_BASE}"
  local p1
  p1="$(get_active_policy_path)"

  sudo -E ip netns exec "${NS_A}" "${CLI_BIN}" etch icmp let --iface "${IFACE_A}" --backend "${backend}" --pin-base "${PIN_BASE}"
  sudo -E ip netns exec "${NS_A}" "${CLI_BIN}" etch tcp let 8080 --iface "${IFACE_A}" --backend "${backend}" --pin-base "${PIN_BASE}"
  sudo -E ip netns exec "${NS_A}" "${CLI_BIN}" etch tcp forbid 9090 --iface "${IFACE_A}" --backend "${backend}" --pin-base "${PIN_BASE}"
  local p2
  p2="$(get_active_policy_path)"

  sudo -E ip netns exec "${NS_A}" "${CLI_BIN}" invoke "${p1}" --iface "${IFACE_A}" --backend "${backend}" --pin-base "${PIN_BASE}" --state-root "${STATE_ROOT}"
  sudo -E ip netns exec "${NS_A}" "${CLI_BIN}" aura --iface "${IFACE_A}" --backend "${backend}" --pin-base "${PIN_BASE}"

  sudo -E ip netns exec "${NS_A}" "${CLI_BIN}" invoke "${p2}" --iface "${IFACE_A}" --backend "${backend}" --pin-base "${PIN_BASE}" --state-root "${STATE_ROOT}"
  sudo -E ip netns exec "${NS_A}" "${CLI_BIN}" aura --iface "${IFACE_A}" --backend "${backend}" --pin-base "${PIN_BASE}"

  sudo -E ip netns exec "${NS_A}" "${CLI_BIN}" stepback --iface "${IFACE_A}" --backend "${backend}" --pin-base "${PIN_BASE}" --state-root "${STATE_ROOT}"
  sudo -E ip netns exec "${NS_A}" "${CLI_BIN}" aura --iface "${IFACE_A}" --backend "${backend}" --pin-base "${PIN_BASE}"
}

run_etch_sync()
{
  local backend="$1"
  sudo -E ip netns exec "${NS_A}" "${CLI_BIN}" etch icmp forbid --iface "${IFACE_A}" --backend "${backend}" --pin-base "${PIN_BASE}"
  sudo -E ip netns exec "${NS_A}" "${CLI_BIN}" etch tcp forbid 7070 --iface "${IFACE_A}" --backend "${backend}" --pin-base "${PIN_BASE}"
  sudo -E ip netns exec "${NS_A}" "${CLI_BIN}" stepback --iface "${IFACE_A}" --backend "${backend}" --pin-base "${PIN_BASE}" --state-root "${STATE_ROOT}"
}

test_tc()
{
  "${script_dir}/build-host.sh"
  "${script_dir}/build-bpf.sh"
  ensure_bins
  ensure_objs "${TC_OBJ}"

  sudo -E "${script_dir}/netns-up.sh"
  ensure_bpffs

  log_info "starting tc daemon"
  pidfile="/tmp/cindersentineld-tc.pid"
  logfile="/tmp/cindersentineld-tc.log"
  daemon_pid="$(start_daemon tc "${TC_OBJ}" "" "${pidfile}" "${logfile}")"
  trap "stop_daemon '${daemon_pid}' tc ''" EXIT

  sleep 0.2
  check_pins tc

  run_invoke_stepback tc
  run_etch_sync tc
}

test_xdp()
{
  "${script_dir}/build-host.sh"
  "${script_dir}/build-bpf.sh"
  ensure_bins
  ensure_objs "${XDP_OBJ}"

  sudo -E "${script_dir}/netns-up.sh"
  ensure_bpffs

  log_info "starting xdp daemon"
  pidfile="/tmp/cindersentineld-xdp.pid"
  logfile="/tmp/cindersentineld-xdp.log"
  daemon_pid="$(start_daemon xdp "${XDP_OBJ}" "--xdp-mode generic" "${pidfile}" "${logfile}")"
  trap "stop_daemon '${daemon_pid}' xdp '--xdp-mode generic'" EXIT

  sleep 0.2
  check_pins xdp

  run_invoke_stepback xdp
  run_etch_sync xdp
}

cmd="${1:-}"
case "${cmd}" in
  tc)
    test_tc
    ;;
  xdp)
    test_xdp
    ;;
  both)
    test_tc
    test_xdp
    ;;
  -h|--help|"")
    usage
    ;;
  *)
    die "Unknown command: ${cmd}"
    ;;
esac