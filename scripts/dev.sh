#!/usr/bin/env bash
set -euo pipefail

script_dir="$(
  cd "$(dirname "${BASH_SOURCE[0]}")" && pwd
)"
source "${script_dir}/common.sh"

usage()
{
  cat <<USAGE
Usage:
  ${script_dir}/dev.sh build            - build host + bpf objects
  ${script_dir}/dev.sh up               - create netns testbed
  ${script_dir}/dev.sh down             - destroy netns testbed
  ${script_dir}/dev.sh tc               - build everything + run cindersentineld (tc backend) inside netns
  ${script_dir}/dev.sh xdp              - build bpf + attach xdp + ping + watch counters
  ${script_dir}/dev.sh xdp-on           - attach xdp (generic) on cs-a/${IFACE_A}
  ${script_dir}/dev.sh xdp-off          - detach xdp
  ${script_dir}/dev.sh counters         - watch counters map

    ${script_dir}/dev.sh icmp forbid|let|show
    ${script_dir}/dev.sh tcp  forbid|let|show <port?>
    ${script_dir}/dev.sh udp  forbid|let|show <port?>

  ${script_dir}/dev.sh clean            - alias for down
USAGE
}

cmd="${1:-}"
shift || true

case "${cmd}" in
  build)
    "${script_dir}/build-host.sh"
    "${script_dir}/build-bpf.sh"
    ;;

  up)
    sudo -E "${script_dir}/netns-up.sh" "$@"
    ;;

  down|clean)
    sudo -E "${script_dir}/netns-down.sh" "$@"
    ;;

  tc)
    exec "${script_dir}/dev-tc.sh" "$@"
    ;;

  xdp)
    exec "${script_dir}/dev-xdp.sh" "$@"
    ;;

  xdp-on)
    sudo -E "${script_dir}/xdp-attach.sh" "$@"
    ;;

  xdp-off)
    sudo -E "${script_dir}/xdp-detach.sh" "$@"
    ;;

  counters)
    sudo -E "${CLI_BIN}" embers --iface "${IFACE_A}" --backend tc --watch --interval-ms 1000
    ;;

  icmp|tcp|udp)
    sudo -E "${CLI_BIN}" etch "${cmd}" "$@" --iface "${IFACE_A}" --backend tc
    ;;

  -h|--help|"")
    usage
    ;;

  *)
    log_err "Unknown command: ${cmd}"
    usage
    exit 2
    ;;
esac
