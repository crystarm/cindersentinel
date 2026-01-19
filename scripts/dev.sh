#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

usage()
{
  cat <<USAGE
Usage:
  ${SCRIPT_DIR}/dev.sh build            - build host + bpf objects
  ${SCRIPT_DIR}/dev.sh up               - create netns testbed
  ${SCRIPT_DIR}/dev.sh down             - destroy netns testbed
  ${SCRIPT_DIR}/dev.sh tc               - build everything + run cindersentineld (tc backend) inside netns
  ${SCRIPT_DIR}/dev.sh xdp              - build bpf + attach xdp + ping + watch counters
  ${SCRIPT_DIR}/dev.sh xdp-on           - attach xdp (generic) on cs-a/${IFACE_A}
  ${SCRIPT_DIR}/dev.sh xdp-off          - detach xdp
  ${SCRIPT_DIR}/dev.sh counters         - watch counters map

  ${SCRIPT_DIR}/dev.sh icmp on|off|show
  ${SCRIPT_DIR}/dev.sh tcp  block|unblock|show <port?>
  ${SCRIPT_DIR}/dev.sh udp  block|unblock|show <port?>

  ${SCRIPT_DIR}/dev.sh clean            - alias for down
USAGE
}

cmd="${1:-}"
shift || true

case "${cmd}" in
  build)
    "${SCRIPT_DIR}/build-host.sh"
    "${SCRIPT_DIR}/build-bpf.sh"
    ;;

  up)
    sudo -E "${SCRIPT_DIR}/netns-up.sh" "$@"
    ;;

  down|clean)
    sudo -E "${SCRIPT_DIR}/netns-down.sh" "$@"
    ;;

  tc)
    exec "${SCRIPT_DIR}/dev-tc.sh" "$@"
    ;;

  xdp)
    exec "${SCRIPT_DIR}/dev-xdp.sh" "$@"
    ;;

  xdp-on)
    sudo -E "${SCRIPT_DIR}/xdp-attach.sh" "$@"
    ;;

  xdp-off)
    sudo -E "${SCRIPT_DIR}/xdp-detach.sh" "$@"
    ;;

  counters)
    sudo -E "${SCRIPT_DIR}/watch-counters.sh" "$@"
    ;;

  icmp|tcp|udp)
    sudo -E "${SCRIPT_DIR}/rules.sh" "${cmd}" "$@"
    ;;

  -h|--help|"")
    usage
    ;;

  *)
    echo "Unknown command: ${cmd}"
    usage
    exit 2
    ;;
esac
