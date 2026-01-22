#!/usr/bin/env bash
set -euo pipefail

script_dir="$(
  cd "$(dirname "${BASH_SOURCE[0]}")" && pwd
)"
source "${script_dir}/common.sh"
need_root "$@"

if [[ -z "$(resolve_bin bpftool)" ]]; then
  die "rules.sh: bpftool not found"
fi

MAP_ICMP="${MAP_ICMP:-cs_blk_icmp}"
MAP_TCP="${MAP_TCP:-cs_blk_tcp}"
MAP_UDP="${MAP_UDP:-cs_blk_udp}"

find_map_id()
{
  local name="$1"
  local id

  id="$(bpftool map show | awk -v n="$name" '
    $0 ~ (" name " n " ") { gsub(":", "", $1); id=$1 }
    END { if (id=="") exit 1; print id }
  ')" || {
    log_err "cannot find map by name: ${name}"
    bpftool map show | sed -n '1,80p' >&2
    exit 1
  }

  printf '%s\n' "${id}"
}

u16_le_bytes()
{
  local port="$1"
  local lo=$((port & 255))
  local hi=$(((port >> 8) & 255))
  printf '%d %d\n' "${lo}" "${hi}"
}

cmd="${1:-}"; shift || true

case "${cmd}" in
  icmp)
    mode="${1:-}"; shift || true
    map_id="$(find_map_id "${MAP_ICMP}")"
    case "${mode}" in
      on)   bpftool map update id "${map_id}" key 0 0 0 0 value 1 ;;
      off)  bpftool map update id "${map_id}" key 0 0 0 0 value 0 ;;
      show) bpftool map dump id "${map_id}" ;;
      *) die "rules.sh: usage: rules.sh icmp on|off|show" ;;
    esac
    ;;

  tcp)
    sub="${1:-}"; shift || true
    map_id="$(find_map_id "${MAP_TCP}")"
    case "${sub}" in
      block)
        port="${1:?port}"
        bytes="$(u16_le_bytes "${port}")"
        bpftool map update id "${map_id}" key ${bytes} value 1
        ;;
      unblock)
        port="${1:?port}"
        bytes="$(u16_le_bytes "${port}")"
        bpftool map delete id "${map_id}" key ${bytes} 2>/dev/null || true
        ;;
      show)
        bpftool map dump id "${map_id}"
        ;;
      *) die "rules.sh: usage: rules.sh tcp block|unblock|show <port?>" ;;
    esac
    ;;

  udp)
    sub="${1:-}"; shift || true
    map_id="$(find_map_id "${MAP_UDP}")"
    case "${sub}" in
      block)
        port="${1:?port}"
        bytes="$(u16_le_bytes "${port}")"
        bpftool map update id "${map_id}" key ${bytes} value 1
        ;;
      unblock)
        port="${1:?port}"
        bytes="$(u16_le_bytes "${port}")"
        bpftool map delete id "${map_id}" key ${bytes} 2>/dev/null || true
        ;;
      show)
        bpftool map dump id "${map_id}"
        ;;
      *) die "rules.sh: usage: rules.sh udp block|unblock|show <port?>" ;;
    esac
    ;;

  *)
    die "rules.sh: usage: rules.sh icmp|tcp|udp ..."
    ;;
esac
