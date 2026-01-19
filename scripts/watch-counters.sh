#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/common.sh"
need_root "$@"

MAP_ID="$(
  bpftool map show | awk '
    /name cs_cnt/ { id=$1 }
    END {
      if (id == "") exit 1;
      sub(":", "", id);
      print id
    }'
)" || {
  echo "Cannot find map: cs_cnt"
  exit 1
}

echo "watching counters map id=${MAP_ID}"
trap 'exit 0' INT TERM

bpftool map dump id "${MAP_ID}" >/dev/null 2>&1 || true

while true; do
  bpftool map dump id "${MAP_ID}" | awk '
    function le32_to_int(a,b,c,d) { return a + 256*b + 65536*c + 16777216*d }
    function key_name(k) {
      if (k==0) return "passed";
      if (k==1) return "dropped";
      if (k==2) return "drop_icmp";
      if (k==3) return "drop_tcp_port";
      if (k==4) return "drop_udp_port";
      return "key" k;
    }
    /^key:/ {
      if (have) {
        printf "%s=%llu ", key_name(cur_key), sum
      }
      a=strtonum("0x"$2); b=strtonum("0x"$3); c=strtonum("0x"$4); d=strtonum("0x"$5);
      cur_key=le32_to_int(a,b,c,d);
      sum=0;
      have=1;
      next
    }
    /cpu[0-9]+:/ { sum += $NF; next }
    END {
      if (have) {
        printf "%s=%llu\n", key_name(cur_key), sum
      } else {
        printf "\n"
      }
    }'
  sleep 1
done
