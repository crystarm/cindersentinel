#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/common.sh"

mkdir -p "${BUILD_BPF_DIR}"

if [[ -f "${ROOT_DIR}/bpf/cindersentinel_tc.bpf.c" ]]; then
  "${CLANG_BIN}" "${BPF_CFLAGS[@]}" \
    -c "${ROOT_DIR}/bpf/cindersentinel_tc.bpf.c" \
    -o "${TC_OBJ}"
  echo "Built: ${TC_OBJ}"
else
  echo "Skip: bpf/cindersentinel_tc.bpf.c not found"
fi

if [[ -f "${ROOT_DIR}/bpf/cindersentinel_xdp.bpf.c" ]]; then
  "${CLANG_BIN}" "${BPF_CFLAGS[@]}" \
    -c "${ROOT_DIR}/bpf/cindersentinel_xdp.bpf.c" \
    -o "${XDP_OBJ}"
  echo "Built: ${XDP_OBJ}"
else
  echo "Skip: bpf/cindersentinel_xdp.bpf.c not found"
fi
