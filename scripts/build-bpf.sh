#!/usr/bin/env bash
set -euo pipefail

script_dir="$(
  cd "$(dirname "${BASH_SOURCE[0]}")" && pwd
)"
source "${script_dir}/common.sh"

if ! declare -F log_info >/dev/null 2>&1; then
  log_info()
  {
    printf '%s\n' "$*"
  }
fi

if ! declare -F log_warn >/dev/null 2>&1; then
  log_warn()
  {
    printf '%s\n' "$*" >&2
  }
fi

if ! declare -F log_err >/dev/null 2>&1; then
  log_err()
  {
    printf '%s\n' "$*" >&2
  }
fi

if ! declare -F die >/dev/null 2>&1; then
  die()
  {
    log_err "$*"
    exit 1
  }
fi

mkdir -p "${BUILD_BPF_DIR}"

if [[ -f "${ROOT_DIR}/bpf/cindersentinel_tc.bpf.c" ]]; then
  "${CLANG_BIN}" "${BPF_CFLAGS[@]}" \
    -c "${ROOT_DIR}/bpf/cindersentinel_tc.bpf.c" \
    -o "${TC_OBJ}"
  log_info "Built: ${TC_OBJ}"
else
  log_info "Skip: bpf/cindersentinel_tc.bpf.c not found"
fi

if [[ -f "${ROOT_DIR}/bpf/cindersentinel_xdp.bpf.c" ]]; then
  "${CLANG_BIN}" "${BPF_CFLAGS[@]}" \
    -c "${ROOT_DIR}/bpf/cindersentinel_xdp.bpf.c" \
    -o "${XDP_OBJ}"
  log_info "Built: ${XDP_OBJ}"
else
  log_info "Skip: bpf/cindersentinel_xdp.bpf.c not found"
fi
