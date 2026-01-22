#!/usr/bin/env bash
set -euo pipefail

script_dir="$(
  cd "$(dirname "${BASH_SOURCE[0]}")" && pwd
)"
source "${script_dir}/common.sh"

log_info()
{
  printf '%s\n' "$*"
}

log_warn()
{
  printf '%s\n' "$*" >&2
}

log_err()
{
  printf '%s\n' "$*" >&2
}

die()
{
  log_err "$*"
  exit 1
}

resolve_bin()
{
  command -v "$1" 2>/dev/null || true
}

ver1()
{
  local bin="$1"
  local out=""

  if [[ -z "${bin}" ]]; then
    printf '%s' "<not found>"
    return 0
  fi

  out="$("${bin}" --version 2>/dev/null | head -n 1 || true)"
  if [[ -z "${out}" ]]; then
    out="<unknown>"
  fi
  printf '%s' "${out}"
}

want_cc="$(resolve_bin "${HOST_CC}")"
want_cxx="$(resolve_bin "${HOST_CXX}")"
want_bpf_clang="$(resolve_bin "${BPF_CLANG}")"

printf "  %-10s :  %-20s |  %s\n" "CC"        "${want_cc:-<not found>}"        "$(ver1 "${want_cc}")"
printf "  %-10s :  %-20s |  %s\n" "CXX"       "${want_cxx:-<not found>}"       "$(ver1 "${want_cxx}")"
printf "  %-10s :  %-20s |  %s\n" "BPF clang" "${want_bpf_clang:-<not found>}" "$(ver1 "${want_bpf_clang}")"

if [[ -z "${want_cc}" || -z "${want_cxx}" ]]; then
  die "Missing compiler(s): HOST_CC='${HOST_CC}' -> '${want_cc:-<not found>}', HOST_CXX='${HOST_CXX}' -> '${want_cxx:-<not found>}'"
fi

if [[ -z "${want_bpf_clang}" ]]; then
  die "Missing BPF clang: BPF_CLANG='${BPF_CLANG}' -> <not found>"
fi

if [[ -f "${BUILD_HOST_DIR}/CMakeCache.txt" ]]; then
  cur_cc="$(grep -E '^CMAKE_C_COMPILER:FILEPATH=' "${BUILD_HOST_DIR}/CMakeCache.txt" | cut -d= -f2- || true)"
  cur_cxx="$(grep -E '^CMAKE_CXX_COMPILER:FILEPATH=' "${BUILD_HOST_DIR}/CMakeCache.txt" | cut -d= -f2- || true)"
  if [[ -n "${cur_cc}" && -n "${cur_cxx}" ]]; then
    if [[ "${cur_cc}" != "${want_cc}" || "${cur_cxx}" != "${want_cxx}" ]]; then
      log_err "CMake compiler change detected:"
      log_err "  was: C=${cur_cc}, CXX=${cur_cxx}"
      log_err "  now: C=${want_cc}, CXX=${want_cxx}"
      rm -rf "${BUILD_HOST_DIR}"
    fi
  fi
fi

cmake -S "${ROOT_DIR}" -B "${BUILD_HOST_DIR}" \
  -DCMAKE_BUILD_TYPE="${CMAKE_BUILD_TYPE}" \
  -DCMAKE_C_COMPILER="${want_cc}" \
  -DCMAKE_CXX_COMPILER="${want_cxx}" \
  -DCLANG="${want_bpf_clang}"
cmake --build "${BUILD_HOST_DIR}" -j

log_info "Built host: ${HOST_BIN}"
log_info "Built cli:  ${CLI_BIN}"
