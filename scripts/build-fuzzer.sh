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

printf "  %-10s :  %-20s |  %s\n" "CC"  "${want_cc:-<not found>}"  "$(ver1 "${want_cc}")"
printf "  %-10s :  %-20s |  %s\n" "CXX" "${want_cxx:-<not found>}" "$(ver1 "${want_cxx}")"

if [[ -z "${want_cc}" || -z "${want_cxx}" ]]; then
  die "Missing compiler(s): HOST_CC='${HOST_CC}' -> '${want_cc:-<not found>}', HOST_CXX='${HOST_CXX}' -> '${want_cxx:-<not found>}'"
fi

cmake -S "${ROOT_DIR}" -B "${BUILD_HOST_DIR}" \
  -DCMAKE_BUILD_TYPE="${CMAKE_BUILD_TYPE}" \
  -DCMAKE_C_COMPILER="${want_cc}" \
  -DCMAKE_CXX_COMPILER="${want_cxx}" \
  -DENABLE_FUZZERS=ON
cmake --build "${BUILD_HOST_DIR}" -j

if command -v gnatmake >/dev/null 2>&1; then
  log_info "GNAT detected, building Ada validator"
  gnatmake -gnat2012 -O2 -o "${BUILD_HOST_DIR}/cindersentinel-aegis-ada" "${ROOT_DIR}/aegis/src/cindersentinel_aegis.adb"
else
  log_warn "GNAT not found; skipping Ada validator build"
fi

log_info "Built fuzzer: ${BUILD_HOST_DIR}/cindersentinel-cbor-fuzzer"