#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/common.sh"

resolve_bin()
{
  command -v "$1" 2>/dev/null || true
}

want_cc="$(resolve_bin "${HOST_CC}")"
want_cxx="$(resolve_bin "${HOST_CXX}")"
want_bpf_clang="$(resolve_bin "${BPF_CLANG}")"

ver1()
{
  "$1" --version 2>/dev/null | head -n 1
}

printf "  %-10s :  %-20s |  %s\n" "CC"        "$want_cc"        "$(ver1 "$want_cc")"
printf "  %-10s :  %-20s |  %s\n" "CXX"       "$want_cxx"       "$(ver1 "$want_cxx")"
printf "  %-10s :  %-20s |  %s\n" "BPF clang" "$want_bpf_clang" "$(ver1 "$want_bpf_clang")"


if [[ -z "${want_cc}" || -z "${want_cxx}" ]]; then
  echo "Missing compiler(s): HOST_CC='${HOST_CC}' -> '${want_cc:-<not found>}', HOST_CXX='${HOST_CXX}' -> '${want_cxx:-<not found>}'" >&2
  exit 1
fi

if [[ -z "${want_bpf_clang}" ]]; then
  echo "Missing BPF clang: BPF_CLANG='${BPF_CLANG}' -> <not found>" >&2
  exit 1
fi

if [[ -f "${BUILD_HOST_DIR}/CMakeCache.txt" ]]; then
  cur_cc="$(grep -E '^CMAKE_C_COMPILER:FILEPATH=' "${BUILD_HOST_DIR}/CMakeCache.txt" | cut -d= -f2- || true)"
  cur_cxx="$(grep -E '^CMAKE_CXX_COMPILER:FILEPATH=' "${BUILD_HOST_DIR}/CMakeCache.txt" | cut -d= -f2- || true)"
  if [[ -n "${cur_cc}" && -n "${cur_cxx}" ]]; then
    if [[ "${cur_cc}" != "${want_cc}" || "${cur_cxx}" != "${want_cxx}" ]]; then
      echo "CMake compiler change detected:" >&2
      echo "  was: C=${cur_cc}, CXX=${cur_cxx}" >&2
      echo "  now: C=${want_cc}, CXX=${want_cxx}" >&2
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

echo "Built host: ${HOST_BIN}"
echo "Built cli:  ${CLI_BIN}"
