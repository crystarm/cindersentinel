#!/usr/bin/env bash
set -euo pipefail

cs_common_dir="$(
  cd "$(dirname "${BASH_SOURCE[0]}")" && pwd
)"

ROOT_DIR="$(cd "${cs_common_dir}/.." && pwd)"
BUILD_HOST_DIR="${ROOT_DIR}/build-host"
BUILD_BPF_DIR="${ROOT_DIR}/build"

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
  command -v -- "$1" 2>/dev/null || true
}

ver1()
{
  local bin="${1:-}"
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

IFACE_A="${IFACE_A:-cs-vethA}"
IFACE_B="${IFACE_B:-cs-vethB}"
NS_A="${NS_A:-cs-a}"
NS_B="${NS_B:-cs-b}"
IP_A="${IP_A:-10.10.0.1/24}"
IP_B="${IP_B:-10.10.0.2/24}"
IP_A_PLAIN="${IP_A_PLAIN:-10.10.0.1}"
IP_B_PLAIN="${IP_B_PLAIN:-10.10.0.2}"

CMAKE_BUILD_TYPE="${CMAKE_BUILD_TYPE:-RelWithDebInfo}"
HOST_CC="${HOST_CC:-${CC:-clang}}"
HOST_CXX="${HOST_CXX:-${CXX:-clang++}}"

if [[ -z "${BPF_CLANG+x}" ]]; then
  if [[ "${HOST_CC}" == clang* ]]; then
    BPF_CLANG="${HOST_CC}"
  else
    BPF_CLANG="clang"
  fi
fi

CLANG_BIN="${CLANG_BIN:-${BPF_CLANG}}"

MULTIARCH="$(
  dpkg-architecture -qDEB_HOST_MULTIARCH 2>/dev/null || printf '%s\n' "x86_64-linux-gnu"
)"

BPF_CFLAGS=(
  -O2 -g -target bpf -D__TARGET_ARCH_x86
  "-I/usr/include/${MULTIARCH}"
  -I/usr/include
)

HOST_BIN="${BUILD_HOST_DIR}/cindersentineld"
CLI_BIN="${BUILD_HOST_DIR}/cindersentinel"
TC_OBJ="${BUILD_BPF_DIR}/cindersentinel_tc.bpf.o"
XDP_OBJ="${BUILD_BPF_DIR}/cindersentinel_xdp.bpf.o"

need_root()
{
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    exec sudo -E bash "$0" "$@"
  fi
}
