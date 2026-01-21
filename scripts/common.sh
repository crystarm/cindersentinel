#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_HOST_DIR="${ROOT_DIR}/build-host"
BUILD_BPF_DIR="${ROOT_DIR}/build"

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

# BPF toolchain. By default we try to follow host clang version if HOST_CC looks like clang*,
# otherwise we fall back to plain "clang".
if [[ -z "${BPF_CLANG+x}" ]]; then
  if [[ "${HOST_CC}" == clang* ]]; then
    BPF_CLANG="${HOST_CC}"
  else
    BPF_CLANG="clang"
  fi
fi

CLANG_BIN="${CLANG_BIN:-${BPF_CLANG}}"

MULTIARCH="$(
  dpkg-architecture -qDEB_HOST_MULTIARCH 2>/dev/null || echo x86_64-linux-gnu
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
