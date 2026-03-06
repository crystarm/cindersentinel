#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: repro.sh <input> [--] [extra libFuzzer args...]

Reproduce a crashing/mismatching input for cindersentinel-cbor-fuzzer.

Defaults:
  - Looks for fuzzer binary in ./build-host/cindersentinel-cbor-fuzzer
  - Uses ./build-host/cindersentinel-aegis-ada (required) as Ada validator
  - Runs with -runs=1

Env overrides:
  FUZZER_BIN=...        Path to cindersentinel-cbor-fuzzer
  AEGIS_BIN=...         Path to cindersentinel-aegis-ada (exported as CINDERSENTINEL_AEGIS)
  ASAN_OPTIONS=...      ASAN runtime options
  UBSAN_OPTIONS=...     UBSAN runtime options

Examples:
  ./repro.sh ./fuzzer/cbor/corpus/crash-1234
  FUZZER_BIN=./build-host/cindersentinel-cbor-fuzzer ./repro.sh ./crash.bin -runs=1 -print_final_stats=1
USAGE
}

if [[ $# -lt 1 ]]; then
  usage >&2
  exit 2
fi

input="$1"
shift || true

if [[ "$input" == "-h" || "$input" == "--help" ]]; then
  usage
  exit 0
fi

if [[ ! -f "$input" ]]; then
  echo "repro: input not found: $input" >&2
  exit 2
fi

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

fuzzer_bin_default="${root_dir}/build-host/cindersentinel-cbor-fuzzer"
aegis_bin_default="${root_dir}/build-host/cindersentinel-aegis-ada"

fuzzer_bin="${FUZZER_BIN:-$fuzzer_bin_default}"
aegis_bin="${AEGIS_BIN:-$aegis_bin_default}"

if [[ ! -x "$fuzzer_bin" ]]; then
  echo "repro: fuzzer binary not found or not executable: $fuzzer_bin" >&2
  echo "repro: build with: cmake -B build-host -DENABLE_FUZZERS=ON && cmake --build build-host" >&2
  exit 2
fi

if [[ ! -x "$aegis_bin" ]]; then
  echo "repro: Ada validator not found or not executable: $aegis_bin" >&2
  exit 2
fi
export CINDERSENTINEL_AEGIS="$aegis_bin"

export ASAN_OPTIONS="${ASAN_OPTIONS:-abort_on_error=1:halt_on_error=1:detect_leaks=0:allocator_may_return_null=1}"
export UBSAN_OPTIONS="${UBSAN_OPTIONS:-halt_on_error=1:print_stacktrace=1}"

args=()
if [[ $# -gt 0 ]]; then
  # Respect explicit args after input.
  args+=("$@")
else
  args+=("-runs=1")
fi

echo "repro: fuzzer: $fuzzer_bin"
if [[ -n "${CINDERSENTINEL_AEGIS:-}" ]]; then
  echo "repro: aegis:  $CINDERSENTINEL_AEGIS"
else
  echo "repro: aegis:  <not set>"
fi
echo "repro: input:  $input"
echo "repro: args:   ${args[*]}"

exec "$fuzzer_bin" "${args[@]}" "$input"