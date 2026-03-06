#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: podman-fuzz.sh <command> [options]

Commands:
  build-image        Build the fuzzing image (podman).
  run-fuzz           Run libFuzzer in the container.
  run-repro          Reproduce a single input in the container.
  run-cov            Run corpus-based coverage and generate HTML with llvm-cov.

Common options (env):
  PODMAN_IMAGE        Image to use (default: docker.io/library/debian:13)
  PODMAN_NAME         Container name (default: cs-fuzz)
  WORKDIR             Project workdir inside container (default: /work)

Fuzzing options (env):
  FUZZ_TIME_SEC       Fuzzing time in seconds (default: 3600)
  FUZZ_JOBS           libFuzzer -jobs (default: 1)
  FUZZ_WORKERS        libFuzzer -workers (default: 1)
  FUZZ_SEED_DIR       Seed corpus directory (default: fuzzer/cbor/corpus)
  FUZZ_CORPUS_DIR     Runtime corpus directory (default: fuzzer/cbor/corpus.run)
  FUZZ_ARTIFACT_DIR   Crash artifacts directory (default: fuzzer/cbor/artifacts)
  FUZZ_ARGS           Extra libFuzzer args (default: empty)
  CINDERSENTINEL_AEGIS  Path to Ada validator (required; default: build-host/cindersentinel-aegis-ada)
  CINDERSENTINEL_AEGIS_TIMEOUT_MS  Ada validator timeout in ms (default: 1000)

Repro options (env):
  REPRO_INPUT         Input file to reproduce (required for run-repro)

Coverage options (env):
  COV_OUT_DIR         Output dir for HTML report (default: fuzzer/cbor/coverage-html)
  COV_PROFILE_DIR     Directory to store raw profiles (default: fuzzer/cbor/coverage-profraw)
  COV_SEED_DIR        Seed corpus for coverage (default: fuzzer/cbor/corpus)
  COV_CORPUS_DIR      Additional corpus (default: fuzzer/cbor/corpus.run)

Examples:
  ./podman-fuzz.sh build-image
  FUZZ_TIME_SEC=600 ./podman-fuzz.sh run-fuzz
  REPRO_INPUT=./fuzzer/cbor/artifacts/crash-abc ./podman-fuzz.sh run-repro
  ./podman-fuzz.sh run-cov
USAGE
}

command="${1:-}"
if [[ -z "$command" || "$command" == "-h" || "$command" == "--help" ]]; then
  usage
  exit 0
fi

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

PODMAN_IMAGE="${PODMAN_IMAGE:-docker.io/library/debian:13}"
PODMAN_NAME="${PODMAN_NAME:-cs-fuzz}"
WORKDIR="${WORKDIR:-/work}"

FUZZ_TIME_SEC="${FUZZ_TIME_SEC:-3600}"
FUZZ_JOBS="${FUZZ_JOBS:-1}"
FUZZ_WORKERS="${FUZZ_WORKERS:-1}"
FUZZ_SEED_DIR="${FUZZ_SEED_DIR:-fuzzer/cbor/corpus}"
FUZZ_CORPUS_DIR="${FUZZ_CORPUS_DIR:-fuzzer/cbor/corpus.run}"
FUZZ_ARTIFACT_DIR="${FUZZ_ARTIFACT_DIR:-fuzzer/cbor/artifacts}"
FUZZ_ARGS="${FUZZ_ARGS:-}"

REPRO_INPUT="${REPRO_INPUT:-}"

COV_OUT_DIR="${COV_OUT_DIR:-fuzzer/cbor/coverage-html}"
COV_PROFILE_DIR="${COV_PROFILE_DIR:-fuzzer/cbor/coverage-profraw}"
COV_SEED_DIR="${COV_SEED_DIR:-fuzzer/cbor/corpus}"
COV_CORPUS_DIR="${COV_CORPUS_DIR:-fuzzer/cbor/corpus.run}"

uid="$(id -u)"
gid="$(id -g)"

ensure_dirs() {
  mkdir -p "${root_dir}/${FUZZ_CORPUS_DIR}" \
           "${root_dir}/${FUZZ_ARTIFACT_DIR}" \
           "${root_dir}/${COV_OUT_DIR}" \
           "${root_dir}/${COV_PROFILE_DIR}"
}

build_image() {
  podman pull "${PODMAN_IMAGE}"
  podman run --rm -t \
    --pull=never \
    -v "${root_dir}:${WORKDIR}" \
    -w "${WORKDIR}" \
    -e "CI=1" \
    -e "UID=${uid}" \
    -e "GID=${gid}" \
    "${PODMAN_IMAGE}" \
    bash -lc '
      set -euo pipefail
      export DEBIAN_FRONTEND=noninteractive
      apt-get update
      apt-get install -y --no-install-recommends \
        ca-certificates \
        cmake make pkg-config \
        clang lld llvm \
        g++ \
        gnat \
        libssl-dev \
        libbpf-dev libelf-dev zlib1g-dev \
        dpkg-dev \
        xz-utils git
      echo "clang: $(clang --version | head -n1 || true)"
      echo "cmake: $(cmake --version | head -n1 || true)"
      echo "libbpf (pkg-config): $(pkg-config --modversion libbpf || true)"
      echo "ok: toolchain ready"
    '
}

run_fuzz() {
  ensure_dirs
  podman run --rm -t \
    --pull=never \
    -v "${root_dir}:${WORKDIR}" \
    -w "${WORKDIR}" \
    -e "CI=1" \
    -e "UID=${uid}" \
    -e "GID=${gid}" \
    "${PODMAN_IMAGE}" \
    bash -lc "
      set -euo pipefail
      export DEBIAN_FRONTEND=noninteractive
      apt-get update
      apt-get install -y --no-install-recommends \
        ca-certificates \
        cmake make pkg-config \
        clang lld llvm \
        g++ \
        gnat \
        libssl-dev \
        libbpf-dev libelf-dev zlib1g-dev \
        dpkg-dev \
        xz-utils git

      cmake -S . -B build-host -DENABLE_FUZZERS=ON -DCMAKE_BUILD_TYPE=RelWithDebInfo
      cmake --build build-host -j

      gnatmake -gnat2012 -O2 -o build-host/cindersentinel-aegis-ada aegis/src/cindersentinel_aegis.adb

      export ASAN_OPTIONS=\"\${ASAN_OPTIONS:-abort_on_error=1:halt_on_error=1:detect_leaks=0:allocator_may_return_null=1}\"
      export UBSAN_OPTIONS=\"\${UBSAN_OPTIONS:-halt_on_error=1:print_stacktrace=1}\"
      export CINDERSENTINEL_AEGIS=\"\${CINDERSENTINEL_AEGIS:-${WORKDIR}/build-host/cindersentinel-aegis-ada}\"
      if [[ ! -x \"\${CINDERSENTINEL_AEGIS}\" ]]; then
        echo \"error: Ada validator not found: \${CINDERSENTINEL_AEGIS}\" >&2
        exit 2
      fi

      mkdir -p \"${FUZZ_CORPUS_DIR}\" \"${FUZZ_ARTIFACT_DIR}\"

      ./build-host/cindersentinel-cbor-fuzzer \
        -max_total_time=${FUZZ_TIME_SEC} \
        -jobs=${FUZZ_JOBS} \
        -workers=${FUZZ_WORKERS} \
        -artifact_prefix=${FUZZ_ARTIFACT_DIR}/ \
        ${FUZZ_ARGS} \
        ${FUZZ_SEED_DIR} ${FUZZ_CORPUS_DIR}

      if [[ -n \"${uid:-}\" && -n \"${gid:-}\" ]]; then
        chown -R \"${uid}:${gid}\" build-host \"${FUZZ_CORPUS_DIR}\" \"${FUZZ_ARTIFACT_DIR}\" || true
      fi
    "
}

run_repro() {
  if [[ -z "${REPRO_INPUT}" ]]; then
    echo "run-repro: REPRO_INPUT is required" >&2
    exit 2
  fi

  podman run --rm -t \
    --pull=never \
    -v "${root_dir}:${WORKDIR}" \
    -w "${WORKDIR}" \
    -e "CI=1" \
    -e "UID=${uid}" \
    -e "GID=${gid}" \
    "${PODMAN_IMAGE}" \
    bash -lc "
      set -euo pipefail
      export DEBIAN_FRONTEND=noninteractive
      apt-get update
      apt-get install -y --no-install-recommends \
        ca-certificates \
        cmake make pkg-config \
        clang lld llvm \
        g++ \
        gnat \
        libssl-dev \
        libbpf-dev libelf-dev zlib1g-dev \
        dpkg-dev \
        xz-utils git

      cmake -S . -B build-host -DENABLE_FUZZERS=ON -DCMAKE_BUILD_TYPE=RelWithDebInfo
      cmake --build build-host -j

      gnatmake -gnat2012 -O2 -o build-host/cindersentinel-aegis-ada aegis/src/cindersentinel_aegis.adb

      export ASAN_OPTIONS=\"\${ASAN_OPTIONS:-abort_on_error=1:halt_on_error=1:detect_leaks=0:allocator_may_return_null=1}\"
      export UBSAN_OPTIONS=\"\${UBSAN_OPTIONS:-halt_on_error=1:print_stacktrace=1}\"
      export CINDERSENTINEL_AEGIS=\"\${CINDERSENTINEL_AEGIS:-${WORKDIR}/build-host/cindersentinel-aegis-ada}\"
      if [[ ! -x \"\${CINDERSENTINEL_AEGIS}\" ]]; then
        echo \"error: Ada validator not found: \${CINDERSENTINEL_AEGIS}\" >&2
        exit 2
      fi

      ./build-host/cindersentinel-cbor-fuzzer -runs=1 \"${REPRO_INPUT}\"

      if [[ -n \"${uid:-}\" && -n \"${gid:-}\" ]]; then
        chown -R \"${uid}:${gid}\" build-host || true
      fi
    "
}

run_cov() {
  ensure_dirs
  podman run --rm -t \
    --pull=never \
    -v "${root_dir}:${WORKDIR}" \
    -w "${WORKDIR}" \
    -e "CI=1" \
    -e "UID=${uid}" \
    -e "GID=${gid}" \
    "${PODMAN_IMAGE}" \
    bash -lc "
      set -euo pipefail
      export DEBIAN_FRONTEND=noninteractive
      apt-get update
      apt-get install -y --no-install-recommends \
        ca-certificates \
        cmake make pkg-config \
        clang lld llvm \
        g++ \
        gnat \
        libssl-dev \
        libbpf-dev libelf-dev zlib1g-dev \
        dpkg-dev \
        xz-utils git

      cmake -S . -B build-host -DENABLE_FUZZERS=ON -DCMAKE_BUILD_TYPE=RelWithDebInfo \
        -DCMAKE_C_FLAGS='-fprofile-instr-generate -fcoverage-mapping' \
        -DCMAKE_CXX_FLAGS='-fprofile-instr-generate -fcoverage-mapping'
      cmake --build build-host -j

      gnatmake -gnat2012 -O2 -o build-host/cindersentinel-aegis-ada aegis/src/cindersentinel_aegis.adb

      export ASAN_OPTIONS=\"\${ASAN_OPTIONS:-abort_on_error=1:halt_on_error=1:detect_leaks=0:allocator_may_return_null=1}\"
      export UBSAN_OPTIONS=\"\${UBSAN_OPTIONS:-halt_on_error=1:print_stacktrace=1}\"
      export CINDERSENTINEL_AEGIS=\"\${CINDERSENTINEL_AEGIS:-${WORKDIR}/build-host/cindersentinel-aegis-ada}\"
      if [[ ! -x \"\${CINDERSENTINEL_AEGIS}\" ]]; then
        echo \"error: Ada validator not found: \${CINDERSENTINEL_AEGIS}\" >&2
        exit 2
      fi

      mkdir -p \"${COV_PROFILE_DIR}\" \"${COV_OUT_DIR}\"

      LLVM_PROFILE_FILE=\"${COV_PROFILE_DIR}/cbor-fuzzer-%p.profraw\" \
        ./build-host/cindersentinel-cbor-fuzzer \
          -runs=0 \
          ${COV_SEED_DIR} ${COV_CORPUS_DIR}

      llvm-profdata merge -sparse ${COV_PROFILE_DIR}/*.profraw -o ${COV_PROFILE_DIR}/cbor-fuzzer.profdata

      llvm-cov show \
        ./build-host/cindersentinel-cbor-fuzzer \
        -instr-profile=${COV_PROFILE_DIR}/cbor-fuzzer.profdata \
        -format=html \
        -output-dir=${COV_OUT_DIR} \
        -object ./build-host/cindersentinel-cbor-fuzzer

      if [[ -n \"${uid:-}\" && -n \"${gid:-}\" ]]; then
        chown -R \"${uid}:${gid}\" build-host \"${COV_PROFILE_DIR}\" \"${COV_OUT_DIR}\" || true
      fi
    "
}

case "$command" in
  build-image) build_image ;;
  run-fuzz)    run_fuzz ;;
  run-repro)   run_repro ;;
  run-cov)     run_cov ;;
  *)
    echo "Unknown command: $command" >&2
    usage >&2
    exit 2
    ;;
esac