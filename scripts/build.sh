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

usage()
{
  cat <<'EOF'
usage: build.sh [--host] [--bpf] [--all]

Builds host artifacts, BPF objects, and (if GNAT is available) the Ada validator.

Options:
  --host   build host binaries (CMake) + Ada validator (if GNAT)
  --bpf    build BPF objects
  --all    build everything (default)
  -h, --help  show this help
EOF
}

do_host=0
do_bpf=0

if [[ $# -eq 0 ]]; then
  do_host=1
  do_bpf=1
else
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --host)
        do_host=1
        ;;
      --bpf)
        do_bpf=1
        ;;
      --all)
        do_host=1
        do_bpf=1
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        die "unknown option: $1"
        ;;
    esac
    shift
  done
fi

if [[ ${do_host} -eq 1 ]]; then
  log_info "Building host artifacts..."
  "${script_dir}/build-host.sh"
fi

if [[ ${do_bpf} -eq 1 ]]; then
  log_info "Building BPF artifacts..."
  "${script_dir}/build-bpf.sh"
fi
