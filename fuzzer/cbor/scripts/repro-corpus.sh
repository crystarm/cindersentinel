#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: repro-corpus.sh [corpus_dir] [--] [extra libFuzzer args...]

Iterate all inputs in a corpus directory and run repro.sh on each file.

Defaults:
  - corpus_dir: fuzzer/cbor/corpus
  - uses fuzzer/cbor/scripts/repro.sh
  - build fuzzer first: scripts/build-fuzzer.sh
  - stops on first failure

Env overrides:
  CORPUS_DIR=...     Corpus directory to iterate
  REPRO_SCRIPT=...   Path to repro.sh (default: fuzzer/cbor/scripts/repro.sh)
  CONTINUE_ON_ERROR=1  Continue even if a repro fails

Examples:
  ./repro-corpus.sh
  ./repro-corpus.sh fuzzer/cbor/corpus
  CORPUS_DIR=./fuzzer/cbor/corpus CONTINUE_ON_ERROR=1 ./repro-corpus.sh -- -runs=1
USAGE
}

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
repro_script_default="${root_dir}/fuzzer/cbor/scripts/repro.sh"
corpus_dir_default="${root_dir}/fuzzer/cbor/corpus"

corpus_dir="${CORPUS_DIR:-$corpus_dir_default}"
repro_script="${REPRO_SCRIPT:-$repro_script_default}"
continue_on_error="${CONTINUE_ON_ERROR:-0}"

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ $# -gt 0 ]]; then
  if [[ "$1" != "--" ]]; then
    corpus_dir="$1"
    shift || true
  fi
fi

if [[ "${1:-}" == "--" ]]; then
  shift || true
fi

extra_args=("$@")

if [[ ! -x "$repro_script" ]]; then
  echo "repro-corpus: repro script not found or not executable: $repro_script" >&2
  exit 2
fi

if [[ ! -d "$corpus_dir" ]]; then
  echo "repro-corpus: corpus dir not found: $corpus_dir" >&2
  exit 2
fi

shopt -s nullglob
files=("$corpus_dir"/*)
shopt -u nullglob

if [[ ${#files[@]} -eq 0 ]]; then
  echo "repro-corpus: no files in corpus dir: $corpus_dir" >&2
  exit 2
fi

echo "repro-corpus: repro:  $repro_script"
echo "repro-corpus: corpus: $corpus_dir"
echo "repro-corpus: files:  ${#files[@]}"
if [[ ${#extra_args[@]} -gt 0 ]]; then
  echo "repro-corpus: args:   ${extra_args[*]}"
else
  echo "repro-corpus: args:   <default>"
fi

failures=0
for f in "${files[@]}"; do
  if [[ ! -f "$f" ]]; then
    continue
  fi
  echo "repro-corpus: running: $f"
  if ! "$repro_script" "$f" -- "${extra_args[@]}"; then
    echo "repro-corpus: failed: $f" >&2
    failures=$((failures + 1))
    if [[ "$continue_on_error" != "1" ]]; then
      exit 1
    fi
  fi
done

if [[ $failures -gt 0 ]]; then
  echo "repro-corpus: done with failures: $failures" >&2
  exit 1
fi

echo "repro-corpus: done"