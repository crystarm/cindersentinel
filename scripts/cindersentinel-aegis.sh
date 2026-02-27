#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $(basename "$0") <policy.cbor>" >&2
  exit 2
fi

policy="$1"

if [[ ! -f "$policy" ]]; then
  echo "aegis: input not found: $policy" >&2
  exit 2
fi

if command -v cindersentinel-aegis >/dev/null 2>&1; then
  exec cindersentinel-aegis "$policy"
fi

echo "aegis: cindersentinel-aegis not found in PATH" >&2
exit 127