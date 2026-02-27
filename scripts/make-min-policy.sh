#!/usr/bin/env bash
set -euo pipefail

# Generate a minimal canonical policy.cbor using existing CLI.
# This creates a temporary policy via a small inline CBOR generator and then
# canonicalizes it with `cindersentinel try --out`.

usage() {
  echo "usage: $(basename "$0") <out.cbor>" >&2
  exit 2
}

if [[ $# -ne 1 ]]; then
  usage
fi

out="$1"
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

export PATH="$(pwd)/build:${PATH}"

# Minimal CBOR policy (non-canonical form is fine; CLI will canonicalize):
# {
#   kind: "cindersentinel.policy",
#   v: 1,
#   rules: []
# }
# Numeric keys (from policy/keys.h): kind=1, v=2, rules=4
# CBOR (definite lengths):
# A3                                      # map(3)
#   01                                   # uint(1) -> kind
#   74 63696e64657273656e74696e656c2e706f6c696379  # "cindersentinel.policy"
#   02                                   # uint(2) -> v
#   01                                   # uint(1)
#   04                                   # uint(4) -> rules
#   80                                   # array(0)
printf '\xA3\x01\x75cindersentinel.policy\x02\x01\x04\x80' > "$tmp"

# Canonicalize using CLI
./build/cindersentinel try "$tmp" --out "$out" >/dev/null

echo "OK: wrote canonical policy to $out"