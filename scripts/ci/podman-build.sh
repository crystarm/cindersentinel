#!/usr/bin/env bash
set -euo pipefail

img="${CI_DEBIAN_IMAGE:-docker.io/library/debian:13}"
uid="$(id -u)"
gid="$(id -g)"

echo "podman: $(podman --version)"
echo "image : ${img}"
echo "uid:gid: ${uid}:${gid}"

podman pull "${img}"

podman run --rm -t \
  --pull=never \
  -v "$(pwd):/work" \
  -w /work \
  -e "CI=1" \
  -e "UID=${uid}" \
  -e "GID=${gid}" \
  "${img}" \
  bash -lc '
    set -euo pipefail

    export DEBIAN_FRONTEND=noninteractive

    apt-get update
    apt-get install -y --no-install-recommends \
      ca-certificates \
      cmake make pkg-config \
      clang lld llvm \
      g++ \
      libssl-dev \
      libbpf-dev libelf-dev zlib1g-dev \
      dpkg-dev \
      xz-utils git

    echo "clang: $(clang --version | head -n1 || true)"
    echo "cmake: $(cmake --version | head -n1 || true)"
    echo "dpkg-architecture: $(dpkg-architecture -qDEB_HOST_MULTIARCH || true)"
    echo "libbpf (pkg-config): $(pkg-config --modversion libbpf || true)"

    ./scripts/build-host.sh

    if [[ -n "${UID:-}" && -n "${GID:-}" ]]; then
      chown -R "${UID}:${GID}" build-host build || true
    fi
  '

echo "ok: build finished"
ls -la build-host || true
ls -la build || true
