#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/common.sh"

cmake -S "${ROOT_DIR}" -B "${BUILD_HOST_DIR}" -DCMAKE_BUILD_TYPE="${CMAKE_BUILD_TYPE}"
cmake --build "${BUILD_HOST_DIR}" -j
echo "Built host: ${HOST_BIN}"
