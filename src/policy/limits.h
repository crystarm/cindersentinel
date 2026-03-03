#pragma once

#include <cstddef>

namespace cs
{

static constexpr size_t CS_PORT_MAP_MAX = 65536;
static constexpr size_t CS_MAX_EXPANDED_PORTS_PER_PROTO = CS_PORT_MAP_MAX;
static constexpr size_t CS_MAX_TOTAL_OPS = CS_PORT_MAP_MAX * 2;

} // namespace cs