#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace cs
{

std::string sha256_hex(const uint8_t *data, size_t size);

static inline std::string sha256_hex(const std::vector<uint8_t> &b)
{
    return sha256_hex(b.data(), b.size());
}

} // namespace cs
