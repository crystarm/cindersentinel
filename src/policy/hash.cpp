#include "hash.h"

#include <openssl/sha.h>

#include <cstddef>
#include <cstdint>
#include <string>

namespace cs
{

static std::string to_hex(const unsigned char *d, size_t n)
{
    static const char *HEX = "0123456789abcdef";
    std::string s;
    s.resize(n * 2);
    for (size_t i = 0; i < n; ++i)
    {
        s[i * 2 + 0] = HEX[(d[i] >> 4) & 0xF];
        s[i * 2 + 1] = HEX[d[i] & 0xF];
    }
    return s;
}

std::string sha256_hex(const uint8_t *data, size_t size)
{
    unsigned char out[SHA256_DIGEST_LENGTH];
    SHA256(data, size, out);
    return to_hex(out, SHA256_DIGEST_LENGTH);
}

} // namespace cs
