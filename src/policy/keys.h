#pragma once

#include <cstdint>

namespace cs
{

// Stable numeric key mapping for compiled policy (CBOR)
// Changing these numbers is a breaking format change!

enum : uint64_t
{
    CSK_KIND = 1,
    CSK_V = 2,
    CSK_DEFAULT_ACTION = 3,
    CSK_RULES = 4,
};

enum : uint64_t
{
    CSR_ACTION = 1,
    CSR_PROTO = 2,
    CSR_DPORTS = 3,
};

enum : uint64_t
{
    CSA_LET = 0,
    CSA_FORBID = 1,
};

enum : uint64_t
{
    CSP_ICMP = 1,
    CSP_TCP = 2,
    CSP_UDP = 3,
};

} // namespace cs
