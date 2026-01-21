#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace cs
{

struct port_range
{
    uint16_t lo = 0;
    uint16_t hi = 0;
};

struct policy_summary
{
    std::string kind;
    uint64_t v = 0;
    bool icmp_forbid = false;
    std::vector<port_range> tcp_forbid;
    std::vector<port_range> udp_forbid;
    size_t rule_count = 0;
};

struct policy_error
{
    std::string msg;
};

bool policy_parse_validate_canonical(const std::vector<uint8_t> &in,
                                     std::vector<uint8_t> &out_canon,
                                     policy_summary &sum,
                                     policy_error &err);

std::string policy_aware_text(const policy_summary &sum);

} // namespace cs
