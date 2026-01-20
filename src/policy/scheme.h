#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace cs
{

struct PortRange
{
    uint16_t lo = 0;
    uint16_t hi = 0;
};

struct PolicySummary
{
    std::string kind;
    uint64_t v = 0;
    bool icmp_forbid = false;
    std::vector<PortRange> tcp_forbid;
    std::vector<PortRange> udp_forbid;
    size_t rule_count = 0;
};

struct PolicyError
{
    std::string msg;
};

bool PolicyParseValidateCanonical(const std::vector<uint8_t>& in,
                                  std::vector<uint8_t>& out_canon,
                                  PolicySummary& sum,
                                  PolicyError& err);

std::string PolicyAwareText(const PolicySummary& sum);

} // namespace cs
