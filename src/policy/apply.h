#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "limits.h"
#include "scheme.h"
#include "maps_pins.h"

namespace cs
{

struct apply_error
{
    std::string msg;
};

struct runtime_state
{
    bool icmp_forbid = false;
    bool ipv4_frag_drop = true;
    bool ipv4_encap_drop = false;
    std::vector<uint16_t> tcp_forbidden_ports;
    std::vector<uint16_t> udp_forbidden_ports;
};

struct apply_limits
{
    size_t max_expanded_ports_per_proto = CS_MAX_EXPANDED_PORTS_PER_PROTO;
    size_t max_total_ops = CS_MAX_TOTAL_OPS;
};

int read_runtime_state(const maps_fds &maps, runtime_state &out, apply_error &err);

int summary_to_runtime_state(const policy_summary &sum,
                             runtime_state &out,
                             const apply_limits &lim,
                             apply_error &err);

int apply_delta(const maps_fds &maps,
                const runtime_state &old_state,
                const runtime_state &new_state,
                apply_error &err);

int build_policy_from_runtime(const runtime_state &st,
                              std::vector<uint8_t> &out_canon,
                              policy_summary &out_sum,
                              apply_error &err);

} // namespace cs
