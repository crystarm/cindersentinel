#pragma once

#include <cstdint>
#include <initializer_list>
#include <string>
#include <vector>

#include "../maps/maps.h"
#include "../policy/apply.h"

namespace cs::runtime
{

bool is_alias(const std::string &s, std::initializer_list<const char *> xs);

enum class runtime_backend
{
    tc,
    xdp,
    all,
};

struct runtime_opts
{
    std::string iface;
    runtime_backend backend = runtime_backend::all;
    std::string pin_base = "/sys/fs/bpf/cindersentinel";
    std::string state_root = "/var/lib/cindersentinel";
};

bool parse_backend_value(const std::string &s, runtime_backend &out);

void parse_runtime_opts(int argc,
                        char **argv,
                        int start,
                        runtime_opts &out,
                        std::vector<std::string> &rest);

uint64_t now_ms();

void apply_summary_to_maps(const cs::maps_fds &maps,
                           const cs::policy_summary &sum,
                           const char *ctx);

struct backend_view
{
    const char *label;
    const cs::maps_fds *fds;
};

void apply_summary_to_backends_atomic(const std::vector<backend_view> &backends,
                                      const cs::policy_summary &sum,
                                      const char *ctx);

bool runtime_state_equal(const cs::runtime_state &a, const cs::runtime_state &b);

void sync_runtime_to_state(const runtime_opts &rt,
                           const std::vector<backend_view> &backends,
                           const std::string &source);

} // namespace cs::runtime