#include "aegis_c_api.h"

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include "policy/scheme.h"
#include "policy/apply.h"

namespace
{
struct aegis_limits
{
    size_t max_rules = 4096;
    size_t max_ranges_per_proto = 4096;
    size_t max_expanded_ports_per_proto = 200000;
    size_t max_total_ops = 200000;
};

static int set_err(char *buf, size_t buf_len, const std::string &msg)
{
    if (buf && buf_len)
    {
        std::snprintf(buf, buf_len, "%s", msg.c_str());
    }
    return -1;
}

static bool validate_ranges(const std::vector<cs::port_range> &rs, const char *label, std::string &err)
{
    uint32_t prev_hi = 0;
    bool have_prev = false;

    for (const auto &r : rs)
    {
        if (r.lo == 0 || r.hi == 0 || r.lo > r.hi || r.hi > 65535)
        {
            err = std::string("invalid ") + label + " range";
            return false;
        }

        if (have_prev)
        {
            if (r.lo <= prev_hi)
            {
                err = std::string("conflicting ") + label + " ranges (overlap)";
                return false;
            }
        }

        prev_hi = r.hi;
        have_prev = true;
    }

    return true;
}

static bool enforce_limits(const cs::policy_summary &sum, const aegis_limits &lim, std::string &err)
{
    if (sum.kind != "cindersentinel.policy")
    {
        err = "unexpected kind";
        return false;
    }
    if (sum.v != 1)
    {
        err = "unsupported policy version";
        return false;
    }
    if (sum.rule_count > lim.max_rules)
    {
        err = "too many rules";
        return false;
    }
    if (sum.tcp_forbid.size() > lim.max_ranges_per_proto)
    {
        err = "too many tcp ranges";
        return false;
    }
    if (sum.udp_forbid.size() > lim.max_ranges_per_proto)
    {
        err = "too many udp ranges";
        return false;
    }
    return true;
}
} // namespace

extern "C"
{
int aegis_validate(const uint8_t *data, size_t len, char *err_buf, size_t err_buf_len)
{
    if (!data && len != 0)
    {
        return set_err(err_buf, err_buf_len, "invalid input: data is null");
    }
    if (len == 0)
    {
        return set_err(err_buf, err_buf_len, "invalid input: empty policy");
    }
    if (len > (1u << 20))
    {
        return set_err(err_buf, err_buf_len, "policy too large (>1MiB)");
    }

    std::vector<uint8_t> in(data, data + len);
    std::vector<uint8_t> canon;
    cs::policy_summary sum;
    cs::policy_error pe;

    if (!cs::policy_parse_validate_canonical(in, canon, sum, pe))
    {
        return set_err(err_buf, err_buf_len, std::string("policy invalid: ") + pe.msg);
    }

    if (canon != in)
    {
        return set_err(err_buf, err_buf_len, "policy is not canonical");
    }

    std::string err;
    aegis_limits lim;
    if (!enforce_limits(sum, lim, err))
    {
        return set_err(err_buf, err_buf_len, err);
    }

    if (!validate_ranges(sum.tcp_forbid, "tcp", err))
    {
        return set_err(err_buf, err_buf_len, err);
    }
    if (!validate_ranges(sum.udp_forbid, "udp", err))
    {
        return set_err(err_buf, err_buf_len, err);
    }

    cs::apply_limits apply_lim;
    apply_lim.max_expanded_ports_per_proto = lim.max_expanded_ports_per_proto;
    apply_lim.max_total_ops = lim.max_total_ops;

    cs::apply_error ae;
    cs::runtime_state st;
    if (cs::summary_to_runtime_state(sum, st, apply_lim, ae) != 0)
    {
        return set_err(err_buf, err_buf_len, std::string("policy too wide: ") + ae.msg);
    }

    if (err_buf && err_buf_len)
    {
        err_buf[0] = '\0';
    }
    return 0;
}
}