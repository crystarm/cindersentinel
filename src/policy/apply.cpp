#include "apply.h"

#include <bpf/bpf.h>

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "cbor.h"
#include "keys.h"

namespace cs
{

static int set_err(apply_error &err, const std::string &msg)
{
    err.msg = msg;
    return -1;
}

static int set_err_errno(apply_error &err, const std::string &prefix)
{
    err.msg = prefix + ": " + std::string(strerror(errno));
    return -1;
}

static std::vector<uint16_t> dump_port_set(int map_fd)
{
    std::vector<uint16_t> ports;
    uint16_t cur = 0, next = 0;
    bool has_cur = false;

    while (true)
    {
        void *curp = has_cur ? (void *)&cur : nullptr;
        int rc = bpf_map_get_next_key(map_fd, curp, &next);
        if (rc != 0) break;
        ports.push_back(next);
        cur = next;
        has_cur = true;
    }

    std::sort(ports.begin(), ports.end());
    ports.erase(std::unique(ports.begin(), ports.end()), ports.end());
    return ports;
}

int read_runtime_state(const maps_fds &maps, runtime_state &out, apply_error &err)
{
    runtime_state st;

    uint32_t k0 = 0;
    uint8_t v = 0;
    if (bpf_map_lookup_elem(maps.fd_blk_icmp, &k0, &v) != 0)
    {
        return set_err_errno(err, "bpf_map_lookup_elem(cs_blk_icmp) failed");
    }

    st.icmp_forbid = (v != 0);
    st.tcp_forbidden_ports = dump_port_set(maps.fd_blk_tcp);
    st.udp_forbidden_ports = dump_port_set(maps.fd_blk_udp);

    out = std::move(st);
    return 0;
}

static int expand_ranges(const std::vector<port_range> &rs,
                         std::vector<uint16_t> &out,
                         size_t lim,
                         apply_error &err)
{
    out.clear();

    uint64_t cnt = 0;
    for (auto r : rs)
    {
        if (r.hi < r.lo) return set_err(err, "bad port range");
        cnt += (uint64_t)r.hi - (uint64_t)r.lo + 1;
        if (cnt > lim) return set_err(err, "too many ports to expand");
    }

    out.reserve((size_t)cnt);
    for (auto r : rs)
    {
        for (uint32_t p = r.lo; p <= r.hi; ++p)
        {
            out.push_back((uint16_t)p);
        }
    }

    std::sort(out.begin(), out.end());
    out.erase(std::unique(out.begin(), out.end()), out.end());
    return 0;
}

int summary_to_runtime_state(const policy_summary &sum,
                             runtime_state &out,
                             const apply_limits &lim,
                             apply_error &err)
{
    runtime_state st;
    st.icmp_forbid = sum.icmp_forbid;

    int rc = expand_ranges(sum.tcp_forbid, st.tcp_forbidden_ports, lim.max_expanded_ports_per_proto, err);
    if (rc != 0) return rc;

    rc = expand_ranges(sum.udp_forbid, st.udp_forbidden_ports, lim.max_expanded_ports_per_proto, err);
    if (rc != 0) return rc;

    if (st.tcp_forbidden_ports.size() + st.udp_forbidden_ports.size() > lim.max_total_ops)
    {
        return set_err(err, "policy too wide (ops limit)");
    }

    out = std::move(st);
    return 0;
}

static void diff_sorted(const std::vector<uint16_t> &oldv,
                        const std::vector<uint16_t> &newv,
                        std::vector<uint16_t> &add,
                        std::vector<uint16_t> &del)
{
    add.clear();
    del.clear();

    size_t i = 0, j = 0;
    while (i < oldv.size() || j < newv.size())
    {
        if (i == oldv.size())
        {
            add.push_back(newv[j++]);
            continue;
        }
        if (j == newv.size())
        {
            del.push_back(oldv[i++]);
            continue;
        }

        uint16_t a = oldv[i];
        uint16_t b = newv[j];
        if (a == b)
        {
            i++;
            j++;
        }
        else if (a < b)
        {
            del.push_back(a);
            i++;
        }
        else
        {
            add.push_back(b);
            j++;
        }
    }
}

static int apply_add(int map_fd, const std::vector<uint16_t> &ports, apply_error &err)
{
    uint8_t v = 1;
    for (auto p : ports)
    {
        if (bpf_map_update_elem(map_fd, &p, &v, BPF_ANY) != 0)
        {
            return set_err_errno(err, "bpf_map_update_elem failed");
        }
    }
    return 0;
}

static int apply_del(int map_fd, const std::vector<uint16_t> &ports, apply_error &err)
{
    for (auto p : ports)
    {
        if (bpf_map_delete_elem(map_fd, &p) != 0)
        {
            if (errno == ENOENT) continue;
            return set_err_errno(err, "bpf_map_delete_elem failed");
        }
    }
    return 0;
}

static int set_icmp(int map_fd, bool v, apply_error &err)
{
    uint32_t k0 = 0;
    uint8_t x = v ? 1 : 0;
    if (bpf_map_update_elem(map_fd, &k0, &x, BPF_ANY) != 0)
    {
        return set_err_errno(err, "set icmp failed");
    }
    return 0;
}

int apply_delta(const maps_fds &maps,
                const runtime_state &old_state,
                const runtime_state &new_state,
                apply_error &err)
{
    std::vector<uint16_t> add_tcp, del_tcp, add_udp, del_udp;
    diff_sorted(old_state.tcp_forbidden_ports, new_state.tcp_forbidden_ports, add_tcp, del_tcp);
    diff_sorted(old_state.udp_forbidden_ports, new_state.udp_forbidden_ports, add_udp, del_udp);

    int rc = 0;

    rc = apply_add(maps.fd_blk_tcp, add_tcp, err);
    if (rc != 0) return rc;

    rc = apply_add(maps.fd_blk_udp, add_udp, err);
    if (rc != 0) return rc;

    if (new_state.icmp_forbid && !old_state.icmp_forbid)
    {
        rc = set_icmp(maps.fd_blk_icmp, true, err);
        if (rc != 0) return rc;
    }

    rc = apply_del(maps.fd_blk_tcp, del_tcp, err);
    if (rc != 0) return rc;

    rc = apply_del(maps.fd_blk_udp, del_udp, err);
    if (rc != 0) return rc;

    if (!new_state.icmp_forbid && old_state.icmp_forbid)
    {
        rc = set_icmp(maps.fd_blk_icmp, false, err);
        if (rc != 0) return rc;
    }

    return 0;
}

static std::vector<port_range> ports_to_ranges(const std::vector<uint16_t> &ports)
{
    std::vector<port_range> rs;
    if (ports.empty()) return rs;

    uint16_t lo = ports[0];
    uint16_t hi = ports[0];
    for (size_t i = 1; i < ports.size(); ++i)
    {
        uint16_t p = ports[i];
        if ((uint16_t)(hi + 1) == p)
        {
            hi = p;
        }
        else
        {
            rs.push_back(port_range{lo, hi});
            lo = hi = p;
        }
    }
    rs.push_back(port_range{lo, hi});
    return rs;
}

static cbor_value rule_icmp_forbid()
{
    std::vector<uint64_t> ks;
    std::vector<cbor_value> vs;
    ks.reserve(2);
    vs.reserve(2);

    ks.push_back(CSR_ACTION);
    vs.push_back(cbor_value::make_uint(CSA_FORBID));

    ks.push_back(CSR_PROTO);
    vs.push_back(cbor_value::make_uint(CSP_ICMP));

    return cbor_value::make_map(std::move(ks), std::move(vs));
}

static cbor_value rule_ports_forbid(uint64_t proto, const std::vector<port_range> &rs)
{
    std::vector<uint64_t> ks;
    std::vector<cbor_value> vs;
    ks.reserve(3);
    vs.reserve(3);

    ks.push_back(CSR_ACTION);
    vs.push_back(cbor_value::make_uint(CSA_FORBID));

    ks.push_back(CSR_PROTO);
    vs.push_back(cbor_value::make_uint(proto));

    std::vector<cbor_value> dps;
    dps.reserve(rs.size());
    for (auto r : rs)
    {
        std::vector<cbor_value> pair;
        pair.reserve(2);
        pair.push_back(cbor_value::make_uint(r.lo));
        pair.push_back(cbor_value::make_uint(r.hi));
        dps.push_back(cbor_value::make_array(std::move(pair)));
    }

    ks.push_back(CSR_DPORTS);
    vs.push_back(cbor_value::make_array(std::move(dps)));

    return cbor_value::make_map(std::move(ks), std::move(vs));
}

int build_policy_from_runtime(const runtime_state &st,
                              std::vector<uint8_t> &out_canon,
                              policy_summary &out_sum,
                              apply_error &err)
{
    std::vector<port_range> tcp = ports_to_ranges(st.tcp_forbidden_ports);
    std::vector<port_range> udp = ports_to_ranges(st.udp_forbidden_ports);

    std::vector<cbor_value> rules;
    if (st.icmp_forbid) rules.push_back(rule_icmp_forbid());
    if (!tcp.empty()) rules.push_back(rule_ports_forbid(CSP_TCP, tcp));
    if (!udp.empty()) rules.push_back(rule_ports_forbid(CSP_UDP, udp));

    std::vector<uint64_t> root_keys;
    std::vector<cbor_value> root_vals;
    root_keys.reserve(4);
    root_vals.reserve(4);

    root_keys.push_back(CSK_KIND);
    root_vals.push_back(cbor_value::make_text("cindersentinel.policy"));

    root_keys.push_back(CSK_V);
    root_vals.push_back(cbor_value::make_uint(1));

    root_keys.push_back(CSK_DEFAULT_ACTION);
    root_vals.push_back(cbor_value::make_uint(CSA_LET));

    root_keys.push_back(CSK_RULES);
    root_vals.push_back(cbor_value::make_array(std::move(rules)));

    cbor_value root = cbor_value::make_map(std::move(root_keys), std::move(root_vals));

    std::vector<uint8_t> bytes;
    cbor_error ce;
    if (!cbor_encode_canonical(root, bytes, ce))
    {
        return set_err(err, "CBOR encode failed: " + ce.msg);
    }

    policy_error pe;
    std::vector<uint8_t> canon;
    policy_summary sum;
    if (!policy_parse_validate_canonical(bytes, canon, sum, pe))
    {
        return set_err(err, "policy validation failed: " + pe.msg);
    }

    out_canon = std::move(canon);
    out_sum = std::move(sum);
    return 0;
}

} // namespace cs
