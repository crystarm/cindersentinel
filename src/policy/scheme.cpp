#include "scheme.h"

#include "cbor.h"
#include "keys.h"

#include <algorithm>
#include <cstddef>
#include <sstream>
#include <utility>

namespace cs
{

static bool fail(policy_error &err, const std::string &msg)
{
    err.msg = msg;
    return false;
}

static bool get_u64(const cbor_value &v, uint64_t &out)
{
    if (v.t != cbor_type::UINT) return false;
    out = v.u;
    return true;
}

static bool get_text(const cbor_value &v, std::string &out)
{
    if (v.t != cbor_type::TEXT) return false;
    out = v.text;
    return true;
}

static void normalize_ranges(std::vector<port_range> &rs)
{
    std::sort(rs.begin(), rs.end(), [](const port_range &a, const port_range &b)
    {
        if (a.lo != b.lo) return a.lo < b.lo;
        return a.hi < b.hi;
    });

    std::vector<port_range> out;
    out.reserve(rs.size());

    for (auto r : rs)
    {
        if (out.empty())
        {
            out.push_back(r);
            continue;
        }

        auto &last = out.back();
        uint32_t last_hi = last.hi;

        if ((uint32_t)r.lo <= last_hi + 1u)
        {
            if (r.hi > last.hi) last.hi = r.hi;
        }
        else
        {
            out.push_back(r);
        }
    }

    rs.swap(out);
}

static bool parse_ports(const cbor_value &v, std::vector<port_range> &out, policy_error &err)
{
    if (v.t != cbor_type::ARRAY) return fail(err, "dports must be array");
    if (v.arr.empty()) return fail(err, "dports must be non-empty");

    for (const auto &item : v.arr)
    {
        if (item.t == cbor_type::UINT)
        {
            if (item.u < 1 || item.u > 65535) return fail(err, "port out of range");
            out.push_back(port_range{(uint16_t)item.u, (uint16_t)item.u});
            continue;
        }

        if (item.t == cbor_type::ARRAY)
        {
            if (item.arr.size() != 2) return fail(err, "port range must be [lo, hi]");
            uint64_t lo = 0, hi = 0;
            if (!get_u64(item.arr[0], lo) || !get_u64(item.arr[1], hi))
            {
                return fail(err, "port range bounds must be uint");
            }
            if (lo < 1 || lo > 65535 || hi < 1 || hi > 65535 || lo > hi)
            {
                return fail(err, "bad port range");
            }
            out.push_back(port_range{(uint16_t)lo, (uint16_t)hi});
            continue;
        }

        return fail(err, "dports elements must be uint or [lo,hi]");
    }

    normalize_ranges(out);
    return true;
}

static bool map_to_u64_index(const cbor_value &m,
                             std::vector<std::pair<uint64_t, const cbor_value *>> &out,
                             policy_error &err)
{
    if (m.t != cbor_type::MAP) return fail(err, "expected map");
    if (m.map_keys.size() != m.map_vals.size()) return fail(err, "map keys/values size mismatch");

    out.clear();
    out.reserve(m.map_keys.size());

    for (size_t i = 0; i < m.map_keys.size(); ++i)
    {
        out.push_back({m.map_keys[i], &m.map_vals[i]});
    }

    std::sort(out.begin(), out.end(), [](auto a, auto b){ return a.first < b.first; });
    for (size_t i = 1; i < out.size(); ++i)
    {
        if (out[i - 1].first == out[i].first) return fail(err, "duplicate map keys");
    }

    return true;
}

static const cbor_value *find_key(const std::vector<std::pair<uint64_t, const cbor_value *>> &idx, uint64_t k)
{
    auto it = std::lower_bound(idx.begin(), idx.end(), k,
                               [](const auto &a, uint64_t b){ return a.first < b; });
    if (it == idx.end() || it->first != k) return nullptr;
    return it->second;
}

static bool validate_rule(const cbor_value &rule,
                          bool &icmp_forbid,
                          std::vector<port_range> &tcp,
                          std::vector<port_range> &udp,
                          cbor_value &out_rule_norm,
                          policy_error &err)
{
    std::vector<std::pair<uint64_t, const cbor_value *>> idx;
    if (!map_to_u64_index(rule, idx, err)) return false;

    for (auto &kv : idx)
    {
        uint64_t k = kv.first;
        if (k != CSR_ACTION && k != CSR_PROTO && k != CSR_DPORTS)
        {
            return fail(err, "unknown rule field");
        }
    }

    const cbor_value *v_action = find_key(idx, CSR_ACTION);
    const cbor_value *v_proto  = find_key(idx, CSR_PROTO);
    const cbor_value *v_dports = find_key(idx, CSR_DPORTS);

    if (!v_action || !v_proto) return fail(err, "rule must contain action and proto");

    uint64_t action = 0, proto = 0;
    if (!get_u64(*v_action, action)) return fail(err, "action must be uint");
    if (!get_u64(*v_proto, proto)) return fail(err, "proto must be uint");

    if (action == CSA_LET) return fail(err, "'let' in rules is unsupported for now");
    if (action != CSA_FORBID) return fail(err, "unknown action");

    if (proto != CSP_ICMP && proto != CSP_TCP && proto != CSP_UDP)
    {
        return fail(err, "unknown proto");
    }

    std::vector<uint64_t> out_keys;
    std::vector<cbor_value> out_vals;
    out_keys.reserve(3);
    out_vals.reserve(3);

    out_keys.push_back(CSR_ACTION);
    out_vals.push_back(cbor_value::make_uint(action));

    out_keys.push_back(CSR_PROTO);
    out_vals.push_back(cbor_value::make_uint(proto));

    if (proto == CSP_ICMP)
    {
        if (v_dports && !(v_dports->t == cbor_type::ARRAY && v_dports->arr.empty()))
        {
            return fail(err, "icmp rule must not have dports");
        }

        icmp_forbid = true;
        out_rule_norm = cbor_value::make_map(std::move(out_keys), std::move(out_vals));
        return true;
    }

    if (!v_dports) return fail(err, "tcp/udp rule must have dports");

    std::vector<port_range> rs;
    if (!parse_ports(*v_dports, rs, err)) return false;

    if (proto == CSP_TCP) tcp.insert(tcp.end(), rs.begin(), rs.end());
    else udp.insert(udp.end(), rs.begin(), rs.end());

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

    out_keys.push_back(CSR_DPORTS);
    out_vals.push_back(cbor_value::make_array(std::move(dps)));

    out_rule_norm = cbor_value::make_map(std::move(out_keys), std::move(out_vals));
    return true;
}

bool policy_parse_validate_canonical(const std::vector<uint8_t> &in,
                                     std::vector<uint8_t> &out_canon,
                                     policy_summary &sum,
                                     policy_error &err)
{
    sum = policy_summary{};

    cbor_decode_limits lim;
    lim.max_bytes = 1u << 20;
    lim.max_items = 1u << 18;
    lim.max_depth = 64;

    cbor_value root;
    size_t used = 0;
    cbor_error cerr;

    if (!cbor_decode_strict(in.data(), in.size(), root, used, lim, cerr))
    {
        return fail(err, "CBOR decode error: " + cerr.msg);
    }
    if (used != in.size()) return fail(err, "trailing bytes after top-level CBOR value");

    if (root.t != cbor_type::MAP) return fail(err, "policy root must be map");

    std::vector<std::pair<uint64_t, const cbor_value *>> idx;
    if (!map_to_u64_index(root, idx, err)) return false;

    for (auto &kv : idx)
    {
        uint64_t k = kv.first;
        if (k != CSK_KIND && k != CSK_V && k != CSK_DEFAULT_ACTION && k != CSK_RULES)
        {
            return fail(err, "unknown root field");
        }
    }

    const cbor_value *v_kind  = find_key(idx, CSK_KIND);
    const cbor_value *v_v     = find_key(idx, CSK_V);
    const cbor_value *v_def   = find_key(idx, CSK_DEFAULT_ACTION);
    const cbor_value *v_rules = find_key(idx, CSK_RULES);

    if (!v_kind || !v_v || !v_rules) return fail(err, "missing required root fields");

    if (!get_text(*v_kind, sum.kind)) return fail(err, "kind must be text");
    if (sum.kind != "cindersentinel.policy") return fail(err, "unexpected kind");

    if (!get_u64(*v_v, sum.v)) return fail(err, "v must be uint");
    if (sum.v != 1) return fail(err, "unsupported policy version");

    if (v_def)
    {
        uint64_t def = 0;
        if (!get_u64(*v_def, def)) return fail(err, "default_action must be uint");
        if (def != CSA_LET) return fail(err, "default_action forbid unsupported for now");
    }

    if (v_rules->t != cbor_type::ARRAY) return fail(err, "rules must be array");
    if (v_rules->arr.size() > 4096) return fail(err, "too many rules");

    bool icmp_forbid = false;
    std::vector<port_range> tcp;
    std::vector<port_range> udp;

    std::vector<cbor_value> rules_norm;
    rules_norm.reserve(v_rules->arr.size());

    for (const auto &rule : v_rules->arr)
    {
        cbor_value norm;
        if (!validate_rule(rule, icmp_forbid, tcp, udp, norm, err)) return false;
        rules_norm.push_back(std::move(norm));
    }

    sum.icmp_forbid = icmp_forbid;
    normalize_ranges(tcp);
    normalize_ranges(udp);
    sum.tcp_forbid = tcp;
    sum.udp_forbid = udp;
    sum.rule_count = v_rules->arr.size();

    std::vector<uint64_t> root_keys;
    std::vector<cbor_value> root_vals;
    root_keys.reserve(4);
    root_vals.reserve(4);

    root_keys.push_back(CSK_KIND);
    root_vals.push_back(cbor_value::make_text(sum.kind));

    root_keys.push_back(CSK_V);
    root_vals.push_back(cbor_value::make_uint(sum.v));

    if (v_def)
    {
        root_keys.push_back(CSK_DEFAULT_ACTION);
        root_vals.push_back(cbor_value::make_uint(CSA_LET));
    }

    root_keys.push_back(CSK_RULES);
    root_vals.push_back(cbor_value::make_array(std::move(rules_norm)));

    cbor_value policy_norm = cbor_value::make_map(std::move(root_keys), std::move(root_vals));

    out_canon.clear();
    cbor_error e2;
    if (!cbor_encode_canonical(policy_norm, out_canon, e2))
    {
        return fail(err, "CBOR canonical encode error: " + e2.msg);
    }

    return true;
}

static std::string ranges_to_text(const std::vector<port_range> &rs)
{
    if (rs.empty()) return "none";
    std::ostringstream oss;
    for (size_t i = 0; i < rs.size(); ++i)
    {
        if (i) oss << ",";
        if (rs[i].lo == rs[i].hi) oss << rs[i].lo;
        else oss << rs[i].lo << "-" << rs[i].hi;
    }
    return oss.str();
}

std::string policy_aware_text(const policy_summary &sum)
{
    std::ostringstream oss;
    oss << "kind: " << sum.kind << "\n";
    oss << "v: " << sum.v << "\n";
    oss << "rules: " << sum.rule_count << "\n";
    oss << "icmp: " << (sum.icmp_forbid ? "forbid" : "let") << "\n";
    oss << "tcp_forbidden: " << ranges_to_text(sum.tcp_forbid) << "\n";
    oss << "udp_forbidden: " << ranges_to_text(sum.udp_forbid) << "\n";
    return oss.str();
}

} // namespace cs
