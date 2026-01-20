#include "scheme.h"

#include "cbor.h"
#include "keys.h"

#include <algorithm>
#include <cstddef>
#include <sstream>

namespace cs
{

static bool Fail(PolicyError& err, const std::string& msg)
{
    err.msg = msg;
    return false;
}

static bool GetU64(const CborValue& v, uint64_t& out)
{
    if (v.t != CborType::UINT) return false;
    out = v.u;
    return true;
}

static bool GetText(const CborValue& v, std::string& out)
{
    if (v.t != CborType::TEXT) return false;
    out = v.text;
    return true;
}

static void NormalizeRanges(std::vector<PortRange>& rs)
{
    std::sort(rs.begin(), rs.end(), [](const PortRange& a, const PortRange& b)
    {
        if (a.lo != b.lo) return a.lo < b.lo;
        return a.hi < b.hi;
    });

    std::vector<PortRange> out;
    out.reserve(rs.size());

    for (auto r : rs)
    {
        if (out.empty()) { out.push_back(r); continue; }
        auto& last = out.back();
        if (r.lo <= (uint16_t)(last.hi + 1))
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

static bool ParsePorts(const CborValue& v, std::vector<PortRange>& out, PolicyError& err)
{
    if (v.t != CborType::ARRAY) return Fail(err, "dports must be array");
    if (v.arr.empty()) return Fail(err, "dports must be non-empty");

    for (const auto& item : v.arr)
    {
        if (item.t == CborType::UINT)
        {
            if (item.u < 1 || item.u > 65535) return Fail(err, "port out of range");
            out.push_back(PortRange{(uint16_t)item.u, (uint16_t)item.u});
            continue;
        }

        if (item.t == CborType::ARRAY)
        {
            if (item.arr.size() != 2) return Fail(err, "port range must be [lo, hi]");
            uint64_t lo = 0, hi = 0;
            if (!GetU64(item.arr[0], lo) || !GetU64(item.arr[1], hi))
                return Fail(err, "port range bounds must be uint");
            if (lo < 1 || lo > 65535 || hi < 1 || hi > 65535 || lo > hi)
                return Fail(err, "bad port range");
            out.push_back(PortRange{(uint16_t)lo, (uint16_t)hi});
            continue;
        }

        return Fail(err, "dports elements must be uint or [lo,hi]");
    }

    NormalizeRanges(out);
    return true;
}

static bool MapToU64Index(const CborValue& m, std::vector<std::pair<uint64_t, const CborValue*>>& out, PolicyError& err)
{
    if (m.t != CborType::MAP) return Fail(err, "expected map");
    out.clear();
    out.reserve(m.map.size());

    for (const auto& kv : m.map)
    {
        uint64_t k = 0;
        if (!GetU64(kv.first, k)) return Fail(err, "map keys must be uint");
        out.push_back({k, &kv.second});
    }

    std::sort(out.begin(), out.end(), [](auto a, auto b){ return a.first < b.first; });
    for (size_t i = 1; i < out.size(); ++i)
        if (out[i-1].first == out[i].first) return Fail(err, "duplicate map keys");
    return true;
}

static const CborValue* FindKey(const std::vector<std::pair<uint64_t, const CborValue*>>& idx, uint64_t k)
{
    auto it = std::lower_bound(idx.begin(), idx.end(), k,
                               [](const auto& a, uint64_t b){ return a.first < b; });
    if (it == idx.end() || it->first != k) return nullptr;
    return it->second;
}

static bool ValidateRule(const CborValue& rule,
                         bool& icmp_forbid,
                         std::vector<PortRange>& tcp,
                         std::vector<PortRange>& udp,
                         CborValue& out_rule_norm,
                         PolicyError& err)
{
    std::vector<std::pair<uint64_t, const CborValue*>> idx;
    if (!MapToU64Index(rule, idx, err)) return false;

    for (auto& kv : idx)
    {
        uint64_t k = kv.first;
        if (k != CSR_ACTION && k != CSR_PROTO && k != CSR_DPORTS)
            return Fail(err, "unknown rule field");
    }

    const CborValue* v_action = FindKey(idx, CSR_ACTION);
    const CborValue* v_proto = FindKey(idx, CSR_PROTO);
    const CborValue* v_dports = FindKey(idx, CSR_DPORTS);

    if (!v_action || !v_proto) return Fail(err, "rule must contain action and proto");

    uint64_t action = 0, proto = 0;
    if (!GetU64(*v_action, action)) return Fail(err, "action must be uint");
    if (!GetU64(*v_proto, proto)) return Fail(err, "proto must be uint");

    if (action == CSA_LET) return Fail(err, "'let' in rules is unsupported for now");
    if (action != CSA_FORBID) return Fail(err, "unknown action");

    if (proto != CSP_ICMP && proto != CSP_TCP && proto != CSP_UDP)
        return Fail(err, "unknown proto");

    // Normalize rule
    std::vector<std::pair<CborValue, CborValue>> out_map;
    out_map.reserve(3);
    out_map.push_back({CborValue::UInt(CSR_ACTION), CborValue::UInt(action)});
    out_map.push_back({CborValue::UInt(CSR_PROTO), CborValue::UInt(proto)});

    if (proto == CSP_ICMP)
    {
        if (v_dports && !(v_dports->t == CborType::ARRAY && v_dports->arr.empty()))
            return Fail(err, "icmp rule must not have dports");
        icmp_forbid = true;
        out_rule_norm = CborValue::Map(std::move(out_map));
        return true;
    }

    if (!v_dports) return Fail(err, "tcp/udp rule must have dports");

    std::vector<PortRange> rs;
    if (!ParsePorts(*v_dports, rs, err)) return false;

    if (proto == CSP_TCP) tcp.insert(tcp.end(), rs.begin(), rs.end());
    else udp.insert(udp.end(), rs.begin(), rs.end());

    std::vector<CborValue> dps;
    dps.reserve(rs.size());
    for (auto r : rs)
    {
        std::vector<CborValue> pair;
        pair.reserve(2);
        pair.push_back(CborValue::UInt(r.lo));
        pair.push_back(CborValue::UInt(r.hi));
        dps.push_back(CborValue::Array(std::move(pair)));
    }
    out_map.push_back({CborValue::UInt(CSR_DPORTS), CborValue::Array(std::move(dps))});
    out_rule_norm = CborValue::Map(std::move(out_map));
    return true;
}

bool PolicyParseValidateCanonical(const std::vector<uint8_t>& in,
                                  std::vector<uint8_t>& out_canon,
                                  PolicySummary& sum,
                                  PolicyError& err)
{
    sum = PolicySummary{};

    CborDecodeLimits lim;
    lim.max_bytes = 1u << 20;
    lim.max_items = 1u << 18;
    lim.max_depth = 64;

    CborValue root;
    size_t used = 0;
    CborError cerr;
    if (!CborDecodeStrict(in.data(), in.size(), root, used, lim, cerr))
        return Fail(err, "CBOR decode error: " + cerr.msg);
    if (used != in.size()) return Fail(err, "trailing bytes after top-level CBOR value");

    if (root.t != CborType::MAP) return Fail(err, "policy root must be map");

    std::vector<std::pair<uint64_t, const CborValue*>> idx;
    if (!MapToU64Index(root, idx, err)) return false;

    for (auto& kv : idx)
    {
        uint64_t k = kv.first;
        if (k != CSK_KIND && k != CSK_V && k != CSK_DEFAULT_ACTION && k != CSK_RULES)
            return Fail(err, "unknown root field");
    }

    const CborValue* v_kind = FindKey(idx, CSK_KIND);
    const CborValue* v_v = FindKey(idx, CSK_V);
    const CborValue* v_def = FindKey(idx, CSK_DEFAULT_ACTION);
    const CborValue* v_rules = FindKey(idx, CSK_RULES);

    if (!v_kind || !v_v || !v_rules) return Fail(err, "missing required root fields");

    if (!GetText(*v_kind, sum.kind)) return Fail(err, "kind must be text");
    if (sum.kind != "cindersentinel.policy") return Fail(err, "unexpected kind");

    if (!GetU64(*v_v, sum.v)) return Fail(err, "v must be uint");
    if (sum.v != 1) return Fail(err, "unsupported policy version");

    if (v_def)
    {
        uint64_t def = 0;
        if (!GetU64(*v_def, def)) return Fail(err, "default_action must be uint");
        if (def != CSA_LET) return Fail(err, "default_action forbid unsupported for now");
    }

    if (v_rules->t != CborType::ARRAY) return Fail(err, "rules must be array");
    if (v_rules->arr.size() > 4096) return Fail(err, "too many rules");

    bool icmp_forbid = false;
    std::vector<PortRange> tcp;
    std::vector<PortRange> udp;

    std::vector<CborValue> rules_norm;
    rules_norm.reserve(v_rules->arr.size());

    for (const auto& rule : v_rules->arr)
    {
        CborValue norm;
        if (!ValidateRule(rule, icmp_forbid, tcp, udp, norm, err)) return false;
        rules_norm.push_back(std::move(norm));
    }

    sum.icmp_forbid = icmp_forbid;
    NormalizeRanges(tcp);
    NormalizeRanges(udp);
    sum.tcp_forbid = tcp;
    sum.udp_forbid = udp;
    sum.rule_count = v_rules->arr.size();

    std::vector<std::pair<CborValue, CborValue>> root_norm;
    root_norm.reserve(4);
    root_norm.push_back({CborValue::UInt(CSK_KIND), CborValue::Text(sum.kind)});
    root_norm.push_back({CborValue::UInt(CSK_V), CborValue::UInt(sum.v)});
    if (v_def)
        root_norm.push_back({CborValue::UInt(CSK_DEFAULT_ACTION), CborValue::UInt(CSA_LET)});
    root_norm.push_back({CborValue::UInt(CSK_RULES), CborValue::Array(std::move(rules_norm))});

    CborValue policy_norm = CborValue::Map(std::move(root_norm));

    out_canon.clear();
    CborError e2;
    if (!CborEncodeCanonical(policy_norm, out_canon, e2))
        return Fail(err, "CBOR canonical encode error: " + e2.msg);

    return true;
}

static std::string RangesToText(const std::vector<PortRange>& rs)
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

std::string PolicyAwareText(const PolicySummary& sum)
{
    std::ostringstream oss;
    oss << "kind: " << sum.kind << "\n";
    oss << "v: " << sum.v << "\n";
    oss << "rules: " << sum.rule_count << "\n";
    oss << "icmp: " << (sum.icmp_forbid ? "forbid" : "let") << "\n";
    oss << "tcp_forbidden: " << RangesToText(sum.tcp_forbid) << "\n";
    oss << "udp_forbidden: " << RangesToText(sum.udp_forbid) << "\n";
    return oss.str();
}

} // namespace cs
