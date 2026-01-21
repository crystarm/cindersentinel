#include "cbor.h"

#include <algorithm>
#include <cstddef>
#include <sstream>
#include <unordered_set>

namespace cs
{

static bool Fail(CborError& err, const std::string& msg)
{
    err.msg = msg;
    return false;
}

static bool ReadU64(const uint8_t*& p, const uint8_t* end, int nbytes, uint64_t& out, CborError& err)
{
    if ((size_t)(end - p) < (size_t)nbytes) return Fail(err, "truncated integer");
    uint64_t v = 0;
    for (int i = 0; i < nbytes; ++i)
    {
        v = (v << 8) | (uint64_t)(*p++);
    }
    out = v;
    return true;
}

static bool ReadLen(const uint8_t*& p, const uint8_t* end, uint8_t add, uint64_t& out, CborError& err)
{
    if (add < 24)
    {
        out = add;
        return true;
    }
    if (add == 24) return ReadU64(p, end, 1, out, err);
    if (add == 25) return ReadU64(p, end, 2, out, err);
    if (add == 26) return ReadU64(p, end, 4, out, err);
    if (add == 27) return ReadU64(p, end, 8, out, err);
    if (add == 31) return Fail(err, "indefinite lengths are forbidden");
    return Fail(err, "invalid additional info");
}

static bool DecodeAny(const uint8_t*& p, const uint8_t* end,
                      CborValue& out,
                      const CborDecodeLimits& lim,
                      size_t& items,
                      int depth,
                      CborError& err);

static bool CheckLimits(size_t size, const CborDecodeLimits& lim, CborError& err)
{
    if (size > lim.max_bytes) return Fail(err, "input exceeds max_bytes");
    return true;
}

static bool ItemBump(size_t& items, const CborDecodeLimits& lim, CborError& err)
{
    items++;
    if (items > lim.max_items) return Fail(err, "decoded items exceed max_items");
    return true;
}

static bool DecodeAny(const uint8_t*& p, const uint8_t* end,
                      CborValue& out,
                      const CborDecodeLimits& lim,
                      size_t& items,
                      int depth,
                      CborError& err)
{
    if (depth > lim.max_depth) return Fail(err, "max_depth exceeded");
    if (p >= end) return Fail(err, "empty/truncated input");
    if (!ItemBump(items, lim, err)) return false;

    uint8_t ib = *p++;
    uint8_t major = (uint8_t)(ib >> 5);
    uint8_t add = (uint8_t)(ib & 0x1f);

    if (major == 0 || major == 1)
    {
        uint64_t v = 0;
        if (!ReadLen(p, end, add, v, err)) return false;
        if (major == 0)
        {
            out = CborValue::UInt(v);
            return true;
        }
        if (v > (uint64_t)INT64_MAX) return Fail(err, "negative integer overflow");
        out = CborValue::NInt(-(int64_t)(v + 1));
        return true;
    }

    if (major == 2 || major == 3)
    {
        uint64_t n = 0;
        if (!ReadLen(p, end, add, n, err)) return false;
        if (n > (uint64_t)(end - p)) return Fail(err, "truncated bytes/text");
        if (n > (uint64_t)lim.max_bytes) return Fail(err, "bytes/text exceeds limit");

        if (major == 2)
        {
            std::vector<uint8_t> v(p, p + (size_t)n);
            p += (size_t)n;
            out = CborValue::Bytes(std::move(v));
            return true;
        }
        else
        {
            std::string s((const char*)p, (size_t)n);
            p += (size_t)n;
            out = CborValue::Text(std::move(s));
            return true;
        }
    }

    if (major == 4)
    {
        uint64_t n = 0;
        if (!ReadLen(p, end, add, n, err)) return false;
        if (n > (uint64_t)lim.max_items) return Fail(err, "array too large");

        std::vector<CborValue> a;
        a.reserve((size_t)n);
        for (uint64_t i = 0; i < n; ++i)
        {
            CborValue e;
            if (!DecodeAny(p, end, e, lim, items, depth + 1, err)) return false;
            a.push_back(std::move(e));
        }
        out = CborValue::Array(std::move(a));
        return true;
    }

    if (major == 5)
    {
        uint64_t n = 0;
        if (!ReadLen(p, end, add, n, err)) return false;
        if (n > (uint64_t)lim.max_items) return Fail(err, "map too large");

        std::vector<uint64_t> ks;
        std::vector<CborValue> vs;
        ks.reserve((size_t)n);
        vs.reserve((size_t)n);

        for (uint64_t i = 0; i < n; ++i)
        {
            CborValue k, v;
            if (!DecodeAny(p, end, k, lim, items, depth + 1, err)) return false;
            if (!DecodeAny(p, end, v, lim, items, depth + 1, err)) return false;

            if (k.t != CborType::UINT) return Fail(err, "map key must be UINT");
            ks.push_back(k.u);
            vs.push_back(std::move(v));
        }

        out = CborValue::Map(std::move(ks), std::move(vs));
        return true;
    }

    if (major == 6)
    {
        return Fail(err, "CBOR tags are forbidden");
    }

    if (major == 7)
    {
        if (add == 20) { out = CborValue::Bool(false); return true; }
        if (add == 21) { out = CborValue::Bool(true); return true; }
        if (add == 22) { out = CborValue::Nil(); return true; }
        if (add == 23) return Fail(err, "undefined is forbidden");

        if (add == 24) return Fail(err, "simple values (one-byte payload) are forbidden");
        if (add == 25 || add == 26 || add == 27) return Fail(err, "floats are forbidden");
        if (add == 31) return Fail(err, "break/indefinite are forbidden");

        return Fail(err, "unsupported simple/float value");
    }

    return Fail(err, "unknown major type");
}

bool CborDecodeStrict(const uint8_t* data, size_t size,
                      CborValue& out,
                      size_t& bytes_consumed,
                      const CborDecodeLimits& lim,
                      CborError& err)
{
    if (!CheckLimits(size, lim, err)) return false;
    const uint8_t* p = data;
    const uint8_t* end = data + size;
    size_t items = 0;

    if (!DecodeAny(p, end, out, lim, items, 0, err)) return false;
    bytes_consumed = (size_t)(p - data);
    return true;
}

static void EncodeU64Head(uint8_t major, uint64_t v, std::vector<uint8_t>& out)
{
    if (v < 24)
    {
        out.push_back((uint8_t)((major << 5) | (uint8_t)v));
        return;
    }
    if (v <= 0xff)
    {
        out.push_back((uint8_t)((major << 5) | 24));
        out.push_back((uint8_t)v);
        return;
    }
    if (v <= 0xffff)
    {
        out.push_back((uint8_t)((major << 5) | 25));
        out.push_back((uint8_t)(v >> 8));
        out.push_back((uint8_t)(v));
        return;
    }
    if (v <= 0xffffffffULL)
    {
        out.push_back((uint8_t)((major << 5) | 26));
        for (int i = 3; i >= 0; --i) out.push_back((uint8_t)(v >> (8 * i)));
        return;
    }
    out.push_back((uint8_t)((major << 5) | 27));
    for (int i = 7; i >= 0; --i) out.push_back((uint8_t)(v >> (8 * i)));
}

static bool EncodeAnyCanonical(const CborValue& v, std::vector<uint8_t>& out, CborError& err);

static bool EncodeMapCanonical(const CborValue& v, std::vector<uint8_t>& out, CborError& err)
{
    if (v.map_keys.size() != v.map_vals.size())
        return Fail(err, "map keys/values size mismatch");

    std::vector<std::pair<uint64_t, size_t>> order;
    order.reserve(v.map_keys.size());

    std::unordered_set<uint64_t> seen;
    seen.reserve(v.map_keys.size() * 2 + 1);

    for (size_t i = 0; i < v.map_keys.size(); ++i)
    {
        uint64_t k = v.map_keys[i];
        if (seen.find(k) != seen.end()) return Fail(err, "duplicate map key");
        seen.insert(k);
        order.push_back({k, i});
    }

    std::sort(order.begin(), order.end(), [](const auto& a, const auto& b){ return a.first < b.first; });

    EncodeU64Head(5, (uint64_t)v.map_keys.size(), out);
    for (auto [k, idx] : order)
    {
        EncodeU64Head(0, k, out);
        if (!EncodeAnyCanonical(v.map_vals[idx], out, err)) return false;
    }
    return true;
}

static bool EncodeAnyCanonical(const CborValue& v, std::vector<uint8_t>& out, CborError& err)
{
    switch (v.t)
    {
        case CborType::UINT:
            EncodeU64Head(0, v.u, out);
            return true;
        case CborType::NINT:
        {
            if (v.i >= 0) return Fail(err, "NINT must be negative");
            uint64_t enc = (uint64_t)(-(v.i + 1));
            EncodeU64Head(1, enc, out);
            return true;
        }
        case CborType::BYTES:
            EncodeU64Head(2, (uint64_t)v.bytes.size(), out);
            out.insert(out.end(), v.bytes.begin(), v.bytes.end());
            return true;
        case CborType::TEXT:
            EncodeU64Head(3, (uint64_t)v.text.size(), out);
            out.insert(out.end(), (const uint8_t*)v.text.data(), (const uint8_t*)v.text.data() + v.text.size());
            return true;
        case CborType::ARRAY:
            EncodeU64Head(4, (uint64_t)v.arr.size(), out);
            for (const auto& e : v.arr) if (!EncodeAnyCanonical(e, out, err)) return false;
            return true;
        case CborType::MAP:
            return EncodeMapCanonical(v, out, err);
        case CborType::BOOL:
            out.push_back((uint8_t)(0xe0 | (v.b ? 21 : 20)));
            return true;
        case CborType::NIL:
            out.push_back((uint8_t)(0xe0 | 22));
            return true;
    }
    return Fail(err, "unknown cbor type");
}

bool CborEncodeCanonical(const CborValue& v,
                         std::vector<uint8_t>& out,
                         CborError& err)
{
    out.clear();
    return EncodeAnyCanonical(v, out, err);
}

static void Indent(std::ostringstream& oss, int indent)
{
    for (int i = 0; i < indent; ++i) oss << ' ';
}

static void PrettyAny(const CborValue& v, std::ostringstream& oss, int indent)
{
    switch (v.t)
    {
        case CborType::UINT: oss << v.u; return;
        case CborType::NINT: oss << v.i; return;
        case CborType::BOOL: oss << (v.b ? "true" : "false"); return;
        case CborType::NIL: oss << "null"; return;
        case CborType::BYTES:
            oss << "h'";
            for (uint8_t b : v.bytes)
            {
                static const char* he = "0123456789abcdef";
                oss << he[b >> 4] << he[b & 15];
            }
            oss << "'";
            return;
        case CborType::TEXT:
            oss << '"' << v.text << '"';
            return;
        case CborType::ARRAY:
        {
            oss << "[";
            if (!v.arr.empty()) oss << "\n";
            for (size_t i = 0; i < v.arr.size(); ++i)
            {
                Indent(oss, indent + 2);
                PrettyAny(v.arr[i], oss, indent + 2);
                if (i + 1 < v.arr.size()) oss << ",";
                oss << "\n";
            }
            if (!v.arr.empty()) Indent(oss, indent);
            oss << "]";
            return;
        }
        case CborType::MAP:
        {
            oss << "{";
            if (!v.map_keys.empty()) oss << "\n";
            for (size_t i = 0; i < v.map_keys.size(); ++i)
            {
                Indent(oss, indent + 2);
                oss << v.map_keys[i] << ": ";
                PrettyAny(v.map_vals[i], oss, indent + 2);
                if (i + 1 < v.map_keys.size()) oss << ",";
                oss << "\n";
            }
            if (!v.map_keys.empty()) Indent(oss, indent);
            oss << "}";
            return;
        }
    }
}

std::string CborPretty(const CborValue& v, int indent)
{
    std::ostringstream oss;
    PrettyAny(v, oss, indent);
    return oss.str();
}

} // namespace cs
