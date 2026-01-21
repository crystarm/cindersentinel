#include "cbor.h"

#include <algorithm>
#include <cstddef>
#include <sstream>
#include <unordered_set>

namespace cs
{

static bool fail(cbor_error &err, const std::string &msg)
{
    err.msg = msg;
    return false;
}

static bool read_u64(const uint8_t *&p, const uint8_t *end, int nbytes, uint64_t &out, cbor_error &err)
{
    if ((size_t)(end - p) < (size_t)nbytes) return fail(err, "truncated integer");
    uint64_t v = 0;
    for (int i = 0; i < nbytes; ++i)
    {
        v = (v << 8) | (uint64_t)(*p++);
    }
    out = v;
    return true;
}

static bool read_len(const uint8_t *&p, const uint8_t *end, uint8_t add, uint64_t &out, cbor_error &err)
{
    if (add < 24)
    {
        out = add;
        return true;
    }
    if (add == 24) return read_u64(p, end, 1, out, err);
    if (add == 25) return read_u64(p, end, 2, out, err);
    if (add == 26) return read_u64(p, end, 4, out, err);
    if (add == 27) return read_u64(p, end, 8, out, err);
    if (add == 31) return fail(err, "indefinite lengths are forbidden");
    return fail(err, "invalid additional info");
}

static bool decode_any(const uint8_t *&p, const uint8_t *end,
                       cbor_value &out,
                       const cbor_decode_limits &lim,
                       size_t &items,
                       int depth,
                       cbor_error &err);

static bool check_limits(size_t size, const cbor_decode_limits &lim, cbor_error &err)
{
    if (size > lim.max_bytes) return fail(err, "input exceeds max_bytes");
    return true;
}

static bool item_bump(size_t &items, const cbor_decode_limits &lim, cbor_error &err)
{
    items++;
    if (items > lim.max_items) return fail(err, "decoded items exceed max_items");
    return true;
}

static bool decode_any(const uint8_t *&p, const uint8_t *end,
                       cbor_value &out,
                       const cbor_decode_limits &lim,
                       size_t &items,
                       int depth,
                       cbor_error &err)
{
    if (depth > lim.max_depth) return fail(err, "max_depth exceeded");
    if (p >= end) return fail(err, "empty/truncated input");
    if (!item_bump(items, lim, err)) return false;

    uint8_t ib = *p++;
    uint8_t major = (uint8_t)(ib >> 5);
    uint8_t add = (uint8_t)(ib & 0x1f);

    if (major == 0 || major == 1)
    {
        uint64_t v = 0;
        if (!read_len(p, end, add, v, err)) return false;

        if (major == 0)
        {
            out = cbor_value::make_uint(v);
            return true;
        }

        if (v > (uint64_t)INT64_MAX) return fail(err, "negative integer overflow");
        out = cbor_value::make_nint(-(int64_t)(v + 1));
        return true;
    }

    if (major == 2 || major == 3)
    {
        uint64_t n = 0;
        if (!read_len(p, end, add, n, err)) return false;
        if (n > (uint64_t)(end - p)) return fail(err, "truncated bytes/text");
        if (n > (uint64_t)lim.max_bytes) return fail(err, "bytes/text exceeds limit");

        if (major == 2)
        {
            std::vector<uint8_t> v(p, p + (size_t)n);
            p += (size_t)n;
            out = cbor_value::make_bytes(std::move(v));
            return true;
        }

        std::string s((const char *)p, (size_t)n);
        p += (size_t)n;
        out = cbor_value::make_text(std::move(s));
        return true;
    }

    if (major == 4)
    {
        uint64_t n = 0;
        if (!read_len(p, end, add, n, err)) return false;
        if (n > (uint64_t)lim.max_items) return fail(err, "array too large");

        std::vector<cbor_value> a;
        a.reserve((size_t)n);

        for (uint64_t i = 0; i < n; ++i)
        {
            cbor_value e;
            if (!decode_any(p, end, e, lim, items, depth + 1, err)) return false;
            a.push_back(std::move(e));
        }

        out = cbor_value::make_array(std::move(a));
        return true;
    }

    if (major == 5)
    {
        uint64_t n = 0;
        if (!read_len(p, end, add, n, err)) return false;
        if (n > (uint64_t)lim.max_items) return fail(err, "map too large");

        std::vector<uint64_t> ks;
        std::vector<cbor_value> vs;
        ks.reserve((size_t)n);
        vs.reserve((size_t)n);

        std::unordered_set<uint64_t> seen;
        seen.reserve((size_t)n * 2 + 1);

        for (uint64_t i = 0; i < n; ++i)
        {
            cbor_value k, v;
            if (!decode_any(p, end, k, lim, items, depth + 1, err)) return false;
            if (!decode_any(p, end, v, lim, items, depth + 1, err)) return false;

            if (k.t != cbor_type::UINT) return fail(err, "map key must be UINT");
            if (seen.find(k.u) != seen.end()) return fail(err, "duplicate map key");
            seen.insert(k.u);

            ks.push_back(k.u);
            vs.push_back(std::move(v));
        }

        out = cbor_value::make_map(std::move(ks), std::move(vs));
        return true;
    }

    if (major == 6)
    {
        return fail(err, "CBOR tags are forbidden");
    }

    if (major == 7)
    {
        if (add == 20) { out = cbor_value::make_bool(false); return true; }
        if (add == 21) { out = cbor_value::make_bool(true); return true; }
        if (add == 22) { out = cbor_value::make_nil(); return true; }
        if (add == 23) return fail(err, "undefined is forbidden");

        if (add == 24) return fail(err, "simple values (one-byte payload) are forbidden");
        if (add == 25 || add == 26 || add == 27) return fail(err, "floats are forbidden");
        if (add == 31) return fail(err, "break/indefinite are forbidden");

        return fail(err, "unsupported simple/float value");
    }

    return fail(err, "unknown major type");
}

bool cbor_decode_strict(const uint8_t *data, size_t size,
                        cbor_value &out,
                        size_t &bytes_consumed,
                        const cbor_decode_limits &lim,
                        cbor_error &err)
{
    if (!check_limits(size, lim, err)) return false;

    const uint8_t *p = data;
    const uint8_t *end = data + size;
    size_t items = 0;

    if (!decode_any(p, end, out, lim, items, 0, err)) return false;

    bytes_consumed = (size_t)(p - data);
    return true;
}

static void encode_u64_head(uint8_t major, uint64_t v, std::vector<uint8_t> &out)
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

static bool encode_any_canonical(const cbor_value &v, std::vector<uint8_t> &out, cbor_error &err);

static bool encode_map_canonical(const cbor_value &v, std::vector<uint8_t> &out, cbor_error &err)
{
    if (v.map_keys.size() != v.map_vals.size())
        return fail(err, "map keys/values size mismatch");

    std::vector<std::pair<uint64_t, size_t>> order;
    order.reserve(v.map_keys.size());

    std::unordered_set<uint64_t> seen;
    seen.reserve(v.map_keys.size() * 2 + 1);

    for (size_t i = 0; i < v.map_keys.size(); ++i)
    {
        uint64_t k = v.map_keys[i];
        if (seen.find(k) != seen.end()) return fail(err, "duplicate map key");
        seen.insert(k);
        order.push_back({k, i});
    }

    std::sort(order.begin(), order.end(), [](const auto &a, const auto &b)
    {
        return a.first < b.first;
    });

    encode_u64_head(5, (uint64_t)v.map_keys.size(), out);

    for (auto [k, idx] : order)
    {
        encode_u64_head(0, k, out);
        if (!encode_any_canonical(v.map_vals[idx], out, err)) return false;
    }

    return true;
}

static bool encode_any_canonical(const cbor_value &v, std::vector<uint8_t> &out, cbor_error &err)
{
    switch (v.t)
    {
        case cbor_type::UINT:
            encode_u64_head(0, v.u, out);
            return true;

        case cbor_type::NINT:
        {
            if (v.i >= 0) return fail(err, "NINT must be negative");
            uint64_t enc = (uint64_t)(-(v.i + 1));
            encode_u64_head(1, enc, out);
            return true;
        }

        case cbor_type::BYTES:
            encode_u64_head(2, (uint64_t)v.bytes.size(), out);
            out.insert(out.end(), v.bytes.begin(), v.bytes.end());
            return true;

        case cbor_type::TEXT:
            encode_u64_head(3, (uint64_t)v.text.size(), out);
            out.insert(out.end(),
                       (const uint8_t *)v.text.data(),
                       (const uint8_t *)v.text.data() + v.text.size());
            return true;

        case cbor_type::ARRAY:
            encode_u64_head(4, (uint64_t)v.arr.size(), out);
            for (const auto &e : v.arr)
                if (!encode_any_canonical(e, out, err)) return false;
            return true;

        case cbor_type::MAP:
            return encode_map_canonical(v, out, err);

        case cbor_type::BOOL:
            out.push_back((uint8_t)(0xe0 | (v.b ? 21 : 20)));
            return true;

        case cbor_type::NIL:
            out.push_back((uint8_t)(0xe0 | 22));
            return true;
    }

    return fail(err, "unknown cbor type");
}

bool cbor_encode_canonical(const cbor_value &v,
                           std::vector<uint8_t> &out,
                           cbor_error &err)
{
    out.clear();
    return encode_any_canonical(v, out, err);
}

static void indent(std::ostringstream &oss, int n)
{
    for (int i = 0; i < n; ++i) oss << ' ';
}

static void pretty_any(const cbor_value &v, std::ostringstream &oss, int ind)
{
    switch (v.t)
    {
        case cbor_type::UINT: oss << v.u; return;
        case cbor_type::NINT: oss << v.i; return;
        case cbor_type::BOOL: oss << (v.b ? "true" : "false"); return;
        case cbor_type::NIL: oss << "null"; return;

        case cbor_type::BYTES:
            oss << "h'";
            for (uint8_t b : v.bytes)
            {
                static const char *he = "0123456789abcdef";
                oss << he[b >> 4] << he[b & 15];
            }
            oss << "'";
            return;

        case cbor_type::TEXT:
            oss << '"' << v.text << '"';
            return;

        case cbor_type::ARRAY:
        {
            oss << "[";
            if (!v.arr.empty()) oss << "\n";

            for (size_t i = 0; i < v.arr.size(); ++i)
            {
                indent(oss, ind + 2);
                pretty_any(v.arr[i], oss, ind + 2);
                if (i + 1 < v.arr.size()) oss << ",";
                oss << "\n";
            }

            if (!v.arr.empty()) indent(oss, ind);
            oss << "]";
            return;
        }

        case cbor_type::MAP:
        {
            oss << "{";
            if (!v.map_keys.empty()) oss << "\n";

            for (size_t i = 0; i < v.map_keys.size(); ++i)
            {
                indent(oss, ind + 2);
                oss << v.map_keys[i] << ": ";
                pretty_any(v.map_vals[i], oss, ind + 2);
                if (i + 1 < v.map_keys.size()) oss << ",";
                oss << "\n";
            }

            if (!v.map_keys.empty()) indent(oss, ind);
            oss << "}";
            return;
        }
    }
}

std::string cbor_pretty(const cbor_value &v, int ind)
{
    std::ostringstream oss;
    pretty_any(v, oss, ind);
    return oss.str();
}

} // namespace cs
