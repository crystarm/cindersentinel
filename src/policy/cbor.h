#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace cs
{

struct cbor_error
{
    std::string msg;
};

enum class cbor_type
{
    UINT,
    NINT,
    BYTES,
    TEXT,
    ARRAY,
    MAP,
    BOOL,
    NIL,
};

struct cbor_value
{
    cbor_type t = cbor_type::NIL;

    uint64_t u = 0;
    int64_t i = 0;
    bool b = false;
    std::vector<uint8_t> bytes;
    std::string text;
    std::vector<cbor_value> arr;
    std::vector<uint64_t> map_keys;
    std::vector<cbor_value> map_vals;

    static cbor_value make_uint(uint64_t v)
    {
        cbor_value x;
        x.t = cbor_type::UINT;
        x.u = v;
        return x;
    }

    static cbor_value make_nint(int64_t v)
    {
        cbor_value x;
        x.t = cbor_type::NINT;
        x.i = v;
        return x;
    }

    static cbor_value make_bool(bool v)
    {
        cbor_value x;
        x.t = cbor_type::BOOL;
        x.b = v;
        return x;
    }

    static cbor_value make_nil()
    {
        cbor_value x;
        x.t = cbor_type::NIL;
        return x;
    }

    static cbor_value make_bytes(std::vector<uint8_t> v)
    {
        cbor_value x;
        x.t = cbor_type::BYTES;
        x.bytes = std::move(v);
        return x;
    }

    static cbor_value make_text(std::string v)
    {
        cbor_value x;
        x.t = cbor_type::TEXT;
        x.text = std::move(v);
        return x;
    }

    static cbor_value make_array(std::vector<cbor_value> v)
    {
        cbor_value x;
        x.t = cbor_type::ARRAY;
        x.arr = std::move(v);
        return x;
    }

    static cbor_value make_map(std::vector<uint64_t> ks, std::vector<cbor_value> vs)
    {
        cbor_value x;
        x.t = cbor_type::MAP;
        x.map_keys = std::move(ks);
        x.map_vals = std::move(vs);
        return x;
    }
};

struct cbor_decode_limits
{
    size_t max_bytes = 1u << 20;
    size_t max_items = 1u << 18;
    int max_depth = 64;
};

bool cbor_decode_strict(const uint8_t *data, size_t size,
                        cbor_value &out,
                        size_t &bytes_consumed,
                        const cbor_decode_limits &lim,
                        cbor_error &err);

bool cbor_encode_canonical(const cbor_value &v,
                           std::vector<uint8_t> &out,
                           cbor_error &err);

std::string cbor_pretty(const cbor_value &v, int indent = 0);

} // namespace cs
