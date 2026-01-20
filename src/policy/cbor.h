#pragma once

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace cs
{

struct CborError
{
    std::string msg;
};

enum class CborType
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

struct CborValue
{
    CborType t = CborType::NIL;

    uint64_t u = 0;
    int64_t i = 0;
    bool b = false;
    std::vector<uint8_t> bytes;
    std::string text;
    std::vector<CborValue> arr;
    std::vector<std::pair<CborValue, CborValue>> map;

    static CborValue UInt(uint64_t v)
    {
        CborValue x;
        x.t = CborType::UINT;
        x.u = v;
        return x;
    }

    static CborValue NInt(int64_t v)
    {
        CborValue x;
        x.t = CborType::NINT;
        x.i = v;
        return x;
    }

    static CborValue Bool(bool v)
    {
        CborValue x;
        x.t = CborType::BOOL;
        x.b = v;
        return x;
    }

    static CborValue Nil()
    {
        CborValue x;
        x.t = CborType::NIL;
        return x;
    }

    static CborValue Bytes(std::vector<uint8_t> v)
    {
        CborValue x;
        x.t = CborType::BYTES;
        x.bytes = std::move(v);
        return x;
    }

    static CborValue Text(std::string v)
    {
        CborValue x;
        x.t = CborType::TEXT;
        x.text = std::move(v);
        return x;
    }

    static CborValue Array(std::vector<CborValue> v)
    {
        CborValue x;
        x.t = CborType::ARRAY;
        x.arr = std::move(v);
        return x;
    }

    static CborValue Map(std::vector<std::pair<CborValue, CborValue>> v)
    {
        CborValue x;
        x.t = CborType::MAP;
        x.map = std::move(v);
        return x;
    }
};

struct CborDecodeLimits
{
    size_t max_bytes = 1u << 20;
    size_t max_items = 1u << 18;
    int max_depth = 64;
};

bool CborDecodeStrict(const uint8_t* data, size_t size,
                      CborValue& out,
                      size_t& bytes_consumed,
                      const CborDecodeLimits& lim,
                      CborError& err);

bool CborEncodeCanonical(const CborValue& v,
                         std::vector<uint8_t>& out,
                         CborError& err);

std::string CborPretty(const CborValue& v, int indent = 0);

} // namespace cs
