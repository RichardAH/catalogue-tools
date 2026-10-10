// catl — Xahau catalogue toolkit
// util.hpp: small shared vocabulary (bytes, 256-bit keys, hex, endian, errors)
#pragma once

#include <algorithm>
#include <array>
#include <compare>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <functional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace catl {

using u8 = std::uint8_t;
using u16 = std::uint16_t;
using u32 = std::uint32_t;
using u64 = std::uint64_t;
using i32 = std::int32_t;
using i64 = std::int64_t;
using Bytes = std::vector<u8>;
using ByteView = std::span<u8 const>;

struct Error : std::runtime_error
{
    using std::runtime_error::runtime_error;
};

[[noreturn]] inline void
fail(std::string const& msg)
{
    throw Error(msg);
}

inline char const* const kHexDigits = "0123456789ABCDEF";

inline std::string
toHex(u8 const* p, std::size_t n)
{
    std::string s(n * 2, '0');
    for (std::size_t i = 0; i < n; ++i)
    {
        s[2 * i] = kHexDigits[p[i] >> 4];
        s[2 * i + 1] = kHexDigits[p[i] & 15];
    }
    return s;
}
inline std::string
toHex(ByteView v)
{
    return toHex(v.data(), v.size());
}

inline int
hexNibble(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

inline bool
fromHex(std::string_view s, Bytes& out)
{
    if (s.size() % 2)
        return false;
    out.resize(s.size() / 2);
    for (std::size_t i = 0; i < out.size(); ++i)
    {
        int a = hexNibble(s[2 * i]), b = hexNibble(s[2 * i + 1]);
        if (a < 0 || b < 0)
            return false;
        out[i] = u8(a << 4 | b);
    }
    return true;
}

inline bool
isHex(std::string_view s, std::size_t len)
{
    if (s.size() != len)
        return false;
    for (char c : s)
        if (hexNibble(c) < 0)
            return false;
    return true;
}

// A 256-bit value: SHAMap keys, node hashes, ledger hashes.
struct H256
{
    std::array<u8, 32> b{};

    u8*
    data()
    {
        return b.data();
    }
    u8 const*
    data() const
    {
        return b.data();
    }
    static constexpr std::size_t
    size()
    {
        return 32;
    }
    bool
    isZero() const
    {
        for (u8 c : b)
            if (c)
                return false;
        return true;
    }
    int
    nibble(int depth) const
    {
        u8 v = b[depth >> 1];
        return (depth & 1) ? (v & 15) : (v >> 4);
    }
    std::string
    hex() const
    {
        return toHex(b.data(), 32);
    }
    static bool
    parse(std::string_view s, H256& out)
    {
        if (!isHex(s, 64))
            return false;
        Bytes t;
        fromHex(s, t);
        std::memcpy(out.b.data(), t.data(), 32);
        return true;
    }
    static H256
    fromBytes(u8 const* p)
    {
        H256 h;
        std::memcpy(h.b.data(), p, 32);
        return h;
    }
    auto
    operator<=>(H256 const&) const = default;
    bool
    operator==(H256 const&) const = default;
};

struct H256Hasher
{
    std::size_t
    operator()(H256 const& h) const noexcept
    {
        std::size_t v;
        std::memcpy(&v, h.b.data() + 8, sizeof v);  // keys are already uniform
        return v;
    }
};

// ---- endian helpers ------------------------------------------------------

inline u16
getBE16(u8 const* p)
{
    return u16(p[0] << 8 | p[1]);
}
inline u32
getBE32(u8 const* p)
{
    return u32(p[0]) << 24 | u32(p[1]) << 16 | u32(p[2]) << 8 | p[3];
}
inline u64
getBE64(u8 const* p)
{
    return u64(getBE32(p)) << 32 | getBE32(p + 4);
}
inline u16
getLE16(u8 const* p)
{
    return u16(p[0] | p[1] << 8);
}
inline u32
getLE32(u8 const* p)
{
    return u32(p[0]) | u32(p[1]) << 8 | u32(p[2]) << 16 | u32(p[3]) << 24;
}
inline u64
getLE64(u8 const* p)
{
    return u64(getLE32(p)) | u64(getLE32(p + 4)) << 32;
}
inline void
putBE16(u8* p, u16 v)
{
    p[0] = u8(v >> 8);
    p[1] = u8(v);
}
inline void
putBE32(u8* p, u32 v)
{
    p[0] = u8(v >> 24);
    p[1] = u8(v >> 16);
    p[2] = u8(v >> 8);
    p[3] = u8(v);
}
inline void
putBE64(u8* p, u64 v)
{
    putBE32(p, u32(v >> 32));
    putBE32(p + 4, u32(v));
}
inline void
putLE16(u8* p, u16 v)
{
    p[0] = u8(v);
    p[1] = u8(v >> 8);
}
inline void
putLE32(u8* p, u32 v)
{
    for (int i = 0; i < 4; ++i)
        p[i] = u8(v >> (8 * i));
}
inline void
putLE64(u8* p, u64 v)
{
    for (int i = 0; i < 8; ++i)
        p[i] = u8(v >> (8 * i));
}

// ---- formatting ----------------------------------------------------------

inline std::string
humanBytes(u64 n)
{
    static char const* units[] = {"B", "KiB", "MiB", "GiB", "TiB", "PiB"};
    double v = double(n);
    int u = 0;
    while (v >= 1024.0 && u < 5)
    {
        v /= 1024.0;
        ++u;
    }
    char buf[32];
    std::snprintf(buf, sizeof buf, u ? "%.2f %s" : "%.0f %s", v, units[u]);
    return buf;
}

inline std::string
withCommas(u64 n)
{
    std::string s = std::to_string(n), r;
    int c = 0;
    for (auto it = s.rbegin(); it != s.rend(); ++it)
    {
        if (c && c % 3 == 0)
            r.push_back(',');
        r.push_back(*it);
        ++c;
    }
    std::reverse(r.begin(), r.end());
    return r;
}

// Ripple/Xahau network time: seconds since 2000-01-01T00:00:00Z.
constexpr i64 kRippleEpoch = 946684800;

inline std::string
rippleTimeToString(u64 t)
{
    std::time_t tt = std::time_t(i64(t) + kRippleEpoch);
    std::tm tm{};
    gmtime_r(&tt, &tm);
    char buf[40];
    std::strftime(buf, sizeof buf, "%Y-%m-%d %H:%M:%S", &tm);
    return buf;
}

inline std::string
durationString(double secs)
{
    char buf[48];
    if (secs < 0 || secs > 1e9)
        return "?";
    u64 s = u64(secs);
    if (s >= 3600)
        std::snprintf(buf, sizeof buf, "%lluh%02llum", (unsigned long long)(s / 3600), (unsigned long long)(s % 3600 / 60));
    else if (s >= 60)
        std::snprintf(buf, sizeof buf, "%llum%02llus", (unsigned long long)(s / 60), (unsigned long long)(s % 60));
    else
        std::snprintf(buf, sizeof buf, "%.1fs", secs);
    return buf;
}

inline bool
parseU64(std::string_view s, u64& out)
{
    if (s.empty())
        return false;
    u64 v = 0;
    for (char c : s)
    {
        if (c == '_' || c == ',')
            continue;
        if (c < '0' || c > '9')
            return false;
        u64 nv = v * 10 + u64(c - '0');
        if (nv / 10 != v)
            return false;
        v = nv;
    }
    out = v;
    return true;
}

inline bool
parseU32(std::string_view s, u32& out)
{
    u64 v;
    if (!parseU64(s, v) || v > 0xFFFFFFFFull)
        return false;
    out = u32(v);
    return true;
}

// XRPL variable-length prefix (used for VL fields and tx+meta leaves)
inline std::size_t
encodeVL(u8* out, std::size_t len)
{
    if (len <= 192)
    {
        out[0] = u8(len);
        return 1;
    }
    if (len <= 12480)
    {
        len -= 193;
        out[0] = u8(193 + (len >> 8));
        out[1] = u8(len & 0xff);
        return 2;
    }
    if (len <= 918744)
    {
        len -= 12481;
        out[0] = u8(241 + (len >> 16));
        out[1] = u8((len >> 8) & 0xff);
        out[2] = u8(len & 0xff);
        return 3;
    }
    fail("VL length too large");
}

// Returns bytes consumed (0 on error)
inline std::size_t
decodeVL(u8 const* p, std::size_t avail, std::size_t& len)
{
    if (avail < 1)
        return 0;
    u8 b0 = p[0];
    if (b0 <= 192)
    {
        len = b0;
        return 1;
    }
    if (b0 <= 240)
    {
        if (avail < 2)
            return 0;
        len = 193 + std::size_t(b0 - 193) * 256 + p[1];
        return 2;
    }
    if (b0 <= 254)
    {
        if (avail < 3)
            return 0;
        len = 12481 + std::size_t(b0 - 241) * 65536 + std::size_t(p[1]) * 256 + p[2];
        return 3;
    }
    return 0;
}

}  // namespace catl
