// catl — XRPL-alphabet base58check (r-addresses, node public keys)
#pragma once

#include "sha.hpp"
#include "util.hpp"

#include <optional>

namespace catl {

namespace detail {
inline constexpr char const* kAlphabet =
    "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz";

inline std::array<u8, 32>
sha256d(u8 const* p, std::size_t n)
{
    Sha256 a;
    a.update(p, n);
    auto h1 = a.final();
    Sha256 b;
    b.update(h1.data(), h1.size());
    return b.final();
}
}  // namespace detail

inline std::string
base58Encode(u8 const* p, std::size_t n)
{
    std::size_t zeros = 0;
    while (zeros < n && p[zeros] == 0)
        ++zeros;
    std::vector<u8> b58((n - zeros) * 138 / 100 + 1, 0);
    std::size_t len = 0;
    for (std::size_t i = zeros; i < n; ++i)
    {
        int carry = p[i];
        std::size_t j = 0;
        for (auto it = b58.rbegin(); (carry != 0 || j < len) && it != b58.rend(); ++it, ++j)
        {
            carry += 256 * (*it);
            *it = u8(carry % 58);
            carry /= 58;
        }
        len = j;
    }
    auto it = b58.begin() + (b58.size() - len);
    while (it != b58.end() && *it == 0)
        ++it;
    std::string s(zeros, detail::kAlphabet[0]);
    for (; it != b58.end(); ++it)
        s.push_back(detail::kAlphabet[*it]);
    return s;
}

inline std::optional<Bytes>
base58Decode(std::string_view s)
{
    static int8_t map[256];
    static bool init = [] {
        std::memset(map, -1, sizeof map);
        for (int i = 0; i < 58; ++i)
            map[u8(detail::kAlphabet[i])] = int8_t(i);
        return true;
    }();
    (void)init;
    std::size_t zeros = 0;
    while (zeros < s.size() && s[zeros] == detail::kAlphabet[0])
        ++zeros;
    std::vector<u8> b256(s.size() * 733 / 1000 + 1, 0);
    std::size_t len = 0;
    for (std::size_t i = zeros; i < s.size(); ++i)
    {
        int carry = map[u8(s[i])];
        if (carry < 0)
            return std::nullopt;
        std::size_t j = 0;
        for (auto it = b256.rbegin(); (carry != 0 || j < len) && it != b256.rend(); ++it, ++j)
        {
            carry += 58 * (*it);
            *it = u8(carry % 256);
            carry /= 256;
        }
        len = j;
    }
    auto it = b256.begin() + (b256.size() - len);
    Bytes out(zeros, 0);
    out.insert(out.end(), it, b256.end());
    return out;
}

inline std::string
base58CheckEncode(u8 version, u8 const* p, std::size_t n)
{
    Bytes v;
    v.reserve(n + 5);
    v.push_back(version);
    v.insert(v.end(), p, p + n);
    auto ck = detail::sha256d(v.data(), v.size());
    v.insert(v.end(), ck.begin(), ck.begin() + 4);
    return base58Encode(v.data(), v.size());
}

inline std::optional<Bytes>
base58CheckDecode(std::string_view s, u8 version)
{
    auto raw = base58Decode(s);
    if (!raw || raw->size() < 5 || (*raw)[0] != version)
        return std::nullopt;
    auto ck = detail::sha256d(raw->data(), raw->size() - 4);
    if (!std::equal(ck.begin(), ck.begin() + 4, raw->end() - 4))
        return std::nullopt;
    return Bytes(raw->begin() + 1, raw->end() - 4);
}

constexpr u8 kTokenAccountId = 0;
constexpr u8 kTokenNodePublic = 28;

using AccountID = std::array<u8, 20>;

inline std::string
toAddress(u8 const* id20)
{
    return base58CheckEncode(kTokenAccountId, id20, 20);
}

inline std::optional<AccountID>
parseAddress(std::string_view s)
{
    if (isHex(s, 40))
    {
        Bytes b;
        fromHex(s, b);
        AccountID a;
        std::memcpy(a.data(), b.data(), 20);
        return a;
    }
    auto d = base58CheckDecode(s, kTokenAccountId);
    if (!d || d->size() != 20)
        return std::nullopt;
    AccountID a;
    std::memcpy(a.data(), d->data(), 20);
    return a;
}

}  // namespace catl
