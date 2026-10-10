// catl — inline SHA-2 (512, 256) and SHA-1, no external crypto dependency.
#pragma once

#include "util.hpp"

namespace catl {

class Sha512
{
public:
    Sha512()
    {
        reset();
    }
    void
    reset();
    void
    update(void const* data, std::size_t n);
    void
    update(ByteView v)
    {
        update(v.data(), v.size());
    }
    void
    updateBE32(u32 v)
    {
        u8 b[4];
        putBE32(b, v);
        update(b, 4);
    }
    void
    updateBE64(u64 v)
    {
        u8 b[8];
        putBE64(b, v);
        update(b, 8);
    }
    void
    update(H256 const& h)
    {
        update(h.data(), 32);
    }
    std::array<u8, 64>
    final();
    // First 256 bits of SHA-512: the XRPL "SHA512Half" used for every
    // ledger, node, key and transaction identifier.
    H256
    finalHalf()
    {
        auto f = final();
        return H256::fromBytes(f.data());
    }

private:
    void
    compress(u8 const* block);
    u64 h_[8];
    u8 buf_[128];
    std::size_t bufLen_;
    u64 total_;
};

class Sha256
{
public:
    Sha256()
    {
        reset();
    }
    void
    reset();
    void
    update(void const* data, std::size_t n);
    std::array<u8, 32>
    final();

private:
    void
    compress(u8 const* block);
    u32 h_[8];
    u8 buf_[64];
    std::size_t bufLen_;
    u64 total_;
};

class Sha1
{
public:
    Sha1()
    {
        reset();
    }
    void
    reset();
    void
    update(void const* data, std::size_t n);
    std::array<u8, 20>
    final();

private:
    void
    compress(u8 const* block);
    u32 h_[5];
    u8 buf_[64];
    std::size_t bufLen_;
    u64 total_;
};

inline H256
sha512Half(void const* p, std::size_t n)
{
    Sha512 s;
    s.update(p, n);
    return s.finalHalf();
}

// XRPL hash prefixes ('X','Y','Z',0) as big-endian u32
constexpr u32
hashPrefix(char a, char b, char c)
{
    return (u32(u8(a)) << 24) | (u32(u8(b)) << 16) | (u32(u8(c)) << 8);
}
constexpr u32 kPrefixInner = hashPrefix('M', 'I', 'N');
constexpr u32 kPrefixLeaf = hashPrefix('M', 'L', 'N');
constexpr u32 kPrefixTxNode = hashPrefix('S', 'N', 'D');
constexpr u32 kPrefixTxId = hashPrefix('T', 'X', 'N');
constexpr u32 kPrefixLedger = hashPrefix('L', 'W', 'R');

}  // namespace catl
