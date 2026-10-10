// catl — SHA-512 / SHA-256 / SHA-1 (FIPS 180-4), straightforward portable code.
#include "sha.hpp"

namespace catl {

namespace {

constexpr u64 K512[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL};

constexpr u32 K256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

inline u64
rotr64(u64 x, int n)
{
    return (x >> n) | (x << (64 - n));
}
inline u32
rotr32(u32 x, int n)
{
    return (x >> n) | (x << (32 - n));
}
inline u32
rotl32(u32 x, int n)
{
    return (x << n) | (x >> (32 - n));
}

}  // namespace

// ---------------------------------------------------------------- SHA-512

void
Sha512::reset()
{
    static constexpr u64 iv[8] = {
        0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
        0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL, 0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL};
    std::memcpy(h_, iv, sizeof h_);
    bufLen_ = 0;
    total_ = 0;
}

void
Sha512::compress(u8 const* p)
{
    u64 w[80];
    for (int i = 0; i < 16; ++i)
        w[i] = getBE64(p + 8 * i);
    for (int i = 16; i < 80; ++i)
    {
        u64 s0 = rotr64(w[i - 15], 1) ^ rotr64(w[i - 15], 8) ^ (w[i - 15] >> 7);
        u64 s1 = rotr64(w[i - 2], 19) ^ rotr64(w[i - 2], 61) ^ (w[i - 2] >> 6);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    u64 a = h_[0], b = h_[1], c = h_[2], d = h_[3], e = h_[4], f = h_[5], g = h_[6], h = h_[7];
    for (int i = 0; i < 80; ++i)
    {
        u64 S1 = rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41);
        u64 ch = (e & f) ^ (~e & g);
        u64 t1 = h + S1 + ch + K512[i] + w[i];
        u64 S0 = rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39);
        u64 mj = (a & b) ^ (a & c) ^ (b & c);
        u64 t2 = S0 + mj;
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    h_[0] += a;
    h_[1] += b;
    h_[2] += c;
    h_[3] += d;
    h_[4] += e;
    h_[5] += f;
    h_[6] += g;
    h_[7] += h;
}

void
Sha512::update(void const* data, std::size_t n)
{
    auto p = static_cast<u8 const*>(data);
    total_ += n;
    if (bufLen_)
    {
        std::size_t take = std::min(n, 128 - bufLen_);
        std::memcpy(buf_ + bufLen_, p, take);
        bufLen_ += take;
        p += take;
        n -= take;
        if (bufLen_ < 128)
            return;
        compress(buf_);
        bufLen_ = 0;
    }
    while (n >= 128)
    {
        compress(p);
        p += 128;
        n -= 128;
    }
    if (n)
    {
        std::memcpy(buf_, p, n);
        bufLen_ = n;
    }
}

std::array<u8, 64>
Sha512::final()
{
    u64 bits = total_ * 8;
    u8 pad[256] = {0x80};
    std::size_t padLen = (bufLen_ < 112) ? (112 - bufLen_) : (240 - bufLen_);
    update(pad, padLen);
    u8 len[16] = {};
    putBE64(len + 8, bits);
    update(len, 16);
    std::array<u8, 64> out;
    for (int i = 0; i < 8; ++i)
        putBE64(out.data() + 8 * i, h_[i]);
    reset();
    return out;
}

// ---------------------------------------------------------------- SHA-256

void
Sha256::reset()
{
    static constexpr u32 iv[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    std::memcpy(h_, iv, sizeof h_);
    bufLen_ = 0;
    total_ = 0;
}

void
Sha256::compress(u8 const* p)
{
    u32 w[64];
    for (int i = 0; i < 16; ++i)
        w[i] = getBE32(p + 4 * i);
    for (int i = 16; i < 64; ++i)
    {
        u32 s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        u32 s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    u32 a = h_[0], b = h_[1], c = h_[2], d = h_[3], e = h_[4], f = h_[5], g = h_[6], h = h_[7];
    for (int i = 0; i < 64; ++i)
    {
        u32 S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        u32 ch = (e & f) ^ (~e & g);
        u32 t1 = h + S1 + ch + K256[i] + w[i];
        u32 S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        u32 mj = (a & b) ^ (a & c) ^ (b & c);
        u32 t2 = S0 + mj;
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    h_[0] += a;
    h_[1] += b;
    h_[2] += c;
    h_[3] += d;
    h_[4] += e;
    h_[5] += f;
    h_[6] += g;
    h_[7] += h;
}

void
Sha256::update(void const* data, std::size_t n)
{
    auto p = static_cast<u8 const*>(data);
    total_ += n;
    while (n)
    {
        std::size_t take = std::min(n, 64 - bufLen_);
        std::memcpy(buf_ + bufLen_, p, take);
        bufLen_ += take;
        p += take;
        n -= take;
        if (bufLen_ == 64)
        {
            compress(buf_);
            bufLen_ = 0;
        }
    }
}

std::array<u8, 32>
Sha256::final()
{
    u64 bits = total_ * 8;
    u8 pad[128] = {0x80};
    std::size_t padLen = (bufLen_ < 56) ? (56 - bufLen_) : (120 - bufLen_);
    update(pad, padLen);
    u8 len[8];
    putBE64(len, bits);
    update(len, 8);
    std::array<u8, 32> out;
    for (int i = 0; i < 8; ++i)
        putBE32(out.data() + 4 * i, h_[i]);
    reset();
    return out;
}

// ---------------------------------------------------------------- SHA-1
// (only used for the RFC 6455 Sec-WebSocket-Accept check)

void
Sha1::reset()
{
    h_[0] = 0x67452301;
    h_[1] = 0xEFCDAB89;
    h_[2] = 0x98BADCFE;
    h_[3] = 0x10325476;
    h_[4] = 0xC3D2E1F0;
    bufLen_ = 0;
    total_ = 0;
}

void
Sha1::compress(u8 const* p)
{
    u32 w[80];
    for (int i = 0; i < 16; ++i)
        w[i] = getBE32(p + 4 * i);
    for (int i = 16; i < 80; ++i)
        w[i] = rotl32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    u32 a = h_[0], b = h_[1], c = h_[2], d = h_[3], e = h_[4];
    for (int i = 0; i < 80; ++i)
    {
        u32 f, k;
        if (i < 20)
            f = (b & c) | (~b & d), k = 0x5A827999;
        else if (i < 40)
            f = b ^ c ^ d, k = 0x6ED9EBA1;
        else if (i < 60)
            f = (b & c) | (b & d) | (c & d), k = 0x8F1BBCDC;
        else
            f = b ^ c ^ d, k = 0xCA62C1D6;
        u32 t = rotl32(a, 5) + f + e + k + w[i];
        e = d;
        d = c;
        c = rotl32(b, 30);
        b = a;
        a = t;
    }
    h_[0] += a;
    h_[1] += b;
    h_[2] += c;
    h_[3] += d;
    h_[4] += e;
}

void
Sha1::update(void const* data, std::size_t n)
{
    auto p = static_cast<u8 const*>(data);
    total_ += n;
    while (n)
    {
        std::size_t take = std::min(n, 64 - bufLen_);
        std::memcpy(buf_ + bufLen_, p, take);
        bufLen_ += take;
        p += take;
        n -= take;
        if (bufLen_ == 64)
        {
            compress(buf_);
            bufLen_ = 0;
        }
    }
}

std::array<u8, 20>
Sha1::final()
{
    u64 bits = total_ * 8;
    u8 pad[128] = {0x80};
    std::size_t padLen = (bufLen_ < 56) ? (56 - bufLen_) : (120 - bufLen_);
    update(pad, padLen);
    u8 len[8];
    putBE64(len, bits);
    update(len, 8);
    std::array<u8, 20> out;
    for (int i = 0; i < 5; ++i)
        putBE32(out.data() + 4 * i, h_[i]);
    reset();
    return out;
}

}  // namespace catl
