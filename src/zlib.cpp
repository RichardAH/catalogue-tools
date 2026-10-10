// catl — RFC 1950/1951 implementation. Table-driven inflate with a 10-bit
// fast path; deflate with hash chains, lazy matching and dynamic Huffman
// blocks (length-limited via the Kraft-sum adjustment used by miniz).
#include "zlib.hpp"

namespace catl {

u32
adler32(u32 adler, u8 const* p, std::size_t n)
{
    u32 a = adler & 0xffff, b = adler >> 16;
    while (n)
    {
        std::size_t k = std::min<std::size_t>(n, 5552);
        n -= k;
        while (k--)
        {
            a += *p++;
            b += a;
        }
        a %= 65521;
        b %= 65521;
    }
    return (b << 16) | a;
}

namespace {

constexpr u16 kLenBase[29] = {3,  4,  5,  6,  7,  8,  9,  10, 11,  13,  15,  17,  19,  23, 27,
                              31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258};
constexpr u8 kLenExtra[29] = {0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2,
                              2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0};
constexpr u16 kDistBase[30] = {1,   2,   3,   4,   5,   7,    9,    13,   17,   25,
                               33,  49,  65,  97,  129, 193,  257,  385,  513,  769,
                               1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577};
constexpr u8 kDistExtra[30] = {0, 0, 0, 0, 1, 1, 2, 2,  3,  3,  4,  4,  5,  5,  6,
                               6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13};
constexpr u8 kClOrder[19] = {16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15};

inline u32
revBits(u32 code, int len)
{
    u32 r = 0;
    for (int i = 0; i < len; ++i)
    {
        r = (r << 1) | (code & 1);
        code >>= 1;
    }
    return r;
}

}  // namespace

// ============================================================== Inflater

Inflater::Inflater(Fill fill, bool zlibWrapped)
    : fill_(std::move(fill)), zlib_(zlibWrapped), state_(zlibWrapped ? State::Header : State::BlockHeader)
{
    in_.resize(1 << 18);
    win_.resize(kWin);
}

bool
Inflater::refill()
{
    inBase_ += inLen_;
    inPos_ = 0;
    inLen_ = fill_ ? fill_(in_.data(), in_.size()) : 0;
    if (inLen_ == 0)
    {
        if (padBytes_)
            fail("inflate: unexpected end of compressed data (truncated file?)");
        // zero-pad past EOF; a well-formed stream never needs these bits
        // (the adler32 trailer gives 32 bits of slack) and the trailer
        // check below detects truncation.
        std::memset(in_.data(), 0, 8);
        inLen_ = 8;
        padBytes_ += 8;
        return false;
    }
    return true;
}

void
Inflater::need(int n)
{
    while (bitCnt_ < n)
    {
        if (inPos_ == inLen_)
            refill();
        bitBuf_ |= u64(in_[inPos_++]) << bitCnt_;
        bitCnt_ += 8;
    }
}

u32
Inflater::bits(int n)
{
    if (n == 0)
        return 0;
    need(n);
    u32 v = u32(bitBuf_ & ((u64(1) << n) - 1));
    bitBuf_ >>= n;
    bitCnt_ -= n;
    return v;
}

void
Inflater::build(Huff& h, u8 const* lens, int n)
{
    std::memset(h.fast, 0, sizeof h.fast);
    std::memset(h.count, 0, sizeof h.count);
    for (int i = 0; i < n; ++i)
        h.count[lens[i]]++;
    h.count[0] = 0;
    int left = 1;
    for (int len = 1; len < 16; ++len)
    {
        left <<= 1;
        left -= h.count[len];
        if (left < 0)
            fail("inflate: over-subscribed Huffman code");
    }
    u16 offs[16];
    offs[1] = 0;
    for (int len = 1; len < 15; ++len)
        offs[len + 1] = u16(offs[len] + h.count[len]);
    for (int i = 0; i < n; ++i)
        if (lens[i])
            h.symbol[offs[lens[i]]++] = u16(i);
    // fast table: canonical codes, bit-reversed for LSB-first reading
    u32 code = 0;
    int idx = 0;
    for (int len = 1; len <= Huff::kFast; ++len)
    {
        for (int k = 0; k < h.count[len]; ++k, ++idx, ++code)
        {
            u16 sym = h.symbol[idx];
            u32 r = revBits(code, len);
            for (u32 j = r; j < (1u << Huff::kFast); j += (1u << len))
                h.fast[j] = u16((sym << 4) | len);
        }
        code <<= 1;
    }
}

int
Inflater::decodeSym(Huff const& h)
{
    need(Huff::kFast);
    u16 e = h.fast[bitBuf_ & ((1u << Huff::kFast) - 1)];
    if (e)
    {
        int len = e & 15;
        bitBuf_ >>= len;
        bitCnt_ -= len;
        return e >> 4;
    }
    // slow path (codes longer than kFast bits), canonical decoding
    int code = 0, first = 0, index = 0;
    for (int len = 1; len < 16; ++len)
    {
        code |= int(bits(1));
        int count = h.count[len];
        if (code - count < first)
            return h.symbol[index + (code - first)];
        index += count;
        first += count;
        first <<= 1;
        code <<= 1;
    }
    fail("inflate: invalid Huffman code");
}

void
Inflater::readDynamic()
{
    int nlen = int(bits(5)) + 257, ndist = int(bits(5)) + 1, ncode = int(bits(4)) + 4;
    if (nlen > 286 || ndist > 30)
        fail("inflate: bad dynamic block counts");
    u8 lens[320] = {};
    for (int i = 0; i < ncode; ++i)
        lens[kClOrder[i]] = u8(bits(3));
    Huff cl;
    build(cl, lens, 19);
    u8 all[320] = {};
    int i = 0;
    while (i < nlen + ndist)
    {
        int sym = decodeSym(cl);
        if (sym < 16)
            all[i++] = u8(sym);
        else
        {
            int rep, val = 0;
            if (sym == 16)
            {
                if (i == 0)
                    fail("inflate: repeat with no previous length");
                val = all[i - 1];
                rep = 3 + int(bits(2));
            }
            else if (sym == 17)
                rep = 3 + int(bits(3));
            else
                rep = 11 + int(bits(7));
            if (i + rep > nlen + ndist)
                fail("inflate: too many code lengths");
            while (rep--)
                all[i++] = u8(val);
        }
    }
    if (all[256] == 0)
        fail("inflate: missing end-of-block code");
    build(lit_, all, nlen);
    build(dist_, all + nlen, ndist);
}

void
Inflater::maybeCheckpoint()
{
    if (!cpHook_ || pos_ - lastCp_ < cpInterval_ || pos_ == 0)
        return;
    lastCp_ = pos_;
    Checkpoint cp;
    cp.outPos = pos_;
    cp.inBit = (inBase_ + inPos_) * 8 - u64(bitCnt_);
    u64 wlen = std::min<u64>(pos_, 32768);
    cp.window.resize(wlen);
    for (u64 k = 0; k < wlen; ++k)
        cp.window[k] = win_[(pos_ - wlen + k) & kMask];
    cpHook_(std::move(cp));
}

void
Inflater::readBlockHeader()
{
    maybeCheckpoint();
    finalBlock_ = bits(1);
    u32 type = bits(2);
    if (type == 0)
    {
        bitBuf_ >>= (bitCnt_ & 7);
        bitCnt_ -= (bitCnt_ & 7);
        u32 len = bits(16), nlen = bits(16);
        if ((len ^ 0xffff) != nlen)
            fail("inflate: stored block length mismatch");
        storedLeft_ = len;
        state_ = State::Stored;
    }
    else if (type == 1)
    {
        u8 lens[320];
        int i = 0;
        for (; i < 144; ++i)
            lens[i] = 8;
        for (; i < 256; ++i)
            lens[i] = 9;
        for (; i < 280; ++i)
            lens[i] = 7;
        for (; i < 288; ++i)
            lens[i] = 8;
        build(lit_, lens, 288);
        for (i = 0; i < 30; ++i)
            lens[i] = 5;
        build(dist_, lens, 30);
        state_ = State::Huffman;
    }
    else if (type == 2)
    {
        readDynamic();
        state_ = State::Huffman;
    }
    else
        fail("inflate: invalid block type");
}

void
Inflater::updateAdler(u64 from, u64 to)
{
    if (!zlib_ || !adlerValid_)
        return;
    while (from < to)
    {
        u64 off = from & kMask;
        u64 n = std::min<u64>(to - from, kWin - off);
        adler_ = adler32(adler_, win_.data() + off, n);
        from += n;
    }
}

void
Inflater::decodeSome(std::size_t target)
{
    u64 start = pos_;
    auto room = [&] { return u64(kWin) - (pos_ - rpos_); };
    while (!finished_ && pos_ - rpos_ < target)
    {
        switch (state_)
        {
            case State::Header: {
                u32 cmf = bits(8), flg = bits(8);
                if ((cmf & 15) != 8 || ((cmf << 8) | flg) % 31 != 0)
                    fail("inflate: not a zlib stream");
                if (flg & 0x20)
                    fail("inflate: preset dictionary not supported");
                state_ = State::BlockHeader;
                break;
            }
            case State::BlockHeader:
                readBlockHeader();
                break;
            case State::Stored: {
                // drain bit buffer bytes first
                while (storedLeft_ && bitCnt_ >= 8 && room() > 0)
                {
                    put(u8(bits(8)));
                    --storedLeft_;
                }
                while (storedLeft_ && room() > 0)
                {
                    if (inPos_ == inLen_ && !refill())
                        fail("inflate: truncated stored block");
                    std::size_t n = std::min<std::size_t>({storedLeft_, inLen_ - inPos_, std::size_t(room())});
                    for (std::size_t k = 0; k < n; ++k)
                        put(in_[inPos_ + k]);
                    inPos_ += n;
                    storedLeft_ -= u32(n);
                }
                if (!storedLeft_)
                    state_ = finalBlock_ ? State::Trailer : State::BlockHeader;
                else
                    goto out;  // window full
                break;
            }
            case State::Huffman: {
                while (pos_ - rpos_ < target && room() >= 259)
                {
                    int sym = decodeSym(lit_);
                    if (sym < 256)
                    {
                        put(u8(sym));
                        continue;
                    }
                    if (sym == 256)
                    {
                        state_ = finalBlock_ ? State::Trailer : State::BlockHeader;
                        break;
                    }
                    sym -= 257;
                    if (sym >= 29)
                        fail("inflate: invalid length symbol");
                    int len = kLenBase[sym] + int(bits(kLenExtra[sym]));
                    int ds = decodeSym(dist_);
                    if (ds >= 30)
                        fail("inflate: invalid distance symbol");
                    u64 dist = kDistBase[ds] + bits(kDistExtra[ds]);
                    if (dist > pos_ || dist > 32768)
                        fail("inflate: distance too far back");
                    u64 from = pos_ - dist;
                    for (int k = 0; k < len; ++k)
                        put(win_[(from + k) & kMask]);
                }
                if (state_ == State::Huffman)
                    goto out;
                break;
            }
            case State::Trailer: {
                updateAdler(start, pos_);
                start = pos_;
                if (zlib_)
                {
                    bitBuf_ >>= (bitCnt_ & 7);
                    bitCnt_ -= (bitCnt_ & 7);
                    u32 a = 0;
                    for (int k = 0; k < 4; ++k)
                        a = (a << 8) | bits(8);
                    if (adlerValid_ && a != adler_)
                        fail("inflate: adler32 mismatch (corrupt data)");
                }
                if (padBytes_)
                {
                    // consumed bits must not extend into zero padding
                    u64 consumed = (inBase_ + inPos_) * 8 - u64(bitCnt_);
                    u64 real = (inBase_ + inLen_ - padBytes_) * 8;
                    if (consumed > real)
                        fail("inflate: truncated stream");
                }
                state_ = State::Done;
                finished_ = true;
                break;
            }
            case State::Done:
                finished_ = true;
                break;
        }
    }
out:
    updateAdler(start, pos_);
}

std::size_t
Inflater::read(u8* out, std::size_t n)
{
    std::size_t done = 0;
    while (done < n)
    {
        if (rpos_ == pos_)
        {
            if (finished_)
                break;
            decodeSome(std::min<std::size_t>(kWin / 2, std::max<std::size_t>(n - done, 4096)));
            if (rpos_ == pos_ && finished_)
                break;
            continue;
        }
        u64 off = rpos_ & kMask;
        std::size_t k = std::min<std::size_t>({n - done, std::size_t(pos_ - rpos_), std::size_t(kWin - off)});
        std::memcpy(out + done, win_.data() + off, k);
        done += k;
        rpos_ += k;
    }
    return done;
}

void
Inflater::skip(u64 n)
{
    while (n)
    {
        if (rpos_ == pos_)
        {
            if (finished_)
                fail("inflate: skip past end of stream");
            decodeSome(kWin / 2);
            continue;
        }
        u64 k = std::min<u64>(n, pos_ - rpos_);
        rpos_ += k;
        n -= k;
    }
}

void
Inflater::restore(Checkpoint const& cp, Fill fill)
{
    fill_ = std::move(fill);
    state_ = State::BlockHeader;
    finished_ = false;
    adlerValid_ = false;
    pos_ = rpos_ = cp.outPos;
    lastCp_ = cp.outPos;
    for (std::size_t k = 0; k < cp.window.size(); ++k)
        win_[(pos_ - cp.window.size() + k) & kMask] = cp.window[k];
    inBase_ = cp.inBit / 8;
    inPos_ = inLen_ = 0;
    padBytes_ = 0;
    bitBuf_ = 0;
    bitCnt_ = 0;
    // inBase_ is the offset of the next refill; refill() adds inLen_ (0)
    bits(int(cp.inBit % 8));
}

// ============================================================== Deflater

namespace {

struct LevelCfg
{
    int good, lazy, nice, chain;
    bool lazyMode;
};
constexpr LevelCfg kLevels[10] = {
    {0, 0, 0, 0, false},       {4, 4, 8, 4, false},        {4, 5, 16, 8, false},
    {4, 6, 32, 32, false},     {4, 4, 16, 16, true},       {8, 16, 32, 32, true},
    {8, 16, 128, 128, true},   {8, 32, 128, 256, true},    {32, 128, 258, 1024, true},
    {32, 258, 258, 4096, true}};

// Build length-limited Huffman code lengths for freq[0..n).
void
huffLengths(u32 const* freq, int n, int maxLen, u8* lens)
{
    std::memset(lens, 0, std::size_t(n));
    std::vector<std::pair<u32, int>> syms;
    for (int i = 0; i < n; ++i)
        if (freq[i])
            syms.push_back({freq[i], i});
    if (syms.empty())
        return;
    if (syms.size() == 1)
    {
        lens[syms[0].second] = 1;
        return;
    }
    std::sort(syms.begin(), syms.end());
    // two-queue Huffman on sorted leaves
    std::size_t m = syms.size();
    std::vector<u64> w(2 * m);
    std::vector<int> parent(2 * m, -1);
    for (std::size_t i = 0; i < m; ++i)
        w[i] = syms[i].first;
    std::size_t leaf = 0, node = m, nextNode = m;
    auto pick = [&]() -> std::size_t {
        if (leaf < m && (node >= nextNode || w[leaf] <= w[node]))
            return leaf++;
        return node++;
    };
    for (std::size_t k = 0; k < m - 1; ++k)
    {
        std::size_t a = pick(), b = pick();
        w[nextNode] = w[a] + w[b];
        parent[a] = parent[b] = int(nextNode);
        ++nextNode;
    }
    std::vector<int> depth(2 * m, 0);
    for (std::size_t i = nextNode - 1; i-- > 0;)
        depth[i] = depth[std::size_t(parent[i])] + 1;
    std::vector<int> numCodes(33, 0);
    for (std::size_t i = 0; i < m; ++i)
        numCodes[std::min(depth[i], 32)]++;
    for (int i = maxLen + 1; i <= 32; ++i)
        numCodes[maxLen] += numCodes[i], numCodes[i] = 0;
    u32 total = 0;
    for (int i = maxLen; i > 0; --i)
        total += u32(numCodes[i]) << (maxLen - i);
    while (total != (1u << maxLen))
    {
        numCodes[maxLen]--;
        for (int i = maxLen - 1; i > 0; --i)
            if (numCodes[i])
            {
                numCodes[i]--;
                numCodes[i + 1] += 2;
                break;
            }
        total--;
    }
    // most frequent symbols get the shortest codes
    std::size_t j = m;
    for (int len = 1; len <= maxLen; ++len)
        for (int c = numCodes[len]; c > 0; --c)
            lens[syms[--j].second] = u8(len);
}

void
canonicalCodes(u8 const* lens, int n, u16* codes)
{
    int blCount[16] = {}, next[16] = {};
    for (int i = 0; i < n; ++i)
        blCount[lens[i]]++;
    blCount[0] = 0;
    int code = 0;
    for (int b = 1; b < 16; ++b)
    {
        code = (code + blCount[b - 1]) << 1;
        next[b] = code;
    }
    for (int i = 0; i < n; ++i)
        if (lens[i])
            codes[i] = u16(revBits(u32(next[lens[i]]++), lens[i]));
}

inline int
lenCode(int len)
{
    int i = 28;
    while (kLenBase[i] > len)
        --i;
    return i;
}
inline int
distCode(int d)
{
    int i = 29;
    while (kDistBase[i] > d)
        --i;
    return i;
}

}  // namespace

Deflater::Deflater(Sink sink, int level) : sink_(std::move(sink)), level_(std::clamp(level, 1, 9))
{
    auto const& c = kLevels[level_];
    goodLen_ = c.good;
    maxLazy_ = c.lazy;
    niceLen_ = c.nice;
    maxChain_ = c.chain;
    lazy_ = c.lazyMode;
    win_.resize(2 * W + kMaxMatch);
    head_.assign(1 << kHashBits, -1);
    prev_.assign(W, -1);
    symLit_.reserve(kMaxSyms);
    symDist_.reserve(kMaxSyms);
    out_.reserve(1 << 17);
}

void
Deflater::putBits(u32 v, int n)
{
    bitBuf_ |= u64(v) << bitCnt_;
    bitCnt_ += n;
    while (bitCnt_ >= 8)
    {
        out_.push_back(u8(bitBuf_));
        bitBuf_ >>= 8;
        bitCnt_ -= 8;
    }
}

void
Deflater::flushOut(bool all)
{
    if (all || out_.size() >= (1 << 16))
    {
        if (!out_.empty())
            sink_(out_.data(), out_.size());
        out_.clear();
    }
}

inline void
Deflater::insertHash(int p)
{
    u32 v = u32(win_[std::size_t(p)]) | u32(win_[std::size_t(p) + 1]) << 8 | u32(win_[std::size_t(p) + 2]) << 16;
    u32 h = (v * 2654435761u) >> (32 - kHashBits);
    prev_[std::size_t(p) & (W - 1)] = head_[h];
    head_[h] = p;
}

void
Deflater::slide()
{
    std::memmove(win_.data(), win_.data() + W, std::size_t(W + kMaxMatch));
    for (auto& h : head_)
        h = h >= W ? h - W : -1;
    for (auto& p : prev_)
        p = p >= W ? p - W : -1;
    strstart_ -= W;
    prevMatch_ -= W;
}

int
Deflater::longestMatch(int cur, int& matchStart, int prevLen)
{
    int chain = maxChain_;
    if (prevLen >= goodLen_)
        chain >>= 2;
    int best = prevLen;
    int limit = cur > kMaxDist ? cur - kMaxDist : -1;
    int maxLen = std::min(kMaxMatch, lookahead_);
    u8 const* s = win_.data() + cur;
    int cand = prev_[std::size_t(cur) & (W - 1)];  // insertHash(cur) was just called
    while (cand > limit && chain-- > 0)
    {
        u8 const* m = win_.data() + cand;
        if (best < maxLen && m[best] == s[best] && m[0] == s[0] && m[1] == s[1])
        {
            int l = 2;
            while (l < maxLen && m[l] == s[l])
                ++l;
            if (l > best)
            {
                best = l;
                matchStart = cand;
                if (l >= niceLen_ || l >= maxLen)
                    break;
            }
        }
        int nxt = prev_[std::size_t(cand) & (W - 1)];
        if (nxt >= cand)
            break;
        cand = nxt;
    }
    return best;
}

void
Deflater::emitLit(u8 c)
{
    symLit_.push_back(c);
    symDist_.push_back(0);
    if (symLit_.size() >= kMaxSyms)
        flushBlock(false);
}

void
Deflater::emitMatch(int len, int dist)
{
    symLit_.push_back(u16(len));
    symDist_.push_back(u16(dist));
    if (symLit_.size() >= kMaxSyms)
        flushBlock(false);
}

void
Deflater::process(bool flush)
{
    while (lookahead_ > 0 && (flush || lookahead_ >= kMinLookahead))
    {
        if (!lazy_)
        {
            int len = 0, ms = 0;
            if (lookahead_ >= kMinMatch)
            {
                insertHash(strstart_);
                len = longestMatch(strstart_, ms, kMinMatch - 1);
                if (len == kMinMatch && strstart_ - ms > 4096)
                    len = 0;
            }
            if (len >= kMinMatch)
            {
                emitMatch(len, strstart_ - ms);
                lookahead_ -= len;
                if (len <= maxLazy_ && lookahead_ >= kMinMatch)
                {
                    for (int k = 1; k < len; ++k)
                        insertHash(strstart_ + k);
                }
                strstart_ += len;
            }
            else
            {
                emitLit(win_[std::size_t(strstart_)]);
                ++strstart_;
                --lookahead_;
            }
            continue;
        }
        // lazy evaluation (zlib deflate_slow)
        int matchLen = kMinMatch - 1, ms = 0;
        prevLen_ = prevLen_ ? prevLen_ : kMinMatch - 1;
        if (lookahead_ >= kMinMatch)
        {
            insertHash(strstart_);
            if (prevLen_ < maxLazy_)
            {
                matchLen = longestMatch(strstart_, ms, prevLen_);
                if (matchLen == kMinMatch && strstart_ - ms > 4096)
                    matchLen = kMinMatch - 1;
            }
        }
        if (prevLen_ >= kMinMatch && matchLen <= prevLen_)
        {
            int maxInsert = strstart_ + lookahead_ - kMinMatch;
            emitMatch(prevLen_, strstart_ - 1 - prevMatch_);
            lookahead_ -= prevLen_ - 1;
            int n = prevLen_ - 2;
            while (n-- > 0)
            {
                ++strstart_;
                if (strstart_ <= maxInsert)
                    insertHash(strstart_);
            }
            ++strstart_;
            matchAvail_ = 0;
            prevLen_ = kMinMatch - 1;
        }
        else
        {
            if (matchAvail_)
                emitLit(win_[std::size_t(strstart_ - 1)]);
            matchAvail_ = 1;
            prevLen_ = matchLen;
            prevMatch_ = ms;
            ++strstart_;
            --lookahead_;
        }
    }
    if (flush && lazy_ && matchAvail_)
    {
        emitLit(win_[std::size_t(strstart_ - 1)]);
        matchAvail_ = 0;
    }
}

void
Deflater::write(u8 const* p, std::size_t n)
{
    if (!headerDone_)
    {
        static constexpr u8 flg[10] = {0x01, 0x01, 0x5E, 0x5E, 0x5E, 0x5E, 0x9C, 0xDA, 0xDA, 0xDA};
        out_.push_back(0x78);
        out_.push_back(flg[level_]);
        headerDone_ = true;
    }
    adler_ = adler32(adler_, p, n);
    while (n)
    {
        int fillPos = strstart_ + lookahead_;
        if (fillPos >= 2 * W)
        {
            process(false);
            if (strstart_ >= W + kMaxDist)
                slide();
            continue;
        }
        std::size_t k = std::min<std::size_t>(n, std::size_t(2 * W - fillPos));
        std::memcpy(win_.data() + fillPos, p, k);
        lookahead_ += int(k);
        p += k;
        n -= k;
        process(false);
        if (strstart_ >= W + kMaxDist && strstart_ + lookahead_ >= 2 * W)
            slide();
    }
}

void
Deflater::flushBlock(bool final)
{
    u32 lf[288] = {}, df[30] = {};
    for (std::size_t i = 0; i < symLit_.size(); ++i)
    {
        if (symDist_[i] == 0)
            lf[symLit_[i]]++;
        else
        {
            lf[257 + lenCode(symLit_[i])]++;
            df[distCode(symDist_[i])]++;
        }
    }
    lf[256] = 1;
    // keep both trees complete with >= 2 codes
    {
        int nz = 0;
        for (int i = 0; i < 30; ++i)
            nz += df[i] != 0;
        if (nz < 2)
        {
            if (!df[0])
                df[0] = 1;
            if (!df[1])
                df[1] = 1;
        }
        if (!lf[0] && !lf[1])
            lf[0] = 1;
    }
    u8 ll[288], dl[30];
    huffLengths(lf, 286, 15, ll);
    huffLengths(df, 30, 15, dl);
    int hlit = 286;
    while (hlit > 257 && !ll[hlit - 1])
        --hlit;
    int hdist = 30;
    while (hdist > 1 && !dl[hdist - 1])
        --hdist;
    // run-length encode code lengths
    u8 all[316];
    std::memcpy(all, ll, std::size_t(hlit));
    std::memcpy(all + hlit, dl, std::size_t(hdist));
    int total = hlit + hdist;
    std::vector<std::pair<u8, u8>> rle;  // (symbol, extra)
    for (int i = 0; i < total;)
    {
        u8 v = all[i];
        int run = 1;
        while (i + run < total && all[i + run] == v)
            ++run;
        if (v == 0 && run >= 3)
        {
            int r = run;
            while (r >= 11)
            {
                int k = std::min(r, 138);
                rle.push_back({18, u8(k - 11)});
                r -= k;
            }
            if (r >= 3)
            {
                rle.push_back({17, u8(r - 3)});
                r = 0;
            }
            while (r-- > 0)
                rle.push_back({0, 0});
        }
        else if (v != 0 && run >= 4)
        {
            rle.push_back({v, 0});
            int r = run - 1;
            while (r >= 3)
            {
                int k = std::min(r, 6);
                rle.push_back({16, u8(k - 3)});
                r -= k;
            }
            while (r-- > 0)
                rle.push_back({v, 0});
        }
        else
            for (int k = 0; k < run; ++k)
                rle.push_back({v, 0});
        i += run;
    }
    u32 cf[19] = {};
    for (auto& [s, e] : rle)
        cf[s]++;
    u8 cl[19];
    huffLengths(cf, 19, 7, cl);
    int hclen = 19;
    while (hclen > 4 && !cl[kClOrder[hclen - 1]])
        --hclen;

    // cost comparison: dynamic vs fixed
    u64 extra = 0;
    for (std::size_t i = 0; i < symLit_.size(); ++i)
        if (symDist_[i])
            extra += kLenExtra[lenCode(symLit_[i])] + kDistExtra[distCode(symDist_[i])];
    u64 dyn = 5 + 5 + 4 + 3 * u64(hclen), fix = 0;
    for (auto& [s, e] : rle)
        dyn += cl[s] + (s == 16 ? 2 : s == 17 ? 3 : s == 18 ? 7 : 0);
    for (int i = 0; i < 286; ++i)
    {
        dyn += u64(lf[i]) * ll[i];
        fix += u64(lf[i]) * (i < 144 ? 8 : i < 256 ? 9 : i < 280 ? 7 : 8);
    }
    for (int i = 0; i < 30; ++i)
    {
        dyn += u64(df[i]) * dl[i];
        fix += u64(df[i]) * 5;
    }
    bool useDyn = dyn + extra < fix + extra;

    u8 const* LL = ll;
    u8 const* DL = dl;
    u8 fll[288], fdl[30];
    if (!useDyn)
    {
        for (int i = 0; i < 288; ++i)
            fll[i] = u8(i < 144 ? 8 : i < 256 ? 9 : i < 280 ? 7 : 8);
        for (int i = 0; i < 30; ++i)
            fdl[i] = 5;
        LL = fll;
        DL = fdl;
    }
    u16 lc[288] = {}, dc[30] = {};
    canonicalCodes(LL, useDyn ? 286 : 288, lc);
    canonicalCodes(DL, 30, dc);

    putBits(final ? 1 : 0, 1);
    putBits(useDyn ? 2 : 1, 2);
    if (useDyn)
    {
        putBits(u32(hlit - 257), 5);
        putBits(u32(hdist - 1), 5);
        putBits(u32(hclen - 4), 4);
        for (int i = 0; i < hclen; ++i)
            putBits(cl[kClOrder[i]], 3);
        u16 cc[19] = {};
        canonicalCodes(cl, 19, cc);
        for (auto& [s, e] : rle)
        {
            putBits(cc[s], cl[s]);
            if (s == 16)
                putBits(e, 2);
            else if (s == 17)
                putBits(e, 3);
            else if (s == 18)
                putBits(e, 7);
        }
    }
    for (std::size_t i = 0; i < symLit_.size(); ++i)
    {
        if (symDist_[i] == 0)
            putBits(lc[symLit_[i]], LL[symLit_[i]]);
        else
        {
            int len = symLit_[i], d = symDist_[i];
            int lcode = lenCode(len), dcode = distCode(d);
            putBits(lc[257 + lcode], LL[257 + lcode]);
            if (kLenExtra[lcode])
                putBits(u32(len - kLenBase[lcode]), kLenExtra[lcode]);
            putBits(dc[dcode], DL[dcode]);
            if (kDistExtra[dcode])
                putBits(u32(d - kDistBase[dcode]), kDistExtra[dcode]);
        }
    }
    putBits(lc[256], LL[256]);
    symLit_.clear();
    symDist_.clear();
    flushOut(false);
}

void
Deflater::finish()
{
    if (!headerDone_)
        write(nullptr, 0);
    process(true);
    flushBlock(true);
    if (bitCnt_)
        putBits(0, 8 - bitCnt_);
    u8 a[4];
    putBE32(a, adler_);
    out_.insert(out_.end(), a, a + 4);
    flushOut(true);
}

Bytes
zlibCompress(ByteView in, int level)
{
    Bytes out;
    Deflater d([&](u8 const* p, std::size_t n) { out.insert(out.end(), p, p + n); }, level);
    d.write(in.data(), in.size());
    d.finish();
    return out;
}

Bytes
zlibDecompress(ByteView in)
{
    std::size_t off = 0;
    Inflater inf([&](u8* b, std::size_t cap) {
        std::size_t k = std::min(cap, in.size() - off);
        std::memcpy(b, in.data() + off, k);
        off += k;
        return k;
    });
    Bytes out;
    u8 buf[65536];
    for (;;)
    {
        std::size_t k = inf.read(buf, sizeof buf);
        out.insert(out.end(), buf, buf + k);
        if (k < sizeof buf)
            break;
    }
    return out;
}

}  // namespace catl
