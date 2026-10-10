// catl — self-contained RFC 1950/1951 (zlib/deflate) codec.
//
// xahaud writes compressed catalogues through boost::iostreams::zlib with
// window_bits=15 and a zlib header, i.e. one plain zlib stream covering every
// byte after the 88-byte CATL header. This file implements exactly that
// format in both directions so catl needs no libz at all.
//
// The Inflater can also snapshot its state at deflate block boundaries
// (input bit position + 32 KiB history), which is what the sidecar index
// stores to give random access into multi-hundred-GiB compressed files.
#pragma once

#include "util.hpp"

namespace catl {

u32
adler32(u32 adler, u8 const* p, std::size_t n);

class Inflater
{
public:
    // fill(buf, cap) returns bytes written, 0 at EOF.
    using Fill = std::function<std::size_t(u8*, std::size_t)>;

    explicit Inflater(Fill fill, bool zlibWrapped = true);

    // Returns fewer than n bytes only at end of stream. Throws on corruption.
    std::size_t
    read(u8* out, std::size_t n);
    void
    skip(u64 n);

    bool
    eof() const
    {
        return finished_ && rpos_ == pos_;
    }
    u64
    totalOut() const
    {
        return rpos_;
    }  // bytes handed to the caller
    // Compressed bytes consumed so far (relative to the start of the stream)
    u64
    totalIn() const
    {
        return inBase_ + inPos_ - bitCnt_ / 8;
    }

    struct Checkpoint
    {
        u64 outPos = 0;   // uncompressed offset this checkpoint resumes at
        u64 inBit = 0;    // compressed bit offset (from start of zlib stream)
        Bytes window;     // up to 32 KiB of preceding output
    };
    // Called at deflate block boundaries at least `interval` output bytes
    // apart. A checkpoint resumes decoding at cp.outPos; callers wanting a
    // later offset restore and then skip() forward.
    void
    setCheckpointHook(u64 interval, std::function<void(Checkpoint&&)> cb)
    {
        cpInterval_ = interval;
        cpHook_ = std::move(cb);
    }
    // fill must deliver compressed bytes starting at byte floor(cp.inBit/8)
    void
    restore(Checkpoint const& cp, Fill fill);

private:
    enum class State { Header, BlockHeader, Stored, Huffman, Trailer, Done };
    struct Huff
    {
        static constexpr int kFast = 10;
        u16 fast[1 << kFast];
        u16 count[16];
        u16 symbol[320];
    };

    void
    decodeSome(std::size_t target);
    bool
    refill();
    void
    need(int n);
    u32
    bits(int n);
    int
    decodeSym(Huff const& h);
    void
    build(Huff& h, u8 const* lens, int n);
    void
    readBlockHeader();
    void
    maybeCheckpoint();
    void
    readDynamic();
    void
    put(u8 b)
    {
        win_[pos_++ & kMask] = b;
    }
    void
    updateAdler(u64 from, u64 to);

    static constexpr std::size_t kWin = 1 << 18;
    static constexpr u64 kMask = kWin - 1;

    Fill fill_;
    bool zlib_;
    State state_;
    bool finalBlock_ = false;
    bool finished_ = false;
    u64 cpInterval_ = 0;
    u64 lastCp_ = 0;
    std::function<void(Checkpoint&&)> cpHook_;
    bool adlerValid_ = true;
    u32 adler_ = 1;
    u32 storedLeft_ = 0;

    Bytes in_;
    std::size_t inPos_ = 0, inLen_ = 0;
    u64 inBase_ = 0;  // stream offset of in_[0]
    std::size_t padBytes_ = 0;
    u64 bitBuf_ = 0;
    int bitCnt_ = 0;

    Bytes win_;
    u64 pos_ = 0, rpos_ = 0;
    Huff lit_, dist_;
};

class Deflater
{
public:
    using Sink = std::function<void(u8 const*, std::size_t)>;
    Deflater(Sink sink, int level);
    void
    write(u8 const* p, std::size_t n);
    void
    finish();

private:
    static constexpr int W = 32768;
    static constexpr int kMinMatch = 3, kMaxMatch = 258;
    static constexpr int kMinLookahead = kMaxMatch + kMinMatch + 1;
    static constexpr int kMaxDist = W - kMinLookahead;
    static constexpr int kHashBits = 15;
    static constexpr std::size_t kMaxSyms = 1 << 15;

    void
    process(bool flush);
    int
    longestMatch(int cur, int& matchStart, int prevLen);
    void
    insertHash(int p);
    void
    slide();
    void
    emitLit(u8 c);
    void
    emitMatch(int len, int dist);
    void
    flushBlock(bool final);
    void
    putBits(u32 v, int n);
    void
    flushOut(bool all);

    Sink sink_;
    int level_;
    int maxChain_, niceLen_, goodLen_, maxLazy_;
    bool lazy_;
    u32 adler_ = 1;
    bool headerDone_ = false;

    std::vector<u8> win_;
    std::vector<int> head_, prev_;
    int strstart_ = 0, lookahead_ = 0;
    int matchAvail_ = 0, prevLen_ = 0, prevMatch_ = 0;

    std::vector<u16> symLit_, symDist_;

    u64 bitBuf_ = 0;
    int bitCnt_ = 0;
    Bytes out_;
};

// Convenience one-shot helpers (used by the index file and tests)
Bytes
zlibCompress(ByteView in, int level);
Bytes
zlibDecompress(ByteView in);

}  // namespace catl
