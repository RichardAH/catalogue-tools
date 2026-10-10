// catl — the on-disk catalogue format, exactly as written by xahaud's
// catalogue_create (src/xrpld/rpc/handlers/Catalogue.cpp +
// src/xrpld/rpc/detail/CatalogueStream.cpp).
//
//   File   := CATLHeader Body
//   Body   := Stream                  (compression level 0)
//           | zlib(Stream)            (level 1..9, one zlib stream, wbits 15)
//   Stream := Ledger{max-min+1}
//   Ledger := LedgerHeader StateSection TxSection
//   Section:= Item* 0xFF
//   Item   := type:u8 key:32 size:u32le data[size]      (type 3 or 4)
//           | 0xFE key:32                               (removal, state only)
//
// The first ledger's StateSection is a full dump of the state map; every
// later ledger carries only the leaf-level delta against its predecessor.
// TxSection is always the complete transaction map (tx+meta, VL||VL).
// All integers are host (little) endian, structs are packed.
#pragma once

#include "sha.hpp"
#include "util.hpp"
#include "zlib.hpp"

#include <memory>
#include <optional>

namespace catl {

constexpr u32 kCatlMagic = 0x4C544143;  // "CATL" read as LE u32
constexpr std::size_t kFileHeaderSize = 88;
constexpr std::size_t kLedgerHeaderSize = 164;
constexpr std::size_t kHashOffset = 24;  // offsetof(CATLHeader, hash)
constexpr u16 kXahauMainnet = 21337;
constexpr u16 kXahauTestnet = 21338;

enum NodeType : u8 {
    tnINNER = 1,
    tnTRANSACTION_NM = 2,
    tnTRANSACTION_MD = 3,
    tnACCOUNT_STATE = 4,
    tnREMOVE = 254,
    tnTERMINAL = 255,
};

struct FileHeader
{
    u32 magic = kCatlMagic;
    u32 minLedger = 0;
    u32 maxLedger = 0;
    u16 versionField = 1;
    u16 networkId = 0;
    u64 fileSize = 0;
    std::array<u8, 64> hash{};

    u8
    version() const
    {
        return versionField & 0xFF;
    }
    u8
    compressionLevel() const
    {
        return (versionField >> 8) & 0x0F;
    }
    u32
    ledgerCount() const
    {
        return maxLedger - minLedger + 1;
    }
    bool
    hashIsZero() const
    {
        for (u8 b : hash)
            if (b)
                return false;
        return true;
    }
    static FileHeader
    parse(u8 const* p);
    void
    serialize(u8* p) const;
    static u16
    makeVersion(u8 version, u8 level)
    {
        return u16((version & 0xFF) | (std::min<u8>(level, 9) << 8));
    }
};

struct LedgerHeader
{
    u32 seq = 0;
    H256 hash, txHash, accountHash, parentHash;
    u64 drops = 0;
    i32 closeFlags = 0;
    u32 closeTimeResolution = 0;
    u64 closeTime = 0;
    u64 parentCloseTime = 0;

    static LedgerHeader
    parse(u8 const* p);
    void
    serialize(u8* p) const;
    // calculateLedgerHash(): SHA512Half('LWR\0' || canonical header)
    H256
    computeHash() const;
    // The canonical (wire / RPC "ledger_data") 118-byte header encoding
    Bytes
    canonical() const;
    static std::optional<LedgerHeader>
    fromCanonical(ByteView v);
};

// ---------------------------------------------------------------- reading

// Sequential reader over the raw file with a large buffer; optionally tees
// every byte into a SHA-512 (for the whole-file hash in the header).
class RawReader
{
public:
    explicit RawReader(std::string const& path);
    ~RawReader();
    RawReader(RawReader const&) = delete;
    RawReader&
    operator=(RawReader const&) = delete;

    std::size_t
    read(u8* out, std::size_t n);
    void
    seek(u64 off);  // disables hashing
    u64
    pos() const
    {
        return pos_;
    }
    u64
    size() const
    {
        return size_;
    }
    void
    setHasher(Sha512* h)
    {
        hasher_ = h;
    }

private:
    int fd_ = -1;
    u64 size_ = 0;
    u64 pos_ = 0;
    Bytes buf_;
    std::size_t bufPos_ = 0, bufLen_ = 0;
    Sha512* hasher_ = nullptr;
};

struct Item
{
    u8 type = 0;
    H256 key;
    Bytes data;
};

struct Checkpoints;  // defined in index.hpp

class CatReader
{
public:
    struct Options
    {
        bool hashFile = false;  // compute SHA-512 of the file while reading
    };
    explicit CatReader(std::string const& path, Options opts);
    explicit CatReader(std::string const& path) : CatReader(path, Options{}) {}

    FileHeader const&
    header() const
    {
        return hdr_;
    }
    std::string const&
    path() const
    {
        return path_;
    }
    u64
    rawSize() const
    {
        return raw_.size();
    }
    u64
    rawPos() const
    {
        return raw_.pos();
    }
    u64
    streamPos() const
    {
        return logical_;
    }
    bool
    compressed() const
    {
        return bool(inf_);
    }

    // Reads the next ledger header. Returns false at end of stream (no more
    // bytes) — check lastSeq() against the header's max to detect
    // truncation. Throws on a partial header.
    bool
    nextLedger(LedgerHeader& out);
    // Next item of the current section; false once the 0xFF terminator is
    // consumed. Item.data is left empty when skipData is true.
    bool
    nextItem(Item& out, bool skipData = false);
    // Lower-level access: read an item's type/key/size, then (for non-removal
    // items) call readItemData or skipItemData. False at the terminator.
    struct ItemHeader
    {
        u8 type = 0;
        H256 key;
        u32 size = 0;
    };
    bool
    nextItemHeader(ItemHeader& h);
    void
    readItemData(u8* out, u32 n)
    {
        readExact(out, n, "item data");
    }
    void
    skipItemData(u32 n)
    {
        skipBytes(n);
    }
    // Consume the rest of the current section, returning its item count.
    u64
    skipSection();

    // Drain the remainder of the file (e.g. to finish the file hash);
    // returns the number of trailing bytes found after the last ledger.
    u64
    drain();
    // SHA-512 of the file with the header hash field zeroed (requires
    // Options::hashFile and a full sequential read / drain()).
    std::array<u8, 64>
    fileHash();

    // Random access (needs an index for compressed files)
    void
    seekStream(u64 off, Checkpoints const* cps);

    // Inflater checkpoint hook (index building)
    void
    setCheckpointHook(u64 interval, std::function<void(Inflater::Checkpoint&&)> cb);

private:
    std::size_t
    readSome(u8* p, std::size_t n);
    void
    readExact(u8* p, std::size_t n, char const* what);
    void
    skipBytes(u64 n);

    std::string path_;
    Options opts_;
    RawReader raw_;
    Sha512 sha_;
    FileHeader hdr_;
    std::unique_ptr<Inflater> inf_;
    u64 logical_ = 0;
};

// ---------------------------------------------------------------- writing

class CatWriter
{
public:
    // Writes to `path + ".part"`, renamed to `path` by finish().
    CatWriter(std::string path, u32 minLedger, u32 maxLedger, u16 networkId, int level);
    ~CatWriter();

    void
    ledger(LedgerHeader const& h);
    void
    item(u8 type, H256 const& key, u8 const* data, std::size_t n);
    void
    remove(H256 const& key);
    void
    terminal();

    // Flush, patch filesize, hash the file and patch the hash, rename.
    // progress(done, total) is called while re-reading for the hash.
    FileHeader
    finish(std::function<void(u64, u64)> progress = {});

    u64
    bytesWritten() const
    {
        return written_;
    }
    std::string const&
    finalPath() const
    {
        return path_;
    }

private:
    void
    out(u8 const* p, std::size_t n);
    void
    rawOut(u8 const* p, std::size_t n);
    void
    flushRaw();

    std::string path_, tmp_;
    FileHeader hdr_;
    int fd_ = -1;
    std::unique_ptr<Deflater> def_;
    Bytes buf_;
    u64 written_ = 0;
    bool done_ = false;
};

// Rehash an existing catalogue file (header hash zeroed) without parsing it.
std::array<u8, 64>
hashCatalogueFile(std::string const& path, std::function<void(u64, u64)> progress = {});

}  // namespace catl
