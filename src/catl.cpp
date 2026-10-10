// catl — catalogue file reading and writing
#include "catl.hpp"
#include "index.hpp"

#include <cerrno>
#include <cstdio>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace catl {

// ------------------------------------------------------------ headers

FileHeader
FileHeader::parse(u8 const* p)
{
    FileHeader h;
    h.magic = getLE32(p);
    h.minLedger = getLE32(p + 4);
    h.maxLedger = getLE32(p + 8);
    h.versionField = getLE16(p + 12);
    h.networkId = getLE16(p + 14);
    h.fileSize = getLE64(p + 16);
    std::memcpy(h.hash.data(), p + kHashOffset, 64);
    return h;
}

void
FileHeader::serialize(u8* p) const
{
    putLE32(p, magic);
    putLE32(p + 4, minLedger);
    putLE32(p + 8, maxLedger);
    putLE16(p + 12, versionField);
    putLE16(p + 14, networkId);
    putLE64(p + 16, fileSize);
    std::memcpy(p + kHashOffset, hash.data(), 64);
}

LedgerHeader
LedgerHeader::parse(u8 const* p)
{
    LedgerHeader h;
    h.seq = getLE32(p);
    h.hash = H256::fromBytes(p + 4);
    h.txHash = H256::fromBytes(p + 36);
    h.accountHash = H256::fromBytes(p + 68);
    h.parentHash = H256::fromBytes(p + 100);
    h.drops = getLE64(p + 132);
    h.closeFlags = i32(getLE32(p + 140));
    h.closeTimeResolution = getLE32(p + 144);
    h.closeTime = getLE64(p + 148);
    h.parentCloseTime = getLE64(p + 156);
    return h;
}

void
LedgerHeader::serialize(u8* p) const
{
    putLE32(p, seq);
    std::memcpy(p + 4, hash.data(), 32);
    std::memcpy(p + 36, txHash.data(), 32);
    std::memcpy(p + 68, accountHash.data(), 32);
    std::memcpy(p + 100, parentHash.data(), 32);
    putLE64(p + 132, drops);
    putLE32(p + 140, u32(closeFlags));
    putLE32(p + 144, closeTimeResolution);
    putLE64(p + 148, closeTime);
    putLE64(p + 156, parentCloseTime);
}

Bytes
LedgerHeader::canonical() const
{
    Bytes b(118);
    u8* p = b.data();
    putBE32(p, seq);
    putBE64(p + 4, drops);
    std::memcpy(p + 12, parentHash.data(), 32);
    std::memcpy(p + 44, txHash.data(), 32);
    std::memcpy(p + 76, accountHash.data(), 32);
    putBE32(p + 108, u32(parentCloseTime));
    putBE32(p + 112, u32(closeTime));
    p[116] = u8(closeTimeResolution);
    p[117] = u8(closeFlags);
    return b;
}

std::optional<LedgerHeader>
LedgerHeader::fromCanonical(ByteView v)
{
    if (v.size() < 118)
        return std::nullopt;
    u8 const* p = v.data();
    LedgerHeader h;
    h.seq = getBE32(p);
    h.drops = getBE64(p + 4);
    h.parentHash = H256::fromBytes(p + 12);
    h.txHash = H256::fromBytes(p + 44);
    h.accountHash = H256::fromBytes(p + 76);
    h.parentCloseTime = getBE32(p + 108);
    h.closeTime = getBE32(p + 112);
    h.closeTimeResolution = p[116];
    h.closeFlags = p[117];
    h.hash = h.computeHash();
    return h;
}

H256
LedgerHeader::computeHash() const
{
    Sha512 s;
    s.updateBE32(kPrefixLedger);
    auto c = canonical();
    s.update(c.data(), c.size());
    return s.finalHalf();
}

// ------------------------------------------------------------ RawReader

RawReader::RawReader(std::string const& path)
{
    fd_ = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd_ < 0)
        fail("cannot open " + path + ": " + std::strerror(errno));
    struct stat st;
    if (::fstat(fd_, &st) != 0)
        fail("cannot stat " + path);
    size_ = u64(st.st_size);
#ifdef POSIX_FADV_SEQUENTIAL
    ::posix_fadvise(fd_, 0, 0, POSIX_FADV_SEQUENTIAL);
#endif
    buf_.resize(4 << 20);
}

RawReader::~RawReader()
{
    if (fd_ >= 0)
        ::close(fd_);
}

std::size_t
RawReader::read(u8* out, std::size_t n)
{
    std::size_t done = 0;
    while (done < n)
    {
        if (bufPos_ == bufLen_)
        {
            ssize_t r;
            do
                r = ::read(fd_, buf_.data(), buf_.size());
            while (r < 0 && errno == EINTR);
            if (r < 0)
                fail(std::string("read error: ") + std::strerror(errno));
            if (r == 0)
                break;
            bufPos_ = 0;
            bufLen_ = std::size_t(r);
        }
        std::size_t k = std::min(n - done, bufLen_ - bufPos_);
        if (out)
            std::memcpy(out + done, buf_.data() + bufPos_, k);
        if (hasher_)
            hasher_->update(buf_.data() + bufPos_, k);
        bufPos_ += k;
        done += k;
        pos_ += k;
    }
    return done;
}

void
RawReader::seek(u64 off)
{
    hasher_ = nullptr;
    if (::lseek(fd_, off_t(off), SEEK_SET) < 0)
        fail("seek failed");
    pos_ = off;
    bufPos_ = bufLen_ = 0;
}

// ------------------------------------------------------------ CatReader

CatReader::CatReader(std::string const& path, Options opts) : path_(path), opts_(opts), raw_(path)
{
    u8 h[kFileHeaderSize];
    if (raw_.read(h, kFileHeaderSize) != kFileHeaderSize)
        fail(path + ": too small to be a catalogue file");
    hdr_ = FileHeader::parse(h);
    if (hdr_.magic != kCatlMagic)
        fail(path + ": bad magic (not a CATL catalogue file)");
    if (hdr_.minLedger > hdr_.maxLedger)
        fail(path + ": header min_ledger > max_ledger");
    if (hdr_.version() > 1)
        fail(path + ": unsupported catalogue version " + std::to_string(hdr_.version()));
    if (opts_.hashFile)
    {
        std::memset(h + kHashOffset, 0, 64);
        sha_.update(h, kFileHeaderSize);
        raw_.setHasher(&sha_);
    }
    if (hdr_.compressionLevel() > 0)
        inf_ = std::make_unique<Inflater>([this](u8* b, std::size_t cap) { return raw_.read(b, cap); });
}

std::size_t
CatReader::readSome(u8* p, std::size_t n)
{
    std::size_t k = inf_ ? inf_->read(p, n) : raw_.read(p, n);
    logical_ += k;
    return k;
}

void
CatReader::readExact(u8* p, std::size_t n, char const* what)
{
    if (readSome(p, n) != n)
        fail(path_ + ": unexpected end of stream while reading " + what + " at stream offset " +
             std::to_string(logical_));
}

void
CatReader::skipBytes(u64 n)
{
    if (inf_)
    {
        inf_->skip(n);
        logical_ += n;
        return;
    }
    // raw: read through (keeps the file hash flowing); the 4 MiB buffer
    // makes this as fast as seeking for typical leaf sizes
    if (raw_.read(nullptr, std::size_t(n)) != n)
        fail(path_ + ": unexpected end of stream while skipping item data");
    logical_ += n;
}

bool
CatReader::nextLedger(LedgerHeader& out)
{
    u8 b[kLedgerHeaderSize];
    std::size_t k = readSome(b, kLedgerHeaderSize);
    if (k == 0)
        return false;
    if (k != kLedgerHeaderSize)
        fail(path_ + ": truncated ledger header at stream offset " + std::to_string(logical_ - k));
    out = LedgerHeader::parse(b);
    return true;
}

bool
CatReader::nextItemHeader(ItemHeader& h)
{
    u8 t;
    readExact(&t, 1, "item type");
    if (t == tnTERMINAL)
        return false;
    h.type = t;
    readExact(h.key.data(), 32, "item key");
    h.size = 0;
    if (t == tnREMOVE)
        return true;
    u8 sz[4];
    readExact(sz, 4, "item size");
    h.size = getLE32(sz);
    if (h.size > (1u << 30))
        fail(path_ + ": item " + h.key.hex() + " has implausible size " + std::to_string(h.size));
    return true;
}

bool
CatReader::nextItem(Item& out, bool skipData)
{
    ItemHeader h;
    if (!nextItemHeader(h))
        return false;
    out.type = h.type;
    out.key = h.key;
    if (skipData)
    {
        out.data.clear();
        skipBytes(h.size);
    }
    else
    {
        out.data.resize(h.size);
        if (h.size)
            readExact(out.data.data(), h.size, "item data");
    }
    return true;
}

u64
CatReader::skipSection()
{
    Item it;
    u64 n = 0;
    while (nextItem(it, true))
        ++n;
    return n;
}

u64
CatReader::drain()
{
    u64 trailing = 0;
    u8 buf[65536];
    if (inf_)
    {
        for (;;)
        {
            std::size_t k = inf_->read(buf, sizeof buf);
            trailing += k;
            if (k < sizeof buf)
                break;
        }
        u64 consumed = kFileHeaderSize + inf_->totalIn();
        u64 rawTrailing = raw_.size() > consumed ? raw_.size() - consumed : 0;
        trailing += rawTrailing;
        while (raw_.read(nullptr, sizeof buf) == sizeof buf)
            ;
    }
    else
    {
        for (;;)
        {
            std::size_t k = raw_.read(nullptr, sizeof buf);
            trailing += k;
            if (k < sizeof buf)
                break;
        }
    }
    return trailing;
}

std::array<u8, 64>
CatReader::fileHash()
{
    if (!opts_.hashFile)
        fail("file hashing was not enabled for this reader");
    return sha_.final();
}

void
CatReader::setCheckpointHook(u64 interval, std::function<void(Inflater::Checkpoint&&)> cb)
{
    if (inf_)
        inf_->setCheckpointHook(interval, std::move(cb));
}

void
CatReader::seekStream(u64 off, Checkpoints const* cps)
{
    if (!inf_)
    {
        raw_.seek(kFileHeaderSize + off);
        logical_ = off;
        return;
    }
    Inflater::Checkpoint const* best = nullptr;
    if (cps)
    {
        auto it = std::upper_bound(
            cps->list.begin(), cps->list.end(), off, [](u64 v, Inflater::Checkpoint const& c) {
                return v < c.outPos;
            });
        if (it != cps->list.begin())
            best = &*std::prev(it);
    }
    bool forwardOk = off >= logical_ && (!best || best->outPos <= logical_);
    if (!forwardOk)
    {
        if (best)
        {
            raw_.seek(kFileHeaderSize + best->inBit / 8);
            inf_->restore(*best, [this](u8* b, std::size_t cap) { return raw_.read(b, cap); });
            logical_ = best->outPos;
        }
        else
        {
            raw_.seek(kFileHeaderSize);
            inf_ = std::make_unique<Inflater>([this](u8* b, std::size_t cap) { return raw_.read(b, cap); });
            logical_ = 0;
        }
    }
    if (off > logical_)
        skipBytes(off - logical_);
}

// ------------------------------------------------------------ CatWriter

CatWriter::CatWriter(std::string path, u32 minLedger, u32 maxLedger, u16 networkId, int level)
    : path_(std::move(path)), tmp_(path_ + ".part")
{
    if (minLedger > maxLedger)
        fail("writer: min_ledger > max_ledger");
    fd_ = ::open(tmp_.c_str(), O_CREAT | O_TRUNC | O_WRONLY | O_CLOEXEC, 0644);
    if (fd_ < 0)
        fail("cannot create " + tmp_ + ": " + std::strerror(errno));
    hdr_.minLedger = minLedger;
    hdr_.maxLedger = maxLedger;
    hdr_.networkId = networkId;
    hdr_.versionField = FileHeader::makeVersion(1, u8(std::clamp(level, 0, 9)));
    buf_.reserve(4 << 20);
    u8 h[kFileHeaderSize];
    hdr_.serialize(h);
    rawOut(h, sizeof h);
    if (level > 0)
        def_ = std::make_unique<Deflater>([this](u8 const* p, std::size_t n) { rawOut(p, n); }, level);
}

CatWriter::~CatWriter()
{
    if (fd_ >= 0)
        ::close(fd_);
    if (!done_)
        ::unlink(tmp_.c_str());
}

void
CatWriter::rawOut(u8 const* p, std::size_t n)
{
    written_ += n;
    buf_.insert(buf_.end(), p, p + n);
    if (buf_.size() >= (4u << 20))
        flushRaw();
}

void
CatWriter::flushRaw()
{
    std::size_t off = 0;
    while (off < buf_.size())
    {
        ssize_t r = ::write(fd_, buf_.data() + off, buf_.size() - off);
        if (r < 0)
        {
            if (errno == EINTR)
                continue;
            fail("write error on " + tmp_ + ": " + std::strerror(errno));
        }
        off += std::size_t(r);
    }
    buf_.clear();
}

void
CatWriter::out(u8 const* p, std::size_t n)
{
    if (def_)
        def_->write(p, n);
    else
        rawOut(p, n);
}

void
CatWriter::ledger(LedgerHeader const& h)
{
    u8 b[kLedgerHeaderSize];
    h.serialize(b);
    out(b, sizeof b);
}

void
CatWriter::item(u8 type, H256 const& key, u8 const* data, std::size_t n)
{
    u8 b[37];
    b[0] = type;
    std::memcpy(b + 1, key.data(), 32);
    putLE32(b + 33, u32(n));
    out(b, sizeof b);
    out(data, n);
}

void
CatWriter::remove(H256 const& key)
{
    u8 b[33];
    b[0] = tnREMOVE;
    std::memcpy(b + 1, key.data(), 32);
    out(b, sizeof b);
}

void
CatWriter::terminal()
{
    u8 t = tnTERMINAL;
    out(&t, 1);
}

FileHeader
CatWriter::finish(std::function<void(u64, u64)> progress)
{
    if (def_)
        def_->finish();
    flushRaw();
    hdr_.fileSize = written_;
    u8 h[kFileHeaderSize];
    hdr_.serialize(h);
    if (::pwrite(fd_, h, sizeof h, 0) != ssize_t(sizeof h))
        fail("cannot patch header of " + tmp_);
    ::fsync(fd_);
    hdr_.hash = hashCatalogueFile(tmp_, progress);
    hdr_.serialize(h);
    if (::pwrite(fd_, h + kHashOffset, 64, kHashOffset) != 64)
        fail("cannot write hash into " + tmp_);
    ::fsync(fd_);
    ::close(fd_);
    fd_ = -1;
    if (::rename(tmp_.c_str(), path_.c_str()) != 0)
        fail("cannot rename " + tmp_ + " -> " + path_ + ": " + std::strerror(errno));
    done_ = true;
    return hdr_;
}

std::array<u8, 64>
hashCatalogueFile(std::string const& path, std::function<void(u64, u64)> progress)
{
    RawReader r(path);
    u8 h[kFileHeaderSize];
    if (r.read(h, sizeof h) != sizeof h)
        fail(path + ": too small");
    std::memset(h + kHashOffset, 0, 64);
    Sha512 s;
    s.update(h, sizeof h);
    Bytes buf(4 << 20);
    u64 done = sizeof h, lastReport = 0;
    for (;;)
    {
        std::size_t k = r.read(buf.data(), buf.size());
        if (!k)
            break;
        s.update(buf.data(), k);
        done += k;
        if (progress && done - lastReport >= (256u << 20))
        {
            progress(done, r.size());
            lastReport = done;
        }
    }
    if (progress)
        progress(done, r.size());
    return s.final();
}

}  // namespace catl
