// catl — sidecar index implementation
#include "index.hpp"

#include <cerrno>
#include <cstdlib>
#include <fstream>
#include <sys/stat.h>
#include <unistd.h>

namespace catl {

namespace {

constexpr char kIdxMagic[8] = {'C', 'A', 'T', 'L', 'I', 'D', 'X', '2'};

struct W
{
    Bytes b;
    void u8_(u8 v) { b.push_back(v); }
    void u32_(u32 v)
    {
        u8 t[4];
        putLE32(t, v);
        b.insert(b.end(), t, t + 4);
    }
    void u64_(u64 v)
    {
        u8 t[8];
        putLE64(t, v);
        b.insert(b.end(), t, t + 8);
    }
    void raw(u8 const* p, std::size_t n) { b.insert(b.end(), p, p + n); }
};

struct R
{
    Bytes const& b;
    std::size_t i = 0;
    void need(std::size_t n)
    {
        if (i + n > b.size())
            fail("index: truncated");
    }
    u8 u8_()
    {
        need(1);
        return b[i++];
    }
    u32 u32_()
    {
        need(4);
        u32 v = getLE32(b.data() + i);
        i += 4;
        return v;
    }
    u64 u64_()
    {
        need(8);
        u64 v = getLE64(b.data() + i);
        i += 8;
        return v;
    }
    void raw(u8* p, std::size_t n)
    {
        need(n);
        std::memcpy(p, b.data() + i, n);
        i += n;
    }
};

bool
readHeaderAndSize(std::string const& path, FileHeader& h, u64& size, u8* raw88)
{
    std::ifstream f(path, std::ios::binary);
    if (!f)
        return false;
    f.read(reinterpret_cast<char*>(raw88), kFileHeaderSize);
    if (f.gcount() != std::streamsize(kFileHeaderSize))
        return false;
    h = FileHeader::parse(raw88);
    struct stat st;
    if (::stat(path.c_str(), &st) != 0)
        return false;
    size = u64(st.st_size);
    return true;
}

void
mkdirs(std::string const& p)
{
    std::string cur;
    for (std::size_t i = 0; i < p.size(); ++i)
    {
        cur.push_back(p[i]);
        if (p[i] == '/' || i + 1 == p.size())
            ::mkdir(cur.c_str(), 0755);
    }
}

}  // namespace

u64
checkpointInterval()
{
    if (char const* e = std::getenv("CATL_CP_INTERVAL"))
    {
        u64 v;
        if (parseU64(e, v) && v > 0)
            return v;
    }
    return 64ull << 20;
}

std::string
indexDir()
{
    if (char const* e = std::getenv("CATL_INDEX_DIR"); e && *e)
        return e;
    if (char const* e = std::getenv("XDG_CACHE_HOME"); e && *e)
        return std::string(e) + "/catl";
    if (char const* e = std::getenv("HOME"); e && *e)
        return std::string(e) + "/.cache/catl";
    return "/tmp/catl-index";
}

std::string
CatIndex::cachePathFor(std::string const& catPath)
{
    FileHeader h;
    u64 size = 0;
    u8 raw[kFileHeaderSize];
    if (!readHeaderAndSize(catPath, h, size, raw))
        fail("cannot read " + catPath);
    std::string base = catPath.substr(catPath.find_last_of('/') + 1);
    char tail[64];
    std::snprintf(tail, sizeof tail, "-%llx-", (unsigned long long)size);
    return indexDir() + "/" + base + tail + toHex(h.hash.data(), 8) + ".catlidx";
}

bool
CatIndex::save(std::string const& catPath, std::string* err) const
{
    W w;
    w.raw(reinterpret_cast<u8 const*>(kIdxMagic), 8);
    u8 hb[kFileHeaderSize];
    hdr.serialize(hb);
    w.raw(hb, sizeof hb);
    w.u64_(fileSize);
    w.u32_(firstSeq);
    w.u8_(complete ? 1 : 0);
    w.u32_(u32(error.size()));
    w.raw(reinterpret_cast<u8 const*>(error.data()), error.size());
    u8 lh[kLedgerHeaderSize];
    first.serialize(lh);
    w.raw(lh, sizeof lh);
    last.serialize(lh);
    w.raw(lh, sizeof lh);
    w.u64_(ledgers.size());
    for (auto const& e : ledgers)
    {
        w.u64_(e.offset);
        w.u32_(e.stateItems);
        w.u32_(e.txItems);
        w.u32_(e.closeTime);
    }
    w.u64_(flagHashes.size());
    for (auto const& [s, h] : flagHashes)
    {
        w.u32_(s);
        w.raw(h.data(), 32);
    }
    w.u64_(cps.list.size());
    for (auto const& cp : cps.list)
    {
        w.u64_(cp.outPos);
        w.u64_(cp.inBit);
        Bytes z = zlibCompress(cp.window, 6);
        w.u32_(u32(z.size()));
        w.raw(z.data(), z.size());
    }
    std::string path = cachePathFor(catPath);
    mkdirs(indexDir());
    std::string tmp = path + ".tmp";
    {
        std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
        if (!f)
        {
            if (err)
                *err = "cannot write " + tmp;
            return false;
        }
        f.write(reinterpret_cast<char const*>(w.b.data()), std::streamsize(w.b.size()));
        if (!f)
        {
            if (err)
                *err = "write failed for " + tmp;
            return false;
        }
    }
    if (::rename(tmp.c_str(), path.c_str()) != 0)
    {
        if (err)
            *err = "cannot rename index into place";
        return false;
    }
    return true;
}

std::optional<CatIndex>
CatIndex::load(std::string const& catPath)
{
    FileHeader fh;
    u64 size = 0;
    u8 raw[kFileHeaderSize];
    if (!readHeaderAndSize(catPath, fh, size, raw))
        return std::nullopt;
    for (std::string p : {catPath + ".catlidx", cachePathFor(catPath)})
    {
        std::ifstream f(p, std::ios::binary);
        if (!f)
            continue;
        Bytes b((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
        try
        {
            R r{b};
            char m[8];
            r.raw(reinterpret_cast<u8*>(m), 8);
            if (std::memcmp(m, kIdxMagic, 8) != 0)
                continue;
            CatIndex x;
            u8 hb[kFileHeaderSize];
            r.raw(hb, sizeof hb);
            if (std::memcmp(hb, raw, kFileHeaderSize) != 0)
                continue;  // stale: file was rewritten
            x.hdr = FileHeader::parse(hb);
            x.fileSize = r.u64_();
            if (x.fileSize != size)
                continue;  // stale: file grew (in-progress download/creation)
            x.firstSeq = r.u32_();
            x.complete = r.u8_() != 0;
            x.error.resize(r.u32_());
            r.raw(reinterpret_cast<u8*>(x.error.data()), x.error.size());
            u8 lh[kLedgerHeaderSize];
            r.raw(lh, sizeof lh);
            x.first = LedgerHeader::parse(lh);
            r.raw(lh, sizeof lh);
            x.last = LedgerHeader::parse(lh);
            x.ledgers.resize(r.u64_());
            for (auto& e : x.ledgers)
            {
                e.offset = r.u64_();
                e.stateItems = r.u32_();
                e.txItems = r.u32_();
                e.closeTime = r.u32_();
            }
            x.flagHashes.resize(r.u64_());
            for (auto& [s, h] : x.flagHashes)
            {
                s = r.u32_();
                r.raw(h.data(), 32);
            }
            x.cps.list.resize(r.u64_());
            for (auto& cp : x.cps.list)
            {
                cp.outPos = r.u64_();
                cp.inBit = r.u64_();
                Bytes z(r.u32_());
                r.raw(z.data(), z.size());
                cp.window = zlibDecompress(z);
            }
            return x;
        }
        catch (Error const&)
        {
            continue;
        }
    }
    return std::nullopt;
}

CatIndex
CatIndex::build(std::string const& catPath, std::function<void(u64, u64)> progress, std::atomic<bool> const* cancel)
{
    CatIndex idx;
    CatReader r(catPath);
    idx.hdr = r.header();
    idx.fileSize = r.rawSize();
    r.setCheckpointHook(checkpointInterval(), [&](Inflater::Checkpoint&& cp) { idx.cps.list.push_back(std::move(cp)); });
    LedgerHeader h;
    u64 n = 0;
    try
    {
        for (;;)
        {
            if (cancel && cancel->load())
                fail("cancelled");
            u64 off = r.streamPos();
            if (!r.nextLedger(h))
                break;
            if (!idx.ledgers.empty() && h.seq != idx.lastSeq() + 1)
                fail("ledger sequence jumps from " + std::to_string(idx.lastSeq()) + " to " + std::to_string(h.seq));
            u32 s = u32(r.skipSection());
            u32 t = u32(r.skipSection());
            if (idx.ledgers.empty())
            {
                idx.firstSeq = h.seq;
                idx.first = h;
            }
            idx.ledgers.push_back({off, s, t, u32(h.closeTime)});
            idx.last = h;
            if (h.seq % 256 == 0)
                idx.flagHashes.push_back({h.seq, h.hash});
            if (progress && (++n & 1023) == 0)
                progress(r.rawPos(), r.rawSize());
            if (h.seq == idx.hdr.maxLedger)
                break;
        }
    }
    catch (Error const& e)
    {
        idx.error = e.what();
        if (std::string(e.what()) == "cancelled")
            throw;
    }
    if (progress)
        progress(r.rawPos(), r.rawSize());
    idx.complete = idx.error.empty() && !idx.ledgers.empty() && idx.lastSeq() == idx.hdr.maxLedger;
    return idx;
}

CatIndex
CatIndex::get(std::string const& catPath, std::function<void(u64, u64)> progress, std::atomic<bool> const* cancel)
{
    if (auto x = load(catPath))
        return std::move(*x);
    CatIndex x = build(catPath, std::move(progress), cancel);
    x.save(catPath);
    return x;
}

}  // namespace catl
