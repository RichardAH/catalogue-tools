// catl — downloader for the canonical catalogue set: resumable (HTTP Range),
// streams the file SHA-512 while downloading, checks it against the header.
#include "fetch.hpp"
#include "net.hpp"

#include <cerrno>
#include <fcntl.h>
#include <regex>
#include <set>
#include <sys/stat.h>
#include <unistd.h>

namespace catl {

std::vector<RemoteCat>
listRemote(std::string const& baseUrl0)
{
    std::string base = baseUrl0;
    if (base.empty() || base.back() != '/')
        base += '/';
    int status = 0;
    std::string html = httpGetText(base, &status);
    if (status != 200)
        fail("listing " + base + " returned HTTP " + std::to_string(status));
    std::vector<RemoteCat> out;
    std::set<std::string> seen;
    std::regex re(R"re(href="([^"/]*?cat\.(\d+)-(\d+))"[^\n]*?</a>([^\n]*))re");
    for (std::sregex_iterator it(html.begin(), html.end(), re), end; it != end; ++it)
    {
        RemoteCat c;
        c.name = (*it)[1];
        if (!seen.insert(c.name).second)
            continue;
        parseU32((*it)[2].str(), c.minLedger);
        parseU32((*it)[3].str(), c.maxLedger);
        c.url = base + c.name;
        std::string tail = (*it)[4];
        auto e = tail.find_last_not_of(" \t\r");
        if (e != std::string::npos)
        {
            auto s = tail.find_last_of(" \t", e);
            c.listedSize = tail.substr(s == std::string::npos ? 0 : s + 1, e - (s == std::string::npos ? 0 : s + 1) + 1);
            if (!std::regex_match(c.listedSize, std::regex(R"([0-9.]+[KMGTP]?)")))
                c.listedSize.clear();
        }
        out.push_back(c);
    }
    std::sort(out.begin(), out.end(), [](auto const& a, auto const& b) { return a.minLedger < b.minLedger; });
    return out;
}

void
probeRemote(std::vector<RemoteCat>& cats, Progress* p)
{
    std::size_t i = 0;
    for (auto& c : cats)
    {
        if (p)
        {
            p->check();
            (*p)("probe", ++i, cats.size(), c.name, true);
        }
        try
        {
            Bytes b;
            auto r = httpGet(c.url, "Range: bytes=0-87\r\n", [&](u8 const* d, std::size_t n) {
                b.insert(b.end(), d, d + n);
                return b.size() < kFileHeaderSize;
            });
            if (b.size() < kFileHeaderSize)
            {
                c.probeError = "HTTP " + std::to_string(r.status);
                continue;
            }
            auto h = FileHeader::parse(b.data());
            if (h.magic != kCatlMagic)
                c.probeError = "not a catalogue";
            else
                c.hdr = h;
        }
        catch (Error const& e)
        {
            c.probeError = e.what();
        }
    }
}

LocalState
localState(RemoteCat const& c, std::string const& dir, u64* have)
{
    std::string fin = dir + "/" + c.name, part = fin + ".part";
    struct stat st;
    if (::stat(fin.c_str(), &st) == 0)
    {
        if (have)
            *have = u64(st.st_size);
        if (!c.hdr)
            return LocalState::Complete;
        try
        {
            auto lf = openCatFile(fin);
            if (std::memcmp(&lf.hdr.hash, &c.hdr->hash, 64) == 0 && lf.size == c.hdr->fileSize && c.finished())
                return LocalState::Complete;
            if (!c.finished() && lf.hdr.minLedger == c.hdr->minLedger)
                return LocalState::Complete;
        }
        catch (Error const&)
        {
        }
        return LocalState::Different;
    }
    if (::stat(part.c_str(), &st) == 0)
    {
        if (have)
            *have = u64(st.st_size);
        return LocalState::Partial;
    }
    if (have)
        *have = 0;
    return LocalState::Missing;
}

namespace {

// feed bytes at absolute file offset `off` into the catalogue-file hash
// (header hash field [24,88) is hashed as zeros)
void
feedHash(Sha512& s, u64 off, u8 const* p, std::size_t n)
{
    if (off >= kFileHeaderSize)
    {
        s.update(p, n);
        return;
    }
    u8 tmp[kFileHeaderSize];
    std::size_t k = std::min<std::size_t>(n, std::size_t(kFileHeaderSize - off));
    std::memcpy(tmp, p, k);
    for (std::size_t i = 0; i < k; ++i)
        if (off + i >= kHashOffset)
            tmp[i] = 0;
    s.update(tmp, k);
    if (n > k)
        s.update(p + k, n - k);
}

}  // namespace

DownloadResult
downloadCat(RemoteCat const& c, std::string const& dir, bool includeUnfinished, Progress* p)
{
    DownloadResult res;
    if (!c.hdr)
    {
        res.msg = c.name + ": remote header unavailable (" + c.probeError + ")";
        return res;
    }
    if (!c.finished() && !includeUnfinished)
    {
        res.ok = true;
        res.msg = c.name + ": skipped, upstream is still writing it (header filesize/hash unset); use --include-unfinished to take a snapshot";
        return res;
    }
    u64 have = 0;
    auto st = localState(c, dir, &have);
    if (st == LocalState::Complete && c.finished())
    {
        res.ok = true;
        res.msg = c.name + ": already present";
        return res;
    }
    if (st == LocalState::Different)
    {
        res.msg = c.name + ": a different file with this name exists in " + dir + "; move it aside first";
        return res;
    }
    std::string fin = dir + "/" + c.name, part = fin + ".part";
    u64 target = c.hdr->fileSize;  // 0 for unfinished
    if (target && have > target)
        have = 0;
    int fd = ::open(part.c_str(), O_WRONLY | O_CREAT | O_CLOEXEC, 0644);
    if (fd < 0)
    {
        res.msg = "cannot open " + part + ": " + std::strerror(errno);
        return res;
    }
    struct Closer
    {
        int fd;
        ~Closer() { ::close(fd); }
    } closer{fd};
    Sha512 sha;
    if (have)
    {
        // re-hash what we already have so the final check covers it
        RawReader rr(part);
        Bytes buf(4 << 20);
        u64 off = 0;
        while (off < have)
        {
            if (p)
                p->check();
            std::size_t k = rr.read(buf.data(), std::size_t(std::min<u64>(buf.size(), have - off)));
            if (!k)
                break;
            feedHash(sha, off, buf.data(), k);
            off += k;
            if (p)
                (*p)("rehash", off, have, c.name);
        }
        have = off;
    }
    if (::ftruncate(fd, off_t(have)) != 0 || ::lseek(fd, off_t(have), SEEK_SET) < 0)
    {
        res.msg = "cannot prepare " + part;
        return res;
    }
    u64 pos = have;
    Bytes wbuf;
    wbuf.reserve(8 << 20);
    auto flush = [&] {
        std::size_t o = 0;
        while (o < wbuf.size())
        {
            ssize_t r = ::write(fd, wbuf.data() + o, wbuf.size() - o);
            if (r < 0)
            {
                if (errno == EINTR)
                    continue;
                fail("write to " + part + " failed: " + std::strerror(errno));
            }
            o += std::size_t(r);
        }
        wbuf.clear();
    };
    auto t0 = std::chrono::steady_clock::now();
    bool restarted = false;
    std::string range = have ? "Range: bytes=" + std::to_string(have) + "-\r\n" : "";
    if (target && have == target)
        range.clear();  // nothing left; fall through to the check
    else
    {
        auto r = httpGet(c.url, range, [&](u8 const* d, std::size_t n) {
            if (p)
                p->check();
            wbuf.insert(wbuf.end(), d, d + n);
            feedHash(sha, pos, d, n);
            pos += n;
            if (wbuf.size() >= (8u << 20))
                flush();
            if (p)
            {
                double secs = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
                double rate = secs > 0 ? double(pos - have) / secs : 0;
                (*p)("download", pos, target ? target : pos, c.name + "  " + humanBytes(u64(rate)) + "/s");
            }
            return true;
        }, 120);
        if (have && r.status == 200)
            restarted = true;  // server ignored Range: we appended a full copy; redo cleanly below
        else if (r.status != 200 && r.status != 206)
        {
            flush();
            res.msg = c.name + ": HTTP " + std::to_string(r.status);
            return res;
        }
    }
    flush();
    if (restarted)
    {
        if (::ftruncate(fd, 0) != 0)
            res.msg = "cannot truncate " + part;
        res.msg = c.name + ": server does not support resume; partial file discarded, run fetch again";
        return res;
    }
    ::fsync(fd);
    if (target && pos != target)
    {
        res.msg = c.name + ": got " + withCommas(pos) + " of " + withCommas(target) + " bytes (run fetch again to resume)";
        return res;
    }
    auto digest = sha.final();
    if (c.finished())
    {
        if (digest != c.hdr->hash)
        {
            res.msg = c.name + ": SHA-512 MISMATCH after download; kept as " + part;
            return res;
        }
    }
    if (::rename(part.c_str(), fin.c_str()) != 0)
    {
        res.msg = "cannot rename " + part;
        return res;
    }
    res.ok = true;
    res.msg = c.name + ": " + humanBytes(pos) + (c.finished() ? ", SHA-512 verified against header" : ", unfinished upstream snapshot (no hash to check)");
    return res;
}

}  // namespace catl
