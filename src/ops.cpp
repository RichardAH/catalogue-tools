// catl — operations implementation
#include "ops.hpp"
#include "net.hpp"

#include <dirent.h>
#include <fstream>
#include <set>
#include <sys/stat.h>
#include <unordered_set>

namespace catl {

namespace {

std::string
L(u32 seq)
{
    return "ledger " + std::to_string(seq) + ": ";
}

double
secondsSince(std::chrono::steady_clock::time_point t0)
{
    return std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
}

}  // namespace

// ================================================================ files

CatFile
openCatFile(std::string const& path)
{
    std::ifstream in(path, std::ios::binary);
    if (!in)
        fail("cannot open " + path);
    u8 h[kFileHeaderSize];
    in.read(reinterpret_cast<char*>(h), sizeof h);
    if (in.gcount() != std::streamsize(sizeof h))
        fail(path + ": too small to be a catalogue");
    CatFile f;
    f.path = path;
    f.hdr = FileHeader::parse(h);
    if (f.hdr.magic != kCatlMagic)
        fail(path + ": not a catalogue (bad magic)");
    struct stat st;
    ::stat(path.c_str(), &st);
    f.size = u64(st.st_size);
    return f;
}

std::vector<CatFile>
collectFiles(std::vector<std::string> const& args)
{
    std::vector<CatFile> out;
    auto consider = [&](std::string const& p, bool explicitArg) {
        auto ends = [&](char const* s) {
            std::string_view v(p), e(s);
            return v.size() >= e.size() && v.substr(v.size() - e.size()) == e;
        };
        if (!explicitArg && (ends(".part") || ends(".catlidx") || ends(".tmp")))
            return;
        try
        {
            out.push_back(openCatFile(p));
        }
        catch (Error const&)
        {
            if (explicitArg)
                throw;
        }
    };
    for (auto const& a : args)
    {
        struct stat st;
        if (::stat(a.c_str(), &st) != 0)
            fail("no such file or directory: " + a);
        if (S_ISDIR(st.st_mode))
        {
            DIR* d = ::opendir(a.c_str());
            if (!d)
                fail("cannot read directory " + a);
            while (auto* e = ::readdir(d))
            {
                std::string n = e->d_name;
                if (n == "." || n == "..")
                    continue;
                std::string p = a + (a.back() == '/' ? "" : "/") + n;
                struct stat s2;
                if (::stat(p.c_str(), &s2) == 0 && S_ISREG(s2.st_mode) && s2.st_size >= std::int64_t(kFileHeaderSize))
                    consider(p, false);
            }
            ::closedir(d);
        }
        else
            consider(a, true);
    }
    std::sort(out.begin(), out.end(), [](CatFile const& x, CatFile const& y) {
        return std::tie(x.hdr.minLedger, x.hdr.maxLedger, x.path) < std::tie(y.hdr.minLedger, y.hdr.maxLedger, y.path);
    });
    return out;
}

CatFile const*
fileFor(std::vector<CatFile> const& files, u32 seq)
{
    CatFile const* best = nullptr;
    for (auto const& f : files)
        if (seq >= f.hdr.minLedger && seq <= f.hdr.maxLedger)
            if (!best || f.hdr.minLedger > best->hdr.minLedger)
                best = &f;  // latest base = shortest replay for lookups
    return best;
}

// ================================================================ verify

VerifyResult
verifyFile(CatFile const& f, VerifyOptions const& o, Progress* p)
{
    auto t0 = std::chrono::steady_clock::now();
    VerifyResult res;
    res.path = f.path;
    res.hdr = f.hdr;
    res.recomputed = o.structure;
    FileHeader const& H = f.hdr;
    bool inProgress = !f.finished();

    auto err = [&](std::string const& m) {
        if (res.errors.size() < o.maxErrors)
            res.errors.push_back(m);
        else if (res.errors.size() == o.maxErrors)
            res.errors.push_back("... further errors suppressed");
    };

    if (H.fileSize != 0 && H.fileSize != f.size)
        err("header says the file is " + withCommas(H.fileSize) + " bytes but it is " + withCommas(f.size) +
            (f.size < H.fileSize ? " (truncated / partial download?)" : ""));
    if (inProgress)
        res.warnings.push_back(
            "header filesize/hash are unset: this copy was taken while catalogue_create was still writing it");
    if (H.version() != 1)
        res.warnings.push_back("catalogue version " + std::to_string(H.version()));

    if (!o.structure)
    {
        if (o.fileHash)
        {
            auto fh = hashCatalogueFile(f.path, [&](u64 d, u64 t) {
                if (p)
                {
                    p->check();
                    (*p)("hash", d, t, f.name());
                }
            });
            res.fileHash = H.hashIsZero() ? 2 : (fh == H.hash ? 1 : 0);
            if (res.fileHash == 0)
                err("file SHA-512 does not match the hash in its header");
        }
        if (auto idx = CatIndex::load(f.path))
        {
            auto s = summaryFromIndex(f, *idx);
            res.firstSeq = s.firstSeq;
            res.lastSeq = s.lastSeq;
            res.firstHash = s.firstHash;
            res.firstParent = s.firstParent;
            res.lastHash = s.lastHash;
            res.flagHashes = s.flagHashes;
            res.complete = s.complete;
            res.ledgers = s.ledgers;
        }
        res.ok = res.errors.empty();
        res.seconds = secondsSince(t0);
        return res;
    }

    CatReader r(f.path, CatReader::Options{o.fileHash});
    CatIndex idx;
    idx.hdr = H;
    idx.fileSize = f.size;
    if (o.saveIndex)
        r.setCheckpointHook(checkpointInterval(), [&](Inflater::Checkpoint&& cp) { idx.cps.list.push_back(std::move(cp)); });

    bool aborted = false;
    u64 pctMismatch = 0, noops = 0;
    try
    {
        SHAMap state(SHAMap::Kind::State), txm(SHAMap::Kind::TxMeta);
        LedgerHeader h, prev;
        bool havePrev = false;
        Item it;
        u32 expect = H.minLedger;
        for (;;)
        {
            if (p)
                p->check();
            u64 off = r.streamPos();
            if (!r.nextLedger(h))
                break;
            if (h.seq != expect)
            {
                err("expected ledger " + std::to_string(expect) + " but found " + std::to_string(h.seq) +
                    " at stream offset " + std::to_string(off));
                aborted = true;
                break;
            }
            bool base = h.seq == H.minLedger;
            u32 nState = 0, nTx = 0;
            while (r.nextItem(it))
            {
                ++nState;
                if (it.type == tnREMOVE)
                {
                    if (base)
                        err(L(h.seq) + "removal inside the base (full-state) ledger");
                    else if (!state.remove(it.key))
                        err(L(h.seq) + "removal of absent key " + it.key.hex());
                    continue;
                }
                if (it.type != tnACCOUNT_STATE)
                    err(L(h.seq) + "unexpected node type " + std::to_string(it.type) + " in state section");
                auto u = state.upsert(it.key, it.data.data(), it.data.size());
                if (base && u != SHAMap::Upsert::Inserted)
                    err(L(h.seq) + "duplicate key in full-state dump: " + it.key.hex());
                if (!base && u == SHAMap::Upsert::Unchanged)
                    ++noops;
            }
            txm.clear();
            while (r.nextItem(it))
            {
                ++nTx;
                if (it.type != tnTRANSACTION_MD)
                    err(L(h.seq) + "unexpected node type " + std::to_string(it.type) + " in tx section");
                if (o.checkTxIds)
                {
                    ByteView tx, meta;
                    if (!splitTxLeaf(it.data, tx, meta))
                        err(L(h.seq) + "tx leaf " + it.key.hex() + " is not VL(tx)||VL(meta)");
                    else if (txIdOf(tx) != it.key)
                        err(L(h.seq) + "tx key " + it.key.hex() + " != SHA512Half(TXN||tx)");
                }
                if (txm.upsert(it.key, it.data.data(), it.data.size()) != SHAMap::Upsert::Inserted)
                    err(L(h.seq) + "duplicate transaction " + it.key.hex());
            }
            H256 sh = state.rootHash(), th = txm.rootHash(), hh = h.computeHash();
            if (sh != h.accountHash)
                err(L(h.seq) + "state map hash " + sh.hex() + " != header account_hash " + h.accountHash.hex());
            if (th != h.txHash)
                err(L(h.seq) + "tx map hash " + th.hex() + " != header transaction_hash " + h.txHash.hex());
            if (hh != h.hash)
                err(L(h.seq) + "recomputed ledger hash " + hh.hex() + " != stored " + h.hash.hex());
            if (havePrev)
            {
                if (h.parentHash != prev.hash)
                    err(L(h.seq) + "parent_hash " + h.parentHash.hex() + " != hash of ledger " +
                        std::to_string(prev.seq));
                if (h.parentCloseTime != prev.closeTime)
                    ++pctMismatch;
            }
            else
            {
                res.firstSeq = h.seq;
                res.firstHash = hh;
                res.firstParent = h.parentHash;
            }
            if (h.seq % 256 == 0 && hh == h.hash)
                res.flagHashes.push_back({h.seq, hh});
            if (o.saveIndex)
            {
                if (idx.ledgers.empty())
                {
                    idx.firstSeq = h.seq;
                    idx.first = h;
                }
                idx.ledgers.push_back({off, nState, nTx, u32(h.closeTime)});
                idx.last = h;
                if (h.seq % 256 == 0)
                    idx.flagHashes.push_back({h.seq, h.hash});
            }
            res.lastSeq = h.seq;
            res.lastHash = hh;
            res.txs += nTx;
            res.stateOps += nState;
            ++res.ledgers;
            prev = h;
            havePrev = true;
            ++expect;
            if (p)
                (*p)("verify", r.rawPos(), r.rawSize(),
                     f.name() + " ledger " + std::to_string(h.seq) + " (" + withCommas(state.size()) + " objects)");
            if (res.errors.size() > o.maxErrors)
            {
                aborted = true;
                break;
            }
            if (h.seq == H.maxLedger)
                break;
        }
        res.stateEntries = state.size();
    }
    catch (Error const& e)
    {
        if (std::string(e.what()) == "cancelled")
            throw;
        aborted = true;
        if (inProgress)
            res.warnings.push_back(std::string("stream ends inside a ledger (file still being written): ") + e.what());
        else
            err(e.what());
    }
    if (noops)
        res.warnings.push_back(withCommas(noops) + " state items rewrote an entry with identical data");
    if (pctMismatch)
        res.warnings.push_back(withCommas(pctMismatch) + " ledgers have parent_close_time != previous close_time");
    res.complete = res.ledgers > 0 && res.lastSeq == H.maxLedger;
    if (!res.complete && !aborted)
    {
        std::string m = res.ledgers ? "file holds ledgers " + std::to_string(res.firstSeq) + "-" +
                std::to_string(res.lastSeq) + " but its header promises up to " + std::to_string(H.maxLedger)
                                    : std::string("file contains no ledgers");
        if (inProgress)
            res.warnings.push_back(m);
        else
            err(m);
    }

    if (o.fileHash)
    {
        std::array<u8, 64> fh{};
        bool drained = false;
        if (!aborted)
        {
            try
            {
                u64 trailing = r.drain();
                drained = true;
                if (trailing && res.complete)
                    err(withCommas(trailing) + " bytes of unexpected data after ledger " + std::to_string(H.maxLedger));
            }
            catch (Error const& e)
            {
                err(std::string("after last ledger: ") + e.what());
            }
        }
        fh = drained ? r.fileHash() : hashCatalogueFile(f.path);
        res.fileHash = H.hashIsZero() ? 2 : (fh == H.hash ? 1 : 0);
        if (res.fileHash == 0)
            err("file SHA-512 does not match the hash in its header");
    }
    res.ok = res.errors.empty();
    if (o.saveIndex && !aborted && res.errors.empty())
    {
        idx.complete = res.complete;
        idx.save(f.path);
    }
    res.seconds = secondsSince(t0);
    return res;
}

VerifyResult
summaryFromIndex(CatFile const& f, CatIndex const& idx)
{
    VerifyResult r;
    r.path = f.path;
    r.hdr = f.hdr;
    r.firstSeq = idx.firstSeq;
    r.lastSeq = idx.lastSeq();
    r.firstHash = idx.first.hash;
    r.firstParent = idx.first.parentHash;
    r.lastHash = idx.last.hash;
    r.flagHashes = idx.flagHashes;
    r.complete = idx.complete;
    r.ledgers = idx.ledgers.size();
    r.ok = idx.error.empty();
    if (!idx.error.empty())
        r.errors.push_back(idx.error);
    return r;
}

std::vector<ChainIssue>
checkChain(std::vector<VerifyResult> const& rs)
{
    std::vector<ChainIssue> out;
    VerifyResult const* cur = nullptr;
    for (auto const& b : rs)
    {
        if (!b.ledgers)
            continue;
        if (!cur)
        {
            cur = &b;
            continue;
        }
        auto const& a = *cur;
        std::string an = a.path.substr(a.path.find_last_of('/') + 1), bn = b.path.substr(b.path.find_last_of('/') + 1);
        if (a.hdr.networkId != b.hdr.networkId)
            out.push_back({true, an + " and " + bn + " are from different networks (" + std::to_string(a.hdr.networkId) +
                                     " vs " + std::to_string(b.hdr.networkId) + ")"});
        if (b.firstSeq > a.lastSeq + 1)
            out.push_back({true, "gap: no file covers ledgers " + std::to_string(a.lastSeq + 1) + "-" +
                                     std::to_string(b.firstSeq - 1) + " (between " + an + " and " + bn + ")"});
        else if (b.firstSeq == a.lastSeq + 1)
        {
            if (b.firstParent != a.lastHash)
                out.push_back({true, bn + " ledger " + std::to_string(b.firstSeq) + " parent_hash does not match " + an +
                                         " ledger " + std::to_string(a.lastSeq) + " hash: different chains"});
        }
        else
        {
            std::map<u32, H256> fa(a.flagHashes.begin(), a.flagHashes.end());
            u32 agree = 0, disagree = 0;
            for (auto const& [s, h] : b.flagHashes)
                if (auto it = fa.find(s); it != fa.end())
                    (it->second == h ? agree : disagree)++;
            if (b.firstSeq == a.firstSeq && b.firstHash != a.firstHash)
                ++disagree;
            u32 hi = std::min(a.lastSeq, b.lastSeq);
            std::string msg = "overlap " + std::to_string(b.firstSeq) + "-" + std::to_string(hi) + " between " + an +
                " and " + bn + ": " + std::to_string(agree) + " flag-ledger hashes agree";
            if (disagree)
                out.push_back({true, msg + ", " + std::to_string(disagree) + " DISAGREE"});
            else
                out.push_back({false, msg});
        }
        if (b.lastSeq > a.lastSeq)
            cur = &b;
    }
    return out;
}

// ================================================================ remote

namespace {

Json
cmd(char const* c)
{
    Json j = Json::object();
    j.set("command", c);
    return j;
}

std::string
respError(Json const& r)
{
    if (r.has("error"))
        return r["error"].str() + (r.has("error_message") ? " (" + r["error_message"].str() + ")" : "");
    if (r["result"].has("error"))
        return r["result"]["error"].str();
    if (r["status"].str() == "error")
        return "error";
    return "";
}

std::optional<LedgerHeader>
ledgerFromResp(Json const& r, std::string& err)
{
    err = respError(r);
    if (!err.empty())
        return std::nullopt;
    Json const& res = r["result"];
    Bytes b;
    if (!fromHex(res["ledger"]["ledger_data"].str(), b))
    {
        err = "response has no binary ledger_data";
        return std::nullopt;
    }
    auto h = LedgerHeader::fromCanonical(b);
    if (!h)
    {
        err = "short ledger_data";
        return std::nullopt;
    }
    if (res.has("ledger_hash"))
    {
        H256 claimed;
        if (H256::parse(res["ledger_hash"].str(), claimed) && claimed != h->hash)
        {
            err = "server's ledger_hash does not match the header it sent";
            return std::nullopt;
        }
    }
    return h;
}

std::optional<Bytes>
entryFromResp(Json const& r, std::string& err)
{
    err = respError(r);
    if (!err.empty())
        return std::nullopt;
    Bytes b;
    if (!fromHex(r["result"]["node_binary"].str(), b))
    {
        err = "response has no node_binary";
        return std::nullopt;
    }
    return b;
}

Json
ledgerReq(u32 seq)
{
    Json j = cmd("ledger");
    j.set("ledger_index", seq);
    j.set("binary", true);
    return j;
}

Json
entryReq(H256 const& key, H256 const& atLedger)
{
    Json j = cmd("ledger_entry");
    j.set("index", key.hex());
    j.set("ledger_hash", atLedger.hex());
    j.set("binary", true);
    return j;
}

// hash of `seq` from a LedgerHashes object (sfHashes, sfLastLedgerSequence)
std::optional<H256>
fromSkipList(Bytes const& node, u32 seq, u32 stride)
{
    auto hashes = stV256(node, 2);
    auto last = stU32(node, 27);
    if (!last || hashes.empty() || seq > *last)
        return std::nullopt;
    u32 d = *last - seq;
    if (d % stride)
        return std::nullopt;
    u64 back = d / stride;
    if (back >= hashes.size())
        return std::nullopt;
    return hashes[hashes.size() - 1 - back];
}

// Walk headers from `from` (exclusive, whose parent hash is `expect`) down
// to `to`, verifying every link. Returns hash of `to`.
std::optional<H256>
walkDown(WsClient& ws, u32 from, H256 expect, u32 to, std::string& err, Progress* p)
{
    u32 k = from;
    while (k > to)
    {
        std::vector<Json> reqs;
        u32 hi = k - 1, lo = std::max(to, hi > 255 ? hi - 255 : 0u);
        for (u32 s = hi + 1; s-- > lo;)
            reqs.push_back(ledgerReq(s));
        auto resps = ws.callMany(std::move(reqs), 64);
        for (auto const& r : resps)
        {
            auto h = ledgerFromResp(r, err);
            if (!h)
                return std::nullopt;
            if (h->hash != expect)
            {
                err = "server's ledger " + std::to_string(h->seq) + " does not hash to its child's parent_hash";
                return std::nullopt;
            }
            if (h->seq == to)
                return h->hash;
            expect = h->parentHash;
        }
        k = lo;
        if (p)
            (*p)("walk", from - k, from - to, "ledger " + std::to_string(k));
    }
    return expect;
}

}  // namespace

AnchorReport
remoteAnchor(
    std::vector<std::pair<u32, H256>> const& flags,
    std::optional<std::pair<u32, H256>> last,
    u16 networkId,
    AnchorOptions const& o,
    Progress* p)
{
    AnchorReport rep;
    bool serverFailed = false;
    auto line = [&](std::string s) { rep.lines.push_back(std::move(s)); };
    for (auto const& url : o.servers)
    {
        try
        {
            line("server " + url);
            WsClient ws(url);
            auto info = ws.call(cmd("server_info"));
            if (auto nid = info["result"]["info"]["network_id"].asU64(); nid && networkId && *nid != networkId)
            {
                line("  network_id mismatch: catalogue " + std::to_string(networkId) + ", server " + std::to_string(*nid));
                serverFailed = true;
                continue;
            }
            Json tq = cmd("ledger");
            tq.set("ledger_index", "validated");
            tq.set("binary", true);
            auto tr = ws.call(tq);
            std::string err;
            auto tip = ledgerFromResp(tr, err);
            if (!tip)
            {
                line("  cannot fetch validated ledger: " + err);
                serverFailed = true;
                continue;
            }
            if (!tr["result"]["validated"].boolean())
                line("  warning: server did not flag the ledger as validated");
            line("  validated tip " + std::to_string(tip->seq) + " " + tip->hash.hex() + " (" +
                 rippleTimeToString(tip->closeTime) + " UTC), header hash recomputed locally");

            // ---- flag ledgers via long skip lists in the tip's state
            std::map<u32, std::vector<std::pair<u32, H256>>> groups;
            for (auto const& f : flags)
            {
                if (f.first >= tip->seq)
                {
                    ++rep.uncovered;
                    continue;
                }
                groups[f.first >> 16].push_back(f);
            }
            std::vector<Json> reqs;
            std::vector<u32> gids;
            for (auto const& [g, v] : groups)
            {
                reqs.push_back(entryReq(skipKeylet(g << 16), tip->hash));
                gids.push_back(g);
            }
            auto resps = ws.callMany(std::move(reqs), 16);
            u32 m0 = rep.matched, x0 = rep.mismatched;
            for (std::size_t i = 0; i < resps.size(); ++i)
            {
                auto node = entryFromResp(resps[i], err);
                for (auto const& [seq, h] : groups[gids[i]])
                {
                    ++rep.checked;
                    std::optional<H256> nh;
                    if (node)
                        nh = fromSkipList(*node, seq, 256);
                    if (!nh)
                        ++rep.uncovered;
                    else if (*nh == h)
                        ++rep.matched;
                    else
                    {
                        ++rep.mismatched;
                        if (rep.mismatched <= 20)
                            line("  MISMATCH flag ledger " + std::to_string(seq) + ": catalogue " + h.hex() + " network " + nh->hex());
                    }
                }
                if (p)
                    (*p)("anchor", i + 1, resps.size(), "skip list group " + std::to_string(gids[i]));
            }
            if (!flags.empty())
                line("  flag ledgers: " + std::to_string(rep.matched - m0) + " match the network's LedgerHashes, " +
                     std::to_string(rep.mismatched - x0) + " differ (server-attested skip lists in the validated state)");

            // ---- end of range
            if (last)
            {
                auto [L, HL] = *last;
                std::optional<H256> nh;
                std::string how;
                if (L > tip->seq)
                    line("  catalogue ends at " + std::to_string(L) + ", beyond this server's validated tip");
                else if (L == tip->seq)
                {
                    nh = tip->hash;
                    how = "is the validated tip";
                }
                else if (tip->seq - L <= o.walkLimit)
                {
                    nh = walkDown(ws, tip->seq, tip->parentHash, L, err, p);
                    how = "trustless parent-hash walk of " + std::to_string(tip->seq - L) + " headers from the validated tip";
                    if (!nh)
                        line("  header walk failed: " + err);
                }
                else if (tip->seq - L <= 256)
                {
                    auto se = ws.call(entryReq(skipKeylet(), tip->hash));
                    auto node = entryFromResp(se, err);
                    nh = node ? fromSkipList(*node, L, 1) : std::nullopt;
                    how = "short LedgerHashes list in the validated state";
                    if (!nh)
                        line("  short skip list lookup failed: " + (err.empty() ? std::string("no entry") : err));
                }
                else if (o.historyFallback)
                {
                    u32 F = (L % 256 == 0) ? L : ((L >> 8) + 1) << 8;
                    auto ge = ws.call(entryReq(skipKeylet(F), tip->hash));
                    auto node = entryFromResp(ge, err);
                    std::optional<H256> hF = node ? fromSkipList(*node, F, 256) : std::nullopt;
                    if (!hF)
                        line("  no skip-list entry for flag ledger " + std::to_string(F));
                    else if (F == L)
                    {
                        nh = hF;
                        how = "network LedgerHashes entry";
                    }
                    else
                    {
                        Json q = cmd("ledger");
                        q.set("ledger_hash", hF->hex());
                        q.set("binary", true);
                        auto fh = ledgerFromResp(ws.call(q), err);
                        if (!fh || fh->hash != *hF)
                            line("  server lacks history for ledger " + std::to_string(F) +
                                 "; end-of-range anchor skipped (" + (err.empty() ? "hash mismatch" : err) + ")");
                        else
                        {
                            nh = walkDown(ws, F, fh->parentHash, L, err, p);
                            how = "LedgerHashes entry for " + std::to_string(F) + " + parent-hash walk of " + std::to_string(F - L) + " headers";
                            if (!nh)
                                line("  history walk failed: " + err);
                        }
                    }
                }
                if (nh)
                {
                    ++rep.checked;
                    if (*nh == HL)
                    {
                        ++rep.matched;
                        line("  last ledger " + std::to_string(L) + " MATCHES (" + how + ")");
                    }
                    else
                    {
                        ++rep.mismatched;
                        line("  last ledger " + std::to_string(L) + " DIFFERS: catalogue " + HL.hex() + " network " + nh->hex() + " (" + how + ")");
                    }
                }
            }
        }
        catch (Error const& e)
        {
            if (std::string(e.what()) == "cancelled")
                throw;
            line("  error: " + std::string(e.what()));
            serverFailed = true;
        }
    }
    rep.ok = !serverFailed && rep.mismatched == 0 && rep.matched > 0;
    return rep;
}

// ================================================================ repack

std::vector<FileHeader>
repack(
    std::vector<CatFile> const& inputs,
    std::vector<RepackRange> const& outs,
    RepackOptions const& o,
    Progress* p,
    std::function<void(std::string const&)> log)
{
    if (inputs.empty() || outs.empty())
        fail("repack: nothing to do");
    for (std::size_t i = 0; i < outs.size(); ++i)
    {
        if (outs[i].first > outs[i].last)
            fail("bad output range " + std::to_string(outs[i].first) + "-" + std::to_string(outs[i].last));
        if (i && outs[i].first <= outs[i - 1].last)
            fail("output ranges overlap");
        struct stat st;
        if (!o.overwrite && ::stat(outs[i].path.c_str(), &st) == 0)
            fail(outs[i].path + " already exists (use --force to overwrite)");
    }
    u16 net = inputs[0].hdr.networkId;
    for (auto const& f : inputs)
        if (f.hdr.networkId != net)
            fail(f.path + " is from network " + std::to_string(f.hdr.networkId) + ", expected " + std::to_string(net));
    if (outs.front().first < inputs.front().hdr.minLedger)
        fail("requested range starts at " + std::to_string(outs.front().first) + " but inputs start at " +
             std::to_string(inputs.front().hdr.minLedger));
    int level = o.level >= 0 ? o.level : inputs[0].hdr.compressionLevel();
    u64 totalBytes = 0, doneBytes = 0;
    for (auto const& f : inputs)
        totalBytes += f.size;

    SHAMap map(SHAMap::Kind::State), txm(SHAMap::Kind::TxMeta);
    std::unique_ptr<CatWriter> w;
    std::vector<FileHeader> written;
    std::size_t oi = 0;
    bool have = false;
    u32 lastSeq = 0;
    H256 lastHash;
    u32 stopAt = outs.back().last;
    std::vector<Item> delta, txs;
    Item it;

    for (auto const& f : inputs)
    {
        if (have && f.hdr.maxLedger <= lastSeq)
        {
            if (log)
                log("skipping " + f.name() + " (already covered)");
            doneBytes += f.size;
            continue;
        }
        if (have && f.hdr.minLedger > lastSeq + 1)
            fail("gap: no input covers ledgers " + std::to_string(lastSeq + 1) + "-" + std::to_string(f.hdr.minLedger - 1));
        CatReader r(f.path);
        LedgerHeader h;
        bool first = true;
        while (r.nextLedger(h))
        {
            if (p)
                p->check();
            bool base = first;
            first = false;
            if (have && h.seq <= lastSeq)
            {
                if (h.seq == lastSeq && h.hash != lastHash)
                    fail("inputs disagree at ledger " + std::to_string(h.seq) + ": " + h.hash.hex() + " vs " + lastHash.hex());
                r.skipSection();
                r.skipSection();
                continue;
            }
            if (have && h.seq != lastSeq + 1)
                fail(f.name() + ": ledger " + std::to_string(h.seq) + " does not follow " + std::to_string(lastSeq));
            delta.clear();
            if (base && map.size() > 0)
            {
                // a full-state dump arriving mid-chain: turn it into a delta
                std::vector<Item> dump;
                while (r.nextItem(it))
                {
                    if (it.type != tnACCOUNT_STATE)
                        fail(f.name() + ": unexpected node type in base ledger");
                    dump.push_back(std::move(it));
                    it = Item{};
                }
                auto byKey = [](Item const& a, Item const& b) { return a.key < b.key; };
                if (!std::is_sorted(dump.begin(), dump.end(), byKey))
                    std::sort(dump.begin(), dump.end(), byKey);
                std::vector<H256> removed;
                std::size_t j = 0;
                map.forEach([&](SHAMap::Leaf const& l) {
                    while (j < dump.size() && dump[j].key < l.key)
                        delta.push_back(std::move(dump[j++]));
                    if (j < dump.size() && dump[j].key == l.key)
                    {
                        auto& d = dump[j];
                        if (d.data.size() != l.len || std::memcmp(d.data.data(), l.data, l.len) != 0)
                            delta.push_back(std::move(d));
                        ++j;
                    }
                    else
                        removed.push_back(l.key);
                });
                while (j < dump.size())
                    delta.push_back(std::move(dump[j++]));
                dump.clear();
                dump.shrink_to_fit();
                for (auto const& k : removed)
                {
                    Item rm;
                    rm.type = tnREMOVE;
                    rm.key = k;
                    delta.push_back(std::move(rm));
                }
                std::sort(delta.begin(), delta.end(), byKey);
                for (auto const& d : delta)
                {
                    if (d.type == tnREMOVE)
                        map.remove(d.key);
                    else
                        map.upsert(d.key, d.data.data(), d.data.size());
                }
                if (log)
                    log(f.name() + ": base ledger " + std::to_string(h.seq) + " converted to a delta of " +
                        withCommas(delta.size()) + " items");
            }
            else
            {
                while (r.nextItem(it))
                {
                    if (it.type == tnREMOVE)
                    {
                        if (!map.remove(it.key))
                            fail(L(h.seq) + "removal of absent key " + it.key.hex());
                    }
                    else
                        map.upsert(it.key, it.data.data(), it.data.size());
                    if (!base)
                    {
                        delta.push_back(std::move(it));
                        it = Item{};
                    }
                }
            }
            txs.clear();
            while (r.nextItem(it))
            {
                txs.push_back(std::move(it));
                it = Item{};
            }
            if (o.verify)
            {
                if (map.rootHash() != h.accountHash)
                    fail(L(h.seq) + "state hash mismatch; refusing to write a corrupt catalogue (--no-verify overrides)");
                txm.clear();
                for (auto const& t : txs)
                    txm.upsert(t.key, t.data.data(), t.data.size());
                if (txm.rootHash() != h.txHash)
                    fail(L(h.seq) + "tx map hash mismatch");
                if (h.computeHash() != h.hash)
                    fail(L(h.seq) + "ledger hash mismatch");
                if (have && h.parentHash != lastHash)
                    fail(L(h.seq) + "parent hash does not chain");
            }
            if (oi < outs.size() && h.seq >= outs[oi].first)
            {
                auto const& R = outs[oi];
                if (h.seq == R.first)
                {
                    w = std::make_unique<CatWriter>(R.path, R.first, R.last, net, level);
                    w->ledger(h);
                    map.forEach([&](SHAMap::Leaf const& l) { w->item(tnACCOUNT_STATE, l.key, l.data, l.len); });
                    w->terminal();
                }
                else
                {
                    w->ledger(h);
                    for (auto const& d : delta)
                    {
                        if (d.type == tnREMOVE)
                            w->remove(d.key);
                        else
                            w->item(d.type, d.key, d.data.data(), d.data.size());
                    }
                    w->terminal();
                }
                for (auto const& t : txs)
                    w->item(t.type, t.key, t.data.data(), t.data.size());
                w->terminal();
                if (h.seq == R.last)
                {
                    auto fh = w->finish([&](u64 d, u64 t) {
                        if (p)
                            (*p)("hash", d, t, R.path);
                    });
                    written.push_back(fh);
                    if (log)
                        log("wrote " + R.path + "  ledgers " + std::to_string(R.first) + "-" + std::to_string(R.last) +
                            "  " + humanBytes(fh.fileSize) + "  sha512 " + toHex(fh.hash.data(), 8) + "...");
                    w.reset();
                    ++oi;
                }
            }
            have = true;
            lastSeq = h.seq;
            lastHash = h.hash;
            if (p)
                (*p)("repack", doneBytes + r.rawPos(), totalBytes,
                     "ledger " + std::to_string(h.seq) + " (" + withCommas(map.size()) + " objects)");
            if (h.seq >= stopAt)
                break;
        }
        doneBytes += f.size;
        if (have && lastSeq >= stopAt)
            break;
    }
    if (oi < outs.size())
        fail("inputs end at ledger " + std::to_string(lastSeq) + ", before the requested end " + std::to_string(outs[oi].last));
    return written;
}

// ================================================================ lookups

LedgerData
readLedger(CatFile const& f, u32 seq, CatIndex const* idx, Progress* p)
{
    if (seq < f.hdr.minLedger || seq > f.hdr.maxLedger)
        fail(f.name() + " does not contain ledger " + std::to_string(seq));
    CatReader r(f.path);
    LedgerData d;
    if (idx && idx->at(seq))
        r.seekStream(idx->at(seq)->offset, &idx->cps);
    for (;;)
    {
        if (p)
            p->check();
        if (!r.nextLedger(d.hdr))
            fail(f.name() + ": stream ended before ledger " + std::to_string(seq));
        if (d.hdr.seq == seq)
            break;
        if (d.hdr.seq > seq)
            fail(f.name() + ": ledger " + std::to_string(seq) + " not found");
        r.skipSection();
        r.skipSection();
        if (p)
            (*p)("seek", r.rawPos(), r.rawSize(), "ledger " + std::to_string(d.hdr.seq));
    }
    Item it;
    while (r.nextItem(it))
    {
        d.state.push_back(std::move(it));
        it = Item{};
    }
    while (r.nextItem(it))
    {
        d.txs.push_back(std::move(it));
        it = Item{};
    }
    return d;
}

std::map<H256, KeyLookup>
lookupKeys(CatFile const& f, u32 seq, std::vector<H256> const& keys, bool withHistory, Progress* p)
{
    std::map<H256, KeyLookup> out;
    for (auto const& k : keys)
        out[k];
    CatReader r(f.path);
    LedgerHeader h;
    CatReader::ItemHeader ih;
    Bytes d;
    while (r.nextLedger(h) && h.seq <= seq)
    {
        if (p)
            p->check();
        bool base = h.seq == f.hdr.minLedger;
        while (r.nextItemHeader(ih))
        {
            auto it = out.find(ih.key);
            if (it == out.end())
            {
                if (ih.type != tnREMOVE)
                    r.skipItemData(ih.size);
                continue;
            }
            auto& kl = it->second;
            if (ih.type == tnREMOVE)
            {
                kl.found = false;
                kl.lastModified = h.seq;
                kl.data.clear();
                if (withHistory)
                    kl.history.push_back({h.seq, true, {}});
                continue;
            }
            d.resize(ih.size);
            r.readItemData(d.data(), ih.size);
            if (withHistory)
                kl.history.push_back({h.seq, false, d});
            kl.found = true;
            if (!base || kl.lastModified == 0)
                kl.lastModified = h.seq;
            kl.data = d;
        }
        r.skipSection();
        if (p)
            (*p)("scan", r.rawPos(), r.rawSize(), "ledger " + std::to_string(h.seq));
        if (h.seq == seq)
            break;
    }
    return out;
}

std::optional<TxHit>
findTx(std::vector<CatFile> const& files, H256 const& txid, std::optional<u32> seq, Progress* p)
{
    for (auto const& f : files)
    {
        if (seq && (*seq < f.hdr.minLedger || *seq > f.hdr.maxLedger))
            continue;
        auto idx = CatIndex::load(f.path);
        CatReader r(f.path);
        if (seq && idx && idx->at(*seq))
            r.seekStream(idx->at(*seq)->offset, &idx->cps);
        LedgerHeader h;
        CatReader::ItemHeader ih;
        while (r.nextLedger(h))
        {
            if (p)
                p->check();
            if (seq && h.seq < *seq)
            {
                r.skipSection();
                r.skipSection();
                continue;
            }
            if (seq && h.seq > *seq)
                break;
            r.skipSection();
            while (r.nextItemHeader(ih))
            {
                if (ih.key == txid)
                {
                    TxHit hit;
                    hit.seq = h.seq;
                    hit.txid = txid;
                    hit.path = f.path;
                    hit.leaf.resize(ih.size);
                    r.readItemData(hit.leaf.data(), ih.size);
                    return hit;
                }
                r.skipItemData(ih.size);
            }
            if (p)
                (*p)("search", r.rawPos(), r.rawSize(), f.name() + " ledger " + std::to_string(h.seq));
            if (seq && h.seq == *seq)
                break;
        }
    }
    return std::nullopt;
}

}  // namespace catl
