// catl — Xahau catalogue toolkit: command-line entry point
#include "fetch.hpp"
#include "net.hpp"
#include "ops.hpp"
#include "tui.hpp"

#include <cstdio>
#include <iostream>
#include <mutex>
#include <set>
#include <sys/statvfs.h>
#include <thread>
#include <unistd.h>

using namespace catl;

namespace {

constexpr char const* kVersion = "1.0.0";
constexpr char const* kDefaultServer = "wss://xahau.network";

// ------------------------------------------------------------ args

struct Args
{
    std::vector<std::string> pos;
    std::map<std::string, std::vector<std::string>> opt;

    bool
    has(std::string const& k) const
    {
        return opt.count(k) != 0;
    }
    std::string
    get(std::string const& k, std::string const& def = "") const
    {
        auto it = opt.find(k);
        return it == opt.end() || it->second.empty() ? def : it->second.back();
    }
    std::vector<std::string>
    all(std::string const& k) const
    {
        auto it = opt.find(k);
        return it == opt.end() ? std::vector<std::string>{} : it->second;
    }
};

std::set<std::string> const kValued = {
    "ledger", "out", "level", "url", "dest", "from", "to", "every", "at", "range", "server",
    "jobs", "walk-limit", "max-hex", "limit", "latest", "remote"};
std::map<std::string, std::string> const kShort = {
    {"o", "out"}, {"d", "dest"}, {"j", "jobs"}, {"l", "ledger"}, {"y", "yes"}, {"h", "help"},
    {"i", "interactive"}, {"f", "force"}};

Args
parseArgs(int argc, char** argv, int start)
{
    Args a;
    for (int i = start; i < argc; ++i)
    {
        std::string s = argv[i];
        if (s == "--")
        {
            for (++i; i < argc; ++i)
                a.pos.push_back(argv[i]);
            break;
        }
        std::string key, val;
        bool hasVal = false;
        if (s.rfind("--", 0) == 0)
        {
            key = s.substr(2);
            auto eq = key.find('=');
            if (eq != std::string::npos)
            {
                val = key.substr(eq + 1);
                key = key.substr(0, eq);
                hasVal = true;
            }
        }
        else if (s.size() == 2 && s[0] == '-' && !std::isdigit(u8(s[1])))
        {
            auto it = kShort.find(s.substr(1));
            if (it == kShort.end())
                fail("unknown option " + s);
            key = it->second;
        }
        else
        {
            a.pos.push_back(s);
            continue;
        }
        if (!hasVal && kValued.count(key))
        {
            if ((key == "server" || key == "remote") &&
                (i + 1 >= argc || std::string(argv[i + 1]).find("://") == std::string::npos))
                val = key == "server" ? kDefaultServer : "";  // bare --server/--remote: the default server
            else
            {
                if (i + 1 >= argc)
                    fail("option --" + key + " needs a value");
                val = argv[++i];
            }
        }
        a.opt[key].push_back(val);
    }
    return a;
}

// ------------------------------------------------------------ progress

bool gTty = ::isatty(2);
std::mutex gOutMx;

void
clearProgress()
{
    if (gTty)
    {
        std::fprintf(stderr, "\r\033[K");
        std::fflush(stderr);
    }
}

Progress
cliProgress()
{
    Progress p;
    if (!gTty)
        return p;
    p.fn = [](std::string const& stage, u64 done, u64 total, std::string const& detail) {
        static std::set<std::string> const bytesStages = {"verify", "hash", "repack", "download", "rehash", "scan", "search", "seek", "index"};
        double pct = total ? 100.0 * double(done) / double(total) : 0;
        std::string amt = bytesStages.count(stage) ? humanBytes(done) + " / " + humanBytes(total)
                                                   : std::to_string(done) + " / " + std::to_string(total);
        std::lock_guard g(gOutMx);
        std::fprintf(stderr, "\r\033[K%-8s %5.1f%%  %s  %s", stage.c_str(), pct, amt.c_str(), detail.c_str());
        std::fflush(stderr);
    };
    return p;
}

std::vector<CatFile>
filesOrDie(std::vector<std::string> const& paths)
{
    if (paths.empty())
        fail("no catalogue files given");
    auto f = collectFiles(paths);
    if (f.empty())
        fail("no catalogue files found in: " + paths[0] + (paths.size() > 1 ? " ..." : ""));
    return f;
}

std::string
netName(u16 id)
{
    if (id == kXahauMainnet)
        return "Xahau mainnet";
    if (id == kXahauTestnet)
        return "Xahau testnet";
    return "network";
}

void
printHeader(LedgerHeader const& h)
{
    H256 rh = h.computeHash();
    std::printf("ledger            %u\n", h.seq);
    std::printf("hash              %s %s\n", h.hash.hex().c_str(), rh == h.hash ? "(recomputed: ok)" : ("(RECOMPUTED " + rh.hex() + ")").c_str());
    std::printf("parent_hash       %s\n", h.parentHash.hex().c_str());
    std::printf("account_hash      %s\n", h.accountHash.hex().c_str());
    std::printf("transaction_hash  %s\n", h.txHash.hex().c_str());
    std::printf("total_coins       %s drops\n", withCommas(h.drops).c_str());
    std::printf("close_time        %llu (%s UTC)\n", (unsigned long long)h.closeTime, rippleTimeToString(h.closeTime).c_str());
    std::printf("parent_close_time %llu (%s UTC)\n", (unsigned long long)h.parentCloseTime, rippleTimeToString(h.parentCloseTime).c_str());
    std::printf("close_resolution  %u s   close_flags %d\n", h.closeTimeResolution, h.closeFlags);
}

std::vector<std::pair<u32, u32>>
splitRanges(u32 lo, u32 hi, Args const& a)
{
    std::vector<std::pair<u32, u32>> r;
    if (a.has("range"))
    {
        std::string s = a.get("range");
        auto d = s.find('-');
        u32 x, y;
        if (d == std::string::npos || !parseU32(s.substr(0, d), x) || !parseU32(s.substr(d + 1), y) || x > y)
            fail("--range expects A-B");
        r.push_back({x, y});
        return r;
    }
    if (a.has("every"))
    {
        u32 n;
        if (!parseU32(a.get("every"), n) || n == 0)
            fail("--every expects a positive ledger count");
        bool align = !a.has("no-align");
        u32 s = lo;
        while (s <= hi)
        {
            u64 e = align ? (u64(s - 1) / n + 1) * n : u64(s) + n - 1;  // canonical: ranges end on multiples of n
            if (e > hi)
                e = hi;
            r.push_back({s, u32(e)});
            if (e == hi)
                break;
            s = u32(e + 1);
        }
        return r;
    }
    if (a.has("at"))
    {
        std::vector<u32> pts;
        std::string s = a.get("at");
        std::size_t st = 0;
        while (st <= s.size())
        {
            auto c = s.find(',', st);
            std::string t = s.substr(st, c == std::string::npos ? std::string::npos : c - st);
            u32 v;
            if (!parseU32(t, v))
                fail("--at expects comma-separated ledger numbers");
            if (v > lo && v <= hi)
                pts.push_back(v);
            if (c == std::string::npos)
                break;
            st = c + 1;
        }
        std::sort(pts.begin(), pts.end());
        u32 s0 = lo;
        for (u32 p : pts)
        {
            if (p == s0)
                continue;
            r.push_back({s0, p - 1});
            s0 = p;
        }
        r.push_back({s0, hi});
        return r;
    }
    fail("split needs --every N, --at A,B,... or --range A-B");
}

std::string
canonicalName(u32 a, u32 b)
{
    char buf[64];
    std::snprintf(buf, sizeof buf, "cat.%08u-%08u", a, b);
    return buf;
}

// ------------------------------------------------------------ commands

int
cmdInfo(Args const& a)
{
    for (auto const& f : filesOrDie(a.pos))
    {
        auto const& h = f.hdr;
        std::printf("%s\n", f.path.c_str());
        std::printf("  ledgers       %u-%u (%s)\n", h.minLedger, h.maxLedger, withCommas(h.ledgerCount()).c_str());
        std::printf("  network       %u (%s)\n", h.networkId, netName(h.networkId).c_str());
        std::printf("  version       %u, compression %s\n", h.version(),
                    h.compressionLevel() ? ("zlib level " + std::to_string(h.compressionLevel())).c_str() : "none");
        std::printf("  size          %s (%s bytes)%s\n", humanBytes(f.size).c_str(), withCommas(f.size).c_str(),
                    h.fileSize == 0 ? "  [header filesize unset: unfinished]"
                                    : h.fileSize == f.size ? "" : ("  [HEADER SAYS " + withCommas(h.fileSize) + "]").c_str());
        std::printf("  sha512        %s\n", h.hashIsZero() ? "(unset)" : toHex(h.hash.data(), 64).c_str());
        if (auto idx = CatIndex::load(f.path))
        {
            std::printf("  index         %s ledgers %u-%u%s, %zu flag hashes, %zu checkpoints\n",
                        idx->complete ? "complete," : "PARTIAL,", idx->firstSeq, idx->lastSeq(),
                        idx->error.empty() ? "" : (" (" + idx->error + ")").c_str(), idx->flagHashes.size(), idx->cps.list.size());
            std::printf("  time span     %s .. %s UTC\n", rippleTimeToString(idx->first.closeTime).c_str(),
                        rippleTimeToString(idx->last.closeTime).c_str());
        }
        else
            std::printf("  index         none (built by `catl verify` or `catl index`)\n");
    }
    return 0;
}

int
cmdIndex(Args const& a)
{
    int rc = 0;
    for (auto const& f : filesOrDie(a.pos))
    {
        if (!a.has("rebuild"))
            if (auto x = CatIndex::load(f.path))
            {
                std::printf("%s: index present (%zu ledgers)\n", f.name().c_str(), x->ledgers.size());
                continue;
            }
        auto p = cliProgress();
        auto idx = CatIndex::build(f.path, [&](u64 d, u64 t) { p("index", d, t, f.name()); });
        clearProgress();
        std::string err;
        bool saved = idx.save(f.path, &err);
        std::printf("%s: %zu ledgers indexed%s%s -> %s\n", f.name().c_str(), idx.ledgers.size(),
                    idx.complete ? "" : " (incomplete)", idx.error.empty() ? "" : (" [" + idx.error + "]").c_str(),
                    saved ? CatIndex::cachePathFor(f.path).c_str() : err.c_str());
        if (!saved)
            rc = 1;
    }
    return rc;
}

int
cmdLs(Args const& a)
{
    auto files = filesOrDie(a.pos);
    auto p = cliProgress();
    for (auto const& f : files)
    {
        auto idx = CatIndex::get(f.path, [&](u64 d, u64 t) { p("index", d, t, f.name()); });
        clearProgress();
        u32 from = idx.firstSeq, to = idx.lastSeq();
        if (a.has("from"))
            parseU32(a.get("from"), from);
        if (a.has("to"))
            parseU32(a.get("to"), to);
        u64 limit = 0;
        if (a.has("limit"))
            parseU64(a.get("limit"), limit);
        std::printf("# %s\n%-10s  %-19s  %6s  %8s\n", f.name().c_str(), "ledger", "close time (UTC)", "txs", "state Δ");
        u64 n = 0;
        for (u32 s = std::max(from, idx.firstSeq); s <= std::min(to, idx.lastSeq()) && s != 0; ++s)
        {
            auto e = idx.at(s);
            std::printf("%-10u  %s  %6u  %8u\n", s, rippleTimeToString(e->closeTime).c_str(), e->txItems, e->stateItems);
            if (limit && ++n >= limit)
                break;
            if (s == 0xFFFFFFFF)
                break;
        }
    }
    return 0;
}

int
cmdLedger(Args const& a)
{
    if (a.pos.size() < 2)
        fail("usage: catl ledger <files...> <seq>");
    u32 seq;
    if (!parseU32(a.pos.back(), seq))
        fail("last argument must be a ledger sequence");
    auto files = filesOrDie({a.pos.begin(), a.pos.end() - 1});
    auto f = fileFor(files, seq);
    if (!f)
        fail("no file contains ledger " + std::to_string(seq));
    auto idx = CatIndex::load(f->path);
    auto p = cliProgress();
    auto d = readLedger(*f, seq, idx ? &*idx : nullptr, &p);
    clearProgress();
    DecodeOpts dopt;
    if (a.has("max-hex"))
    {
        u64 v = 0;
        parseU64(a.get("max-hex"), v);
        dopt.maxHex = std::size_t(v);
    }
    if (a.has("json"))
    {
        Json j = Json::object();
        Json hj = Json::object();
        hj.set("ledger_index", d.hdr.seq);
        hj.set("ledger_hash", d.hdr.hash.hex());
        hj.set("parent_hash", d.hdr.parentHash.hex());
        hj.set("account_hash", d.hdr.accountHash.hex());
        hj.set("transaction_hash", d.hdr.txHash.hex());
        hj.set("total_coins", std::to_string(d.hdr.drops));
        hj.set("close_time", d.hdr.closeTime);
        hj.set("parent_close_time", d.hdr.parentCloseTime);
        hj.set("close_time_resolution", d.hdr.closeTimeResolution);
        hj.set("close_flags", d.hdr.closeFlags);
        j.set("header", hj);
        Json txs = Json::array();
        for (auto const& t : d.txs)
        {
            ByteView tx, meta;
            Json e = Json::object();
            e.set("hash", t.key.hex());
            if (splitTxLeaf(t.data, tx, meta))
            {
                e.set("tx", stDecode(tx, dopt));
                e.set("meta", stDecode(meta, dopt));
            }
            txs.push(e);
        }
        j.set("transactions", txs);
        if (a.has("state"))
        {
            Json st = Json::array();
            for (auto const& s : d.state)
            {
                Json e = Json::object();
                e.set("index", s.key.hex());
                if (s.type == tnREMOVE)
                    e.set("deleted", true);
                else
                    e.set("node", stDecode(s.data, dopt));
                st.push(e);
            }
            j.set(seq == f->hdr.minLedger ? "state_full" : "state_changes", st);
        }
        std::printf("%s\n", j.dump(2).c_str());
        return 0;
    }
    printHeader(d.hdr);
    std::printf("\ntransactions (%zu)\n", d.txs.size());
    for (auto const& t : d.txs)
    {
        auto s = txSummary(t.data);
        std::printf("  %s  %-22s %-35s %s\n", t.key.hex().c_str(), s.type.c_str(), s.account.c_str(), s.result.c_str());
    }
    bool base = seq == f->hdr.minLedger;
    std::printf("\n%s (%zu)%s\n", base ? "state (full dump: first ledger of file)" : "state changes", d.state.size(),
                base && !a.has("state") ? "  [use --state to list]" : "");
    if (!base || a.has("state"))
    {
        std::size_t shown = 0;
        for (auto const& s : d.state)
        {
            if (!a.has("state") && ++shown > 200)
            {
                std::printf("  ... %zu more (use --state)\n", d.state.size() - 200);
                break;
            }
            std::printf("  %s  %-6s %s\n", s.key.hex().c_str(), s.type == tnREMOVE ? "DEL" : "SET",
                        s.type == tnREMOVE ? "" : leTypeOf(s.data).c_str());
        }
    }
    return 0;
}

int
cmdGet(Args const& a)
{
    std::vector<std::string> paths, specs;
    for (auto const& p : a.pos)
    {
        std::string err;
        bool isPath = ::access(p.c_str(), F_OK) == 0;
        if (isPath)
            paths.push_back(p);
        else
            specs.push_back(p);
    }
    if (specs.empty())
        fail("usage: catl get <files...> [--ledger N] <keylet>...\nkeylets:\n" + std::string(keyletHelp()));
    auto files = filesOrDie(paths);
    u32 seq = files.back().hdr.maxLedger;
    for (auto const& f : files)
        seq = std::max(seq, f.hdr.maxLedger);
    if (a.has("ledger") && !parseU32(a.get("ledger"), seq))
        fail("bad --ledger");
    auto f = fileFor(files, seq);
    if (!f)
        fail("no file contains ledger " + std::to_string(seq));
    std::vector<H256> keys;
    for (auto const& s : specs)
    {
        std::string err;
        auto k = parseKeylet(s, err);
        if (!k)
            fail("keylet '" + s + "': " + err + "\nkeylets:\n" + keyletHelp());
        keys.push_back(*k);
    }
    auto p = cliProgress();
    auto res = lookupKeys(*f, seq, keys, a.has("history"), &p);
    clearProgress();
    int rc = 0;
    for (std::size_t i = 0; i < keys.size(); ++i)
    {
        auto const& r = res[keys[i]];
        std::printf("# %s  key %s  as of ledger %u (%s)\n", specs[i].c_str(), keys[i].hex().c_str(), seq, f->name().c_str());
        if (a.has("history"))
        {
            for (auto const& e : r.history)
            {
                if (e.removed)
                    std::printf("  %u  DELETED\n", e.seq);
                else
                    std::printf("  %u  %s%s\n", e.seq, e.seq == f->hdr.minLedger ? "(file base) " : "",
                                a.has("hex") ? toHex(e.data).c_str() : stDecode(e.data).dump().c_str());
            }
        }
        if (!r.found)
        {
            std::printf("  not present%s\n", r.lastModified ? (" (deleted in ledger " + std::to_string(r.lastModified) + ")").c_str() : "");
            rc = 1;
            continue;
        }
        if (r.lastModified > f->hdr.minLedger)
            std::printf("  last modified in ledger %u\n", r.lastModified);
        else
            std::printf("  unchanged since the file's base ledger %u\n", f->hdr.minLedger);
        if (a.has("hex"))
            std::printf("%s\n", toHex(r.data).c_str());
        else
            std::printf("%s\n", stDecode(r.data).dump(2).c_str());
    }
    return rc;
}

int
cmdTx(Args const& a)
{
    std::vector<std::string> paths;
    std::optional<H256> txid;
    for (auto const& p : a.pos)
    {
        H256 h;
        if (H256::parse(p, h))
            txid = h;
        else
            paths.push_back(p);
    }
    if (!txid)
        fail("usage: catl tx <files...> <txid> [--ledger N]");
    auto files = filesOrDie(paths);
    std::optional<u32> seq;
    if (a.has("ledger"))
    {
        u32 s;
        if (!parseU32(a.get("ledger"), s))
            fail("bad --ledger");
        seq = s;
    }
    else
        std::fprintf(stderr, "no --ledger given: scanning every transaction section (slow on large sets)\n");
    auto p = cliProgress();
    auto hit = findTx(files, *txid, seq, &p);
    clearProgress();
    if (!hit)
    {
        std::printf("transaction %s not found\n", txid->hex().c_str());
        return 1;
    }
    std::printf("# %s in ledger %u (%s)\n", hit->txid.hex().c_str(), hit->seq, hit->path.c_str());
    ByteView tx, meta;
    if (a.has("hex"))
        std::printf("%s\n", toHex(hit->leaf).c_str());
    else if (splitTxLeaf(hit->leaf, tx, meta))
    {
        Json j = Json::object();
        j.set("tx", stDecode(tx));
        j.set("meta", stDecode(meta));
        std::printf("%s\n", j.dump(2).c_str());
    }
    return 0;
}

void
printVerify(VerifyResult const& r)
{
    std::string name = r.path.substr(r.path.find_last_of('/') + 1);
    char const* fh = r.fileHash == 1 ? "sha512 ok" : r.fileHash == 0 ? "SHA512 MISMATCH" : r.fileHash == 2 ? "sha512 unset" : "sha512 skipped";
    std::printf("%-26s %s  ", name.c_str(), r.ok ? "\033[32mOK  \033[0m" : "\033[31mFAIL\033[0m");
    if (r.ledgers)
        std::printf("ledgers %u-%u (%s)%s  ", r.firstSeq, r.lastSeq, withCommas(r.ledgers).c_str(), r.recomputed ? "" : " [from index]");
    if (r.recomputed)
        std::printf("txs %s  objects %s  ", withCommas(r.txs).c_str(), withCommas(r.stateEntries).c_str());
    std::printf("%s  %s\n", fh, durationString(r.seconds).c_str());
    for (auto const& w : r.warnings)
        std::printf("    warning: %s\n", w.c_str());
    for (auto const& e : r.errors)
        std::printf("    \033[31merror:\033[0m %s\n", e.c_str());
}

int
runRemote(std::vector<VerifyResult> const& rs, Args const& a)
{
    AnchorOptions ao;
    ao.servers = a.all("server");
    if (a.has("remote"))
        for (auto const& s : a.all("remote"))
            if (!s.empty())
                ao.servers.push_back(s);
    if (ao.servers.empty())
        ao.servers.push_back(kDefaultServer);
    if (a.has("walk-limit"))
        parseU32(a.get("walk-limit"), ao.walkLimit);
    std::map<u32, H256> flags;
    std::optional<std::pair<u32, H256>> last;
    u16 net = 0;
    for (auto const& r : rs)
    {
        if (!r.ledgers)
            continue;
        net = r.hdr.networkId;
        for (auto const& f : r.flagHashes)
            flags.emplace(f.first, f.second);
        if (!last || r.lastSeq > last->first)
            last = {r.lastSeq, r.lastHash};
    }
    std::printf("\nremote anchoring (%zu flag-ledger hashes, end ledger %u)\n", flags.size(), last ? last->first : 0);
    auto p = cliProgress();
    auto rep = remoteAnchor({flags.begin(), flags.end()}, last, net, ao, &p);
    clearProgress();
    for (auto const& l : rep.lines)
        std::printf("%s\n", l.c_str());
    std::printf("remote: %s  (%u checked, %u match, %u differ, %u not covered)\n",
                rep.ok ? "\033[32mANCHORED\033[0m" : "\033[31mNOT ANCHORED\033[0m", rep.checked, rep.matched, rep.mismatched, rep.uncovered);
    return rep.ok ? 0 : 1;
}

int
cmdVerify(Args const& a)
{
    auto files = filesOrDie(a.pos);
    VerifyOptions o;
    o.structure = !a.has("quick");
    o.fileHash = !a.has("no-hash");
    o.saveIndex = !a.has("no-index");
    u32 jobs = 1;
    if (a.has("jobs"))
        parseU32(a.get("jobs"), jobs);
    jobs = std::clamp<u32>(jobs, 1, 64);
    std::vector<VerifyResult> results(files.size());
    std::atomic<bool> cancel{false};
    if (jobs == 1)
    {
        for (std::size_t i = 0; i < files.size(); ++i)
        {
            auto p = cliProgress();
            results[i] = verifyFile(files[i], o, &p);
            clearProgress();
            printVerify(results[i]);
            std::fflush(stdout);
        }
    }
    else
    {
        std::atomic<std::size_t> next{0};
        std::vector<std::atomic<u64>> done(files.size());
        u64 total = 0;
        for (auto const& f : files)
            total += f.size;
        std::atomic<int> running{int(jobs)};
        std::vector<std::thread> th;
        for (u32 t = 0; t < jobs; ++t)
            th.emplace_back([&] {
                for (;;)
                {
                    std::size_t i = next++;
                    if (i >= files.size())
                        break;
                    Progress p;
                    p.fn = [&, i](std::string const&, u64 d, u64, std::string const&) { done[i] = d; };
                    try
                    {
                        results[i] = verifyFile(files[i], o, &p);
                    }
                    catch (Error const& e)
                    {
                        results[i].path = files[i].path;
                        results[i].errors.push_back(e.what());
                    }
                    done[i] = files[i].size;
                    std::lock_guard g(gOutMx);
                    if (gTty)
                        std::fprintf(stderr, "\r\033[K");
                    printVerify(results[i]);
                    std::fflush(stdout);
                }
                --running;
            });
        while (running > 0)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(300));
            u64 d = 0;
            for (auto& x : done)
                d += x;
            if (gTty)
            {
                std::lock_guard g(gOutMx);
                std::fprintf(stderr, "\r\033[Kverify   %5.1f%%  %s / %s  (%u workers)", total ? 100.0 * double(d) / double(total) : 0.0,
                             humanBytes(d).c_str(), humanBytes(total).c_str(), jobs);
                std::fflush(stderr);
            }
        }
        for (auto& t : th)
            t.join();
        clearProgress();
    }
    bool allOk = std::all_of(results.begin(), results.end(), [](auto const& r) { return r.ok; });
    if (files.size() > 1)
    {
        auto issues = checkChain(results);
        bool chainOk = std::none_of(issues.begin(), issues.end(), [](auto const& i) { return i.fatal; });
        u32 lo = 0, hi = 0;
        for (auto const& r : results)
            if (r.ledgers)
            {
                lo = lo ? std::min(lo, r.firstSeq) : r.firstSeq;
                hi = std::max(hi, r.lastSeq);
            }
        std::printf("\nchain: %s  ledgers %u-%u across %zu files%s\n", chainOk ? "\033[32mLINKED\033[0m" : "\033[31mBROKEN\033[0m", lo, hi,
                    files.size(), o.structure ? "" : " (quick mode: links use index hashes where available)");
        for (auto const& i : issues)
            std::printf("  %s%s\n", i.fatal ? "\033[31merror:\033[0m " : "note: ", i.msg.c_str());
        allOk = allOk && chainOk;
    }
    if (a.has("remote") || a.has("server"))
        allOk = runRemote(results, a) == 0 && allOk;
    else if (allOk)
        std::printf("\ntip: add --remote to anchor these hashes against the live network (%s)\n", kDefaultServer);
    return allOk ? 0 : 1;
}

int
cmdAnchor(Args const& a)
{
    auto files = filesOrDie(a.pos);
    std::vector<VerifyResult> rs;
    for (auto const& f : files)
    {
        auto p = cliProgress();
        auto idx = CatIndex::get(f.path, [&](u64 d, u64 t) { p("index", d, t, f.name()); });
        clearProgress();
        rs.push_back(summaryFromIndex(f, idx));
    }
    std::printf("using stored header hashes from the index; run `catl verify` to recompute them from the data\n");
    for (auto const& i : checkChain(rs))
        std::printf("  %s%s\n", i.fatal ? "error: " : "note: ", i.msg.c_str());
    Args b = a;
    if (!b.has("server") && !b.has("remote"))
        b.opt["server"].push_back(kDefaultServer);
    return runRemote(rs, b);
}

int
cmdMerge(Args const& a)
{
    if (!a.has("out"))
        fail("usage: catl merge -o <output> <files...>");
    auto files = filesOrDie(a.pos);
    u32 lo = files.front().hdr.minLedger, hi = 0;
    for (auto const& f : files)
        hi = std::max(hi, f.hdr.maxLedger);
    RepackOptions o;
    o.verify = !a.has("no-verify");
    o.overwrite = a.has("force");
    if (a.has("level"))
        o.level = std::atoi(a.get("level").c_str());
    std::string out = a.get("out");
    auto p = cliProgress();
    repack(files, {{lo, hi, out}}, o, &p, [](std::string const& m) {
        clearProgress();
        std::printf("%s\n", m.c_str());
    });
    clearProgress();
    return 0;
}

int
cmdSplit(Args const& a, bool extract)
{
    auto files = filesOrDie(a.pos);
    u32 lo = files.front().hdr.minLedger, hi = 0;
    for (auto const& f : files)
        hi = std::max(hi, f.hdr.maxLedger);
    auto ranges = splitRanges(lo, hi, a);
    std::string out = a.get("out", ".");
    std::vector<RepackRange> rr;
    bool single = extract && ranges.size() == 1 && a.has("out") && ::access(out.c_str(), F_OK) != 0 &&
        out.find('/') != out.size() - 1;
    for (auto [x, y] : ranges)
    {
        if (x < lo || y > hi)
            fail("range " + std::to_string(x) + "-" + std::to_string(y) + " is outside the inputs (" + std::to_string(lo) + "-" + std::to_string(hi) + ")");
        rr.push_back({x, y, single ? out : out + "/" + canonicalName(x, y)});
    }
    RepackOptions o;
    o.verify = !a.has("no-verify");
    o.overwrite = a.has("force");
    if (a.has("level"))
        o.level = std::atoi(a.get("level").c_str());
    std::printf("writing %zu file(s):\n", rr.size());
    for (auto const& r : rr)
        std::printf("  %s  (%u-%u)\n", r.path.c_str(), r.first, r.last);
    auto p = cliProgress();
    repack(files, rr, o, &p, [](std::string const& m) {
        clearProgress();
        std::printf("%s\n", m.c_str());
    });
    clearProgress();
    return 0;
}

int
cmdKeylet(Args const& a)
{
    if (a.pos.empty())
    {
        std::printf("usage: catl keylet <spec>...\n%s", keyletHelp());
        return 2;
    }
    for (auto const& s : a.pos)
    {
        std::string err;
        auto k = parseKeylet(s, err);
        if (!k)
            fail(s + ": " + err);
        std::printf("%s  %s\n", k->hex().c_str(), s.c_str());
    }
    return 0;
}

int
cmdDecode(Args const& a)
{
    for (auto const& s : a.pos)
    {
        Bytes b;
        if (!fromHex(s, b))
            fail("not hex: " + s.substr(0, 20));
        ByteView tx, meta;
        if (a.has("tx") && splitTxLeaf(b, tx, meta))
        {
            Json j = Json::object();
            j.set("hash", txIdOf(tx).hex());
            j.set("tx", stDecode(tx));
            j.set("meta", stDecode(meta));
            std::printf("%s\n", j.dump(2).c_str());
        }
        else
            std::printf("%s\n", stDecode(b).dump(2).c_str());
    }
    return 0;
}

int
cmdFetch(Args const& a)
{
    std::string url = a.get("url", kCanonicalUrl);
    std::string dir = a.get("dest", ".");
    std::printf("canonical catalogue set: %s\n", url.c_str());
    auto cats = listRemote(url);
    if (cats.empty())
        fail("no catalogue files found at " + url);
    auto p = cliProgress();
    probeRemote(cats, &p);
    clearProgress();

    // selection
    std::vector<RemoteCat*> sel;
    bool any = a.has("all") || a.has("from") || a.has("to") || a.has("latest") || !a.pos.empty();
    u32 from = 0, to = 0xFFFFFFFF;
    if (a.has("from"))
        parseU32(a.get("from"), from);
    if (a.has("to"))
        parseU32(a.get("to"), to);
    for (auto& c : cats)
    {
        bool want = a.has("all") || ((a.has("from") || a.has("to")) && c.maxLedger >= from && c.minLedger <= to);
        for (auto const& n : a.pos)
        {
            u32 s;
            if (n == c.name || (parseU32(n, s) && s >= c.minLedger && s <= c.maxLedger))
                want = true;
        }
        if (want)
            sel.push_back(&c);
    }
    if (a.has("latest"))
    {
        u32 k = 1;
        parseU32(a.get("latest"), k);
        std::vector<RemoteCat*> fin;
        for (auto& c : cats)
            if (c.finished() || a.has("include-unfinished"))
                fin.push_back(&c);
        for (std::size_t i = fin.size() > k ? fin.size() - k : 0; i < fin.size(); ++i)
            if (std::find(sel.begin(), sel.end(), fin[i]) == sel.end())
                sel.push_back(fin[i]);
    }

    u64 totalRemote = 0, needBytes = 0;
    std::printf("\n  %-24s %-22s %10s  %-10s %s\n", "file", "ledgers", "size", "upstream", ("local (" + dir + ")").c_str());
    for (auto& c : cats)
    {
        u64 have = 0;
        auto ls = localState(c, dir, &have);
        bool chosen = std::find(sel.begin(), sel.end(), &c) != sel.end();
        u64 sz = c.hdr ? (c.hdr->fileSize ? c.hdr->fileSize : 0) : 0;
        totalRemote += sz;
        if (chosen && ls != LocalState::Complete && (c.finished() || a.has("include-unfinished")))
            needBytes += sz > have ? sz - have : 0;
        char const* lst = ls == LocalState::Complete ? "present" : ls == LocalState::Partial ? "partial" : ls == LocalState::Different ? "DIFFERENT" : "-";
        std::printf("%c %-24s %10u-%-10u %10s  %-10s %s\n", chosen ? '*' : ' ', c.name.c_str(), c.minLedger, c.maxLedger,
                    sz ? humanBytes(sz).c_str() : c.listedSize.c_str(),
                    !c.hdr ? ("? " + c.probeError).c_str() : c.finished() ? "complete" : "WRITING", lst);
    }
    struct statvfs vf;
    u64 freeB = ::statvfs(dir.c_str(), &vf) == 0 ? u64(vf.f_bavail) * vf.f_frsize : 0;
    std::printf("\n  %zu files, %s upstream (complete files only); free space in %s: %s\n", cats.size(),
                humanBytes(totalRemote).c_str(), dir.c_str(), humanBytes(freeB).c_str());

    if (a.has("print-commands"))
    {
        std::printf("\n# equivalent shell commands (resumable):\nmkdir -p '%s'\n", dir.c_str());
        for (auto* c : (any ? sel : std::vector<RemoteCat*>{}))
            std::printf("curl -fL -C - -o '%s/%s' '%s'\n", dir.c_str(), c->name.c_str(), c->url.c_str());
        if (!any)
            for (auto& c : cats)
                if (c.finished())
                    std::printf("curl -fL -C - -o '%s/%s' '%s'\n", dir.c_str(), c.name.c_str(), c.url.c_str());
        return 0;
    }
    if (!any)
    {
        std::printf("\nnothing selected. Examples:\n"
                    "  catl fetch -d /data/cat --all             # the whole canonical set\n"
                    "  catl fetch -d /data/cat --latest 2        # newest two finished files\n"
                    "  catl fetch -d /data/cat --from 14000000 --to 15000000\n"
                    "  catl fetch -d /data/cat 16500001          # the file holding that ledger\n"
                    "  catl fetch --print-commands -d /data/cat  # curl commands instead\n"
                    "then: catl verify /data/cat --remote\n");
        return 0;
    }
    std::printf("  selected %zu file(s), %s to download\n", sel.size(), humanBytes(needBytes).c_str());
    if (needBytes > freeB && !a.has("force"))
        fail("not enough free space in " + dir + " (need " + humanBytes(needBytes) + "); use --force to try anyway");
    if (!a.has("yes"))
    {
        if (!::isatty(0))
            fail("refusing to start a large download without -y when stdin is not a terminal");
        std::printf("  proceed? [y/N] ");
        std::fflush(stdout);
        std::string ans;
        std::getline(std::cin, ans);
        if (ans != "y" && ans != "Y" && ans != "yes")
            return 1;
    }
    int rc = 0;
    for (auto* c : sel)
    {
        auto pp = cliProgress();
        auto r = downloadCat(*c, dir, a.has("include-unfinished"), &pp);
        clearProgress();
        std::printf("%s %s\n", r.ok ? "ok  " : "FAIL", r.msg.c_str());
        if (!r.ok)
            rc = 1;
    }
    if (rc == 0)
        std::printf("\nnext: catl verify %s --remote    (full structural verification + network anchoring)\n", dir.c_str());
    return rc;
}

void
usage()
{
    std::printf(
        "catl %s — Xahau catalogue toolkit (explore, verify, merge, split, anchor, fetch)\n\n"
        "usage: catl <command> [options] [files|dirs...]\n\n"
        "  fetch    [-d DIR] [--all|--latest K|--from N --to M|NAME|SEQ] [-y]\n"
        "           download the canonical set from %s (resumable, hash-checked)\n"
        "  info     FILES...                     header, size, compression, index status\n"
        "  verify   FILES|DIRS... [--quick] [--no-hash] [-j N] [--remote [URL]] [--server URL]...\n"
        "           rebuild every SHAMap, recompute every hash, check the file SHA-512 and\n"
        "           the parent-hash chain across files; --remote anchors to the live network\n"
        "  anchor   FILES|DIRS... [--server URL]  network anchoring using indexed header hashes\n"
        "  ls       FILE [--from N] [--to M] [--limit K]       list ledgers\n"
        "  ledger   FILES... SEQ [--json] [--state] [--max-hex N]   show one ledger\n"
        "  get      FILES... [--ledger N] KEYLET... [--history] [--hex]   look up state objects\n"
        "  tx       FILES... TXID [--ledger N] [--hex]          look up a transaction\n"
        "  merge    -o OUT FILES... [--level 0-9] [--no-verify] [--force]\n"
        "  split    FILES... -o DIR (--every N [--no-align] | --at A,B,.. | --range A-B)\n"
        "  extract  FILES... --range A-B -o OUT\n"
        "  index    FILES... [--rebuild]          build the sidecar index (%s)\n"
        "  keylet   SPEC...                       compute ledger keys\n"
        "  decode   HEX... [--tx]                 decode serialized objects / tx leaves\n"
        "  tui      [DIR|FILES...]                interactive browser (also: catl -i)\n\n"
        "keylet specs:\n%s\n"
        "network: %s (TLS %s)\n",
        kVersion, kCanonicalUrl, indexDir().c_str(), keyletHelp(), kDefaultServer, tlsSupported() ? "enabled" : "NOT available in this build");
}

}  // namespace

int
main(int argc, char** argv)
{
    try
    {
        if (argc < 2)
        {
            usage();
            return 2;
        }
        std::string c = argv[1];
        if (c == "-i" || c == "--interactive")
            c = "tui";
        Args a = parseArgs(argc, argv, 2);
        if (c == "help" || c == "-h" || c == "--help" || a.has("help"))
        {
            usage();
            return 0;
        }
        if (c == "version" || c == "--version")
        {
            std::printf("catl %s (TLS %s)\n", kVersion, tlsSupported() ? "yes" : "no");
            return 0;
        }
        if (c == "info")
            return cmdInfo(a);
        if (c == "index")
            return cmdIndex(a);
        if (c == "ls" || c == "ledgers")
            return cmdLs(a);
        if (c == "ledger")
            return cmdLedger(a);
        if (c == "get")
            return cmdGet(a);
        if (c == "tx")
            return cmdTx(a);
        if (c == "verify")
            return cmdVerify(a);
        if (c == "anchor")
            return cmdAnchor(a);
        if (c == "merge")
            return cmdMerge(a);
        if (c == "split")
            return cmdSplit(a, false);
        if (c == "extract")
            return cmdSplit(a, true);
        if (c == "keylet")
            return cmdKeylet(a);
        if (c == "decode")
            return cmdDecode(a);
        if (c == "fetch")
            return cmdFetch(a);
        if (c == "tui")
            return runTui(a.pos.empty() ? std::vector<std::string>{"."} : a.pos);
        std::fprintf(stderr, "unknown command '%s' (try catl help)\n", c.c_str());
        return 2;
    }
    catch (std::exception const& e)
    {
        clearProgress();
        std::fprintf(stderr, "catl: %s\n", e.what());
        return 1;
    }
}
