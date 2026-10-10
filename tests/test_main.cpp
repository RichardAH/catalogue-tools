// catl — tests: published vectors from xahaud fixtures, codec round trips,
// and end-to-end synthetic catalogues (write, verify, index/seek, split,
// merge, overlap, lookups, corruption). `catl_tests --make-sample DIR`
// writes a sample set (plus chain.json for the fake-network test).
#include "../src/fetch.hpp"
#include "../src/ops.hpp"

#include <cstdio>
#include <fstream>
#include <random>
#include <set>
#include <sys/stat.h>
#include <unistd.h>

using namespace catl;

namespace {

int gFail = 0, gPass = 0;
#define CHECK(c)                                                              \
    do                                                                        \
    {                                                                         \
        if (c)                                                                \
            ++gPass;                                                          \
        else                                                                  \
        {                                                                     \
            ++gFail;                                                          \
            std::printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #c);        \
        }                                                                     \
    } while (0)

#include "vectors.inc"

H256
h256(char const* s)
{
    H256 h;
    if (!H256::parse(s, h))
        std::abort();
    return h;
}
Bytes
hexb(char const* s)
{
    Bytes b;
    fromHex(s, b);
    return b;
}

void
testDigests()
{
    std::printf("digests\n");
    Sha512 a;
    a.update("abc", 3);
    auto d = a.final();
    CHECK(toHex(d.data(), 64) ==
          "DDAF35A193617ABACC417349AE20413112E6FA4E89A97EA20A9EEEE64B55D39A2192992A274FC1A836BA3C23A3FEEBBD454D4423643CE80E2A9AC94FA54CA49F");
    Sha256 b;
    b.update("abc", 3);
    auto e = b.final();
    CHECK(toHex(e.data(), 32) == "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD");
    Sha1 c;
    c.update("abc", 3);
    auto f = c.final();
    CHECK(toHex(f.data(), 20) == "A9993E364706816ABA3E25717850C26C9CD0D89D");
    // multi-block / odd split
    std::string big(1000, 'x');
    Sha512 s1, s2;
    s1.update(big.data(), big.size());
    s2.update(big.data(), 3);
    s2.update(big.data() + 3, 997);
    CHECK(s1.final() == s2.final());
}

void
testXpopVectors()
{
    std::printf("real-chain vectors (XPOP fixture)\n");
    LedgerHeader h;
    h.seq = kXpopSeq;
    h.drops = kXpopCoins;
    h.parentHash = h256(kXpopPhash);
    h.txHash = h256(kXpopTxroot);
    h.accountHash = h256(kXpopAcroot);
    h.parentCloseTime = kXpopPclose;
    h.closeTime = kXpopClose;
    h.closeTimeResolution = kXpopCres;
    h.closeFlags = i32(kXpopFlags);
    CHECK(h.computeHash().hex() == "14D6124F7810B6C55EBBC1BE3EF120ED71AD1177069F57516958352A49A48828");
    auto rt = LedgerHeader::fromCanonical(h.canonical());
    CHECK(rt && rt->hash == h.computeHash() && rt->seq == h.seq);
    // catalogue on-disk header round trip
    u8 buf[kLedgerHeaderSize];
    h.hash = h.computeHash();
    h.serialize(buf);
    auto p = LedgerHeader::parse(buf);
    CHECK(p.hash == h.hash && p.drops == h.drops && p.closeTime == h.closeTime && p.closeFlags == h.closeFlags);

    Bytes tx = hexb(kXpopTx), meta = hexb(kXpopMeta);
    H256 id = txIdOf(tx);
    CHECK(id.hex() == "81B99F7D5E6A060F8A95BA1242558A5242169F468C7CAC4D747F5308C00E0BDD");
    Bytes leaf;
    u8 vl[3];
    leaf.insert(leaf.end(), vl, vl + encodeVL(vl, tx.size()));
    leaf.insert(leaf.end(), tx.begin(), tx.end());
    leaf.insert(leaf.end(), vl, vl + encodeVL(vl, meta.size()));
    leaf.insert(leaf.end(), meta.begin(), meta.end());
    SHAMap m(SHAMap::Kind::TxMeta);
    m.upsert(id, leaf.data(), leaf.size());
    CHECK(m.rootHash() == h256(kXpopTxroot));
    ByteView a, b;
    CHECK(splitTxLeaf(leaf, a, b) && a.size() == tx.size() && b.size() == meta.size());
    auto j = stDecode(tx);
    CHECK(j["TransactionType"].str() == "AccountSet");
    CHECK(j["Fee"].str() == "10");
    CHECK(j["Account"].str().size() > 25 && j["Account"].str()[0] == 'r');
    auto jm = stDecode(meta);
    CHECK(jm["TransactionResult"].str() == "tesSUCCESS");
    CHECK(!jm.has("_error") && !j.has("_error"));
    auto s = txSummary(leaf);
    CHECK(s.type == "AccountSet" && s.result == "tesSUCCESS");
}

void
testShamapVectors()
{
    std::printf("SHAMap (xahaud SHAMap_test build/tear vectors)\n");
    SHAMap m(SHAMap::Kind::TxNoMeta);
    CHECK(m.rootHash().isZero());
    for (int k = 0; k < 8; ++k)
    {
        Bytes d(32, u8(k));
        m.upsert(h256(kShamapKeys[k]), d.data(), d.size());
        CHECK(m.rootHash() == h256(kShamapHashes[k]));
    }
    for (int k = 7; k >= 0; --k)
    {
        CHECK(m.rootHash() == h256(kShamapHashes[k]));
        CHECK(m.remove(h256(kShamapKeys[k])));
    }
    CHECK(m.rootHash().isZero() && m.size() == 0);

    // canonical shape: insertion order must not matter
    std::mt19937_64 rng(7);
    std::vector<std::pair<H256, Bytes>> items;
    for (int i = 0; i < 3000; ++i)
    {
        H256 k;
        for (auto& c : k.b)
            c = u8(rng());
        if (i % 7 == 0)
            k.b[0] = 0xAB, k.b[1] = 0xCD, k.b[2] = u8(i & 3);  // force deep shared prefixes
        items.push_back({k, Bytes(1 + rng() % 40, u8(i))});
    }
    SHAMap x(SHAMap::Kind::State), y(SHAMap::Kind::State);
    for (auto& [k, d] : items)
        x.upsert(k, d.data(), d.size());
    for (auto it = items.rbegin(); it != items.rend(); ++it)
        y.upsert(it->first, it->second.data(), it->second.size());
    CHECK(x.rootHash() == y.rootHash());
    // delete half from y, rebuild z from the survivors: same hash
    SHAMap z(SHAMap::Kind::State);
    for (std::size_t i = 0; i < items.size(); ++i)
        if (i % 2)
            y.remove(items[i].first);
        else
            z.upsert(items[i].first, items[i].second.data(), items[i].second.size());
    CHECK(y.rootHash() == z.rootHash());
    CHECK(y.size() == z.size());
}

void
testBase58Keylets()
{
    std::printf("base58 / keylets / amendments\n");
    auto a = parseAddress("rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh");
    CHECK(a && toHex(a->data(), 20) == "B5F762798A53D543A014CAF8B297CFF8F2F937E8");
    CHECK(a && toAddress(a->data()) == "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh");
    CHECK(!parseAddress("rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTi"));
    std::string err;
    auto k = parseKeylet("account:rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh", err);
    CHECK(k && k->hex() == "2B6AC232AA4C4BE41BF49D2459FA4A0347E1B543A4C92FCEE0821C0201E2E9A8");
    CHECK(skipKeylet().hex() == "B4979A36CDC7F3D3D5C31A4EAE2AC7D7209DDA877588B9AFC66799692AB0D66B");
    k = parseKeylet("amendments", err);
    CHECK(k && k->hex() == "7DB0788C020F02780A673DC74757F23823FA3014C1866E72CC4CD8B226CD6EF4");
    k = parseKeylet("fees", err);
    CHECK(k && k->hex() == "4BC50C9B0D8515D3EAAE1E74B29A95804346C491EE1A95BF25E4AAB854A6A651");
    auto n = amendmentName(h256("4C97EBA926031A7CF7D7B36FDE3ED66DDA5421192D63DE53FFB46E43B9DC8373"));
    CHECK(n && std::string(n) == "MultiSign");
    CHECK(!parseKeylet("bogus:x", err) && !err.empty());
    CHECK(parseKeylet("line:rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh:rrrrrrrrrrrrrrrrrrrrBZbvji:USD", err) ==
          parseKeylet("line:rrrrrrrrrrrrrrrrrrrrBZbvji:rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh:USD", err));
    k = parseKeylet("page:2B6AC232AA4C4BE41BF49D2459FA4A0347E1B543A4C92FCEE0821C0201E2E9A8:0", err);
    CHECK(k && k->hex() == "2B6AC232AA4C4BE41BF49D2459FA4A0347E1B543A4C92FCEE0821C0201E2E9A8");
    CHECK(fieldById(STI_UINT256, 30) && std::string(fieldById(STI_UINT256, 30)->name) == "HookStateKey");
    CHECK(txTypeName(22) && std::string(txTypeName(22)) == "SetHook");
    CHECK(leTypeName(0x76) && std::string(leTypeName(0x76)) == "HookState");
}

void
testZlib()
{
    std::printf("zlib codec\n");
    std::mt19937_64 rng(3);
    for (int lvl : {1, 4, 6, 9})
        for (std::size_t n : {std::size_t(0), std::size_t(1), std::size_t(300), std::size_t(70000), std::size_t(600000)})
        {
            Bytes in(n);
            for (std::size_t i = 0; i < n; ++i)
                in[i] = (i % 97 < 60) ? u8("catalogue"[i % 9]) : u8(rng());
            auto z = zlibCompress(in, lvl);
            CHECK(zlibDecompress(z) == in);
        }
    // truncation and corruption are detected
    Bytes in(200000, 'q');
    for (std::size_t i = 0; i < in.size(); i += 7)
        in[i] = u8(rng());
    auto z = zlibCompress(in, 6);
    bool threw = false;
    try
    {
        zlibDecompress(ByteView(z.data(), z.size() / 2));
    }
    catch (Error const&)
    {
        threw = true;
    }
    CHECK(threw);
    z[z.size() / 2] ^= 0x10;
    threw = false;
    try
    {
        zlibDecompress(z);
    }
    catch (Error const&)
    {
        threw = true;
    }
    CHECK(threw);
}

// ---------------------------------------------------------------- generator

struct Ser
{
    Bytes b;
    void id(int sti, int code)
    {
        if (sti < 16 && code < 16)
            b.push_back(u8(sti << 4 | code));
        else if (sti < 16)
        {
            b.push_back(u8(sti << 4));
            b.push_back(u8(code));
        }
        else if (code < 16)
        {
            b.push_back(u8(code));
            b.push_back(u8(sti));
        }
        else
        {
            b.push_back(0);
            b.push_back(u8(sti));
            b.push_back(u8(code));
        }
    }
    void u16_(int code, u16 v)
    {
        id(1, code);
        u8 t[2];
        putBE16(t, v);
        b.insert(b.end(), t, t + 2);
    }
    void u32_(int code, u32 v)
    {
        id(2, code);
        u8 t[4];
        putBE32(t, v);
        b.insert(b.end(), t, t + 4);
    }
    void u8_(int code, u8 v)
    {
        id(16, code);
        b.push_back(v);
    }
    void drops(int code, u64 v)
    {
        id(6, code);
        u8 t[8];
        putBE64(t, v | 0x4000000000000000ull);
        b.insert(b.end(), t, t + 8);
    }
    void vl(int sti, int code, ByteView v)
    {
        id(sti, code);
        u8 t[3];
        b.insert(b.end(), t, t + encodeVL(t, v.size()));
        b.insert(b.end(), v.begin(), v.end());
    }
};

struct Chain
{
    std::vector<LedgerHeader> headers;
    std::map<u32, std::map<H256, Bytes>> snapshots;  // seq -> full state (some seqs)
    std::vector<std::pair<u32, H256>> someTxs;
    std::map<H256, Bytes> finalState;
};

// Builds a synthetic but format-exact ledger chain and writes it as one
// catalogue file. Maintains LedgerHashes like Ledger::updateSkipList.
Chain
genCatalogue(std::string const& path, u32 first, u32 count, int level, u64 seed, std::set<u32> snapAt = {})
{
    std::mt19937_64 rng(seed);
    std::map<H256, Bytes> state;
    std::vector<AccountID> accts;
    auto rnd = [&](u64 n) { return u64(rng() % n); };
    auto acctRoot = [&](AccountID const& a, u32 seq, u64 bal) {
        Ser s;
        s.u16_(1, 0x61);
        s.u32_(2, 0);
        s.u32_(4, seq);
        s.drops(2, bal);
        s.vl(8, 1, ByteView(a.data(), 20));
        return s.b;
    };
    for (int i = 0; i < 120; ++i)
    {
        AccountID a;
        for (auto& c : a)
            c = u8(rng());
        accts.push_back(a);
        state[indexHash('a', {ByteView(a.data(), 20)})] = acctRoot(a, 1, 1000000000 + rnd(1000000));
    }
    auto hookState = [&](AccountID const& a) {
        H256 key, ns;
        for (auto& c : key.b)
            c = u8(rng());
        Bytes data(1 + rnd(120));
        for (auto& c : data)
            c = u8(rng());
        Ser s;
        s.u16_(1, 0x76);
        s.u32_(2, 0);
        s.vl(7, 22, data);
        return std::make_pair(indexHash('v', {ByteView(a.data(), 20), ByteView(key.data(), 32), ByteView(ns.data(), 32)}), s.b);
    };
    for (int i = 0; i < 150; ++i)
        state.insert(hookState(accts[rnd(accts.size())]));

    auto skipSle = [&](std::vector<H256> const& hashes, u32 last) {
        Ser s;
        s.u16_(1, 0x68);
        s.u32_(2, 0);
        s.u32_(27, last);
        Bytes hv;
        for (auto const& h : hashes)
            hv.insert(hv.end(), h.b.begin(), h.b.end());
        s.vl(19, 2, hv);
        return s.b;
    };
    std::map<H256, std::vector<H256>> skipLists;

    Chain ch;
    H256 prevHash;
    for (auto& c : prevHash.b)
        c = u8(rng());
    u64 prevClose = 780000000;
    u64 coins = 99999999999000000ull;
    CatWriter w(path, first, first + count - 1, kXahauMainnet, level);
    SHAMap smap(SHAMap::Kind::State);
    for (auto const& [k, v] : state)
        smap.upsert(k, v.data(), v.size());
    std::map<H256, Bytes> before = state;
    for (u32 seq = first; seq < first + count; ++seq)
    {
        std::map<H256, std::optional<Bytes>> delta;
        auto set = [&](H256 const& k, Bytes v) {
            state[k] = v;
            delta[k] = std::move(v);
        };
        auto del = [&](H256 const& k) {
            state.erase(k);
            delta[k] = std::nullopt;
        };
        // updateSkipList
        u32 prevIndex = seq - 1;
        if ((prevIndex & 0xff) == 0)
        {
            H256 k = skipKeylet(prevIndex);
            skipLists[k].push_back(prevHash);
            set(k, skipSle(skipLists[k], prevIndex));
        }
        {
            H256 k = skipKeylet();
            auto& v = skipLists[k];
            if (v.size() == 256)
                v.erase(v.begin());
            v.push_back(prevHash);
            set(k, skipSle(v, prevIndex));
        }
        // account activity + transactions
        SHAMap tmap(SHAMap::Kind::TxMeta);
        std::vector<Item> txItems;
        int ntx = int(rnd(6));
        for (int t = 0; t < ntx; ++t)
        {
            auto const& a = accts[rnd(accts.size())];
            Ser tx;
            tx.u16_(2, 3);  // AccountSet
            tx.u32_(4, u32(rng()));
            tx.drops(8, 10 + rnd(5));
            tx.vl(8, 1, ByteView(a.data(), 20));
            Ser meta;
            meta.u32_(28, u32(t));
            meta.u8_(3, rnd(10) ? 0 : 100);
            Item it;
            it.type = tnTRANSACTION_MD;
            it.key = txIdOf(tx.b);
            u8 vl[3];
            it.data.insert(it.data.end(), vl, vl + encodeVL(vl, tx.b.size()));
            it.data.insert(it.data.end(), tx.b.begin(), tx.b.end());
            it.data.insert(it.data.end(), vl, vl + encodeVL(vl, meta.b.size()));
            it.data.insert(it.data.end(), meta.b.begin(), meta.b.end());
            tmap.upsert(it.key, it.data.data(), it.data.size());
            if (rnd(4) == 0)
                ch.someTxs.push_back({seq, it.key});
            txItems.push_back(std::move(it));
            set(indexHash('a', {ByteView(a.data(), 20)}), acctRoot(a, u32(seq), 1000000000 + rnd(1000000)));
            coins -= 10;
        }
        for (int k = int(rnd(3)); k > 0; --k)
        {
            auto hs = hookState(accts[rnd(accts.size())]);
            set(hs.first, hs.second);
        }
        if (rnd(2))
        {
            // delete a random hook state
            auto it = state.begin();
            std::advance(it, long(rnd(state.size())));
            if (!it->second.empty() && it->second[1] == 0x00 && it->second[2] == 0x76)
                del(it->first);
        }
        for (auto const& [k, v] : delta)
        {
            if (v)
                smap.upsert(k, v->data(), v->size());
            else
                smap.remove(k);
        }
        LedgerHeader h;
        h.seq = seq;
        h.drops = coins;
        h.parentHash = prevHash;
        h.accountHash = smap.rootHash();
        h.txHash = tmap.rootHash();
        h.parentCloseTime = prevClose;
        h.closeTime = prevClose + 3 + rnd(2);
        h.closeTimeResolution = 10;
        h.closeFlags = 0;
        h.hash = h.computeHash();
        w.ledger(h);
        if (seq == first)
        {
            smap.forEach([&](SHAMap::Leaf const& l) { w.item(tnACCOUNT_STATE, l.key, l.data, l.len); });
        }
        else
        {
            for (auto const& [k, v] : delta)
            {
                auto old = before.find(k);
                if (!v)
                {
                    if (old != before.end())
                        w.remove(k);
                }
                else if (old == before.end() || old->second != *v)
                    w.item(tnACCOUNT_STATE, k, v->data(), v->size());
            }
        }
        w.terminal();
        for (auto const& t : txItems)
            w.item(t.type, t.key, t.data.data(), t.data.size());
        w.terminal();
        for (auto const& [k, v] : delta)
        {
            if (v)
                before[k] = *v;
            else
                before.erase(k);
        }
        ch.headers.push_back(h);
        if (snapAt.count(seq))
            ch.snapshots[seq] = state;
        prevHash = h.hash;
        prevClose = h.closeTime;
    }
    w.finish();
    ch.finalState = state;
    return ch;
}

std::string gTmp;

std::string
tmp(std::string const& n)
{
    return gTmp + "/" + n;
}

void
copyFile(std::string const& a, std::string const& b, std::size_t limit = std::size_t(-1))
{
    std::ifstream i(a, std::ios::binary);
    std::ofstream o(b, std::ios::binary | std::ios::trunc);
    std::vector<char> buf(1 << 16);
    std::size_t done = 0;
    while (i && done < limit)
    {
        i.read(buf.data(), std::streamsize(std::min(buf.size(), limit - done)));
        o.write(buf.data(), i.gcount());
        done += std::size_t(i.gcount());
    }
}

void
testEndToEnd()
{
    std::printf("end-to-end synthetic catalogues\n");
    ::setenv("CATL_INDEX_DIR", tmp("idx").c_str(), 1);
    ::setenv("CATL_CP_INTERVAL", "32768", 1);
    std::set<u32> snaps = {1000, 1300, 1555, 1699};
    auto chA = genCatalogue(tmp("A.cat"), 1000, 700, 0, 42, snaps);
    auto chB = genCatalogue(tmp("B.cat"), 1000, 700, 6, 42);
    CHECK(chA.headers.back().hash == chB.headers.back().hash);
    auto A = openCatFile(tmp("A.cat")), B = openCatFile(tmp("B.cat"));
    CHECK(A.finished() && B.finished() && B.hdr.compressionLevel() == 6 && B.size < A.size);

    for (auto const* f : {&A, &B})
    {
        auto r = verifyFile(*f, VerifyOptions{});
        CHECK(r.ok);
        CHECK(r.fileHash == 1);
        CHECK(r.complete && r.ledgers == 700 && r.lastHash == chA.headers.back().hash);
        CHECK(r.flagHashes.size() == 3);  // 1024 1280 1536
        if (!r.ok)
            for (auto const& e : r.errors)
                std::printf("    %s\n", e.c_str());
    }
    // the long skip list in the final state carries the flag hashes
    {
        H256 key = skipKeylet(1536);
        auto const& sle = chA.finalState.at(key);
        auto hashes = stV256(sle, 2);
        auto last = stU32(sle, 27);
        CHECK(last && *last == 1536 && hashes.size() == 3);
        CHECK(hashes.back() == chA.headers[1536 - 1000].hash && hashes.front() == chA.headers[1024 - 1000].hash);
    }
    // index + random access (compressed file uses inflate checkpoints)
    {
        auto idx = CatIndex::build(B.path);
        CHECK(idx.complete && idx.ledgers.size() == 700 && !idx.cps.list.empty());
        CHECK(idx.save(B.path));
        auto ld = CatIndex::load(B.path);
        CHECK(ld && ld->cps.list.size() == idx.cps.list.size() && ld->ledgers.size() == 700);
        for (u32 s : {1699u, 1000u, 1333u, 1001u, 1600u})
        {
            auto x = readLedger(B, s, &*ld);
            auto y = readLedger(A, s);
            CHECK(x.hdr.hash == chA.headers[s - 1000].hash && y.hdr.hash == x.hdr.hash);
            CHECK(x.txs.size() == y.txs.size() && x.state.size() == y.state.size());
        }
    }
    // lookups
    {
        for (auto const& [seq, snap] : chA.snapshots)
        {
            std::vector<H256> keys;
            int n = 0;
            for (auto const& [k, v] : snap)
                if (n++ % 37 == 0)
                    keys.push_back(k);
            H256 absent;
            absent.b[0] = 0x42;
            keys.push_back(absent);
            auto res = lookupKeys(B, seq, keys, false);
            bool good = true;
            for (auto const& k : keys)
            {
                auto it = snap.find(k);
                auto const& r = res[k];
                if ((it == snap.end()) != !r.found || (r.found && r.data != it->second))
                    good = false;
            }
            CHECK(good);
        }
        auto [tseq, tid] = chA.someTxs.at(chA.someTxs.size() / 2);
        auto hit = findTx({A}, tid, tseq);
        CHECK(hit && hit->seq == tseq && txIdOf([&] {
                  ByteView a, b;
                  splitTxLeaf(hit->leaf, a, b);
                  return a;
              }()) == tid);
        auto hit2 = findTx({B}, tid, std::nullopt);
        CHECK(hit2 && hit2->seq == tseq);
    }
    // split into three (different compression), verify, chain
    std::vector<RepackRange> parts = {{1000, 1255, tmp("p1.cat")}, {1256, 1499, tmp("p2.cat")}, {1500, 1699, tmp("p3.cat")}};
    {
        RepackOptions o;
        o.level = 3;
        auto hs = repack({A}, parts, o);
        CHECK(hs.size() == 3);
        std::vector<VerifyResult> rs;
        for (auto const& p : parts)
        {
            auto r = verifyFile(openCatFile(p.path), VerifyOptions{});
            CHECK(r.ok && r.firstSeq == p.first && r.lastSeq == p.last);
            CHECK(r.lastHash == chA.headers[p.last - 1000].hash);
            rs.push_back(r);
        }
        auto issues = checkChain(rs);
        CHECK(issues.empty());
    }
    // merge back (level 0) => same chain, and identical bytes to the original
    {
        RepackOptions o;
        o.level = 0;
        auto files = collectFiles({tmp("p3.cat"), tmp("p1.cat"), tmp("p2.cat")});
        CHECK(files.size() == 3 && files[0].hdr.minLedger == 1000);
        repack(files, {{1000, 1699, tmp("M.cat")}}, o);
        auto M = openCatFile(tmp("M.cat"));
        auto r = verifyFile(M, VerifyOptions{});
        CHECK(r.ok && r.lastHash == chA.headers.back().hash);
        std::ifstream a(A.path, std::ios::binary), b(M.path, std::ios::binary);
        std::string sa((std::istreambuf_iterator<char>(a)), {}), sb((std::istreambuf_iterator<char>(b)), {});
        CHECK(sa == sb);  // delta reconstruction is byte-exact
    }
    // overlapping inputs + extract
    {
        repack({A}, {{1000, 1300, tmp("o1.cat")}}, RepackOptions{});
        repack({B}, {{1200, 1699, tmp("o2.cat")}}, RepackOptions{});
        auto files = collectFiles({tmp("o1.cat"), tmp("o2.cat")});
        std::vector<VerifyResult> rs;
        for (auto const& f : files)
            rs.push_back(verifyFile(f, VerifyOptions{}));
        auto issues = checkChain(rs);
        CHECK(issues.size() == 1 && !issues[0].fatal);  // overlap note, flags agree
        repack(files, {{1100, 1650, tmp("o3.cat")}}, RepackOptions{});
        auto r = verifyFile(openCatFile(tmp("o3.cat")), VerifyOptions{});
        CHECK(r.ok && r.firstSeq == 1100 && r.lastHash == chA.headers[650].hash);
    }
    // gap detection
    {
        std::vector<VerifyResult> rs = {verifyFile(openCatFile(tmp("p1.cat")), VerifyOptions{}),
                                        verifyFile(openCatFile(tmp("p3.cat")), VerifyOptions{})};
        auto issues = checkChain(rs);
        CHECK(issues.size() == 1 && issues[0].fatal);
        bool threw = false;
        try
        {
            repack(collectFiles({tmp("p1.cat"), tmp("p3.cat")}), {{1000, 1699, tmp("bad.cat")}}, RepackOptions{});
        }
        catch (Error const&)
        {
            threw = true;
        }
        CHECK(threw);
    }
    // corruption: flip one byte in the middle of an item
    {
        copyFile(A.path, tmp("C.cat"));
        {
            std::fstream f(tmp("C.cat"), std::ios::in | std::ios::out | std::ios::binary);
            f.seekp(std::streamoff(A.size / 2));
            char c;
            f.read(&c, 1);
            f.seekp(std::streamoff(A.size / 2));
            c ^= 0x01;
            f.write(&c, 1);
        }
        auto r = verifyFile(openCatFile(tmp("C.cat")), VerifyOptions{});
        CHECK(!r.ok && r.fileHash == 0);
        // structure-only still finds it (a hash or framing error)
        VerifyOptions o;
        o.fileHash = false;
        auto r2 = verifyFile(openCatFile(tmp("C.cat")), o);
        CHECK(!r2.ok);
    }
    // truncation (raw + compressed) fails cleanly
    for (auto const* f : {&A, &B})
    {
        copyFile(f->path, tmp("T.cat"), std::size_t(f->size * 6 / 10));
        auto r = verifyFile(openCatFile(tmp("T.cat")), VerifyOptions{});
        CHECK(!r.ok && !r.errors.empty() && r.ledgers > 0 && r.ledgers < 700);
    }
}

void
makeSample(std::string const& dir)
{
    for (std::size_t i = 1; i <= dir.size(); ++i)
        if (i == dir.size() || dir[i] == '/')
            ::mkdir(dir.substr(0, i).c_str(), 0755);
    auto ch = genCatalogue(dir + "/full.tmp", 1000, 1200, 0, 1234);
    auto full = openCatFile(dir + "/full.tmp");
    std::vector<RepackRange> parts;
    for (u32 s = 1000; s <= 2199;)
    {
        u32 e = std::min<u32>((s - 1) / 300 * 300 + 300, 2199);
        char nm[64];
        std::snprintf(nm, sizeof nm, "/cat.%08u-%08u", s, e);
        parts.push_back({s, e, dir + nm});
        s = e + 1;
    }
    RepackOptions o;
    o.level = 0;
    repack({full}, parts, o);
    ::unlink((dir + "/full.tmp").c_str());
    // chain.json for the fake network server: headers + skip lists
    Json j = Json::object();
    Json hs = Json::array();
    for (auto const& h : ch.headers)
        hs.push(toHex(h.canonical()));
    j.set("headers", hs);
    Json st = Json::object();
    for (auto const& [k, v] : ch.finalState)
        if (v.size() > 3 && v[1] == 0x00 && v[2] == 0x68)
            st.set(k.hex(), toHex(v));
    j.set("skiplists", st);
    std::ofstream(dir + "/chain.json") << j.dump();
    std::printf("sample catalogues written to %s (ledgers 1000-2199, %zu files) + chain.json\n", dir.c_str(), parts.size());
}

}  // namespace

int
main(int argc, char** argv)
{
    if (argc == 3 && std::string(argv[1]) == "--make-sample")
    {
        makeSample(argv[2]);
        return 0;
    }
    char tpl[] = "/tmp/catl-test-XXXXXX";
    gTmp = ::mkdtemp(tpl);
    try
    {
        testDigests();
        testXpopVectors();
        testShamapVectors();
        testBase58Keylets();
        testZlib();
        testEndToEnd();
    }
    catch (std::exception const& e)
    {
        std::printf("  EXCEPTION: %s\n", e.what());
        ++gFail;
    }
    std::string rm = "rm -rf '" + gTmp + "'";
    if (!gFail)
        if (std::system(rm.c_str()) != 0)
            std::printf("could not remove %s\n", gTmp.c_str());
    std::printf("\n%d checks passed, %d failed\n", gPass, gFail);
    return gFail ? 1 : 0;
}
