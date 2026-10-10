// catl — high-level operations: file sets, verification, remote anchoring
// against the live network, repacking (merge/split/extract) and lookups.
#pragma once

#include "catl.hpp"
#include "index.hpp"
#include "protocol.hpp"
#include "shamap.hpp"

#include <atomic>
#include <chrono>
#include <map>
#include <optional>

namespace catl {

struct Progress
{
    // (stage, done, total, detail)
    std::function<void(std::string const&, u64, u64, std::string const&)> fn;
    std::atomic<bool>* cancel = nullptr;
    std::chrono::steady_clock::time_point last{};

    void
    operator()(std::string const& stage, u64 done, u64 total, std::string const& detail = "", bool force = false)
    {
        if (!fn)
            return;
        auto now = std::chrono::steady_clock::now();
        if (!force && now - last < std::chrono::milliseconds(200))
            return;
        last = now;
        fn(stage, done, total, detail);
    }
    void
    check() const
    {
        if (cancel && cancel->load())
            fail("cancelled");
    }
};

struct CatFile
{
    std::string path;
    FileHeader hdr;
    u64 size = 0;
    // header filesize/hash are only written once catalogue_create finishes
    bool
    finished() const
    {
        return hdr.fileSize != 0 && !hdr.hashIsZero();
    }
    std::string
    name() const
    {
        return path.substr(path.find_last_of('/') + 1);
    }
};

CatFile
openCatFile(std::string const& path);
// Expands directories (non-recursive), keeps files with CATL magic, sorts
// by ledger range.
std::vector<CatFile>
collectFiles(std::vector<std::string> const& args);
CatFile const*
fileFor(std::vector<CatFile> const& files, u32 seq);

// ---------------------------------------------------------------- verify

struct VerifyOptions
{
    bool fileHash = true;   // whole-file SHA-512 vs header
    bool structure = true;  // rebuild maps, recompute every hash
    bool checkTxIds = true;
    bool saveIndex = true;  // write the sidecar index as a by-product
    std::size_t maxErrors = 25;
};

struct VerifyResult
{
    std::string path;
    FileHeader hdr;
    bool ok = false;
    bool complete = false;
    bool recomputed = false;  // hashes recomputed (true) or taken from index (false)
    std::vector<std::string> errors, warnings;
    int fileHash = -1;  // -1 not checked, 0 mismatch, 1 ok, 2 header carries no hash
    u32 firstSeq = 0, lastSeq = 0;
    H256 firstHash, firstParent, lastHash;
    u64 ledgers = 0, txs = 0, stateOps = 0, stateEntries = 0;
    std::vector<std::pair<u32, H256>> flagHashes;
    double seconds = 0;
};

VerifyResult
verifyFile(CatFile const& f, VerifyOptions const& o, Progress* p = nullptr);
VerifyResult
summaryFromIndex(CatFile const& f, CatIndex const& idx);

struct ChainIssue
{
    bool fatal;
    std::string msg;
};
std::vector<ChainIssue>
checkChain(std::vector<VerifyResult> const& sortedResults);

// ---------------------------------------------------------------- remote

struct AnchorOptions
{
    std::vector<std::string> servers;
    u32 walkLimit = 2000;  // trustless header walk if the end is this close to the tip
    bool historyFallback = true;
};
struct AnchorReport
{
    bool ok = false;
    std::vector<std::string> lines;
    u32 checked = 0, matched = 0, mismatched = 0, uncovered = 0;
};
AnchorReport
remoteAnchor(
    std::vector<std::pair<u32, H256>> const& flagHashes,
    std::optional<std::pair<u32, H256>> lastLedger,
    u16 networkId,
    AnchorOptions const& o,
    Progress* p = nullptr);

// ---------------------------------------------------------------- repack

struct RepackRange
{
    u32 first, last;
    std::string path;
};
struct RepackOptions
{
    int level = -1;  // -1: same as the first input
    bool verify = true;
    bool overwrite = false;
};
std::vector<FileHeader>
repack(
    std::vector<CatFile> const& inputs,
    std::vector<RepackRange> const& outs,
    RepackOptions const& o,
    Progress* p = nullptr,
    std::function<void(std::string const&)> log = {});

// ---------------------------------------------------------------- lookups

struct LedgerData
{
    LedgerHeader hdr;
    std::vector<Item> state;
    std::vector<Item> txs;
};
LedgerData
readLedger(CatFile const& f, u32 seq, CatIndex const* idx = nullptr, Progress* p = nullptr);

struct KeyEvent
{
    u32 seq;
    bool removed;
    Bytes data;
};
struct KeyLookup
{
    bool found = false;
    u32 lastModified = 0;
    Bytes data;
    std::vector<KeyEvent> history;
};
std::map<H256, KeyLookup>
lookupKeys(CatFile const& f, u32 seq, std::vector<H256> const& keys, bool withHistory, Progress* p = nullptr);

struct TxHit
{
    u32 seq = 0;
    H256 txid;
    Bytes leaf;
    std::string path;
};
std::optional<TxHit>
findTx(std::vector<CatFile> const& files, H256 const& txid, std::optional<u32> seq, Progress* p = nullptr);

}  // namespace catl
