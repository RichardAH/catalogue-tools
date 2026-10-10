// catl — sidecar index: per-ledger stream offsets, item counts, stored
// flag-ledger hashes and (for compressed files) inflate checkpoints, so a
// multi-hundred-GiB catalogue can be browsed and seeked instantly after
// one sequential pass. Stored under $CATL_INDEX_DIR, else
// $XDG_CACHE_HOME/catl, else ~/.cache/catl (or beside the file as
// <file>.catlidx if one exists there).
#pragma once

#include "catl.hpp"

#include <atomic>
#include <optional>

namespace catl {

struct Checkpoints
{
    std::vector<Inflater::Checkpoint> list;
};

struct LedgerIdx
{
    u64 offset = 0;  // logical stream offset of the ledger header
    u32 stateItems = 0;
    u32 txItems = 0;
    u32 closeTime = 0;
};

struct CatIndex
{
    FileHeader hdr;
    u64 fileSize = 0;
    u32 firstSeq = 0;
    bool complete = false;  // indexed through header.maxLedger
    std::string error;      // why indexing stopped early, if it did
    std::vector<LedgerIdx> ledgers;
    std::vector<std::pair<u32, H256>> flagHashes;  // stored hash, seq % 256 == 0
    LedgerHeader first, last;
    Checkpoints cps;

    u32
    lastSeq() const
    {
        return ledgers.empty() ? 0 : firstSeq + u32(ledgers.size()) - 1;
    }
    LedgerIdx const*
    at(u32 seq) const
    {
        if (ledgers.empty() || seq < firstSeq || seq > lastSeq())
            return nullptr;
        return &ledgers[seq - firstSeq];
    }

    static std::string
    cachePathFor(std::string const& catPath);
    static std::optional<CatIndex>
    load(std::string const& catPath);
    bool
    save(std::string const& catPath, std::string* err = nullptr) const;
    static CatIndex
    build(
        std::string const& catPath,
        std::function<void(u64, u64)> progress = {},
        std::atomic<bool> const* cancel = nullptr);
    // load, or build and save
    static CatIndex
    get(std::string const& catPath, std::function<void(u64, u64)> progress = {}, std::atomic<bool> const* cancel = nullptr);
};

u64
checkpointInterval();
std::string
indexDir();

}  // namespace catl
