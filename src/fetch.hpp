// catl — fetching the canonical catalogue set (https://cat.xahau.network/)
#pragma once

#include "ops.hpp"

namespace catl {

constexpr char const* kCanonicalUrl = "https://cat.xahau.network/";

struct RemoteCat
{
    std::string name, url;
    u32 minLedger = 0, maxLedger = 0;
    std::string listedSize;          // as shown by the index page ("146G")
    std::optional<FileHeader> hdr;   // from a Range request for the first 88 bytes
    std::string probeError;
    bool
    finished() const
    {
        return hdr && hdr->fileSize != 0 && !hdr->hashIsZero();
    }
};

std::vector<RemoteCat>
listRemote(std::string const& baseUrl);
void
probeRemote(std::vector<RemoteCat>& cats, Progress* p = nullptr);

enum class LocalState { Missing, Partial, Complete, Different };
LocalState
localState(RemoteCat const& c, std::string const& dir, u64* haveBytes = nullptr);

struct DownloadResult
{
    bool ok = false;
    std::string msg;
};
DownloadResult
downloadCat(RemoteCat const& c, std::string const& dir, bool includeUnfinished, Progress* p = nullptr);

}  // namespace catl
