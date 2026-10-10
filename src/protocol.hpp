// catl — XRPL/Xahau binary codec (STObject -> JSON), field tables generated
// from xahaud's macro files, transaction/ledger-entry summaries, keylets.
#pragma once

#include "base58.hpp"
#include "json.hpp"
#include "sha.hpp"

#include <optional>

namespace catl {

enum STI : int {
    STI_UINT16 = 1, STI_UINT32 = 2, STI_UINT64 = 3, STI_UINT128 = 4, STI_UINT256 = 5,
    STI_AMOUNT = 6, STI_VL = 7, STI_ACCOUNT = 8, STI_NUMBER = 9, STI_OBJECT = 14,
    STI_ARRAY = 15, STI_UINT8 = 16, STI_UINT160 = 17, STI_PATHSET = 18, STI_VECTOR256 = 19,
    STI_UINT96 = 20, STI_UINT192 = 21, STI_UINT384 = 22, STI_UINT512 = 23, STI_ISSUE = 24,
    STI_XCHAIN_BRIDGE = 25, STI_CURRENCY = 26,
};

struct FieldDef
{
    char const* name;
    int sti;
    int code;
    bool baseTen;
};

FieldDef const*
fieldById(int sti, int code);
char const*
txTypeName(int code);
char const*
leTypeName(int code);
char const*
terName(int code);
char const*
amendmentName(H256 const& id);

// One top-level field of a serialized object
struct STRaw
{
    int sti = 0;
    int code = 0;
    ByteView value;
};
bool
stParse(ByteView obj, std::vector<STRaw>& out, std::string* err = nullptr);
std::optional<ByteView>
stFind(ByteView obj, int sti, int code);
std::optional<u32>
stU32(ByteView obj, int code);
std::optional<u16>
stU16(ByteView obj, int code);
std::optional<u8>
stU8(ByteView obj, int code);
std::vector<H256>
stV256(ByteView obj, int code);
std::optional<std::string>
stAccount(ByteView obj, int code);

struct DecodeOpts
{
    std::size_t maxHex = 0;  // truncate long blobs (0 = never)
};
// Never throws: malformed input yields a partial object with "_error".
Json
stDecode(ByteView obj, DecodeOpts const& o = {});

// tx-map leaves are VL(tx) || VL(meta)
bool
splitTxLeaf(ByteView leaf, ByteView& tx, ByteView& meta);
H256
txIdOf(ByteView tx);

std::string
currencyToString(u8 const* c20);

struct TxSummary
{
    std::string type, account, result;
};
TxSummary
txSummary(ByteView leaf);
std::string
leTypeOf(ByteView sle);

// ---- keylets ------------------------------------------------------------
H256
indexHash(u16 space, std::initializer_list<ByteView> parts);
H256
skipKeylet();
H256
skipKeylet(u32 seq);
std::optional<H256>
parseKeylet(std::string_view spec, std::string& err);
char const*
keyletHelp();

}  // namespace catl
