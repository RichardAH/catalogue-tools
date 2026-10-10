// catl — binary codec and keylets
#include "protocol.hpp"

#include <mutex>
#include <unordered_map>

namespace catl {

// ------------------------------------------------------------ tables

namespace {

FieldDef const kFields[] = {
#define CATL_FIELD(name, sti, code, bt) {#name, sti, code, bool(bt)},
#define CATL_TXTYPE(name, code)
#define CATL_LETYPE(name, code)
#define CATL_TER(name, code)
#define CATL_AMENDMENT(name)
#include "protocol_defs.inc"
#undef CATL_FIELD
#undef CATL_TXTYPE
#undef CATL_LETYPE
#undef CATL_TER
#undef CATL_AMENDMENT
};

struct NameCode
{
    char const* name;
    int code;
};
NameCode const kTx[] = {
#define CATL_FIELD(name, sti, code, bt)
#define CATL_TXTYPE(name, code) {#name, code},
#define CATL_LETYPE(name, code)
#define CATL_TER(name, code)
#define CATL_AMENDMENT(name)
#include "protocol_defs.inc"
#undef CATL_FIELD
#undef CATL_TXTYPE
#undef CATL_LETYPE
#undef CATL_TER
#undef CATL_AMENDMENT
};
NameCode const kLe[] = {
#define CATL_FIELD(name, sti, code, bt)
#define CATL_TXTYPE(name, code)
#define CATL_LETYPE(name, code) {#name, code},
#define CATL_TER(name, code)
#define CATL_AMENDMENT(name)
#include "protocol_defs.inc"
#undef CATL_FIELD
#undef CATL_TXTYPE
#undef CATL_LETYPE
#undef CATL_TER
#undef CATL_AMENDMENT
};
NameCode const kTer[] = {
#define CATL_FIELD(name, sti, code, bt)
#define CATL_TXTYPE(name, code)
#define CATL_LETYPE(name, code)
#define CATL_TER(name, code) {#name, code},
#define CATL_AMENDMENT(name)
#include "protocol_defs.inc"
#undef CATL_FIELD
#undef CATL_TXTYPE
#undef CATL_LETYPE
#undef CATL_TER
#undef CATL_AMENDMENT
};
char const* const kAmendments[] = {
#define CATL_FIELD(name, sti, code, bt)
#define CATL_TXTYPE(name, code)
#define CATL_LETYPE(name, code)
#define CATL_TER(name, code)
#define CATL_AMENDMENT(name) name,
#include "protocol_defs.inc"
#undef CATL_FIELD
#undef CATL_TXTYPE
#undef CATL_LETYPE
#undef CATL_TER
#undef CATL_AMENDMENT
};

char const*
lookup(NameCode const* t, std::size_t n, int code)
{
    for (std::size_t i = 0; i < n; ++i)
        if (t[i].code == code)
            return t[i].name;
    return nullptr;
}

}  // namespace

FieldDef const*
fieldById(int sti, int code)
{
    static std::unordered_map<int, FieldDef const*> const m = [] {
        std::unordered_map<int, FieldDef const*> r;
        for (auto const& f : kFields)
            r[f.sti << 16 | f.code] = &f;
        return r;
    }();
    auto it = m.find(sti << 16 | code);
    return it == m.end() ? nullptr : it->second;
}

char const*
txTypeName(int c)
{
    return lookup(kTx, std::size(kTx), c);
}
char const*
leTypeName(int c)
{
    return lookup(kLe, std::size(kLe), c);
}
char const*
terName(int c)
{
    return lookup(kTer, std::size(kTer), c);
}

char const*
amendmentName(H256 const& id)
{
    static std::vector<std::pair<H256, char const*>> const v = [] {
        std::vector<std::pair<H256, char const*>> r;
        for (char const* n : kAmendments)
            r.push_back({sha512Half(n, std::strlen(n)), n});
        return r;
    }();
    for (auto& [h, n] : v)
        if (h == id)
            return n;
    return nullptr;
}

// ------------------------------------------------------------ cursor

namespace {

struct Cur
{
    u8 const* p;
    std::size_t n;
    std::size_t i = 0;
    std::size_t left() const { return n - i; }
    void need(std::size_t k)
    {
        if (left() < k)
            fail("object truncated at byte " + std::to_string(i));
    }
    u8 byte()
    {
        need(1);
        return p[i++];
    }
    ByteView take(std::size_t k)
    {
        need(k);
        ByteView v{p + i, k};
        i += k;
        return v;
    }
    std::size_t vl()
    {
        std::size_t len = 0, used = decodeVL(p + i, left(), len);
        if (!used)
            fail("bad VL prefix");
        i += used;
        return len;
    }
};

void
fieldId(Cur& c, int& sti, int& code)
{
    u8 b = c.byte();
    sti = b >> 4;
    code = b & 15;
    if (sti == 0)
        sti = c.byte();
    if (code == 0)
        code = c.byte();
}

void skipValue(Cur& c, int sti, int depth);

void
skipIssue(Cur& c)
{
    ByteView cur = c.take(20);
    bool zero = std::all_of(cur.begin(), cur.end(), [](u8 x) { return x == 0; });
    if (zero)
        return;
    ByteView acc = c.take(20);
    bool noAccount = std::all_of(acc.begin(), acc.end() - 1, [](u8 x) { return x == 0; }) && acc[19] == 1;
    if (noAccount)
        c.take(4);
}

std::size_t
amountLen(Cur& c)
{
    c.need(1);
    u8 b = c.p[c.i];
    if (b & 0x80)
        return 48;
    if (b & 0x20)
        return 33;
    return 8;
}

void
skipValue(Cur& c, int sti, int depth)
{
    if (depth > 64)
        fail("object nested too deeply");
    switch (sti)
    {
        case STI_UINT8: c.take(1); return;
        case STI_UINT16: c.take(2); return;
        case STI_UINT32: c.take(4); return;
        case STI_UINT64: c.take(8); return;
        case STI_UINT96: c.take(12); return;
        case STI_UINT128: c.take(16); return;
        case STI_UINT160: c.take(20); return;
        case STI_UINT192: c.take(24); return;
        case STI_UINT256: c.take(32); return;
        case STI_UINT384: c.take(48); return;
        case STI_UINT512: c.take(64); return;
        case STI_NUMBER: c.take(12); return;
        case STI_CURRENCY: c.take(20); return;
        case STI_AMOUNT: c.take(amountLen(c)); return;
        case STI_VL:
        case STI_ACCOUNT:
        case STI_VECTOR256: c.take(c.vl()); return;
        case STI_ISSUE: skipIssue(c); return;
        case STI_XCHAIN_BRIDGE:
            c.take(c.vl());
            skipIssue(c);
            c.take(c.vl());
            skipIssue(c);
            return;
        case STI_PATHSET:
            for (;;)
            {
                u8 t = c.byte();
                if (t == 0x00)
                    return;
                if (t == 0xFF)
                    continue;
                if (t & 0x01)
                    c.take(20);
                if (t & 0x10)
                    c.take(20);
                if (t & 0x20)
                    c.take(20);
            }
        case STI_OBJECT:
            for (;;)
            {
                int s, k;
                fieldId(c, s, k);
                if (s == STI_OBJECT && k == 1)
                    return;
                skipValue(c, s, depth + 1);
            }
        case STI_ARRAY:
            for (;;)
            {
                int s, k;
                fieldId(c, s, k);
                if (s == STI_ARRAY && k == 1)
                    return;
                skipValue(c, s, depth + 1);
            }
        default: fail("unknown serialized type " + std::to_string(sti));
    }
}

std::string
hexMaybeTrunc(ByteView v, DecodeOpts const& o)
{
    if (o.maxHex && v.size() > o.maxHex)
        return toHex(v.data(), o.maxHex) + "...(" + std::to_string(v.size()) + " bytes)";
    return toHex(v);
}

std::string
u64Hex(u64 v)
{
    char b[24];
    std::snprintf(b, sizeof b, "%llX", (unsigned long long)v);
    return b;
}

std::string
decimalFromMantissa(u64 mant, int exp, bool neg)
{
    if (mant == 0)
        return "0";
    std::string d = std::to_string(mant);
    // strip trailing zeros into exponent
    while (d.size() > 1 && d.back() == '0')
    {
        d.pop_back();
        ++exp;
    }
    std::string r;
    int pointPos = int(d.size()) + exp;  // digits before decimal point
    if (exp >= 0 && pointPos <= 28)
        r = d + std::string(std::size_t(exp), '0');
    else if (exp < 0 && pointPos > 0)
        r = d.substr(0, std::size_t(pointPos)) + "." + d.substr(std::size_t(pointPos));
    else if (exp < 0 && pointPos > -20)
        r = "0." + std::string(std::size_t(-pointPos), '0') + d;
    else
        r = d + "e" + std::to_string(exp);
    return neg ? "-" + r : r;
}

Json
issueJson(Cur& c)
{
    Json j = Json::object();
    ByteView cur = c.take(20);
    bool zero = std::all_of(cur.begin(), cur.end(), [](u8 x) { return x == 0; });
    if (zero)
    {
        j.set("currency", "XAH");
        return j;
    }
    ByteView acc = c.take(20);
    bool noAccount = std::all_of(acc.begin(), acc.end() - 1, [](u8 x) { return x == 0; }) && acc[19] == 1;
    if (noAccount)
    {
        ByteView seq = c.take(4);
        Bytes id(seq.begin(), seq.end());
        id.insert(id.end(), cur.begin(), cur.end());
        j.set("mpt_issuance_id", toHex(id));
        return j;
    }
    j.set("currency", currencyToString(cur.data()));
    j.set("issuer", toAddress(acc.data()));
    return j;
}

Json
amountJson(ByteView v)
{
    u64 x = getBE64(v.data());
    if (v.size() == 8)
    {
        bool pos = x & 0x4000000000000000ull;
        u64 drops = x & 0x3FFFFFFFFFFFFFFFull;
        return Json((pos ? "" : "-") + std::to_string(drops));
    }
    if (v.size() == 33)
    {
        bool pos = v[0] & 0x40;
        u64 val = getBE64(v.data() + 1);
        Json j = Json::object();
        j.set("mpt_issuance_id", toHex(v.data() + 9, 24));
        j.set("value", (pos ? "" : "-") + std::to_string(val));
        return j;
    }
    Json j = Json::object();
    std::string value;
    if ((x & 0x3FFFFFFFFFFFFFFFull) == 0)
        value = "0";
    else
    {
        bool pos = x & 0x4000000000000000ull;
        int exp = int((x >> 54) & 0xFF) - 97;
        u64 mant = x & 0x003FFFFFFFFFFFFFull;
        value = decimalFromMantissa(mant, exp, !pos);
    }
    j.set("currency", currencyToString(v.data() + 8));
    j.set("issuer", toAddress(v.data() + 28));
    j.set("value", value);
    return j;
}

std::string
numberText(ByteView v)
{
    i64 mant = i64(getBE64(v.data()));
    i32 exp = i32(getBE32(v.data() + 8));
    if (mant == 0)
        return "0";
    bool neg = mant < 0;
    u64 m = neg ? u64(-(mant + 1)) + 1 : u64(mant);
    return decimalFromMantissa(m, exp, neg);
}

Json decodeObjectBody(Cur& c, DecodeOpts const& o, int depth, bool untilEnd);

std::string
fieldName(int sti, int code)
{
    if (auto f = fieldById(sti, code))
        return f->name;
    return "Field_" + std::to_string(sti) + "_" + std::to_string(code);
}

Json
decodeValue(Cur& c, int sti, int code, DecodeOpts const& o, int depth)
{
    if (depth > 64)
        fail("object nested too deeply");
    switch (sti)
    {
        case STI_UINT8: {
            u8 v = c.byte();
            if (code == 3)
                if (auto n = terName(v))
                    return Json(n);
            return Json(int(v));
        }
        case STI_UINT16: {
            u16 v = getBE16(c.take(2).data());
            if (code == 1)
                if (auto n = leTypeName(v))
                    return Json(n);
            if (code == 2)
                if (auto n = txTypeName(v))
                    return Json(n);
            return Json(int(v));
        }
        case STI_UINT32: return Json(getBE32(c.take(4).data()));
        case STI_UINT64: {
            u64 v = getBE64(c.take(8).data());
            auto f = fieldById(sti, code);
            return Json((f && f->baseTen) ? std::to_string(v) : u64Hex(v));
        }
        case STI_UINT96: return Json(toHex(c.take(12)));
        case STI_UINT128: return Json(toHex(c.take(16)));
        case STI_UINT160: return Json(toHex(c.take(20)));
        case STI_UINT192: return Json(toHex(c.take(24)));
        case STI_UINT256: return Json(toHex(c.take(32)));
        case STI_UINT384: return Json(toHex(c.take(48)));
        case STI_UINT512: return Json(toHex(c.take(64)));
        case STI_NUMBER: return Json(numberText(c.take(12)));
        case STI_CURRENCY: return Json(currencyToString(c.take(20).data()));
        case STI_AMOUNT: return amountJson(c.take(amountLen(c)));
        case STI_VL: return Json(hexMaybeTrunc(c.take(c.vl()), o));
        case STI_ACCOUNT: {
            ByteView v = c.take(c.vl());
            return v.size() == 20 ? Json(toAddress(v.data())) : Json(toHex(v));
        }
        case STI_VECTOR256: {
            ByteView v = c.take(c.vl());
            Json a = Json::array();
            for (std::size_t k = 0; k + 32 <= v.size(); k += 32)
                a.push(toHex(v.data() + k, 32));
            return a;
        }
        case STI_ISSUE: return issueJson(c);
        case STI_XCHAIN_BRIDGE: {
            Json j = Json::object();
            ByteView a = c.take(c.vl());
            j.set("LockingChainDoor", a.size() == 20 ? toAddress(a.data()) : toHex(a));
            j.set("LockingChainIssue", issueJson(c));
            ByteView b = c.take(c.vl());
            j.set("IssuingChainDoor", b.size() == 20 ? toAddress(b.data()) : toHex(b));
            j.set("IssuingChainIssue", issueJson(c));
            return j;
        }
        case STI_PATHSET: {
            Json paths = Json::array(), path = Json::array();
            for (;;)
            {
                u8 t = c.byte();
                if (t == 0x00 || t == 0xFF)
                {
                    paths.push(std::move(path));
                    path = Json::array();
                    if (t == 0x00)
                        return paths;
                    continue;
                }
                Json step = Json::object();
                if (t & 0x01)
                    step.set("account", toAddress(c.take(20).data()));
                if (t & 0x10)
                    step.set("currency", currencyToString(c.take(20).data()));
                if (t & 0x20)
                    step.set("issuer", toAddress(c.take(20).data()));
                path.push(std::move(step));
            }
        }
        case STI_OBJECT: return decodeObjectBody(c, o, depth + 1, true);
        case STI_ARRAY: {
            Json a = Json::array();
            for (;;)
            {
                int s, k;
                fieldId(c, s, k);
                if (s == STI_ARRAY && k == 1)
                    return a;
                Json wrap = Json::object();
                wrap.set(fieldName(s, k), decodeValue(c, s, k, o, depth + 1));
                a.push(std::move(wrap));
            }
        }
        default: fail("unknown serialized type " + std::to_string(sti));
    }
}

Json
decodeObjectBody(Cur& c, DecodeOpts const& o, int depth, bool untilEnd)
{
    Json j = Json::object();
    while (c.left() || untilEnd)
    {
        int s, k;
        fieldId(c, s, k);
        if (untilEnd && s == STI_OBJECT && k == 1)
            return j;
        std::string name = fieldName(s, k);
        Json v = decodeValue(c, s, k, o, depth);
        if (s == STI_VECTOR256 && name == "Amendments")
        {
            Json names = Json::array();
            for (auto const& e : v.elems())
            {
                H256 h;
                H256::parse(e.str(), h);
                auto n = amendmentName(h);
                names.push(n ? n : "?");
            }
            j.set(name, std::move(v));
            j.set("_AmendmentNames", std::move(names));
            continue;
        }
        if (s == STI_UINT256 && name == "Amendment")
        {
            H256 h;
            H256::parse(v.str(), h);
            j.set(name, std::move(v));
            if (auto n = amendmentName(h))
                j.set("_AmendmentName", n);
            continue;
        }
        j.set(name, std::move(v));
    }
    return j;
}

}  // namespace

std::string
currencyToString(u8 const* c)
{
    bool allZero = true;
    for (int i = 0; i < 20; ++i)
        allZero &= c[i] == 0;
    if (allZero)
        return "XAH";
    bool std3 = true;
    for (int i = 0; i < 20; ++i)
        if ((i < 12 || i > 14) && c[i] != 0)
            std3 = false;
    if (std3)
    {
        std::string s(reinterpret_cast<char const*>(c + 12), 3);
        if (std::all_of(s.begin(), s.end(), [](char ch) { return ch > 32 && ch < 127; }))
            return s;
    }
    return toHex(c, 20);
}

bool
stParse(ByteView obj, std::vector<STRaw>& out, std::string* err)
{
    out.clear();
    try
    {
        Cur c{obj.data(), obj.size()};
        while (c.left())
        {
            STRaw r;
            fieldId(c, r.sti, r.code);
            std::size_t start = c.i;
            skipValue(c, r.sti, 0);
            r.value = ByteView{obj.data() + start, c.i - start};
            out.push_back(r);
        }
        return true;
    }
    catch (Error const& e)
    {
        if (err)
            *err = e.what();
        return false;
    }
}

std::optional<ByteView>
stFind(ByteView obj, int sti, int code)
{
    std::vector<STRaw> f;
    stParse(obj, f);
    for (auto const& r : f)
        if (r.sti == sti && r.code == code)
            return r.value;
    return std::nullopt;
}

std::optional<u32>
stU32(ByteView obj, int code)
{
    auto v = stFind(obj, STI_UINT32, code);
    if (!v || v->size() != 4)
        return std::nullopt;
    return getBE32(v->data());
}
std::optional<u16>
stU16(ByteView obj, int code)
{
    auto v = stFind(obj, STI_UINT16, code);
    if (!v || v->size() != 2)
        return std::nullopt;
    return getBE16(v->data());
}
std::optional<u8>
stU8(ByteView obj, int code)
{
    auto v = stFind(obj, STI_UINT8, code);
    if (!v || v->size() != 1)
        return std::nullopt;
    return (*v)[0];
}
std::vector<H256>
stV256(ByteView obj, int code)
{
    std::vector<H256> r;
    auto v = stFind(obj, STI_VECTOR256, code);
    if (!v)
        return r;
    std::size_t len = 0, used = decodeVL(v->data(), v->size(), len);
    for (std::size_t k = used; k + 32 <= v->size(); k += 32)
        r.push_back(H256::fromBytes(v->data() + k));
    return r;
}
std::optional<std::string>
stAccount(ByteView obj, int code)
{
    auto v = stFind(obj, STI_ACCOUNT, code);
    if (!v || v->size() != 21)
        return std::nullopt;
    return toAddress(v->data() + 1);
}

Json
stDecode(ByteView obj, DecodeOpts const& o)
{
    Cur c{obj.data(), obj.size()};
    Json j = Json::object();
    try
    {
        j = decodeObjectBody(c, o, 0, false);
    }
    catch (Error const& e)
    {
        // re-run field by field to keep what decoded cleanly
        Cur c2{obj.data(), obj.size()};
        Json partial = Json::object();
        try
        {
            while (c2.left())
            {
                int s, k;
                fieldId(c2, s, k);
                partial.set(fieldName(s, k), decodeValue(c2, s, k, o, 0));
            }
        }
        catch (Error const&)
        {
        }
        partial.set("_error", e.what());
        return partial;
    }
    return j;
}

bool
splitTxLeaf(ByteView leaf, ByteView& tx, ByteView& meta)
{
    std::size_t l1 = 0, u1 = decodeVL(leaf.data(), leaf.size(), l1);
    if (!u1 || u1 + l1 > leaf.size())
        return false;
    tx = ByteView{leaf.data() + u1, l1};
    std::size_t rest = leaf.size() - u1 - l1;
    std::size_t l2 = 0, u2 = decodeVL(leaf.data() + u1 + l1, rest, l2);
    if (!u2 || u2 + l2 != rest)
        return false;
    meta = ByteView{leaf.data() + u1 + l1 + u2, l2};
    return true;
}

H256
txIdOf(ByteView tx)
{
    Sha512 s;
    s.updateBE32(kPrefixTxId);
    s.update(tx);
    return s.finalHalf();
}

TxSummary
txSummary(ByteView leaf)
{
    TxSummary t;
    ByteView tx, meta;
    if (!splitTxLeaf(leaf, tx, meta))
    {
        t.type = "?";
        return t;
    }
    if (auto v = stU16(tx, 2))
    {
        auto n = txTypeName(*v);
        t.type = n ? n : std::to_string(*v);
    }
    if (auto a = stAccount(tx, 1))
        t.account = *a;
    if (auto r = stU8(meta, 3))
    {
        auto n = terName(*r);
        t.result = n ? n : std::to_string(*r);
    }
    return t;
}

std::string
leTypeOf(ByteView sle)
{
    if (auto v = stU16(sle, 1))
    {
        auto n = leTypeName(*v);
        return n ? n : std::to_string(*v);
    }
    return "?";
}

// ------------------------------------------------------------ keylets

H256
indexHash(u16 space, std::initializer_list<ByteView> parts)
{
    Sha512 s;
    u8 sp[2];
    putBE16(sp, space);
    s.update(sp, 2);
    for (auto const& p : parts)
        s.update(p);
    return s.finalHalf();
}

namespace {

ByteView
bv(AccountID const& a)
{
    return {a.data(), 20};
}
ByteView
bv(H256 const& h)
{
    return {h.data(), 32};
}

struct BE32Buf
{
    u8 b[4];
    explicit BE32Buf(u32 v) { putBE32(b, v); }
    ByteView v() const { return {b, 4}; }
};
struct BE64Buf
{
    u8 b[8];
    explicit BE64Buf(u64 v) { putBE64(b, v); }
    ByteView v() const { return {b, 8}; }
};

std::vector<std::string>
splitColon(std::string_view s)
{
    std::vector<std::string> r;
    std::size_t st = 0;
    for (std::size_t i = 0; i <= s.size(); ++i)
        if (i == s.size() || s[i] == ':')
        {
            r.emplace_back(s.substr(st, i - st));
            st = i + 1;
        }
    return r;
}

std::optional<std::array<u8, 20>>
parseCurrency(std::string const& s)
{
    std::array<u8, 20> c{};
    if (s == "XAH" || s == "XRP")
        return c;
    if (s.size() == 3)
    {
        std::memcpy(c.data() + 12, s.data(), 3);
        return c;
    }
    if (isHex(s, 40))
    {
        Bytes b;
        fromHex(s, b);
        std::memcpy(c.data(), b.data(), 20);
        return c;
    }
    return std::nullopt;
}

}  // namespace

H256
skipKeylet()
{
    return indexHash('s', {});
}

H256
skipKeylet(u32 seq)
{
    BE32Buf g(seq >> 16);
    return indexHash('s', {g.v()});
}

char const*
keyletHelp()
{
    return "  <64 hex>                      raw ledger key\n"
           "  account:<r>                   AccountRoot\n"
           "  owner_dir:<r>                 owner directory root\n"
           "  page:<root hex>:<n>           directory page n\n"
           "  signers:<r>                   SignerList\n"
           "  line:<r>:<r>:<currency>       trust line (RippleState)\n"
           "  offer|escrow|check|ticket|nft_offer:<r>:<seq>\n"
           "  paychan:<src>:<dst>:<seq>     payment channel\n"
           "  deposit_preauth:<owner>:<r>   deposit preauth\n"
           "  hook:<r>                      Hook object\n"
           "  hook_def:<hookhash>           HookDefinition\n"
           "  hook_state:<r>:<key>:<ns>     HookState (key/ns 64 hex)\n"
           "  hook_state_dir:<r>:<ns>       HookState directory\n"
           "  emitted:<txid>  emitted_dir   emitted txn / directory\n"
           "  uritoken:<issuer>:<uri>       URIToken (uri as text, or hex:<..>)\n"
           "  import_vlseq:<pubkey hex>     ImportVLSequence\n"
           "  did:<r>                       DID\n"
           "  skip | skip:<seq>             LedgerHashes (short / long list)\n"
           "  amendments | fees | nunl | unl_report\n";
}

std::optional<H256>
parseKeylet(std::string_view spec, std::string& err)
{
    H256 raw;
    if (H256::parse(spec, raw))
        return raw;
    auto p = splitColon(spec);
    std::string const& k = p[0];
    auto acct = [&](std::size_t i) -> std::optional<AccountID> {
        if (i >= p.size())
        {
            err = "missing account";
            return std::nullopt;
        }
        auto a = parseAddress(p[i]);
        if (!a)
            err = "bad account: " + p[i];
        return a;
    };
    auto hash = [&](std::size_t i) -> std::optional<H256> {
        H256 h;
        if (i >= p.size() || !H256::parse(p[i], h))
        {
            err = "expected 64 hex digits";
            return std::nullopt;
        }
        return h;
    };
    auto num = [&](std::size_t i) -> std::optional<u64> {
        u64 v;
        if (i >= p.size() || !parseU64(p[i], v))
        {
            err = "expected a number";
            return std::nullopt;
        }
        return v;
    };
    auto argc = [&](std::size_t n) {
        if (p.size() != n + 1)
        {
            err = k + " expects " + std::to_string(n) + " argument(s)";
            return false;
        }
        return true;
    };

    if (k == "skip")
    {
        if (p.size() == 1)
            return skipKeylet();
        if (auto s = num(1))
            return skipKeylet(u32(*s));
        return std::nullopt;
    }
    if (k == "amendments" && argc(0))
        return indexHash('f', {});
    if (k == "fees" && argc(0))
        return indexHash('e', {});
    if (k == "nunl" && argc(0))
        return indexHash('N', {});
    if (k == "unl_report" && argc(0))
        return indexHash('R', {});
    if (k == "emitted_dir" && argc(0))
        return indexHash('F', {});

    std::pair<char const*, u16> single[] = {{"account", 'a'}, {"owner_dir", 'O'}, {"hook", 'H'}, {"did", 0x0149}};
    for (auto [name, sp] : single)
        if (k == name)
        {
            if (!argc(1))
                return std::nullopt;
            auto a = acct(1);
            if (!a)
                return std::nullopt;
            return indexHash(sp, {bv(*a)});
        }
    if (k == "signers")
    {
        auto a = argc(1) ? acct(1) : std::nullopt;
        if (!a)
            return std::nullopt;
        BE32Buf z(0);
        return indexHash('S', {bv(*a), z.v()});
    }
    std::pair<char const*, u16> seqd[] = {{"offer", 'o'}, {"escrow", 'u'}, {"check", 'C'}, {"ticket", 'T'}, {"nft_offer", 'q'}};
    for (auto [name, sp] : seqd)
        if (k == name)
        {
            if (!argc(2))
                return std::nullopt;
            auto a = acct(1);
            auto s = num(2);
            if (!a || !s)
                return std::nullopt;
            BE32Buf sb{u32(*s)};
            return indexHash(sp, {bv(*a), sb.v()});
        }
    if (k == "line")
    {
        if (!argc(3))
            return std::nullopt;
        auto a = acct(1), b = acct(2);
        auto c = parseCurrency(p[3]);
        if (!a || !b)
            return std::nullopt;
        if (!c)
        {
            err = "bad currency";
            return std::nullopt;
        }
        auto [lo, hi] = std::minmax(*a, *b);
        return indexHash('r', {bv(lo), bv(hi), ByteView{c->data(), 20}});
    }
    if (k == "paychan")
    {
        if (!argc(3))
            return std::nullopt;
        auto a = acct(1), b = acct(2);
        auto s = num(3);
        if (!a || !b || !s)
            return std::nullopt;
        BE32Buf sb{u32(*s)};
        return indexHash('x', {bv(*a), bv(*b), sb.v()});
    }
    if (k == "deposit_preauth")
    {
        if (!argc(2))
            return std::nullopt;
        auto a = acct(1), b = acct(2);
        if (!a || !b)
            return std::nullopt;
        return indexHash('p', {bv(*a), bv(*b)});
    }
    if (k == "page")
    {
        if (!argc(2))
            return std::nullopt;
        auto r = hash(1);
        auto n = num(2);
        if (!r || !n)
            return std::nullopt;
        if (*n == 0)
            return *r;
        BE64Buf nb(*n);
        return indexHash('d', {bv(*r), nb.v()});
    }
    if (k == "hook_def" || k == "emitted")
    {
        if (!argc(1))
            return std::nullopt;
        auto h = hash(1);
        if (!h)
            return std::nullopt;
        return indexHash(k == "hook_def" ? 'D' : 'E', {bv(*h)});
    }
    if (k == "hook_state")
    {
        if (!argc(3))
            return std::nullopt;
        auto a = acct(1);
        auto key = hash(2), ns = hash(3);
        if (!a || !key || !ns)
            return std::nullopt;
        return indexHash('v', {bv(*a), bv(*key), bv(*ns)});
    }
    if (k == "hook_state_dir")
    {
        if (!argc(2))
            return std::nullopt;
        auto a = acct(1);
        auto ns = hash(2);
        if (!a || !ns)
            return std::nullopt;
        return indexHash('J', {bv(*a), bv(*ns)});
    }
    if (k == "uritoken")
    {
        if (p.size() < 3)
        {
            err = "uritoken expects <issuer>:<uri>";
            return std::nullopt;
        }
        auto a = acct(1);
        if (!a)
            return std::nullopt;
        std::string uri(spec.substr(spec.find(':', spec.find(':') + 1) + 1));
        Bytes u;
        if (uri.rfind("hex:", 0) == 0)
        {
            if (!fromHex(uri.substr(4), u))
            {
                err = "bad hex uri";
                return std::nullopt;
            }
        }
        else
            u.assign(uri.begin(), uri.end());
        return indexHash('U', {bv(*a), ByteView{u.data(), u.size()}});
    }
    if (k == "import_vlseq")
    {
        Bytes pk;
        if (p.size() != 2 || !fromHex(p[1], pk) || pk.size() != 33)
        {
            err = "import_vlseq expects a 33-byte public key in hex";
            return std::nullopt;
        }
        return indexHash('I', {ByteView{pk.data(), pk.size()}});
    }
    if (err.empty())
        err = "unknown keylet type '" + k + "'";
    return std::nullopt;
}

}  // namespace catl
