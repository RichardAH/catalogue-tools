// catl — minimal ordered JSON value, parser and writer (RPC responses and
// decoded ledger objects). Numbers are kept as their source text.
#pragma once

#include "util.hpp"

#include <optional>
#include <type_traits>

namespace catl {

class Json
{
public:
    enum class T : u8 { Null, Bool, Num, Str, Arr, Obj };

    Json() = default;
    Json(std::nullptr_t) {}
    Json(bool v) : t_(T::Bool), b_(v) {}
    template <class I>
        requires(std::is_integral_v<I> && !std::is_same_v<I, bool>)
    Json(I v) : t_(T::Num), s_(std::to_string(v))
    {
    }
    Json(char const* v) : t_(T::Str), s_(v) {}
    Json(std::string v) : t_(T::Str), s_(std::move(v)) {}
    Json(std::string_view v) : t_(T::Str), s_(v) {}

    static Json
    object()
    {
        Json j;
        j.t_ = T::Obj;
        return j;
    }
    static Json
    array()
    {
        Json j;
        j.t_ = T::Arr;
        return j;
    }
    static Json
    number(std::string raw)
    {
        Json j;
        j.t_ = T::Num;
        j.s_ = std::move(raw);
        return j;
    }

    T
    type() const
    {
        return t_;
    }
    bool isNull() const { return t_ == T::Null; }
    bool isObj() const { return t_ == T::Obj; }
    bool isArr() const { return t_ == T::Arr; }
    bool isStr() const { return t_ == T::Str; }
    bool isNum() const { return t_ == T::Num; }
    bool isBool() const { return t_ == T::Bool; }

    Json&
    set(std::string const& k, Json v)
    {
        t_ = T::Obj;
        for (auto& kv : o_)
            if (kv.first == k)
            {
                kv.second = std::move(v);
                return kv.second;
            }
        o_.emplace_back(k, std::move(v));
        return o_.back().second;
    }
    bool
    has(std::string_view k) const
    {
        for (auto& kv : o_)
            if (kv.first == k)
                return true;
        return false;
    }
    Json const&
    operator[](std::string_view k) const
    {
        for (auto& kv : o_)
            if (kv.first == k)
                return kv.second;
        return nullValue();
    }
    Json const&
    operator[](std::size_t i) const
    {
        return i < a_.size() ? a_[i] : nullValue();
    }
    Json&
    push(Json v)
    {
        t_ = T::Arr;
        a_.push_back(std::move(v));
        return a_.back();
    }
    std::size_t
    size() const
    {
        return t_ == T::Arr ? a_.size() : t_ == T::Obj ? o_.size() : 0;
    }
    std::vector<Json> const&
    elems() const
    {
        return a_;
    }
    std::vector<std::pair<std::string, Json>> const&
    items() const
    {
        return o_;
    }
    std::string const&
    str() const
    {
        return s_;
    }
    bool
    boolean() const
    {
        return t_ == T::Bool && b_;
    }
    std::optional<u64>
    asU64() const
    {
        u64 v;
        if ((t_ == T::Num || t_ == T::Str) && parseU64(s_, v))
            return v;
        return std::nullopt;
    }

    std::string
    dump(int indent = -1) const
    {
        std::string out;
        write(out, indent, 0);
        return out;
    }

    static Json
    parse(std::string_view s)
    {
        std::size_t i = 0;
        Json j = parseValue(s, i, 0);
        skipWs(s, i);
        if (i != s.size())
            fail("json: trailing characters");
        return j;
    }

private:
    static Json const&
    nullValue()
    {
        static Json const n;
        return n;
    }
    static void
    escape(std::string& out, std::string const& s)
    {
        out.push_back('"');
        for (unsigned char c : s)
        {
            switch (c)
            {
                case '"': out += "\\\""; break;
                case '\\': out += "\\\\"; break;
                case '\n': out += "\\n"; break;
                case '\r': out += "\\r"; break;
                case '\t': out += "\\t"; break;
                default:
                    if (c < 0x20)
                    {
                        char b[8];
                        std::snprintf(b, sizeof b, "\\u%04x", c);
                        out += b;
                    }
                    else
                        out.push_back(char(c));
            }
        }
        out.push_back('"');
    }
    void
    write(std::string& out, int indent, int depth) const
    {
        auto nl = [&](int d) {
            if (indent < 0)
                return;
            out.push_back('\n');
            out.append(std::size_t(indent * d), ' ');
        };
        switch (t_)
        {
            case T::Null: out += "null"; break;
            case T::Bool: out += b_ ? "true" : "false"; break;
            case T::Num: out += s_; break;
            case T::Str: escape(out, s_); break;
            case T::Arr:
                if (a_.empty())
                {
                    out += "[]";
                    break;
                }
                out.push_back('[');
                for (std::size_t i = 0; i < a_.size(); ++i)
                {
                    if (i)
                        out.push_back(',');
                    nl(depth + 1);
                    a_[i].write(out, indent, depth + 1);
                }
                nl(depth);
                out.push_back(']');
                break;
            case T::Obj:
                if (o_.empty())
                {
                    out += "{}";
                    break;
                }
                out.push_back('{');
                for (std::size_t i = 0; i < o_.size(); ++i)
                {
                    if (i)
                        out.push_back(',');
                    nl(depth + 1);
                    escape(out, o_[i].first);
                    out += indent < 0 ? ":" : ": ";
                    o_[i].second.write(out, indent, depth + 1);
                }
                nl(depth);
                out.push_back('}');
                break;
        }
    }
    static void
    skipWs(std::string_view s, std::size_t& i)
    {
        while (i < s.size() && (s[i] == ' ' || s[i] == '\n' || s[i] == '\r' || s[i] == '\t'))
            ++i;
    }
    static void
    utf8(std::string& o, u32 cp)
    {
        if (cp < 0x80)
            o.push_back(char(cp));
        else if (cp < 0x800)
        {
            o.push_back(char(0xC0 | (cp >> 6)));
            o.push_back(char(0x80 | (cp & 63)));
        }
        else if (cp < 0x10000)
        {
            o.push_back(char(0xE0 | (cp >> 12)));
            o.push_back(char(0x80 | ((cp >> 6) & 63)));
            o.push_back(char(0x80 | (cp & 63)));
        }
        else
        {
            o.push_back(char(0xF0 | (cp >> 18)));
            o.push_back(char(0x80 | ((cp >> 12) & 63)));
            o.push_back(char(0x80 | ((cp >> 6) & 63)));
            o.push_back(char(0x80 | (cp & 63)));
        }
    }
    static std::string
    parseString(std::string_view s, std::size_t& i)
    {
        std::string o;
        ++i;  // opening quote
        while (i < s.size() && s[i] != '"')
        {
            char c = s[i++];
            if (c != '\\')
            {
                o.push_back(c);
                continue;
            }
            if (i >= s.size())
                break;
            char e = s[i++];
            switch (e)
            {
                case 'n': o.push_back('\n'); break;
                case 't': o.push_back('\t'); break;
                case 'r': o.push_back('\r'); break;
                case 'b': o.push_back('\b'); break;
                case 'f': o.push_back('\f'); break;
                case 'u': {
                    auto hex4 = [&](u32& v) {
                        if (i + 4 > s.size())
                            fail("json: bad \\u escape");
                        v = 0;
                        for (int k = 0; k < 4; ++k)
                        {
                            int n = hexNibble(s[i++]);
                            if (n < 0)
                                fail("json: bad \\u escape");
                            v = v * 16 + u32(n);
                        }
                    };
                    u32 cp;
                    hex4(cp);
                    if (cp >= 0xD800 && cp < 0xDC00 && i + 1 < s.size() && s[i] == '\\' && s[i + 1] == 'u')
                    {
                        i += 2;
                        u32 lo;
                        hex4(lo);
                        cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                    }
                    utf8(o, cp);
                    break;
                }
                default: o.push_back(e);
            }
        }
        if (i >= s.size())
            fail("json: unterminated string");
        ++i;
        return o;
    }
    static Json
    parseValue(std::string_view s, std::size_t& i, int depth)
    {
        if (depth > 200)
            fail("json: nesting too deep");
        skipWs(s, i);
        if (i >= s.size())
            fail("json: unexpected end");
        char c = s[i];
        if (c == '{')
        {
            Json j = object();
            ++i;
            skipWs(s, i);
            if (i < s.size() && s[i] == '}')
            {
                ++i;
                return j;
            }
            for (;;)
            {
                skipWs(s, i);
                if (i >= s.size() || s[i] != '"')
                    fail("json: expected key");
                std::string k = parseString(s, i);
                skipWs(s, i);
                if (i >= s.size() || s[i] != ':')
                    fail("json: expected ':'");
                ++i;
                j.o_.emplace_back(std::move(k), parseValue(s, i, depth + 1));
                skipWs(s, i);
                if (i < s.size() && s[i] == ',')
                {
                    ++i;
                    continue;
                }
                if (i < s.size() && s[i] == '}')
                {
                    ++i;
                    return j;
                }
                fail("json: expected ',' or '}'");
            }
        }
        if (c == '[')
        {
            Json j = array();
            ++i;
            skipWs(s, i);
            if (i < s.size() && s[i] == ']')
            {
                ++i;
                return j;
            }
            for (;;)
            {
                j.a_.push_back(parseValue(s, i, depth + 1));
                skipWs(s, i);
                if (i < s.size() && s[i] == ',')
                {
                    ++i;
                    continue;
                }
                if (i < s.size() && s[i] == ']')
                {
                    ++i;
                    return j;
                }
                fail("json: expected ',' or ']'");
            }
        }
        if (c == '"')
            return Json(parseString(s, i));
        if (s.substr(i, 4) == "true")
        {
            i += 4;
            return Json(true);
        }
        if (s.substr(i, 5) == "false")
        {
            i += 5;
            return Json(false);
        }
        if (s.substr(i, 4) == "null")
        {
            i += 4;
            return Json();
        }
        std::size_t st = i;
        while (i < s.size() && (std::isdigit(u8(s[i])) || s[i] == '-' || s[i] == '+' || s[i] == '.' || s[i] == 'e' || s[i] == 'E'))
            ++i;
        if (st == i)
            fail("json: unexpected character");
        return number(std::string(s.substr(st, i - st)));
    }

    T t_ = T::Null;
    bool b_ = false;
    std::string s_;
    std::vector<Json> a_;
    std::vector<std::pair<std::string, Json>> o_;
};

}  // namespace catl
