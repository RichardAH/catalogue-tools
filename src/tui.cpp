// catl — interactive browser in the spirit of XTree Gold: blue screen, box
// panes, a tree of catalogue files, one-letter commands on the bottom bar.
// Raw ANSI/termios, no curses dependency. Long operations run on a worker
// thread with live progress in the info pane (^C cancels).
#include "tui.hpp"
#include "fetch.hpp"
#include "net.hpp"
#include "ops.hpp"

#include <csignal>
#include <ctime>
#include <memory>
#include <mutex>
#include <poll.h>
#include <set>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <termios.h>
#include <thread>
#include <unistd.h>

namespace catl {
namespace {

// ================================================================ terminal

enum Key : int {
    kNone = 0, kCtrlC = 3, kTab = 9, kEnter = 13, kEsc = 27, kBs = 127,
    kUp = 1000, kDown, kLeft, kRight, kPgUp, kPgDn, kHome, kEnd, kF1, kDel,
};

volatile std::sig_atomic_t gResized = 0;
void
onWinch(int)
{
    gResized = 1;
}

struct Term
{
    termios orig{};
    bool active = false;
    int w = 80, h = 24;

    void
    out(std::string const& s)
    {
        std::size_t o = 0;
        while (o < s.size())
        {
            ssize_t r = ::write(1, s.data() + o, s.size() - o);
            if (r <= 0)
            {
                if (errno == EINTR)
                    continue;
                return;
            }
            o += std::size_t(r);
        }
    }
    void
    enter()
    {
        ::tcgetattr(0, &orig);
        termios t = orig;
        t.c_lflag &= ~tcflag_t(ICANON | ECHO | ISIG | IEXTEN);
        t.c_iflag &= ~tcflag_t(IXON | ICRNL | BRKINT | INPCK | ISTRIP);
        t.c_cc[VMIN] = 0;
        t.c_cc[VTIME] = 0;
        ::tcsetattr(0, TCSAFLUSH, &t);
        active = true;
        out("\033[?1049h\033[?25l\033[?7l\033[2J");
        size();
    }
    void
    leave()
    {
        if (!active)
            return;
        out("\033[0m\033[2J\033[?7h\033[?25h\033[?1049l");
        ::tcsetattr(0, TCSAFLUSH, &orig);
        active = false;
    }
    void
    size()
    {
        winsize ws{};
        if (::ioctl(1, TIOCGWINSZ, &ws) == 0 && ws.ws_col)
        {
            w = ws.ws_col;
            h = ws.ws_row;
        }
    }
};

std::string gPending;

int
readKey(int timeoutMs)
{
    auto fillMore = [](int ms) {
        pollfd p{0, POLLIN, 0};
        if (::poll(&p, 1, ms) <= 0)
            return false;
        char b[256];
        ssize_t n = ::read(0, b, sizeof b);
        if (n <= 0)
            return false;
        gPending.append(b, std::size_t(n));
        return true;
    };
    if (gPending.empty() && !fillMore(timeoutMs))
        return kNone;
    u8 c = u8(gPending[0]);
    if (c != 27)
    {
        gPending.erase(0, 1);
        if (c == '\n')
            return kEnter;
        if (c == 8)
            return kBs;
        return c;
    }
    if (gPending.size() == 1)
        fillMore(30);
    if (gPending.size() == 1)
    {
        gPending.clear();
        return kEsc;
    }
    static std::pair<char const*, int> const seqs[] = {
        {"\033[A", kUp}, {"\033[B", kDown}, {"\033[C", kRight}, {"\033[D", kLeft}, {"\033OA", kUp},
        {"\033OB", kDown}, {"\033OC", kRight}, {"\033OD", kLeft}, {"\033[5~", kPgUp}, {"\033[6~", kPgDn},
        {"\033[H", kHome}, {"\033[F", kEnd}, {"\033[1~", kHome}, {"\033[4~", kEnd}, {"\033OH", kHome},
        {"\033OF", kEnd}, {"\033OP", kF1}, {"\033[11~", kF1}, {"\033[3~", kDel}, {"\033[7~", kHome}, {"\033[8~", kEnd}};
    for (int tries = 0; tries < 3; ++tries)
    {
        for (auto [s, k] : seqs)
        {
            std::size_t n = std::strlen(s);
            if (gPending.compare(0, n, s) == 0)
            {
                gPending.erase(0, n);
                return k;
            }
        }
        if (!fillMore(20))
            break;
    }
    // unknown sequence: drop it
    std::size_t i = 1;
    while (i < gPending.size() && !(std::isalpha(u8(gPending[i])) || gPending[i] == '~'))
        ++i;
    gPending.erase(0, std::min(i + 1, gPending.size()));
    return kNone;
}

// ================================================================ screen

enum : u8 { BLK, RED, GRN, YEL, BLU, MAG, CYN, WHT, GRY, LRED, LGRN, LYEL, LBLU, LMAG, LCYN, BWHT };

struct Cell
{
    char32_t ch = U' ';
    u8 fg = WHT, bg = BLU;
};

std::u32string
toU32(std::string_view s)
{
    std::u32string r;
    for (std::size_t i = 0; i < s.size();)
    {
        u8 c = u8(s[i]);
        char32_t cp;
        int n;
        if (c < 0x80)
            cp = c, n = 1;
        else if ((c >> 5) == 6)
            cp = c & 31, n = 2;
        else if ((c >> 4) == 14)
            cp = c & 15, n = 3;
        else
            cp = c & 7, n = 4;
        for (int k = 1; k < n && i + std::size_t(k) < s.size(); ++k)
            cp = (cp << 6) | (u8(s[i + std::size_t(k)]) & 63);
        r.push_back(cp < 32 ? U' ' : cp);
        i += std::size_t(n);
    }
    return r;
}

void
appendUtf8(std::string& o, char32_t cp)
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

struct Screen
{
    int w = 80, h = 24;
    std::vector<Cell> c;
    std::vector<std::string> prev;

    void
    resize(int W, int H)
    {
        w = W;
        h = H;
        c.assign(std::size_t(w * h), Cell{});
        prev.assign(std::size_t(h), "\x01");
    }
    void
    fill(int x, int y, int ww, int hh, u8 fg, u8 bg, char32_t ch = U' ')
    {
        for (int j = y; j < y + hh; ++j)
            for (int i = x; i < x + ww; ++i)
                if (i >= 0 && j >= 0 && i < w && j < h)
                    c[std::size_t(j * w + i)] = {ch, fg, bg};
    }
    int
    text(int x, int y, std::string_view s, u8 fg, u8 bg, int maxw = 1 << 20)
    {
        if (y < 0 || y >= h)
            return 0;
        int n = 0;
        for (char32_t cp : toU32(s))
        {
            if (n >= maxw || x + n >= w)
                break;
            if (x + n >= 0)
                c[std::size_t(y * w + x + n)] = {cp, fg, bg};
            ++n;
        }
        return n;
    }
    void
    flush(Term& t)
    {
        std::string out;
        for (int y = 0; y < h; ++y)
        {
            std::string line;
            int fg = -1, bg = -1;
            for (int x = 0; x < w; ++x)
            {
                Cell const& k = c[std::size_t(y * w + x)];
                if (k.fg != fg || k.bg != bg)
                {
                    fg = k.fg;
                    bg = k.bg;
                    line += "\033[0;" + std::to_string(fg < 8 ? 30 + fg : 90 + fg - 8) + ";" +
                        std::to_string(bg < 8 ? 40 + bg : 100 + bg - 8) + "m";
                }
                appendUtf8(line, k.ch);
            }
            if (line != prev[std::size_t(y)])
            {
                out += "\033[" + std::to_string(y + 1) + ";1H" + line;
                prev[std::size_t(y)] = std::move(line);
            }
        }
        if (!out.empty())
            t.out(out);
    }
};

std::string
padRight(std::string s, std::size_t n)
{
    std::size_t len = toU32(s).size();
    if (len < n)
        s.append(n - len, ' ');
    return s;
}

std::string
fit(std::string const& s, std::size_t n)
{
    auto u = toU32(s);
    if (u.size() <= n)
        return s;
    std::string o;
    for (std::size_t i = 0; i + 1 < n; ++i)
        appendUtf8(o, u[i]);
    o += "…";
    return o;
}

// ================================================================ app

struct App;

struct Job
{
    std::string name;
    std::thread th;
    std::atomic<bool> cancel{false}, finished{false};
    std::mutex mx;
    std::string stage, detail;
    u64 done = 0, total = 0;
    std::vector<std::string> out;
    std::vector<VerifyResult> results;  // handed to the UI thread after join()
    bool ok = false;
    std::string error;
    std::function<void(App&, Job&)> onDone;

    Progress
    progress()
    {
        Progress p;
        p.cancel = &cancel;
        p.fn = [this](std::string const& s, u64 d, u64 t, std::string const& det) {
            std::lock_guard g(mx);
            stage = s;
            done = d;
            total = t;
            detail = det;
        };
        return p;
    }
    void
    log(std::string s)
    {
        std::lock_guard g(mx);
        out.push_back(std::move(s));
    }
};

struct ListNav
{
    int sel = 0, top = 0;
    bool
    key(int k, int n, int vis)
    {
        int old = sel;
        switch (k)
        {
            case kUp: --sel; break;
            case kDown: ++sel; break;
            case kPgUp: sel -= std::max(1, vis - 1); break;
            case kPgDn: sel += std::max(1, vis - 1); break;
            case kHome: sel = 0; break;
            case kEnd: sel = n - 1; break;
            default: return false;
        }
        clamp(n, vis);
        return sel != old || true;
    }
    void
    clamp(int n, int vis)
    {
        if (n <= 0)
        {
            sel = top = 0;
            return;
        }
        sel = std::clamp(sel, 0, n - 1);
        if (sel < top)
            top = sel;
        if (sel >= top + vis)
            top = sel - vis + 1;
        top = std::clamp(top, 0, std::max(0, n - vis));
    }
};

using KV = std::vector<std::pair<std::string, std::string>>;

struct View
{
    virtual ~View() = default;
    virtual std::string
    title() const = 0;
    virtual void
    draw(App&, Screen&, int x, int y, int w, int h) = 0;
    virtual void
    info(App&, KV&)
    {
    }
    virtual bool
    key(App&, int k) = 0;
    virtual std::vector<std::string>
    menu() const
    {
        return {};
    }
    virtual std::string
    hints() const
    {
        return "◄─┘ open   Esc back   F1 help   ^C cancel job   Q quit";
    }
};

struct App
{
    Term term;
    Screen scr;
    std::vector<std::string> roots;
    std::vector<CatFile> files;
    std::vector<std::unique_ptr<View>> stack;
    std::map<std::string, VerifyResult> verified;
    std::map<std::string, std::shared_ptr<CatIndex>> indexes;
    std::set<std::string> tagged;
    std::unique_ptr<Job> job;
    std::string status = "F1 for help.  Point at a directory of cat.* files, or press F to fetch the canonical set.";
    bool prompting = false;
    std::string promptLabel, promptValue;
    std::function<void(App&, std::string)> promptCb;
    bool quit = false;
    std::string dest = ".";

    void
    rescan()
    {
        try
        {
            files = collectFiles(roots);
        }
        catch (Error const& e)
        {
            files.clear();
            status = e.what();
        }
    }
    void
    push(std::unique_ptr<View> v)
    {
        stack.push_back(std::move(v));
    }
    void
    ask(std::string label, std::string def, std::function<void(App&, std::string)> cb)
    {
        prompting = true;
        promptLabel = std::move(label);
        promptValue = std::move(def);
        promptCb = std::move(cb);
    }
    bool
    busy()
    {
        if (job)
        {
            status = "busy with " + job->name + " (^C to cancel it first)";
            return true;
        }
        return false;
    }
    void
    startJob(std::string name, std::function<void(Job&)> fn, std::function<void(App&, Job&)> onDone)
    {
        if (busy())
            return;
        job = std::make_unique<Job>();
        job->name = name;
        job->onDone = std::move(onDone);
        Job* j = job.get();
        j->th = std::thread([j, fn = std::move(fn)] {
            try
            {
                fn(*j);
                j->ok = true;
            }
            catch (std::exception const& e)
            {
                j->error = e.what();
            }
            j->finished = true;
        });
        status = name + " started";
    }
    std::shared_ptr<CatIndex>
    indexFor(CatFile const& f)
    {
        auto it = indexes.find(f.path);
        if (it != indexes.end())
            return it->second;
        if (auto x = CatIndex::load(f.path))
        {
            auto sp = std::make_shared<CatIndex>(std::move(*x));
            indexes[f.path] = sp;
            return sp;
        }
        return nullptr;
    }
    int
    run();
    void
    draw();
    void
    pollJob();
};

// ---------------------------------------------------------------- text view

struct TextView : View
{
    std::string ttl;
    std::vector<std::string> lines, alt;
    bool showAlt = false;
    int top = 0, left = 0, lastH = 10;

    TextView(std::string t, std::vector<std::string> l, std::vector<std::string> a = {})
        : ttl(std::move(t)), lines(std::move(l)), alt(std::move(a))
    {
    }
    static std::vector<std::string>
    split(std::string const& s)
    {
        std::vector<std::string> r;
        std::size_t st = 0;
        for (std::size_t i = 0; i <= s.size(); ++i)
            if (i == s.size() || s[i] == '\n')
            {
                r.push_back(s.substr(st, i - st));
                st = i + 1;
            }
        return r;
    }
    std::string
    title() const override
    {
        return ttl;
    }
    std::vector<std::string> const&
    cur() const
    {
        return showAlt && !alt.empty() ? alt : lines;
    }
    void
    draw(App&, Screen& s, int x, int y, int w, int h) override
    {
        lastH = h;
        auto const& L = cur();
        top = std::clamp(top, 0, std::max(0, int(L.size()) - h));
        for (int i = 0; i < h && top + i < int(L.size()); ++i)
        {
            auto u = toU32(L[std::size_t(top + i)]);
            std::string seg;
            for (std::size_t k = std::size_t(left); k < u.size() && int(k) < left + w; ++k)
                appendUtf8(seg, u[k]);
            u8 fg = BWHT;
            auto const& ln = L[std::size_t(top + i)];
            if (ln.find("error") != std::string::npos || ln.find("MISMATCH") != std::string::npos ||
                ln.find("DIFFERS") != std::string::npos || ln.find("FAIL") != std::string::npos)
                fg = LRED;
            else if (ln.find(" OK") != std::string::npos || ln.find("MATCHES") != std::string::npos ||
                     ln.find("ANCHORED") != std::string::npos || ln.find("LINKED") != std::string::npos)
                fg = LGRN;
            else if (ln.find("warning") != std::string::npos || ln.find("note:") != std::string::npos)
                fg = LYEL;
            s.text(x, y + i, seg, fg, BLU, w);
        }
    }
    void
    info(App&, KV& kv) override
    {
        kv.push_back({"Lines", withCommas(cur().size())});
        kv.push_back({"Line", std::to_string(top + 1)});
        if (!alt.empty())
            kv.push_back({"View", showAlt ? "hex" : "decoded"});
    }
    bool
    key(App&, int k) override
    {
        int n = int(cur().size());
        switch (k)
        {
            case kUp: --top; break;
            case kDown: ++top; break;
            case kPgUp: top -= lastH - 1; break;
            case kPgDn: top += lastH - 1; break;
            case kHome: top = 0, left = 0; break;
            case kEnd: top = n; break;
            case kRight: left += 16; break;
            case kLeft:
                if (left == 0)
                    return false;
                left = std::max(0, left - 16);
                break;
            case 'x':
                if (alt.empty())
                    return false;
                showAlt = !showAlt;
                top = 0;
                break;
            default: return false;
        }
        top = std::clamp(top, 0, std::max(0, n - 1));
        return true;
    }
    std::vector<std::string>
    menu() const override
    {
        if (!alt.empty())
            return {"X toggle hex/decoded"};
        return {};
    }
    std::string
    hints() const override
    {
        return "↑↓ PgUp PgDn scroll   ←→ pan   Esc back   F1 help";
    }
};

std::vector<std::string>
jsonLines(Json const& j)
{
    return TextView::split(j.dump(2));
}

std::vector<std::string>
hexLines(ByteView v)
{
    std::vector<std::string> r;
    for (std::size_t o = 0; o < v.size(); o += 32)
    {
        char b[32];
        std::snprintf(b, sizeof b, "%06zx  ", o);
        r.push_back(b + toHex(v.data() + o, std::min<std::size_t>(32, v.size() - o)));
    }
    return r;
}

// ---------------------------------------------------------------- ledger view

LedgerData
readLedgerLite(CatFile const& f, u32 seq, CatIndex const* idx, std::size_t maxState, u64& stateTotal)
{
    CatReader r(f.path);
    LedgerData d;
    if (idx && idx->at(seq))
        r.seekStream(idx->at(seq)->offset, &idx->cps);
    for (;;)
    {
        if (!r.nextLedger(d.hdr))
            fail("ledger " + std::to_string(seq) + " not found");
        if (d.hdr.seq == seq)
            break;
        r.skipSection();
        r.skipSection();
    }
    Item it;
    stateTotal = 0;
    while (r.nextItem(it, d.state.size() >= maxState))
    {
        ++stateTotal;
        if (d.state.size() < maxState)
        {
            d.state.push_back(std::move(it));
            it = Item{};
        }
    }
    while (r.nextItem(it))
    {
        d.txs.push_back(std::move(it));
        it = Item{};
    }
    return d;
}

struct LedgerView : View
{
    CatFile file;
    u32 seq;
    std::shared_ptr<LedgerData> data;
    u64 stateTotal = 0;
    std::vector<TxSummary> txs;
    std::vector<std::string> leTypes;
    ListNav nav;
    int lastH = 10;

    LedgerView(App& app, CatFile f, u32 s) : file(std::move(f)), seq(s)
    {
        auto idx = app.indexFor(file);
        data = std::make_shared<LedgerData>(readLedgerLite(file, seq, idx.get(), 50000, stateTotal));
        for (auto const& t : data->txs)
            txs.push_back(txSummary(t.data));
        for (auto const& st : data->state)
            leTypes.push_back(st.type == tnREMOVE ? "" : leTypeOf(st.data));
    }
    int
    rows() const
    {
        return 2 + int(data->txs.size()) + int(data->state.size()) + (stateTotal > data->state.size() ? 1 : 0);
    }
    // row 0: "Transactions" header, 1..T tx rows, T+1 "State" header, then state rows
    std::string
    title() const override
    {
        return "Ledger " + std::to_string(seq);
    }
    void
    draw(App&, Screen& s, int x, int y, int w, int h) override
    {
        lastH = h;
        nav.clamp(rows(), h);
        int T = int(data->txs.size());
        bool base = seq == file.hdr.minLedger;
        for (int i = 0; i < h; ++i)
        {
            int r = nav.top + i;
            if (r >= rows())
                break;
            bool sel = r == nav.sel;
            u8 fg = BWHT, bg = sel ? CYN : BLU;
            std::string line;
            if (r == 0)
            {
                line = " Transactions (" + std::to_string(T) + ")";
                fg = LYEL;
            }
            else if (r <= T)
            {
                auto const& t = txs[std::size_t(r - 1)];
                line = "  " + data->txs[std::size_t(r - 1)].key.hex().substr(0, 16) + "…  " + padRight(t.type, 22) + " " +
                    padRight(t.account, 35) + " " + t.result;
                if (!sel && t.result.rfind("tes", 0) != 0)
                    fg = LYEL;
            }
            else if (r == T + 1)
            {
                line = std::string(base ? " State: full dump (first ledger of file) — " : " State changes — ") +
                    withCommas(stateTotal) + " items";
                fg = LYEL;
            }
            else if (r - T - 2 < int(data->state.size()))
            {
                auto const& st = data->state[std::size_t(r - T - 2)];
                line = std::string(st.type == tnREMOVE ? "  DEL  " : "  SET  ") + st.key.hex().substr(0, 24) + "…  " +
                    leTypes[std::size_t(r - T - 2)];
                if (!sel && st.type == tnREMOVE)
                    fg = LRED;
            }
            else
            {
                line = "  … " + withCommas(stateTotal - data->state.size()) + " more (use L to look up a specific key)";
                fg = WHT;
            }
            if (sel)
                fg = BLK;
            s.fill(x, y + i, w, 1, fg, bg);
            s.text(x, y + i, line, fg, bg, w);
        }
    }
    void
    info(App&, KV& kv) override
    {
        auto const& H = data->hdr;
        kv.push_back({"LEDGER", std::to_string(H.seq)});
        auto chunks = [&](std::string const& label, H256 const& h) {
            std::string x = h.hex();
            for (std::size_t o = 0; o < 64; o += 22)
                kv.push_back({o ? " " : label, x.substr(o, 22)});
        };
        chunks("Hash", H.hash);
        kv.push_back({"Recomputed", H.computeHash() == H.hash ? "✓ matches" : "✗ DIFFERS"});
        chunks("Parent", H.parentHash);
        kv.push_back({"Closed", rippleTimeToString(H.closeTime)});
        kv.push_back({"Resolution", std::to_string(H.closeTimeResolution) + "s flags " + std::to_string(H.closeFlags)});
        kv.push_back({"Coins", withCommas(H.drops / 1000000) + " XAH"});
        kv.push_back({"Txs", withCommas(data->txs.size())});
        kv.push_back({"State Δ", withCommas(stateTotal)});
        kv.push_back({"File", file.name()});
    }
    bool
    key(App& app, int k) override
    {
        if (nav.key(k, rows(), lastH))
            return true;
        int T = int(data->txs.size());
        int r = nav.sel;
        if (k == kEnter || k == kRight)
        {
            if (r >= 1 && r <= T)
            {
                auto const& it = data->txs[std::size_t(r - 1)];
                ByteView tx, meta;
                Json j = Json::object();
                j.set("hash", it.key.hex());
                j.set("ledger_index", seq);
                if (splitTxLeaf(it.data, tx, meta))
                {
                    DecodeOpts o;
                    o.maxHex = 512;
                    j.set("tx", stDecode(tx, o));
                    j.set("meta", stDecode(meta, o));
                }
                app.push(std::make_unique<TextView>("Tx " + it.key.hex().substr(0, 12) + "…", jsonLines(j), hexLines(it.data)));
            }
            else if (r >= T + 2 && r - T - 2 < int(data->state.size()))
            {
                auto const& it = data->state[std::size_t(r - T - 2)];
                std::vector<std::string> lines;
                if (it.type == tnREMOVE)
                    lines = {"index " + it.key.hex(), "", "DELETED in ledger " + std::to_string(seq),
                             "", "press H on the list to see this key's history in this file"};
                else
                {
                    DecodeOpts o;
                    o.maxHex = 512;
                    Json j = Json::object();
                    j.set("index", it.key.hex());
                    j.set("node", stDecode(it.data, o));
                    lines = jsonLines(j);
                }
                app.push(std::make_unique<TextView>("Object " + it.key.hex().substr(0, 12) + "…", lines, hexLines(it.data)));
            }
            return true;
        }
        if (k == 'h' && r >= T + 2 && r - T - 2 < int(data->state.size()))
        {
            H256 key = data->state[std::size_t(r - T - 2)].key;
            CatFile f = file;
            u32 s = seq;
            app.startJob("history", [f, s, key](Job& j) {
                auto p = j.progress();
                auto res = lookupKeys(f, s, {key}, true, &p);
                auto const& kl = res[key];
                j.log("history of " + key.hex() + " in " + f.name() + " up to ledger " + std::to_string(s));
                j.log("");
                for (auto const& e : kl.history)
                {
                    if (e.removed)
                        j.log(std::to_string(e.seq) + "  DELETED");
                    else
                        j.log(std::to_string(e.seq) + (e.seq == f.hdr.minLedger ? " (file base)  " : "  ") + stDecode(e.data).dump());
                }
            }, [](App& a, Job& j) { a.push(std::make_unique<TextView>("History", j.out)); });
            return true;
        }
        return false;
    }
    std::vector<std::string>
    menu() const override
    {
        return {"History of key"};
    }
};

// ---------------------------------------------------------------- ledger list

struct LedgerListView : View
{
    CatFile file;
    std::shared_ptr<CatIndex> idx;
    ListNav nav;
    int lastH = 10;
    bool requested = false;

    LedgerListView(App& app, CatFile f) : file(std::move(f))
    {
        idx = app.indexFor(file);
        if (!idx)
            requestIndex(app);
    }
    void
    requestIndex(App& app)
    {
        if (requested || app.job)
            return;
        requested = true;
        CatFile f = file;
        app.startJob("index " + f.name(), [f](Job& j) {
            auto p = j.progress();
            auto x = CatIndex::build(f.path, [&](u64 d, u64 t) { p("index", d, t, f.name()); }, &j.cancel);
            x.save(f.path);
        }, [f](App& a, Job& j) {
            if (!j.ok)
            {
                a.status = "indexing failed: " + j.error;
                return;
            }
            a.indexes.erase(f.path);
            a.indexFor(f);
            a.status = "index built for " + f.name();
        });
    }
    std::string
    title() const override
    {
        return file.name();
    }
    void
    draw(App& app, Screen& s, int x, int y, int w, int h) override
    {
        lastH = h - 1;
        if (!idx)
        {
            idx = app.indexFor(file);
            if (!idx)
            {
                if (!app.job)
                    requestIndex(app);
                s.text(x + 1, y + 1, "Building the ledger index (one sequential pass; cached afterwards)…", LYEL, BLU, w - 2);
                s.text(x + 1, y + 3, "Progress is shown in the info pane.  ^C cancels.", WHT, BLU, w - 2);
                return;
            }
        }
        s.text(x, y, padRight(" Ledger      Close time (UTC)       Txs   State Δ", std::size_t(w)), LCYN, BLU, w);
        int n = int(idx->ledgers.size());
        nav.clamp(n, lastH);
        for (int i = 0; i < lastH && nav.top + i < n; ++i)
        {
            int r = nav.top + i;
            auto const& e = idx->ledgers[std::size_t(r)];
            u32 seq = idx->firstSeq + u32(r);
            char buf[256];
            std::snprintf(buf, sizeof buf, " %-10u  %s  %6u  %8u%s", seq, rippleTimeToString(e.closeTime).c_str(), e.txItems,
                          e.stateItems, r == 0 ? "   (full state)" : (seq % 256 == 0 ? "   flag" : ""));
            bool sel = r == nav.sel;
            s.fill(x, y + 1 + i, w, 1, sel ? BLK : BWHT, sel ? CYN : BLU);
            s.text(x, y + 1 + i, buf, sel ? BLK : (seq % 256 == 0 ? LCYN : BWHT), sel ? CYN : BLU, w);
        }
    }
    void
    info(App& app, KV& kv) override
    {
        kv.push_back({"FILE", file.name()});
        kv.push_back({"Ledgers", withCommas(file.hdr.ledgerCount())});
        kv.push_back({"Size", humanBytes(file.size)});
        if (idx && !idx->ledgers.empty())
        {
            u32 seq = idx->firstSeq + u32(nav.sel);
            kv.push_back({"Selected", std::to_string(seq)});
            kv.push_back({"Indexed", idx->complete ? "complete" : "partial"});
            kv.push_back({"From", rippleTimeToString(idx->first.closeTime)});
            kv.push_back({"To", rippleTimeToString(idx->last.closeTime)});
        }
        if (auto it = app.verified.find(file.path); it != app.verified.end())
            kv.push_back({"Verified", it->second.ok ? "✓ OK" : "✗ FAILED"});
    }
    bool
    key(App& app, int k) override
    {
        if (!idx)
            return false;
        int n = int(idx->ledgers.size());
        if (nav.key(k, n, lastH))
            return true;
        if (k == kEnter || k == kRight)
        {
            if (n == 0)
                return true;
            app.push(std::make_unique<LedgerView>(app, file, idx->firstSeq + u32(nav.sel)));
            return true;
        }
        if (k == 'g')
        {
            app.ask("Go to ledger in " + file.name() + ":", "", [this](App& a, std::string v) {
                u32 s;
                if (!parseU32(v, s) || !idx || !idx->at(s))
                {
                    a.status = "ledger not in this file";
                    return;
                }
                nav.sel = int(s - idx->firstSeq);
            });
            return true;
        }
        return false;
    }
    std::vector<std::string>
    menu() const override
    {
        return {"Goto ledger"};
    }
};

// ---------------------------------------------------------------- fetch view

struct FetchState
{
    std::mutex mx;
    std::vector<RemoteCat> cats;
    bool loaded = false;
    std::string error;
};

struct FetchView : View
{
    std::shared_ptr<FetchState> st = std::make_shared<FetchState>();
    ListNav nav;
    int lastH = 10;
    std::set<std::string> tag;
    std::string url = kCanonicalUrl;

    explicit FetchView(App& app)
    {
        load(app);
    }
    void
    load(App& app)
    {
        auto s = st;
        std::string u = url;
        app.startJob("list " + u, [s, u](Job& j) {
            auto p = j.progress();
            auto cats = listRemote(u);
            probeRemote(cats, &p);
            std::lock_guard g(s->mx);
            s->cats = std::move(cats);
            s->loaded = true;
        }, [s](App& a, Job& j) {
            if (!j.ok)
            {
                std::lock_guard g(s->mx);
                s->error = j.error;
                a.status = "listing failed: " + j.error;
            }
            else
                a.status = "listing loaded";
        });
    }
    std::string
    title() const override
    {
        return "Fetch canonical set";
    }
    void
    draw(App& app, Screen& s, int x, int y, int w, int h) override
    {
        lastH = h - 4;
        std::lock_guard g(st->mx);
        s.text(x + 1, y, "Source: " + url + "   destination: " + app.dest, LCYN, BLU, w - 2);
        if (!st->loaded)
        {
            s.text(x + 1, y + 2, st->error.empty() ? "Reading the listing and each file's 88-byte header…" : "Error: " + st->error,
                   st->error.empty() ? LYEL : LRED, BLU, w - 2);
            return;
        }
        s.text(x, y + 2, padRight("   File                      Ledgers                 Size      Upstream  Local", std::size_t(w)), LCYN, BLU, w);
        int n = int(st->cats.size());
        nav.clamp(n, lastH);
        for (int i = 0; i < lastH && nav.top + i < n; ++i)
        {
            auto const& c = st->cats[std::size_t(nav.top + i)];
            u64 have = 0;
            auto ls = localState(c, app.dest, &have);
            std::string loc = ls == LocalState::Complete ? "present" : ls == LocalState::Partial ? "partial " + humanBytes(have)
                : ls == LocalState::Different ? "DIFFERENT" : "-";
            char buf[200];
            std::snprintf(buf, sizeof buf, " %s %-24s %10u-%-10u %10s  %-9s %s", tag.count(c.name) ? "*" : " ", c.name.c_str(),
                          c.minLedger, c.maxLedger, c.hdr && c.hdr->fileSize ? humanBytes(c.hdr->fileSize).c_str() : c.listedSize.c_str(),
                          !c.hdr ? "?" : c.finished() ? "complete" : "WRITING", loc.c_str());
            bool sel = nav.top + i == nav.sel;
            u8 fg = sel ? BLK : ls == LocalState::Complete ? LGRN : (c.finished() ? BWHT : LYEL);
            s.fill(x, y + 3 + i, w, 1, fg, sel ? CYN : BLU);
            s.text(x, y + 3 + i, buf, fg, sel ? CYN : BLU, w);
        }
    }
    void
    info(App& app, KV& kv) override
    {
        std::lock_guard g(st->mx);
        u64 total = 0, missing = 0;
        for (auto const& c : st->cats)
        {
            u64 sz = c.hdr ? c.hdr->fileSize : 0;
            total += sz;
            u64 have = 0;
            if (localState(c, app.dest, &have) != LocalState::Complete && c.finished())
                missing += sz > have ? sz - have : 0;
        }
        struct statvfs vf;
        u64 freeB = ::statvfs(app.dest.c_str(), &vf) == 0 ? u64(vf.f_bavail) * vf.f_frsize : 0;
        kv.push_back({"FETCH", ""});
        kv.push_back({"Files", std::to_string(st->cats.size())});
        kv.push_back({"Upstream", humanBytes(total)});
        kv.push_back({"Still need", humanBytes(missing)});
        kv.push_back({"Free here", humanBytes(freeB)});
        kv.push_back({"Tagged", std::to_string(tag.size())});
        kv.push_back({"TLS", tlsSupported() ? "yes" : "NO (rebuild)"});
    }
    bool
    key(App& app, int k) override
    {
        std::vector<RemoteCat> sel;
        {
            std::lock_guard g(st->mx);
            if (nav.key(k, int(st->cats.size()), lastH))
                return true;
            if (k == ' ' && !st->cats.empty())
            {
                auto const& n = st->cats[std::size_t(nav.sel)].name;
                if (!tag.erase(n))
                    tag.insert(n);
                nav.sel = std::min(nav.sel + 1, int(st->cats.size()) - 1);
                return true;
            }
            if (k == 'a')
            {
                for (auto const& c : st->cats)
                    if (c.finished())
                        tag.insert(c.name);
                return true;
            }
            if (k == 'p')
            {
                std::vector<std::string> l = {"# resumable curl commands for the canonical set", "mkdir -p '" + app.dest + "'"};
                for (auto const& c : st->cats)
                    if (tag.empty() ? c.finished() : tag.count(c.name) != 0)
                        l.push_back("curl -fL -C - -o '" + app.dest + "/" + c.name + "' '" + c.url + "'");
                app.push(std::make_unique<TextView>("curl commands", l));
                return true;
            }
            if (k == 'd' || k == kEnter)
            {
                for (auto const& c : st->cats)
                    if (tag.count(c.name))
                        sel.push_back(c);
                if (sel.empty() && !st->cats.empty())
                    sel.push_back(st->cats[std::size_t(nav.sel)]);
            }
        }
        if (k == 'o')
        {
            app.ask("Download destination directory:", app.dest, [](App& a, std::string v) {
                if (!v.empty())
                    a.dest = v;
            });
            return true;
        }
        if (!sel.empty())
        {
            std::string dir = app.dest;
            app.startJob("download", [sel, dir](Job& j) {
                for (auto const& c : sel)
                {
                    auto p = j.progress();
                    auto r = downloadCat(c, dir, false, &p);
                    j.log(std::string(r.ok ? "ok    " : "FAIL  ") + r.msg);
                }
            }, [](App& a, Job& j) {
                if (!j.ok)
                    j.out.push_back("error: " + j.error);
                if (std::find(a.roots.begin(), a.roots.end(), a.dest) == a.roots.end())
                    a.roots.push_back(a.dest);
                a.rescan();
                j.out.push_back("");
                j.out.push_back("Next: Esc back to the tree, tag files and press V to verify (A anchors to the network).");
                a.push(std::make_unique<TextView>("Download results", j.out));
            });
            return true;
        }
        return false;
    }
    std::vector<std::string>
    menu() const override
    {
        return {"Download", "All complete", "Output dir", "Print curl cmds"};
    }
    std::string
    hints() const override
    {
        return "Space tag   ◄─┘ download   Esc back   F1 help   ^C cancel";
    }
};

// ---------------------------------------------------------------- set view

struct SetRow
{
    int kind;  // 0 dir, 1 file, 2 gap/overlap note
    std::string text;
    int file = -1;
    bool last = false;
};

struct SetView : View
{
    ListNav nav;
    int lastH = 10;
    std::vector<SetRow> rows;

    void
    build(App& app)
    {
        rows.clear();
        std::string lastDir = "\x01";
        auto const& F = app.files;
        for (std::size_t i = 0; i < F.size(); ++i)
        {
            std::string dir = F[i].path.substr(0, F[i].path.find_last_of('/') + 1);
            if (dir.empty())
                dir = "./";
            if (dir != lastDir)
            {
                rows.push_back({0, dir});
                lastDir = dir;
            }
            rows.push_back({1, F[i].name(), int(i)});
            if (i + 1 < F.size())
            {
                u32 a = F[i].hdr.maxLedger, b = F[i + 1].hdr.minLedger;
                if (b > a + 1)
                    rows.push_back({2, "gap: ledgers " + std::to_string(a + 1) + "–" + std::to_string(b - 1) + " missing"});
                else if (b <= a)
                    rows.push_back({2, "overlap: " + std::to_string(b) + "–" + std::to_string(std::min(a, F[i + 1].hdr.maxLedger))});
            }
        }
        for (std::size_t i = 0; i < rows.size(); ++i)
            if (rows[i].kind == 1)
            {
                bool more = false;
                for (std::size_t j = i + 1; j < rows.size() && rows[j].kind != 0; ++j)
                    more |= rows[j].kind == 1;
                rows[i].last = !more;
            }
    }
    CatFile const*
    selected(App& app) const
    {
        if (nav.sel < 0 || nav.sel >= int(rows.size()) || rows[std::size_t(nav.sel)].kind != 1)
            return nullptr;
        return &app.files[std::size_t(rows[std::size_t(nav.sel)].file)];
    }
    std::vector<CatFile>
    targets(App& app) const
    {
        std::vector<CatFile> r;
        for (auto const& f : app.files)
            if (app.tagged.count(f.path))
                r.push_back(f);
        if (r.empty())
            if (auto f = selected(app))
                r.push_back(*f);
        return r;
    }
    std::string
    title() const override
    {
        return "Catalogue tree";
    }
    void
    draw(App& app, Screen& s, int x, int y, int w, int h) override
    {
        build(app);
        lastH = h;
        nav.clamp(int(rows.size()), h);
        if (rows.empty())
        {
            s.text(x + 1, y + 1, "No catalogue files under: " + (app.roots.empty() ? std::string(".") : app.roots[0]), LYEL, BLU, w - 2);
            s.text(x + 1, y + 3, "Press F to download the canonical set from " + std::string(kCanonicalUrl), BWHT, BLU, w - 2);
            s.text(x + 1, y + 4, "(it is the reference history of Xahau; files are large, pick the ranges you need).", WHT, BLU, w - 2);
            return;
        }
        for (int i = 0; i < h && nav.top + i < int(rows.size()); ++i)
        {
            auto const& r = rows[std::size_t(nav.top + i)];
            bool sel = nav.top + i == nav.sel;
            u8 bg = sel ? CYN : BLU;
            s.fill(x, y + i, w, 1, BWHT, bg);
            if (r.kind == 0)
            {
                s.text(x, y + i, " " + r.text, sel ? BLK : LYEL, bg, w);
                continue;
            }
            if (r.kind == 2)
            {
                s.text(x, y + i, " │     ⚠ " + r.text, sel ? BLK : LRED, bg, w);
                continue;
            }
            auto const& f = app.files[std::size_t(r.file)];
            std::string glyph = r.last ? " └──" : " ├──";
            bool tg = app.tagged.count(f.path);
            int c = s.text(x, y + i, glyph, sel ? BLK : LCYN, bg);
            c += s.text(x + c, y + i, tg ? "*" : " ", sel ? BLK : LYEL, bg);
            c += s.text(x + c, y + i, padRight(f.name(), 24), sel ? BLK : BWHT, bg);
            char buf[96];
            std::snprintf(buf, sizeof buf, " %10u–%-10u %10s ", f.hdr.minLedger, f.hdr.maxLedger, humanBytes(f.size).c_str());
            c += s.text(x + c, y + i, buf, sel ? BLK : WHT, bg);
            std::string mark;
            u8 mc = WHT;
            if (auto it = app.verified.find(f.path); it != app.verified.end())
            {
                mark = it->second.ok ? "✓ verified" : "✗ FAILED";
                mc = it->second.ok ? LGRN : LRED;
            }
            else if (!f.finished())
            {
                mark = "~ being written";
                mc = LYEL;
            }
            else
                mark = app.indexes.count(f.path) ? "≡ indexed" : "·";
            s.text(x + c, y + i, mark, sel ? u8(BLK) : mc, bg, w - c);
        }
    }
    void
    info(App& app, KV& kv) override
    {
        u64 total = 0;
        u32 lo = 0, hi = 0;
        for (auto const& f : app.files)
        {
            total += f.size;
            lo = lo ? std::min(lo, f.hdr.minLedger) : f.hdr.minLedger;
            hi = std::max(hi, f.hdr.maxLedger);
        }
        kv.push_back({"SET", ""});
        kv.push_back({"Files", std::to_string(app.files.size())});
        kv.push_back({"Bytes", humanBytes(total)});
        if (hi)
            kv.push_back({"Ledgers", std::to_string(lo) + "–" + std::to_string(hi)});
        kv.push_back({"Tagged", std::to_string(app.tagged.size())});
        if (auto f = selected(app))
        {
            kv.push_back({"", ""});
            kv.push_back({"FILE", f->name()});
            kv.push_back({"Ledgers", withCommas(f->hdr.ledgerCount())});
            kv.push_back({"Network", std::to_string(f->hdr.networkId)});
            kv.push_back({"Compress", f->hdr.compressionLevel() ? "zlib " + std::to_string(f->hdr.compressionLevel()) : "none"});
            kv.push_back({"Header", f->finished() ? (f->hdr.fileSize == f->size ? "complete" : "SIZE MISMATCH") : "unfinished"});
            kv.push_back({"SHA-512", f->hdr.hashIsZero() ? "unset" : toHex(f->hdr.hash.data(), 6) + "…"});
            if (auto it = app.verified.find(f->path); it != app.verified.end())
            {
                auto const& v = it->second;
                kv.push_back({"Verified", v.ok ? "✓ OK" : "✗ " + std::to_string(v.errors.size()) + " errors"});
                if (v.recomputed)
                    kv.push_back({"Objects", withCommas(v.stateEntries)});
            }
        }
    }
    bool
    key(App& app, int k) override
    {
        if (nav.key(k, int(rows.size()), lastH))
            return true;
        auto const* f = selected(app);
        switch (k)
        {
            case kEnter:
            case kRight:
                if (f)
                    app.push(std::make_unique<LedgerListView>(app, *f));
                return true;
            case ' ':
                if (f && !app.tagged.erase(f->path))
                    app.tagged.insert(f->path);
                nav.sel = std::min(nav.sel + 1, int(rows.size()) - 1);
                return true;
            case 'r':
                app.rescan();
                app.status = "rescanned: " + std::to_string(app.files.size()) + " files";
                return true;
            case 'f': app.push(std::make_unique<FetchView>(app)); return true;
            case 'v': verify(app, false); return true;
            case 'a': verify(app, true); return true;
            case 'i': {
                auto t = targets(app);
                app.startJob("index", [t](Job& j) {
                    for (auto const& f : t)
                    {
                        auto p = j.progress();
                        auto x = CatIndex::build(f.path, [&](u64 d, u64 tt) { p("index", d, tt, f.name()); }, &j.cancel);
                        x.save(f.path);
                        j.log(f.name() + ": " + std::to_string(x.ledgers.size()) + " ledgers indexed" + (x.error.empty() ? "" : " (" + x.error + ")"));
                    }
                }, [t](App& a, Job& j) {
                    for (auto const& f : t)
                        a.indexes.erase(f.path), a.indexFor(f);
                    a.status = j.ok ? "indexing done" : "indexing failed: " + j.error;
                });
                return true;
            }
            case 'm': merge(app); return true;
            case 's': split(app); return true;
            default: return false;
        }
    }
    void
    verify(App& app, bool anchorOnly)
    {
        auto t = targets(app);
        if (t.empty())
            return;
        if (app.tagged.empty() && t.size() == 1 && app.files.size() > 1 && anchorOnly)
            t = app.files;
        app.startJob(anchorOnly ? "anchor" : "verify", [t, anchorOnly](Job& j) {
            std::vector<VerifyResult> rs;
            for (auto const& f : t)
            {
                auto p = j.progress();
                VerifyResult r;
                if (anchorOnly)
                {
                    auto idx = CatIndex::get(f.path, [&](u64 d, u64 tt) { p("index", d, tt, f.name()); }, &j.cancel);
                    r = summaryFromIndex(f, idx);
                }
                else
                    r = verifyFile(f, VerifyOptions{}, &p);
                std::string line = padRight(f.name(), 26) + (r.ok ? " OK   " : " FAIL ") + "ledgers " + std::to_string(r.firstSeq) + "-" +
                    std::to_string(r.lastSeq);
                if (!anchorOnly)
                    line += "  sha512 " + std::string(r.fileHash == 1 ? "ok" : r.fileHash == 0 ? "MISMATCH" : "unset") + "  " +
                        durationString(r.seconds);
                j.log(line);
                for (auto const& w : r.warnings)
                    j.log("    warning: " + w);
                for (auto const& e : r.errors)
                    j.log("    error: " + e);
                rs.push_back(std::move(r));
            }
            if (rs.size() > 1)
            {
                auto issues = checkChain(rs);
                bool ok = std::none_of(issues.begin(), issues.end(), [](auto const& i) { return i.fatal; });
                j.log("");
                j.log(std::string("chain: ") + (ok ? "LINKED" : "BROKEN"));
                for (auto const& i : issues)
                    j.log(std::string(i.fatal ? "  error: " : "  note: ") + i.msg);
            }
            if (anchorOnly)
            {
                std::map<u32, H256> flags;
                std::optional<std::pair<u32, H256>> last;
                u16 net = 0;
                for (auto const& r : rs)
                {
                    net = r.hdr.networkId;
                    for (auto const& f : r.flagHashes)
                        flags.emplace(f.first, f.second);
                    if (r.ledgers && (!last || r.lastSeq > last->first))
                        last = {r.lastSeq, r.lastHash};
                }
                AnchorOptions ao;
                ao.servers = {"wss://xahau.network"};
                auto p = j.progress();
                auto rep = remoteAnchor({flags.begin(), flags.end()}, last, net, ao, &p);
                j.log("");
                for (auto const& l : rep.lines)
                    j.log(l);
                j.log(std::string("remote: ") + (rep.ok ? "ANCHORED" : "NOT ANCHORED") + "  (" + std::to_string(rep.matched) + " match, " +
                      std::to_string(rep.mismatched) + " differ, " + std::to_string(rep.uncovered) + " not covered)");
                j.log("(anchoring uses the header hashes stored in the files; V recomputes them from the data)");
            }
            j.results = std::move(rs);
        }, [anchorOnly](App& a, Job& j) {
            std::vector<std::string> lines;
            for (auto const& l : j.out)
                if (l.empty() || l[0] != '\x01')
                    lines.push_back(l);
            if (!j.ok)
                lines.push_back("error: " + j.error);
            else if (!anchorOnly)
                for (auto const& r : j.results)
                    a.verified[r.path] = r;
            a.push(std::make_unique<TextView>(anchorOnly ? "Anchor report" : "Verify report", lines));
        });
    }
    void
    merge(App& app)
    {
        std::vector<CatFile> t;
        for (auto const& f : app.files)
            if (app.tagged.count(f.path))
                t.push_back(f);
        if (t.size() < 2)
        {
            app.status = "tag two or more contiguous files with Space, then press M";
            return;
        }
        u32 lo = t.front().hdr.minLedger, hi = 0;
        for (auto const& f : t)
            hi = std::max(hi, f.hdr.maxLedger);
        char nm[64];
        std::snprintf(nm, sizeof nm, "cat.%08u-%08u", lo, hi);
        std::string dir = t.front().path.substr(0, t.front().path.find_last_of('/') + 1);
        app.ask("Merge " + std::to_string(t.size()) + " files into:", dir + nm, [t, lo, hi](App& a, std::string out) {
            a.startJob("merge", [t, lo, hi, out](Job& j) {
                auto p = j.progress();
                repack(t, {{lo, hi, out}}, RepackOptions{}, &p, [&](std::string const& m) { j.log(m); });
            }, [](App& a2, Job& j) {
                if (!j.ok)
                    j.out.push_back("error: " + j.error);
                a2.rescan();
                a2.push(std::make_unique<TextView>("Merge", j.out));
            });
        });
    }
    void
    split(App& app)
    {
        auto t = targets(app);
        if (t.empty())
            return;
        app.ask("Split every N ledgers (aligned like the canonical set):", "100000", [t](App& a, std::string nstr) {
            u32 n;
            if (!parseU32(nstr, n) || n == 0)
            {
                a.status = "not a number";
                return;
            }
            std::string dir = t.front().path.substr(0, t.front().path.find_last_of('/') + 1) + "split";
            a.ask("Output directory:", dir, [t, n](App& a2, std::string out) {
                ::mkdir(out.c_str(), 0755);
                u32 lo = t.front().hdr.minLedger, hi = 0;
                for (auto const& f : t)
                    hi = std::max(hi, f.hdr.maxLedger);
                std::vector<RepackRange> rr;
                for (u32 s = lo; s <= hi;)
                {
                    u64 e = std::min<u64>((u64(s - 1) / n + 1) * n, hi);
                    char nm[64];
                    std::snprintf(nm, sizeof nm, "/cat.%08u-%08u", s, u32(e));
                    rr.push_back({s, u32(e), out + nm});
                    if (e == hi)
                        break;
                    s = u32(e + 1);
                }
                a2.startJob("split", [t, rr](Job& j) {
                    auto p = j.progress();
                    repack(t, rr, RepackOptions{}, &p, [&](std::string const& m) { j.log(m); });
                }, [out](App& a3, Job& j) {
                    if (!j.ok)
                        j.out.push_back("error: " + j.error);
                    if (std::find(a3.roots.begin(), a3.roots.end(), out) == a3.roots.end())
                        a3.roots.push_back(out);
                    a3.rescan();
                    a3.push(std::make_unique<TextView>("Split", j.out));
                });
            });
        });
    }
    std::vector<std::string>
    menu() const override
    {
        return {"Verify", "Anchor", "Index", "Lookup", "Tx", "Goto", "Merge", "Split", "Fetch", "Rescan"};
    }
    std::string
    hints() const override
    {
        return "◄─┘ ledgers   Space tag   F1 help   ^C cancel job   Q quit";
    }
};

// ---------------------------------------------------------------- globals

void
globalLookup(App& app)
{
    if (app.files.empty())
        return;
    u32 hi = 0;
    for (auto const& f : app.files)
        hi = std::max(hi, f.hdr.maxLedger);
    app.ask("Keylet (account:r…, line:r…:r…:USD, hook_state:…, 64-hex …):", "", [hi](App& a, std::string spec) {
        std::string err;
        auto key = parseKeylet(spec, err);
        if (!key)
        {
            a.status = "keylet: " + err;
            return;
        }
        a.ask("As of ledger:", std::to_string(hi), [spec, k = *key](App& a2, std::string ls) {
            u32 seq;
            if (!parseU32(ls, seq))
            {
                a2.status = "bad ledger";
                return;
            }
            auto f = fileFor(a2.files, seq);
            if (!f)
            {
                a2.status = "no file contains ledger " + ls;
                return;
            }
            CatFile cf = *f;
            a2.startJob("lookup", [cf, seq, k, spec](Job& j) {
                auto p = j.progress();
                auto res = lookupKeys(cf, seq, {k}, false, &p);
                auto const& r = res[k];
                j.log(spec);
                j.log("key " + k.hex() + "  as of ledger " + std::to_string(seq) + "  (" + cf.name() + ")");
                if (!r.found)
                {
                    j.log(r.lastModified ? "deleted in ledger " + std::to_string(r.lastModified) : "not present");
                    return;
                }
                j.log(r.lastModified > cf.hdr.minLedger ? "last modified in ledger " + std::to_string(r.lastModified)
                                                         : "unchanged since the file's base ledger");
                j.log("");
                for (auto& l : jsonLines(stDecode(r.data)))
                    j.log(l);
            }, [](App& a3, Job& j) {
                if (!j.ok)
                    j.out.push_back("error: " + j.error);
                a3.push(std::make_unique<TextView>("Lookup", j.out));
            });
        });
    });
}

void
globalTx(App& app)
{
    app.ask("Transaction hash [ledger]:", "", [](App& a, std::string v) {
        auto sp = v.find(' ');
        H256 id;
        if (!H256::parse(v.substr(0, sp), id))
        {
            a.status = "expected 64 hex digits";
            return;
        }
        std::optional<u32> seq;
        if (sp != std::string::npos)
        {
            u32 s;
            if (parseU32(v.substr(sp + 1), s))
                seq = s;
        }
        auto files = a.files;
        a.startJob("tx search", [files, id, seq](Job& j) {
            auto p = j.progress();
            auto hit = findTx(files, id, seq, &p);
            if (!hit)
            {
                j.log("transaction " + id.hex() + " not found");
                return;
            }
            ByteView tx, meta;
            Json o = Json::object();
            o.set("hash", id.hex());
            o.set("ledger_index", hit->seq);
            if (splitTxLeaf(hit->leaf, tx, meta))
            {
                o.set("tx", stDecode(tx));
                o.set("meta", stDecode(meta));
            }
            for (auto& l : jsonLines(o))
                j.log(l);
        }, [](App& a2, Job& j) {
            if (!j.ok)
                j.out.push_back("error: " + j.error);
            a2.push(std::make_unique<TextView>("Transaction", j.out));
        });
    });
}

void
globalGoto(App& app)
{
    app.ask("Go to ledger:", "", [](App& a, std::string v) {
        u32 seq;
        if (!parseU32(v, seq))
            return;
        auto f = fileFor(a.files, seq);
        if (!f)
        {
            a.status = "no file contains ledger " + v;
            return;
        }
        if (!a.indexFor(*f) && f->hdr.compressionLevel() > 0)
            a.status = "tip: index " + f->name() + " (I) for instant random access";
        try
        {
            a.push(std::make_unique<LedgerView>(a, *f, seq));
        }
        catch (Error const& e)
        {
            a.status = e.what();
        }
    });
}

std::vector<std::string>
helpLines()
{
    return {
        "catl — interactive catalogue browser",
        "",
        "Tree (start screen)",
        "  ↑ ↓ PgUp PgDn Home End   move            Space   tag / untag a file",
        "  Enter / →                open the file's ledger list (builds the index once)",
        "  V  verify tagged (or highlighted) files: rebuild SHAMaps, recompute every hash,",
        "     file SHA-512, parent-hash links across files",
        "  A  anchor: compare flag-ledger and end-of-range hashes with wss://xahau.network",
        "  I  build the sidecar index        R  rescan directories",
        "  L  look up a ledger object by keylet as of any ledger",
        "  T  find a transaction (hash, optionally followed by a ledger number)",
        "  G  go to a ledger anywhere in the set",
        "  M  merge tagged contiguous files  S  split tagged/highlighted files every N ledgers",
        "  F  fetch the canonical set from https://cat.xahau.network/",
        "",
        "Ledger list:  Enter opens a ledger, G jumps to a sequence",
        "Ledger view:  Enter decodes a transaction or state object, H shows a key's history",
        "Object view:  ←→ pan, X toggles decoded JSON / raw hex",
        "Fetch view:   Space tag, A tag all complete files, Enter/D download (resumable,",
        "              SHA-512 checked), O output directory, P print curl commands",
        "",
        "Esc / ← back     ^C cancel the running job     Q quit",
        "",
        "Command-line equivalents: catl help",
    };
}

// ---------------------------------------------------------------- app impl

void
App::pollJob()
{
    if (job && job->finished)
    {
        job->th.join();
        std::unique_ptr<Job> j = std::move(job);
        status = j->name + (j->ok ? " finished" : (j->error == "cancelled" ? " cancelled" : " failed: " + j->error));
        if (j->onDone)
            j->onDone(*this, *j);
    }
}

void
App::draw()
{
    int W = scr.w, H = scr.h;
    scr.fill(0, 0, W, H, BWHT, BLU);
    if (W < 70 || H < 16)
    {
        scr.text(1, 1, "catl: terminal too small (need 70x16)", LYEL, BLU);
        return;
    }
    // path line
    std::string path;
    for (std::size_t i = 0; i < stack.size(); ++i)
        path += (i ? " › " : "") + stack[i]->title();
    std::time_t now = std::time(nullptr);
    char tbuf[32];
    std::strftime(tbuf, sizeof tbuf, "%H:%M:%S", std::localtime(&now));
    std::string right = std::string("CATL-TREE  ") + tbuf + " ";
    scr.text(1, 0, "Path: ", LCYN, BLU);
    scr.text(7, 0, fit(path, std::size_t(W - 8 - int(right.size()))), BWHT, BLU);
    scr.text(W - int(right.size()), 0, right, LCYN, BLU);
    // frame
    int R = std::clamp(W / 3, 28, 40);
    int div = W - R - 1;
    int bot = H - 4;
    for (int xx = 0; xx < W; ++xx)
    {
        scr.c[std::size_t(1 * W + xx)] = {U'─', LCYN, BLU};
        scr.c[std::size_t(bot * W + xx)] = {U'─', LCYN, BLU};
    }
    for (int yy = 2; yy < bot; ++yy)
    {
        scr.c[std::size_t(yy * W)] = {U'│', LCYN, BLU};
        scr.c[std::size_t(yy * W + div)] = {U'│', LCYN, BLU};
        scr.c[std::size_t(yy * W + W - 1)] = {U'│', LCYN, BLU};
    }
    scr.c[std::size_t(W)] = {U'┌', LCYN, BLU};
    scr.c[std::size_t(W + div)] = {U'┬', LCYN, BLU};
    scr.c[std::size_t(W + W - 1)] = {U'┐', LCYN, BLU};
    scr.c[std::size_t(bot * W)] = {U'└', LCYN, BLU};
    scr.c[std::size_t(bot * W + div)] = {U'┴', LCYN, BLU};
    scr.c[std::size_t(bot * W + W - 1)] = {U'┘', LCYN, BLU};
    View& v = *stack.back();
    scr.text(2, 1, " " + fit(v.title(), std::size_t(div - 6)) + " ", LYEL, BLU);
    scr.text(div + 2, 1, " Info ", LYEL, BLU);
    try
    {
        v.draw(*this, scr, 1, 2, div - 1, bot - 2);
    }
    catch (std::exception const& e)
    {
        status = e.what();
    }
    // info pane
    KV kv;
    try
    {
        v.info(*this, kv);
    }
    catch (std::exception const&)
    {
    }
    int iy = 2, ix = div + 2, iw = R - 3;
    for (auto const& [k, val] : kv)
    {
        if (iy >= bot - (job ? 7 : 0))
            break;
        if (!k.empty() && val.empty())
            scr.text(ix, iy, fit(k, std::size_t(iw)), LYEL, BLU);
        else
        {
            scr.text(ix, iy, fit(k, 11), LCYN, BLU);
            scr.text(ix + 11, iy, fit(val, std::size_t(iw - 11)), BWHT, BLU);
        }
        ++iy;
    }
    if (job)
    {
        std::string stage, detail;
        u64 d, t;
        {
            std::lock_guard g(job->mx);
            stage = job->stage;
            detail = job->detail;
            d = job->done;
            t = job->total;
        }
        int jy = bot - 6;
        for (int xx = div + 1; xx < W - 1; ++xx)
            scr.c[std::size_t(jy * W + xx)] = {U'─', LCYN, BLU};
        scr.text(ix, jy, " JOB " + fit(job->name, std::size_t(iw - 6)) + " ", LYEL, BLU);
        double pct = t ? double(d) / double(t) : 0;
        int bw = iw - 7;
        std::string bar;
        int filled = int(pct * bw);
        for (int k = 0; k < bw; ++k)
            bar += k < filled ? "█" : "░";
        char pb[16];
        std::snprintf(pb, sizeof pb, " %5.1f%%", pct * 100);
        scr.text(ix, jy + 1, stage.empty() ? "starting…" : stage, BWHT, BLU, iw);
        scr.text(ix, jy + 2, bar, LGRN, BLU);
        scr.text(ix + bw, jy + 2, pb, BWHT, BLU);
        bool bytes = stage == "verify" || stage == "index" || stage == "download" || stage == "repack" || stage == "hash" ||
            stage == "scan" || stage == "search" || stage == "rehash";
        if (t)
            scr.text(ix, jy + 3, bytes ? humanBytes(d) + " / " + humanBytes(t) : std::to_string(d) + " / " + std::to_string(t), WHT, BLU, iw);
        auto du = toU32(detail);
        std::string l1, l2;
        for (std::size_t k = 0; k < du.size(); ++k)
            appendUtf8(int(k) < iw ? l1 : l2, du[k]);
        scr.text(ix, jy + 4, l1, WHT, BLU, iw);
        scr.text(ix, jy + 5, l2, WHT, BLU, iw);
    }
    // menus
    int mx = 1;
    std::string lead = stack.size() == 1 ? "CATL" : "VIEW";
    mx += scr.text(mx, H - 3, lead, LCYN, BLU) + 2;
    for (auto const& m : v.menu())
    {
        if (mx + int(m.size()) + 2 >= W)
            break;
        scr.text(mx, H - 3, m.substr(0, 1), LYEL, BLU);
        mx += 1 + scr.text(mx + 1, H - 3, m.substr(1), BWHT, BLU) + 2;
    }
    scr.text(1, H - 2, "COMMANDS", LCYN, BLU);
    scr.text(11, H - 2, fit(v.hints(), std::size_t(W - 12)), BWHT, BLU);
    // status / prompt
    scr.fill(0, H - 1, W, 1, BLK, CYN);
    if (prompting)
    {
        int c = scr.text(1, H - 1, promptLabel + " ", BLK, CYN);
        std::string shown = promptValue;
        int avail = W - 3 - c;
        auto u = toU32(shown);
        if (int(u.size()) > avail)
        {
            std::string t2;
            for (std::size_t k = u.size() - std::size_t(avail); k < u.size(); ++k)
                appendUtf8(t2, u[k]);
            shown = t2;
        }
        int n = scr.text(1 + c, H - 1, shown, BLK, CYN);
        scr.text(1 + c + n, H - 1, "█", BLK, CYN);
    }
    else
        scr.text(1, H - 1, fit(status, std::size_t(W - 2)), BLK, CYN);
}

int
App::run()
{
    if (!::isatty(0) || !::isatty(1))
    {
        std::fprintf(stderr, "catl tui needs an interactive terminal\n");
        return 2;
    }
    rescan();
    if (!roots.empty())
    {
        struct stat st;
        if (::stat(roots[0].c_str(), &st) == 0 && S_ISDIR(st.st_mode))
            dest = roots[0];
    }
    for (auto const& f : files)
        indexFor(f);
    push(std::make_unique<SetView>());
    std::signal(SIGWINCH, onWinch);
    term.enter();
    scr.resize(term.w, term.h);
    while (!quit)
    {
        if (gResized)
        {
            gResized = 0;
            term.size();
            scr.resize(term.w, term.h);
            term.out("\033[2J");
        }
        pollJob();
        draw();
        scr.flush(term);
        int k = readKey(job ? 150 : 1000);
        if (k == kNone)
            continue;
        try
        {
            if (prompting)
            {
                if (k == kEsc || k == kCtrlC)
                {
                    prompting = false;
                    status = "cancelled";
                }
                else if (k == kEnter)
                {
                    prompting = false;
                    auto cb = std::move(promptCb);
                    std::string v = promptValue;
                    cb(*this, v);
                }
                else if (k == kBs || k == kDel)
                {
                    auto u = toU32(promptValue);
                    if (!u.empty())
                    {
                        u.pop_back();
                        promptValue.clear();
                        for (auto c : u)
                            appendUtf8(promptValue, c);
                    }
                }
                else if (k >= 32 && k < 127)
                    promptValue.push_back(char(k));
                continue;
            }
            if (k == kCtrlC)
            {
                if (job)
                {
                    job->cancel = true;
                    status = "cancelling " + job->name + "…";
                }
                else
                    status = "press Q to quit";
                continue;
            }
            if (k == kF1 || k == '?')
            {
                push(std::make_unique<TextView>("Help", helpLines()));
                continue;
            }
            int lk = (k < 128) ? std::tolower(k) : k;
            if (stack.back()->key(*this, lk))
                continue;
            if (lk == 'q')
                quit = true;
            else if ((k == kEsc || k == kLeft) && stack.size() > 1)
                stack.pop_back();
            else if (lk == 'l')
                globalLookup(*this);
            else if (lk == 't')
                globalTx(*this);
            else if (lk == 'g')
                globalGoto(*this);
            else if (lk == 'f')
                push(std::make_unique<FetchView>(*this));
        }
        catch (std::exception const& e)
        {
            status = std::string("error: ") + e.what();
        }
    }
    if (job)
    {
        job->cancel = true;
        term.leave();
        std::fprintf(stderr, "waiting for %s to stop…\n", job->name.c_str());
        job->th.join();
    }
    term.leave();
    return 0;
}

}  // namespace

int
runTui(std::vector<std::string> const& paths)
{
    App app;
    app.roots = paths;
    try
    {
        return app.run();
    }
    catch (...)
    {
        app.term.leave();
        throw;
    }
}

}  // namespace catl
