// catl — network layer implementation
#include "net.hpp"
#include "sha.hpp"

#include <cerrno>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <random>
#include <sys/socket.h>
#include <unistd.h>

#ifdef CATL_WITH_OPENSSL
#include <openssl/err.h>
#include <openssl/ssl.h>
#endif

namespace catl {

std::optional<Url>
Url::parse(std::string_view s)
{
    Url u;
    auto p = s.find("://");
    if (p == std::string_view::npos)
        return std::nullopt;
    u.scheme = std::string(s.substr(0, p));
    for (auto& c : u.scheme)
        c = char(std::tolower(u8(c)));
    s = s.substr(p + 3);
    auto slash = s.find('/');
    std::string_view hp = s.substr(0, slash);
    u.path = slash == std::string_view::npos ? "/" : std::string(s.substr(slash));
    if (!hp.empty() && hp[0] == '[')
    {
        auto e = hp.find(']');
        if (e == std::string_view::npos)
            return std::nullopt;
        u.host = std::string(hp.substr(1, e - 1));
        if (e + 1 < hp.size() && hp[e + 1] == ':')
            u.port = std::string(hp.substr(e + 2));
    }
    else
    {
        auto c = hp.rfind(':');
        u.host = std::string(hp.substr(0, c));
        if (c != std::string_view::npos)
            u.port = std::string(hp.substr(c + 1));
    }
    if (u.host.empty())
        return std::nullopt;
    if (u.scheme != "http" && u.scheme != "https" && u.scheme != "ws" && u.scheme != "wss")
        return std::nullopt;
    return u;
}

bool
tlsSupported()
{
#ifdef CATL_WITH_OPENSSL
    return true;
#else
    return false;
#endif
}

namespace {

int
tcpConnect(std::string const& host, std::string const& port, int timeoutSec)
{
    addrinfo hints{}, *res = nullptr;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;
    int rc = ::getaddrinfo(host.c_str(), port.c_str(), &hints, &res);
    if (rc != 0)
        fail("cannot resolve " + host + ": " + gai_strerror(rc));
    std::string lastErr = "no addresses";
    int fd = -1;
    for (auto* ai = res; ai; ai = ai->ai_next)
    {
        fd = ::socket(ai->ai_family, ai->ai_socktype | SOCK_CLOEXEC, ai->ai_protocol);
        if (fd < 0)
            continue;
        int fl = ::fcntl(fd, F_GETFL);
        ::fcntl(fd, F_SETFL, fl | O_NONBLOCK);
        int r = ::connect(fd, ai->ai_addr, ai->ai_addrlen);
        if (r != 0 && errno == EINPROGRESS)
        {
            pollfd pf{fd, POLLOUT, 0};
            r = ::poll(&pf, 1, timeoutSec * 1000);
            if (r == 1)
            {
                int e = 0;
                socklen_t l = sizeof e;
                ::getsockopt(fd, SOL_SOCKET, SO_ERROR, &e, &l);
                r = e ? -1 : 0;
                errno = e;
            }
            else
            {
                r = -1;
                errno = ETIMEDOUT;
            }
        }
        if (r == 0)
        {
            ::fcntl(fd, F_SETFL, fl);
            timeval tv{timeoutSec, 0};
            ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
            ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
            int one = 1;
            ::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
            break;
        }
        lastErr = std::strerror(errno);
        ::close(fd);
        fd = -1;
    }
    ::freeaddrinfo(res);
    if (fd < 0)
        fail("cannot connect to " + host + ":" + port + ": " + lastErr);
    return fd;
}

class PlainStream : public NetStream
{
public:
    explicit PlainStream(int fd) : fd_(fd) {}
    ~PlainStream() override { ::close(fd_); }
    std::size_t
    read(u8* p, std::size_t n) override
    {
        for (;;)
        {
            ssize_t r = ::recv(fd_, p, n, 0);
            if (r >= 0)
                return std::size_t(r);
            if (errno == EINTR)
                continue;
            fail(std::string("network read: ") + (errno == EAGAIN ? "timed out" : std::strerror(errno)));
        }
    }
    void
    write(u8 const* p, std::size_t n) override
    {
        while (n)
        {
            ssize_t r = ::send(fd_, p, n, MSG_NOSIGNAL);
            if (r < 0)
            {
                if (errno == EINTR)
                    continue;
                fail(std::string("network write: ") + std::strerror(errno));
            }
            p += r;
            n -= std::size_t(r);
        }
    }

private:
    int fd_;
};

#ifdef CATL_WITH_OPENSSL
class TlsStream : public NetStream
{
public:
    TlsStream(int fd, std::string const& host) : fd_(fd)
    {
        ctx_ = SSL_CTX_new(TLS_client_method());
        if (!ctx_)
            fail("TLS: cannot create context");
        SSL_CTX_set_default_verify_paths(ctx_);
        SSL_CTX_set_verify(ctx_, SSL_VERIFY_PEER, nullptr);
        ssl_ = SSL_new(ctx_);
        SSL_set_fd(ssl_, fd_);
        SSL_set_tlsext_host_name(ssl_, host.c_str());
        SSL_set1_host(ssl_, host.c_str());
        if (SSL_connect(ssl_) != 1)
        {
            unsigned long e = ERR_get_error();
            char buf[256];
            ERR_error_string_n(e, buf, sizeof buf);
            long v = SSL_get_verify_result(ssl_);
            std::string msg = std::string("TLS handshake with ") + host + " failed: " + buf;
            if (v != X509_V_OK)
                msg += std::string(" (") + X509_verify_cert_error_string(v) + ")";
            cleanup();
            fail(msg);
        }
    }
    ~TlsStream() override { cleanup(); }
    std::size_t
    read(u8* p, std::size_t n) override
    {
        int r = SSL_read(ssl_, p, int(std::min<std::size_t>(n, 1 << 30)));
        if (r > 0)
            return std::size_t(r);
        int e = SSL_get_error(ssl_, r);
        if (e == SSL_ERROR_ZERO_RETURN || (e == SSL_ERROR_SYSCALL && errno == 0))
            return 0;
        fail(std::string("TLS read failed") + (errno == EAGAIN ? ": timed out" : ""));
    }
    void
    write(u8 const* p, std::size_t n) override
    {
        while (n)
        {
            int r = SSL_write(ssl_, p, int(std::min<std::size_t>(n, 1 << 30)));
            if (r <= 0)
                fail("TLS write failed");
            p += r;
            n -= std::size_t(r);
        }
    }

private:
    void
    cleanup()
    {
        if (ssl_)
        {
            SSL_shutdown(ssl_);
            SSL_free(ssl_);
            ssl_ = nullptr;
        }
        if (ctx_)
        {
            SSL_CTX_free(ctx_);
            ctx_ = nullptr;
        }
        if (fd_ >= 0)
        {
            ::close(fd_);
            fd_ = -1;
        }
    }
    int fd_;
    SSL_CTX* ctx_ = nullptr;
    SSL* ssl_ = nullptr;
};
#endif

// Reads headers; returns leftover body bytes in `rest`.
int
readHeaders(NetStream& s, std::map<std::string, std::string>& hdrs, Bytes& rest)
{
    std::string buf;
    u8 tmp[16384];
    std::size_t end;
    for (;;)
    {
        end = buf.find("\r\n\r\n");
        if (end != std::string::npos)
            break;
        if (buf.size() > (1 << 20))
            fail("HTTP: header too large");
        std::size_t k = s.read(tmp, sizeof tmp);
        if (!k)
            fail("HTTP: connection closed before headers");
        buf.append(reinterpret_cast<char*>(tmp), k);
    }
    rest.assign(buf.begin() + std::ptrdiff_t(end + 4), buf.end());
    std::string head = buf.substr(0, end);
    std::size_t ls = head.find("\r\n");
    std::string status = head.substr(0, ls);
    auto sp = status.find(' ');
    if (status.rfind("HTTP/", 0) != 0 || sp == std::string::npos)
        fail("HTTP: bad status line: " + status);
    int code = std::atoi(status.c_str() + sp + 1);
    std::size_t pos = ls == std::string::npos ? head.size() : ls + 2;
    while (pos < head.size())
    {
        std::size_t e = head.find("\r\n", pos);
        if (e == std::string::npos)
            e = head.size();
        std::string line = head.substr(pos, e - pos);
        auto c = line.find(':');
        if (c != std::string::npos)
        {
            std::string k = line.substr(0, c), v = line.substr(c + 1);
            for (auto& ch : k)
                ch = char(std::tolower(u8(ch)));
            while (!v.empty() && (v[0] == ' ' || v[0] == '\t'))
                v.erase(0, 1);
            hdrs[k] = v;
        }
        pos = e + 2;
    }
    return code;
}

std::string
defaultPort(Url const& u)
{
    if (!u.port.empty())
        return u.port;
    return u.tls() ? "443" : "80";
}

}  // namespace

std::unique_ptr<NetStream>
connectUrl(Url const& u, int timeoutSec)
{
    int fd = tcpConnect(u.host, defaultPort(u), timeoutSec);
    if (!u.tls())
        return std::make_unique<PlainStream>(fd);
#ifdef CATL_WITH_OPENSSL
    return std::make_unique<TlsStream>(fd, u.host);
#else
    ::close(fd);
    fail(u.scheme + "://" + " needs TLS, but catl was built without OpenSSL (rebuild with TLS=1, or use a plain ws:// / http:// endpoint)");
#endif
}

std::string
base64Encode(u8 const* p, std::size_t n)
{
    static char const* t = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string o;
    for (std::size_t i = 0; i < n; i += 3)
    {
        u32 v = u32(p[i]) << 16 | (i + 1 < n ? u32(p[i + 1]) << 8 : 0) | (i + 2 < n ? p[i + 2] : 0);
        o.push_back(t[v >> 18]);
        o.push_back(t[(v >> 12) & 63]);
        o.push_back(i + 1 < n ? t[(v >> 6) & 63] : '=');
        o.push_back(i + 2 < n ? t[v & 63] : '=');
    }
    return o;
}

HttpResult
httpGet(
    std::string const& url0,
    std::string const& extraHeaders,
    std::function<bool(u8 const*, std::size_t)> const& onBody,
    int timeoutSec)
{
    std::string url = url0;
    for (int redirects = 0; redirects < 6; ++redirects)
    {
        auto u = Url::parse(url);
        if (!u || (u->scheme != "http" && u->scheme != "https"))
            fail("bad URL: " + url);
        auto s = connectUrl(*u, timeoutSec);
        std::string req = "GET " + u->path + " HTTP/1.1\r\nHost: " + u->host +
            (u->port.empty() ? "" : ":" + u->port) +
            "\r\nUser-Agent: catl/1.0\r\nAccept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n" +
            extraHeaders + "\r\n";
        s->write(reinterpret_cast<u8 const*>(req.data()), req.size());
        HttpResult res;
        Bytes rest;
        res.status = readHeaders(*s, res.headers, rest);
        res.finalUrl = url;
        if (res.status >= 300 && res.status < 400 && res.headers.count("location"))
        {
            std::string loc = res.headers["location"];
            if (loc.rfind("http", 0) == 0)
                url = loc;
            else if (!loc.empty() && loc[0] == '/')
                url = u->origin() + loc;
            else
                url = u->origin() + u->path.substr(0, u->path.rfind('/') + 1) + loc;
            continue;
        }
        bool chunked = res.headers.count("transfer-encoding") &&
            res.headers["transfer-encoding"].find("chunked") != std::string::npos;
        std::optional<u64> clen;
        if (res.headers.count("content-length"))
        {
            u64 v;
            if (parseU64(res.headers["content-length"], v))
                clen = v;
        }
        Bytes buf = std::move(rest);
        std::size_t bp = 0;
        u8 tmp[1 << 16];
        auto more = [&]() -> bool {
            if (bp > 0 && bp == buf.size())
            {
                buf.clear();
                bp = 0;
            }
            std::size_t k = s->read(tmp, sizeof tmp);
            if (!k)
                return false;
            buf.insert(buf.end(), tmp, tmp + k);
            return true;
        };
        if (!chunked)
        {
            u64 got = 0;
            for (;;)
            {
                if (bp < buf.size())
                {
                    std::size_t k = buf.size() - bp;
                    if (clen)
                        k = std::size_t(std::min<u64>(k, *clen - got));
                    if (k && !onBody(buf.data() + bp, k))
                        return res;
                    got += k;
                    bp += k;
                }
                if (clen && got >= *clen)
                    break;
                if (!more())
                {
                    if (clen && got < *clen)
                        fail("HTTP: connection closed after " + std::to_string(got) + " of " + std::to_string(*clen) + " bytes");
                    break;
                }
            }
            return res;
        }
        // chunked
        for (;;)
        {
            std::size_t eol;
            while ((eol = std::string_view(reinterpret_cast<char*>(buf.data()) + bp, buf.size() - bp).find("\r\n")) ==
                   std::string_view::npos)
                if (!more())
                    fail("HTTP: truncated chunked body");
            std::string line(reinterpret_cast<char*>(buf.data()) + bp, eol);
            bp += eol + 2;
            u64 n = std::strtoull(line.c_str(), nullptr, 16);
            if (n == 0)
                return res;
            while (n)
            {
                if (bp == buf.size() && !more())
                    fail("HTTP: truncated chunk");
                std::size_t k = std::size_t(std::min<u64>(n, buf.size() - bp));
                if (!onBody(buf.data() + bp, k))
                    return res;
                bp += k;
                n -= k;
            }
            while (buf.size() - bp < 2)
                if (!more())
                    fail("HTTP: truncated chunk trailer");
            bp += 2;
        }
    }
    fail("HTTP: too many redirects");
}

std::string
httpGetText(std::string const& url, int* status)
{
    std::string out;
    auto r = httpGet(url, "", [&](u8 const* p, std::size_t n) {
        out.append(reinterpret_cast<char const*>(p), n);
        return out.size() < (64u << 20);
    });
    if (status)
        *status = r.status;
    return out;
}

// ------------------------------------------------------------ WebSocket

WsClient::WsClient(std::string const& url, int timeoutSec) : url_(url)
{
    auto u = Url::parse(url);
    if (!u || (u->scheme != "ws" && u->scheme != "wss"))
        fail("bad websocket URL: " + url);
    s_ = connectUrl(*u, timeoutSec);
    u8 rnd[16];
    std::random_device rd;
    for (auto& b : rnd)
        b = u8(rd());
    std::string key = base64Encode(rnd, 16);
    std::string req = "GET " + u->path + " HTTP/1.1\r\nHost: " + u->host + (u->port.empty() ? "" : ":" + u->port) +
        "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: " + key +
        "\r\nSec-WebSocket-Version: 13\r\nUser-Agent: catl/1.0\r\n\r\n";
    s_->write(reinterpret_cast<u8 const*>(req.data()), req.size());
    std::map<std::string, std::string> h;
    int st = readHeaders(*s_, h, rbuf_);
    if (st != 101)
        fail("websocket upgrade to " + url + " refused (HTTP " + std::to_string(st) + ")");
    Sha1 sha;
    std::string k2 = key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    sha.update(k2.data(), k2.size());
    auto d = sha.final();
    if (h["sec-websocket-accept"] != base64Encode(d.data(), d.size()))
        fail("websocket: bad Sec-WebSocket-Accept from " + url);
}

void
WsClient::sendFrame(u8 opcode, u8 const* p, std::size_t n)
{
    Bytes f;
    f.push_back(u8(0x80 | opcode));
    if (n < 126)
        f.push_back(u8(0x80 | n));
    else if (n < 65536)
    {
        f.push_back(0x80 | 126);
        f.push_back(u8(n >> 8));
        f.push_back(u8(n));
    }
    else
    {
        f.push_back(0x80 | 127);
        for (int i = 7; i >= 0; --i)
            f.push_back(u8(u64(n) >> (8 * i)));
    }
    static thread_local std::mt19937 rng{std::random_device{}()};
    u8 mask[4];
    for (auto& m : mask)
        m = u8(rng());
    f.insert(f.end(), mask, mask + 4);
    std::size_t off = f.size();
    f.insert(f.end(), p, p + n);
    for (std::size_t i = 0; i < n; ++i)
        f[off + i] ^= mask[i & 3];
    s_->write(f.data(), f.size());
}

void
WsClient::sendText(std::string const& s)
{
    sendFrame(0x1, reinterpret_cast<u8 const*>(s.data()), s.size());
}

void
WsClient::fill(std::size_t n)
{
    while (rbuf_.size() - rpos_ < n)
    {
        if (rpos_ && rpos_ == rbuf_.size())
        {
            rbuf_.clear();
            rpos_ = 0;
        }
        u8 tmp[1 << 16];
        std::size_t k = s_->read(tmp, sizeof tmp);
        if (!k)
            fail("websocket: connection closed by " + url_);
        rbuf_.insert(rbuf_.end(), tmp, tmp + k);
    }
}

std::string
WsClient::readMessage()
{
    std::string msg;
    for (;;)
    {
        fill(2);
        u8 b0 = rbuf_[rpos_], b1 = rbuf_[rpos_ + 1];
        rpos_ += 2;
        u64 len = b1 & 0x7F;
        if (len == 126)
        {
            fill(2);
            len = getBE16(&rbuf_[rpos_]);
            rpos_ += 2;
        }
        else if (len == 127)
        {
            fill(8);
            len = getBE64(&rbuf_[rpos_]);
            rpos_ += 8;
        }
        u8 mask[4] = {};
        bool masked = b1 & 0x80;
        if (masked)
        {
            fill(4);
            std::memcpy(mask, &rbuf_[rpos_], 4);
            rpos_ += 4;
        }
        if (len > (256u << 20))
            fail("websocket: frame too large");
        fill(std::size_t(len));
        std::string payload(reinterpret_cast<char*>(&rbuf_[rpos_]), std::size_t(len));
        rpos_ += std::size_t(len);
        if (masked)
            for (std::size_t i = 0; i < payload.size(); ++i)
                payload[i] = char(payload[i] ^ mask[i & 3]);
        u8 op = b0 & 0x0F;
        if (op == 0x8)
            fail("websocket: server closed the connection");
        if (op == 0x9)
        {
            sendFrame(0xA, reinterpret_cast<u8 const*>(payload.data()), payload.size());
            continue;
        }
        if (op == 0xA)
            continue;
        msg += payload;
        if (b0 & 0x80)
            return msg;
    }
}

Json
WsClient::call(Json req)
{
    return callMany({std::move(req)}, 1).at(0);
}

std::vector<Json>
WsClient::callMany(std::vector<Json> reqs, std::size_t window)
{
    std::vector<Json> out(reqs.size());
    std::map<u64, std::size_t> pending;
    std::size_t sent = 0, done = 0;
    while (done < reqs.size())
    {
        while (sent < reqs.size() && pending.size() < std::max<std::size_t>(window, 1))
        {
            u64 id = nextId_++;
            reqs[sent].set("id", id);
            sendText(reqs[sent].dump());
            pending[id] = sent++;
        }
        Json m = Json::parse(readMessage());
        auto id = m["id"].asU64();
        if (!id)
            continue;  // unsolicited stream message
        auto it = pending.find(*id);
        if (it == pending.end())
            continue;
        out[it->second] = std::move(m);
        pending.erase(it);
        ++done;
    }
    return out;
}

}  // namespace catl
