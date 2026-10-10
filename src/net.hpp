// catl — tiny network layer: TCP (+ optional TLS via OpenSSL), HTTP/1.1 GET
// with Range and redirects, and an RFC 6455 WebSocket client for the
// xahaud JSON API. Build without OpenSSL and ws:// / http:// still work.
#pragma once

#include "json.hpp"

#include <map>
#include <memory>
#include <optional>

namespace catl {

struct Url
{
    std::string scheme, host, port, path;
    bool
    tls() const
    {
        return scheme == "https" || scheme == "wss";
    }
    static std::optional<Url>
    parse(std::string_view s);
    std::string
    origin() const
    {
        return scheme + "://" + host + (port.empty() ? "" : ":" + port);
    }
};

bool
tlsSupported();

class NetStream
{
public:
    virtual ~NetStream() = default;
    virtual std::size_t
    read(u8* p, std::size_t n) = 0;  // 0 = closed
    virtual void
    write(u8 const* p, std::size_t n) = 0;
};

std::unique_ptr<NetStream>
connectUrl(Url const& u, int timeoutSec = 30);

struct HttpResult
{
    int status = 0;
    std::map<std::string, std::string> headers;  // lower-case names
    std::string finalUrl;
};

// GET url; body chunks go to onBody (return false to stop early).
HttpResult
httpGet(
    std::string const& url,
    std::string const& extraHeaders,
    std::function<bool(u8 const*, std::size_t)> const& onBody,
    int timeoutSec = 60);
std::string
httpGetText(std::string const& url, int* status = nullptr);

class WsClient
{
public:
    explicit WsClient(std::string const& url, int timeoutSec = 30);
    // Sends one request (an "id" is added) and waits for its response.
    Json
    call(Json req);
    // Pipelined: keeps up to `window` requests in flight.
    std::vector<Json>
    callMany(std::vector<Json> reqs, std::size_t window = 32);
    std::string const&
    url() const
    {
        return url_;
    }

private:
    void
    sendText(std::string const& s);
    std::string
    readMessage();
    void
    sendFrame(u8 opcode, u8 const* p, std::size_t n);
    void
    fill(std::size_t n);

    std::string url_;
    std::unique_ptr<NetStream> s_;
    Bytes rbuf_;
    std::size_t rpos_ = 0;
    u64 nextId_ = 1;
};

std::string
base64Encode(u8 const* p, std::size_t n);

}  // namespace catl
