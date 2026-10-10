#!/usr/bin/env python3
"""Minimal fake xahaud WebSocket API over a synthetic chain, for testing
`catl verify --remote` / `catl anchor` offline. Serves server_info,
ledger (validated / index / hash, binary) and ledger_entry (binary).

    catl_tests --make-sample /tmp/s     # writes chain.json next to the files
    tools/fake_xahaud.py /tmp/s/chain.json 8765 [--tamper] [--tls CERT KEY]
    catl anchor /tmp/s --server ws://127.0.0.1:8765
"""
import base64, hashlib, json, socket, struct, sys, threading

chain = json.load(open(sys.argv[1]))
port = int(sys.argv[2])
tamper = '--tamper' in sys.argv
headers = [bytes.fromhex(h) for h in chain['headers']]
bseq = {struct.unpack('>I', h[:4])[0]: h for h in headers}
lhash = lambda h: hashlib.sha512(b'LWR\0' + h).digest()[:32].hex().upper()
bhash = {lhash(h): h for h in headers}
tip = headers[-1]
skips = dict(chain['skiplists'])
if tamper:  # corrupt the newest hash in every skip list
    for k, v in skips.items():
        b = bytearray(bytes.fromhex(v)); b[-1] ^= 1; skips[k] = b.hex().upper()

def respond(req):
    c, rid = req.get('command'), req.get('id')
    ok = lambda r: {'id': rid, 'result': r, 'status': 'success', 'type': 'response'}
    err = lambda e: {'id': rid, 'error': e, 'status': 'error', 'type': 'response'}
    if c == 'server_info':
        return ok({'info': {'network_id': 21337, 'build_version': 'fake'}})
    if c == 'ledger':
        if req.get('ledger_index') == 'validated': h = tip
        elif 'ledger_hash' in req: h = bhash.get(req['ledger_hash'].upper())
        else: h = bseq.get(int(req.get('ledger_index', 0)))
        if h is None: return err('lgrNotFound')
        return ok({'ledger': {'closed': True, 'ledger_data': h.hex().upper()}, 'ledger_hash': lhash(h),
                   'ledger_index': struct.unpack('>I', h[:4])[0], 'validated': True})
    if c == 'ledger_entry':
        v = skips.get(req.get('index', '').upper())
        return ok({'index': req['index'], 'node_binary': v, 'validated': True}) if v else err('entryNotFound')
    return err('unknownCmd')

def recv_exact(s, n):
    b = b''
    while len(b) < n:
        d = s.recv(n - len(b))
        if not d: raise EOFError
        b += d
    return b

def serve(s):
    try:
        data = b''
        while b'\r\n\r\n' not in data: data += s.recv(4096)
        key = [l.split(b':', 1)[1].strip() for l in data.split(b'\r\n') if l.lower().startswith(b'sec-websocket-key')][0]
        acc = base64.b64encode(hashlib.sha1(key + b'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest())
        s.sendall(b'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ' + acc + b'\r\n\r\n')
        while True:
            b0, b1 = recv_exact(s, 2)
            n = b1 & 127
            if n == 126: n = struct.unpack('>H', recv_exact(s, 2))[0]
            elif n == 127: n = struct.unpack('>Q', recv_exact(s, 8))[0]
            mask = recv_exact(s, 4) if b1 & 128 else b'\0' * 4
            p = bytes(c ^ mask[i % 4] for i, c in enumerate(recv_exact(s, n)))
            if b0 & 15 == 8: break
            out = json.dumps(respond(json.loads(p))).encode()
            if len(out) < 126: hdr = bytes([0x81, len(out)])
            elif len(out) < 65536: hdr = bytes([0x81, 126]) + struct.pack('>H', len(out))
            else: hdr = bytes([0x81, 127]) + struct.pack('>Q', len(out))
            s.sendall(hdr + out)
    except (EOFError, ConnectionError):
        pass
    finally:
        s.close()

srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(('127.0.0.1', port)); srv.listen(16)
ctx = None
if '--tls' in sys.argv:
    import ssl
    i = sys.argv.index('--tls')
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(sys.argv[i + 1], sys.argv[i + 2])
while True:
    c, _ = srv.accept()
    if ctx:
        try:
            c = ctx.wrap_socket(c, server_side=True)
        except Exception:
            c.close(); continue
    threading.Thread(target=serve, args=(c,), daemon=True).start()
