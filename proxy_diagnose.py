#!/usr/bin/env python3
"""proxy_diagnose.py: find the step where a proxy connection fails.

Walks one request through a proxy one step at a time (resolve the proxy host,
open TCP to it, proxy handshake and login, tunnel to the target, TLS, HTTP)
and stops at the first step that fails, with the reason in plain words.

Usage:
  python3 proxy_diagnose.py PROXY_URL [TARGET_URL] [--timeout S] [--cafile PEM] [--insecure]

  PROXY_URL   http://USER:PASS@HOST:PORT, socks5://..., or socks5h://...
  TARGET_URL  default https://www.example.com/

Exit code: 0 when every step passed, otherwise the number of the failed step.
Standard library only, Python 3.8+. Maintained by Proxy302, MIT licensed.
"""
import argparse
import base64
import ipaddress
import socket
import ssl
import sys
import time
from urllib.parse import unquote, urlsplit

SOCKS_REPLIES = {
    0x01: "general SOCKS server failure",
    0x02: "connection not allowed by the proxy's rules",
    0x03: "network unreachable from the proxy",
    0x04: "host unreachable from the proxy (or the proxy could not resolve the name)",
    0x05: "connection refused by the target",
    0x06: "TTL expired (the proxy timed out reaching the target)",
    0x07: "command not supported",
    0x08: "address type not supported",
}


class Fail(Exception):
    def __init__(self, short, advice):
        super().__init__(short)
        self.short, self.advice = short, advice


def ms(t0):
    return "%d ms" % round((time.monotonic() - t0) * 1000)


def masked(u):
    if u.password is None:
        return u.geturl()
    netloc = "%s:****@%s" % (u.username, u.hostname if ":" not in (u.hostname or "") else "[%s]" % u.hostname)
    if u.port:
        netloc += ":%d" % u.port
    return "%s://%s" % (u.scheme, netloc)


def recv_http_head(sock):
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
        if len(buf) > 65536:
            break
    return buf


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise Fail("the proxy closed the connection in the middle of the SOCKS5 handshake",
                       "This is usually not a SOCKS5 port, or the proxy rejected your address before login.")
        buf += chunk
    return buf


def looks_like(first):
    if first.startswith(b"HTTP/"):
        return "an HTTP proxy (it answered with an HTTP status line)"
    if first[:1] == b"\x05":
        return "a SOCKS5 proxy (it answered with SOCKS5 bytes)"
    if first[:2] == b"\x16\x03" or first[:2] == b"\x15\x03":
        return "a TLS server (an HTTPS proxy port, or not a proxy at all)"
    if first[:4] == b"SSH-":
        return "an SSH server"
    return "something else (first bytes: %s)" % first[:8].hex(" ")


def raise_407(head, user):
    scheme = ""
    for l in head.decode("latin-1").split("\r\n"):
        if l.lower().startswith("proxy-authenticate:"):
            scheme = l.split(":", 1)[1].strip()
    if user is None:
        raise Fail("407: the proxy wants a username and password and none were given (%s)" % scheme,
                   "Put them in the URL: http://USER:PASS@HOST:PORT, or add your IP to the provider's allowlist.")
    raise Fail("407: the proxy rejected this username and password (%s)" % scheme,
               "Copy them again from the provider. Percent-encode @ : / # % in the password. "
               "If the IP has expired, its old credentials stop working too.")


def check_http_answer(head):
    if not head:
        raise Fail("the proxy closed the connection without answering",
                   "Common causes: the port speaks another protocol (a SOCKS5 port: try socks5h://), "
                   "or an IP-allowlist proxy refusing an address that is not on its list.")
    if not head.startswith(b"HTTP/"):
        raise Fail("this port is not an HTTP proxy; it looks like " + looks_like(head),
                   "Use the scheme the IP was bought with: socks5h:// for SOCKS5, http:// for HTTP.")
    status_line = head.split(b"\r\n", 1)[0].decode("latin-1")
    parts = status_line.split(" ", 2)
    code = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
    return status_line, code


def http_forward(sock, target, user, pw, hosthdr):
    """Plain http:// target through an HTTP proxy: absolute-form GET, no CONNECT."""
    lines = ["GET %s HTTP/1.1" % target, "Host: " + hosthdr,
             "User-Agent: proxy_diagnose/1.0", "Accept: */*", "Connection: close"]
    if user is not None:
        token = base64.b64encode(("%s:%s" % (user, pw or "")).encode()).decode()
        lines.append("Proxy-Authorization: Basic " + token)
    t0 = time.monotonic()
    sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode())
    try:
        first = sock.recv(1)
        ttfb = ms(t0)
        head = first + (recv_http_head(sock) if first else b"")
    except socket.timeout:
        raise Fail("connected, but the proxy sent nothing back to the request",
                   "The port accepted TCP and then stayed silent. Common causes: it is a SOCKS5 port "
                   "(try socks5h://), it expects TLS first, or the proxy is overloaded.")
    status_line, code = check_http_answer(head)
    if code == 407:
        raise_407(head, user)
    return status_line, code, ttfb


def http_handshake(sock, proxy, host, port, user, pw):
    lines = ["CONNECT %s:%d HTTP/1.1" % (host if ":" not in host else "[%s]" % host, port),
             "Host: %s:%d" % (host if ":" not in host else "[%s]" % host, port)]
    if user is not None:
        token = base64.b64encode(("%s:%s" % (user, pw or "")).encode()).decode()
        lines.append("Proxy-Authorization: Basic " + token)
    sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode())
    try:
        head = recv_http_head(sock)
    except socket.timeout:
        raise Fail("connected, but the proxy sent nothing back to the CONNECT request",
                   "The port accepted TCP and then stayed silent. Common causes: it is a SOCKS5 port "
                   "(try socks5h://), it expects TLS first, or the proxy is overloaded.")
    status_line, code = check_http_answer(head)
    if code == 200:
        return status_line
    if code == 407:
        raise_407(head, user)
    if code in (403, 405):
        raise Fail("%s: the proxy refuses to open a tunnel to %s:%d" % (status_line, host, port),
                   "The proxy's rules block this host or this port. Many proxies only allow CONNECT to 443 and a few other ports.")
    if code in (502, 503):
        raise Fail("%s: the proxy accepted you but could not connect to %s:%d" % (status_line, host, port),
                   "The target refused or could not be resolved from the proxy. Check the host and port; try another target to confirm the proxy itself is fine.")
    if code == 504:
        raise Fail("%s: the proxy timed out reaching %s:%d" % (status_line, host, port),
                   "The target is slow or unreachable from the proxy's location. Try again, or try another target.")
    raise Fail("unexpected answer to CONNECT: " + status_line, "Read the proxy's documentation for this status.")


def socks_handshake(sock, host, port, user, pw, remote_dns):
    methods = b"\x00\x02" if user is not None else b"\x00"
    sock.sendall(b"\x05" + bytes([len(methods)]) + methods)
    try:
        first = sock.recv(2)
    except socket.timeout:
        raise Fail("connected, but the proxy did not answer the SOCKS5 greeting",
                   "This is probably an HTTP proxy port (it waits for a full HTTP request line). Try http://.")
    if not first:
        raise Fail("the proxy closed the connection on the SOCKS5 greeting",
                   "Probably not a SOCKS5 port, or an IP-allowlist proxy refusing your address.")
    if first[:1] != b"\x05":
        more = first
        try:
            more += sock.recv(64)
        except socket.timeout:
            pass
        raise Fail("this port is not a SOCKS5 proxy; it looks like " + looks_like(more),
                   "Use the scheme the IP was bought with: http:// for HTTP, socks5h:// for SOCKS5.")
    method = first[1]
    if method == 0xFF:
        raise Fail("the SOCKS5 proxy accepted none of the login methods offered",
                   "It needs a username and password: socks5h://USER:PASS@HOST:PORT." if user is None
                   else "It does not accept username/password login. Check the scheme and port.")
    if method == 0x02:
        u = (user or "").encode()
        p = (pw or "").encode()
        sock.sendall(b"\x01" + bytes([len(u)]) + u + bytes([len(p)]) + p)
        status = recv_exact(sock, 2)
        if status[1] != 0:
            raise Fail("the SOCKS5 proxy rejected this username and password",
                       "Copy them again from the provider; percent-encode @ : / # % in the URL.")
    if remote_dns:
        h = host.encode("idna")
        addr = b"\x03" + bytes([len(h)]) + h
        shown = host + " (name sent to the proxy)"
    else:
        ip = host
        try:
            ipaddress.ip_address(host)
        except ValueError:
            ip = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)[0][4][0]
        packed = ipaddress.ip_address(ip).packed
        addr = (b"\x01" if len(packed) == 4 else b"\x04") + packed
        shown = "%s (resolved on this computer; use socks5h:// to let the proxy resolve)" % ip
    sock.sendall(b"\x05\x01\x00" + addr + port.to_bytes(2, "big"))
    rep = recv_exact(sock, 4)
    if rep[1] != 0:
        why = SOCKS_REPLIES.get(rep[1], "unknown reply 0x%02x" % rep[1])
        advice = {
            0x02: "The proxy's rules block this host or port.",
            0x04: "Check the target host name. With socks5:// your computer resolves it; with socks5h:// the proxy does.",
            0x05: "Nothing listens on that port at the target. The proxy itself works.",
            0x06: "The target is slow or unreachable from the proxy. Try another target to compare.",
        }.get(rep[1], "Try another target to see whether the proxy works at all.")
        raise Fail("SOCKS5 CONNECT to %s port %d failed: %s" % (shown, port, why), advice)
    atyp = rep[3]
    skip = {1: 4, 4: 16}.get(atyp)
    if skip is None:
        (l,) = recv_exact(sock, 1)
        skip = l
    recv_exact(sock, skip + 2)
    return "SOCKS5 CONNECT %s -> succeeded" % shown


def main():
    ap = argparse.ArgumentParser(description="Find the step where a proxy connection fails.")
    ap.add_argument("proxy")
    ap.add_argument("target", nargs="?", default="https://www.example.com/")
    ap.add_argument("--timeout", type=float, default=10.0, help="seconds per step (default 10)")
    ap.add_argument("--cafile", help="extra CA certificate (PEM) to trust for the target")
    ap.add_argument("--insecure", action="store_true", help="do not verify the target's certificate")
    a = ap.parse_args()

    p = urlsplit(a.proxy if "://" in a.proxy else "http://" + a.proxy)
    t = urlsplit(a.target)
    if p.scheme not in ("http", "socks5", "socks5h"):
        print("Unsupported proxy scheme %r (use http, socks5 or socks5h)." % p.scheme)
        return 64
    if t.scheme not in ("http", "https") or not t.hostname:
        print("TARGET_URL must start with http:// or https://")
        return 64
    user = unquote(p.username) if p.username is not None else None
    pw = unquote(p.password) if p.password is not None else None
    phost, pport = p.hostname, p.port or (1080 if p.scheme.startswith("socks") else 8080)
    thost = t.hostname
    tport = t.port or (443 if t.scheme == "https" else 80)
    path = (t.path or "/") + ("?" + t.query if t.query else "")

    print("proxy   %s" % masked(p))
    print("target  %s" % a.target)
    print()
    step = 0
    sock = None

    def ok(name, detail):
        print("[%d] %-22s ok    %s" % (step, name, detail))

    try:
        step = 1
        t0 = time.monotonic()
        try:
            infos = socket.getaddrinfo(phost, pport, type=socket.SOCK_STREAM)
        except socket.gaierror as e:
            raise Fail("the proxy host name %r does not resolve (%s)" % (phost, e.strerror),
                       "Check the host for typos, or copy it again from the provider.")
        addr = infos[0][4]
        ok("resolve proxy host", "%s  (%s)" % (addr[0], ms(t0)))

        step = 2
        t0 = time.monotonic()
        sock = socket.socket(infos[0][0], socket.SOCK_STREAM)
        sock.settimeout(a.timeout)
        try:
            sock.connect(addr)
        except ConnectionRefusedError:
            raise Fail("connection refused by %s:%d" % (addr[0], pport),
                       "Nothing is listening on that port: wrong port, the proxy service is down, "
                       "or a firewall that actively rejects your address (some IP-allowlist proxies do).")
        except socket.timeout:
            raise Fail("no answer to the TCP connection within %gs" % a.timeout,
                       "Packets are being dropped: a wrong host or port, a firewall on your network that "
                       "blocks this port, or a proxy that silently ignores addresses not on its allowlist.")
        except OSError as e:
            raise Fail("TCP connection failed: %s" % e.strerror,
                       "Your computer has no route to the proxy. Check your own network first.")
        ok("TCP connect to proxy", ms(t0))

        step = 3
        t0 = time.monotonic()
        if p.scheme == "http" and t.scheme == "http":
            hosthdr = thost if t.port is None else "%s:%d" % (thost, t.port)
            status_line, code, ttfb = http_forward(sock, a.target, user, pw, hosthdr)
            ok("request via proxy", "%s, first byte after %s" % (status_line, ttfb))
            print()
            if 200 <= code < 400:
                print("Verdict: every step passed. The proxy works for this URL.")
            elif code in (502, 503, 504):
                print("Verdict: login worked, but %d came back. For plain http:// either the proxy could not "
                      "reach the site or the site sent it; try an https:// URL on the same site to tell them apart." % code)
            else:
                print("Verdict: the proxy works; the answer was %d, which normally comes from the website." % code)
            return 3 if code in (502, 503, 504) else 0
        if p.scheme == "http":
            detail = http_handshake(sock, p, thost, tport, user, pw)
        else:
            detail = socks_handshake(sock, thost, tport, user, pw, p.scheme == "socks5h")
        ok("proxy login + tunnel", "%s  (%s)" % (detail, ms(t0)))

        if t.scheme == "https":
            step = 4
            t0 = time.monotonic()
            ctx = ssl.create_default_context(cafile=a.cafile) if a.cafile else ssl.create_default_context()
            if a.insecure:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            try:
                sock = ctx.wrap_socket(sock, server_hostname=thost)
            except ssl.SSLCertVerificationError as e:
                raise Fail("the tunnel works, but the target's certificate is not trusted: %s" % e.verify_message,
                           "Either something between you and the site is inspecting TLS (a company "
                           "proxy, antivirus, or the proxy itself), or the host name is wrong. If it is "
                           "your own test server, pass its CA with --cafile.")
            except (ssl.SSLError, ConnectionResetError, socket.timeout) as e:
                raise Fail("the tunnel opened, but TLS with the target failed: %s" % e,
                           "The target may not speak TLS on this port, or the connection was cut inside the tunnel.")
            cert = sock.getpeercert() or {}
            cn = ""
            for field in cert.get("subject", ()):
                for k, v in field:
                    if k == "commonName":
                        cn = v
            ok("TLS with target", "%s, certificate for %s  (%s)" % (sock.version(), cn or thost, ms(t0)))

        step = 5 if t.scheme == "https" else 4
        t0 = time.monotonic()
        hosthdr = thost if t.port is None else "%s:%d" % (thost, t.port)
        req = "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: proxy_diagnose/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n" % (path, hosthdr)
        sock.sendall(req.encode())
        try:
            first = sock.recv(1)
            ttfb = ms(t0)
            rest = recv_http_head(sock)
        except socket.timeout:
            raise Fail("no response from the target within %gs" % a.timeout,
                       "The tunnel and TLS worked, so the proxy is fine; the site is slow or holding the request.")
        head = first + rest
        status_line = head.split(b"\r\n", 1)[0].decode("latin-1")
        code = status_line.split(" ")[1] if " " in status_line else "?"
        ok("HTTP response", "%s, first byte after %s" % (status_line, ttfb))
        print()
        if code.startswith(("2", "3")):
            print("Verdict: every step passed. The proxy works for this URL.")
        else:
            print("Verdict: the proxy works; the website itself answered %s. "
                  "That is the site's decision, not a proxy fault." % code)
        return 0
    except Fail as f:
        print("[%d] FAILED: %s" % (step, f.short))
        print()
        print("What it means: " + f.advice)
        return step
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass


if __name__ == "__main__":
    sys.exit(main())
