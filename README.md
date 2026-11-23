# proxy-error-diagnose: is it a 407, a timeout or a refused connection?

A failing proxy fails at one of a few steps, and each step has its own fix. **Refused** means your computer reached the host but nothing accepted a connection on that port (wrong port, service down, or a firewall that rejects you). **Timeout** means no answer came back at all, so packets are being dropped somewhere (wrong host, a blocked port on your network, or an IP-allowlist proxy that ignores unknown addresses). **407** means the connection worked and the proxy turned down your username and password. A **403/502/504 to CONNECT** means the login was fine and the proxy would not or could not reach the site. A **certificate error** after a working tunnel means something is inspecting TLS or the host name is wrong. `proxy_diagnose.py` walks one request through these steps in order and stops at the first one that fails, with the reason in plain words. Proxy302 maintains this tool and sells proxies: a static residential (ISP) IP costs $7.99 for 30 days, or $0.50 for a one-day test ([prices](https://proxy302.com/pricing/)). The script works with any provider's HTTP or SOCKS5 proxy.

> Maintained by [Proxy302](https://proxy302.com). MIT licensed.

## Usage

```bash
git clone https://github.com/proxy302/proxy-error-diagnose
cd proxy-error-diagnose
python3 proxy_diagnose.py "http://USER:PASS@HOST:PORT"                         # target defaults to https://www.example.com/
python3 proxy_diagnose.py "socks5h://USER:PASS@HOST:PORT" https://YOUR-SITE/   # the site that fails for you
python3 proxy_diagnose.py "http://USER:PASS@HOST:PORT" https://YOUR-SITE/ --timeout 20
```

USER, PASS, HOST and PORT are placeholders. Percent-encode `@ : / # %` in the password. Python 3.8 or later, standard library only, no `pip install`.

Options: `--timeout S` per step (default 10), `--cafile PEM` to trust your own test CA, `--insecure` to skip certificate checks. The exit code is 0 when everything passed, otherwise the number of the step that failed, so you can use it in a monitoring script.

## The steps

| # | Step | What a failure here means |
|---|---|---|
| 1 | Resolve the proxy host | Typo in the host name, or your DNS cannot see it |
| 2 | TCP connection to the proxy | **Refused**: nothing listens on that port, or a firewall rejects you. **Timeout**: packets are dropped (wrong address, your network blocks the port, or an allowlist proxy ignores you) |
| 3 | Proxy login and tunnel | **407**: wrong or missing credentials. **403**: the proxy's rules block that host or port. **502/504**: the proxy could not reach the site. **No answer / wrong bytes**: you used `http://` on a SOCKS5 port or the other way round. For SOCKS5, the proxy's reply code is translated (RFC 1928) |
| 4 | TLS with the site (https only) | The tunnel works but the certificate is not trusted: TLS inspection on the way, or the wrong host |
| 5 | HTTP response | The proxy is fine. A 403 or 429 here is the website's own answer, not a proxy fault |

For a plain `http://` target through an HTTP proxy there is no tunnel: the request goes to the proxy as `GET http://...`, so steps 3 to 5 are one step.

With `socks5://` the script resolves the site's name on your computer and sends the address; with `socks5h://` it sends the name and the proxy resolves it, as curl does. The output says which one happened.

## Example output

Recorded on 23 November 2026 against a test proxy and a test HTTPS site running on the same Mac (user `alice`, port 23128 HTTP, the site on 28443 with a self-signed certificate). Real output, nothing edited.

Everything works:

```text
$ python3 proxy_diagnose.py "http://alice:s3cret@127.0.0.1:23128" https://localhost:28443/ --cafile testbed-ca.pem
proxy   http://alice:****@127.0.0.1:23128
target  https://localhost:28443/

[1] resolve proxy host     ok    127.0.0.1  (2 ms)
[2] TCP connect to proxy   ok    0 ms
[3] proxy login + tunnel   ok    HTTP/1.1 200 Connection established  (1 ms)
[4] TLS with target        ok    TLSv1.2, certificate for localhost  (2 ms)
[5] HTTP response          ok    HTTP/1.1 200 OK, first byte after 0 ms

Verdict: every step passed. The proxy works for this URL.
```

Wrong password (407):

```text
$ python3 proxy_diagnose.py "http://alice:wrong@127.0.0.1:23128" https://localhost:28443/
proxy   http://alice:****@127.0.0.1:23128
target  https://localhost:28443/

[1] resolve proxy host     ok    127.0.0.1  (2 ms)
[2] TCP connect to proxy   ok    0 ms
[3] FAILED: 407: the proxy rejected this username and password (Basic realm="testbed")

What it means: Copy them again from the provider. Percent-encode @ : / # % in the password. If the IP has expired, its old credentials stop working too.
```

Wrong port (refused):

```text
$ python3 proxy_diagnose.py "http://alice:s3cret@127.0.0.1:23130" https://localhost:28443/
proxy   http://alice:****@127.0.0.1:23130
target  https://localhost:28443/

[1] resolve proxy host     ok    127.0.0.1  (2 ms)
[2] FAILED: connection refused by 127.0.0.1:23130

What it means: Nothing is listening on that port: wrong port, the proxy service is down, or a firewall that actively rejects your address (some IP-allowlist proxies do).
```

An address that never answers (timeout; 192.0.2.1 is a documentation-only address):

```text
$ python3 proxy_diagnose.py "http://alice:s3cret@192.0.2.1:8080" --timeout 5
proxy   http://alice:****@192.0.2.1:8080
target  https://www.example.com/

[1] resolve proxy host     ok    192.0.2.1  (3 ms)
[2] FAILED: no answer to the TCP connection within 5s

What it means: Packets are being dropped: a wrong host or port, a firewall on your network that blocks this port, or a proxy that silently ignores addresses not on its allowlist.
```

SOCKS5 scheme on an HTTP proxy port:

```text
$ python3 proxy_diagnose.py "socks5h://alice:s3cret@127.0.0.1:23128" https://localhost:28443/ --timeout 3
proxy   socks5h://alice:****@127.0.0.1:23128
target  https://localhost:28443/

[1] resolve proxy host     ok    127.0.0.1  (2 ms)
[2] TCP connect to proxy   ok    0 ms
[3] FAILED: connected, but the proxy did not answer the SOCKS5 greeting

What it means: This is probably an HTTP proxy port (it waits for a full HTTP request line). Try http://.
```

A port the proxy will not tunnel to (the test proxy, like Squid's default configuration, only allows CONNECT to a short list of ports):

```text
$ python3 proxy_diagnose.py "http://alice:s3cret@127.0.0.1:23128" https://localhost:28025/
proxy   http://alice:****@127.0.0.1:23128
target  https://localhost:28025/

[1] resolve proxy host     ok    127.0.0.1  (2 ms)
[2] TCP connect to proxy   ok    0 ms
[3] FAILED: HTTP/1.1 403 Forbidden: the proxy refuses to open a tunnel to localhost:28025

What it means: The proxy's rules block this host or this port. Many proxies only allow CONNECT to 443 and a few other ports.
```

The tunnel works but the certificate is not trusted (same run without `--cafile`):

```text
$ python3 proxy_diagnose.py "http://alice:s3cret@127.0.0.1:23128" https://localhost:28443/
proxy   http://alice:****@127.0.0.1:23128
target  https://localhost:28443/

[1] resolve proxy host     ok    127.0.0.1  (2 ms)
[2] TCP connect to proxy   ok    0 ms
[3] proxy login + tunnel   ok    HTTP/1.1 200 Connection established  (1 ms)
[4] FAILED: the tunnel works, but the target's certificate is not trusted: self signed certificate

What it means: Either something between you and the site is inspecting TLS (a company proxy, antivirus, or the proxy itself), or the host name is wrong. If it is your own test server, pass its CA with --cafile.
```

## Reading the result

- **Run it twice with two targets.** If `https://www.example.com/` passes and your site fails at step 3 with 502 or 504, the proxy is fine and the problem is between the proxy and that site.
- **Refused versus timeout is a strong hint.** Refused is quick and definite: wrong port or nothing running. A timeout takes the full `--timeout` and usually means a firewall, either on your side (office and hotel networks often block unusual ports) or on the proxy's side.
- **A 407 after an IP expires is normal.** When a static IP's term ends, its credentials stop working. Renew before the end date, or turn on auto-renew for that IP.
- **Step 5 failing with 403 or a CAPTCHA page** is the website deciding, not the proxy breaking. That is a different question from this tool's.

## Limits

- Proxy login is Basic (HTTP) and username/password (SOCKS5). NTLM, Kerberos and Digest proxies will show as 407.
- `https://` proxy URLs (TLS to the proxy itself) are not supported. If step 3 says the port looks like a TLS server, that is probably what you have.
- One request, one exit. For a whole list of proxies at once, use [proxy-list-health-check](https://github.com/proxy302/proxy-list-health-check).

## Related

- [Proxy 407, timeouts and failed checks: how to troubleshoot](https://github.com/proxy302/proxy-guides/blob/main/proxy-407-timeout-troubleshooting-zh/README.md) (Chinese)
- [What does ERR_TUNNEL_CONNECTION_FAILED mean?](https://github.com/proxy302/proxy-guides/blob/main/err-tunnel-connection-failed/README.md)
- [What does curl's "Proxy CONNECT aborted" mean?](https://github.com/proxy302/proxy-guides/blob/main/curl-proxy-connect-aborted/README.md)
- [proxy-password-special-characters](https://github.com/proxy302/proxy-password-special-characters): when the password has `@` or `#` in it

*Checked 23 November 2026.*
