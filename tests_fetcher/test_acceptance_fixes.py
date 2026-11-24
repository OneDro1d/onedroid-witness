"""Tests for the four defects acceptance testing found on the deployed fetcher (24 Nov 2026), written before the fix.

D1  DNS went to the cluster DNS service (10.4.3.10:53), a private address. The proxy must resolve through configured
    PUBLIC resolvers (FETCHER_RESOLVERS, default 1.1.1.1,8.8.8.8), each passing the address rules, over UDP with TCP
    fallback, and never through the system resolver (getaddrinfo) for a capture target, robots.txt included.
D2  A redirect refused at its hop lost the first hop: every error answer after at least one request carries a partial
    manifest {requested_url, redirects, fetched_at, fetch_ms, resolved_ips, robots}; the log line has the chain too.
D3  A dropped SYN (no SYN-ACK on any vetted address of the main document) was `unreachable`; it is `timeout` (408).
D4  robots-disallowed carried no manifest: it carries the partial manifest with robots "disallowed" and the robots.txt
    URL and sha256.

Unit tests replace the worker (nsrun.run_worker) with a fake that sends the browser's requests through the real egress
proxy over its Unix socket; the integration tests (marker `integration`) run the real namespace and Chromium.
"""
import asyncio
import contextlib
import hashlib
import importlib
import ipaddress
import json
import logging
import os
import socket
import struct
import time

import pytest

from claim_fetcher import capture as C
from claim_fetcher import addr, nsrun
from claim_fetcher import proxy as P
from claim_fetcher import server as S
from conftest import FIXTURE_IP, FakeResolver, need_sandbox, seam_connector
from test_isolation import page

FILES = ("capture.wacz", "response.body", "screenshot.png", "rendered.html", "hidden-nodes.json")


def _dns():
    """The public-resolver module (imported per test, so each test fails on its own while it does not exist)."""
    return importlib.import_module("claim_fetcher.dnsclient")


# a fake DNS server ----------------------------------------------------------------------------------------------------

def _question(query):
    off, labels = 12, []
    while query[off]:
        n = query[off]
        labels.append(query[off + 1:off + 1 + n].decode().lower())
        off += 1 + n
    qtype = struct.unpack("!H", query[off + 1:off + 3])[0]
    return ".".join(labels), qtype, off + 5


def dns_reply(query, table, tc=False):
    """A resolver's answer to `query` from `table` (name -> list of addresses, or "NXDOMAIN"); answer owner names are
    compression pointers to the question."""
    name, qtype, qend = _question(query)
    entry = table.get(name, [])
    answers = []
    if entry == "NXDOMAIN":
        flags = 0x8183
    else:
        flags = 0x8180 | (0x0200 if tc else 0)
        if not tc:
            answers = [ip for ip in entry if (":" in ip) == (qtype == 28)]
    rr = b""
    for ip in answers:
        data = ipaddress.ip_address(ip).packed
        rr += b"\xc0\x0c" + struct.pack("!HHIH", qtype, 1, 60, len(data)) + data
    return query[:2] + struct.pack("!HHHHH", flags, 1, len(answers), 0, 0) + query[12:qend] + rr


class FakeDNS:
    """Stands in for dnsclient.udp_exchange / tcp_exchange: records (transport, server, name, qtype)."""

    def __init__(self, table, truncate_udp=False, dead=()):
        self.table, self.truncate_udp, self.dead = table, truncate_udp, set(dead)
        self.calls = []

    def udp(self, server, packet, timeout):
        name, qtype, _ = _question(packet)
        self.calls.append(("udp", server, name, qtype))
        if server in self.dead:
            raise socket.timeout("timed out")
        return dns_reply(packet, self.table, tc=self.truncate_udp)

    def tcp(self, server, packet, timeout):
        name, qtype, _ = _question(packet)
        self.calls.append(("tcp", server, name, qtype))
        if server in self.dead:
            raise socket.timeout("timed out")
        return dns_reply(packet, self.table)


def _install_fake_dns(monkeypatch, table, **kw):
    fake = FakeDNS(table, **kw)
    with contextlib.suppress(ImportError):
        mod = _dns()
        monkeypatch.setattr(mod, "udp_exchange", fake.udp)
        monkeypatch.setattr(mod, "tcp_exchange", fake.tcp)
    return fake


class GetaddrinfoSpy:
    """socket.getaddrinfo replaced: records every call and answers none of them."""

    def __init__(self):
        self.calls = []

    def __call__(self, host, *a, **kw):
        self.calls.append(host)
        raise socket.gaierror(socket.EAI_NONAME, "getaddrinfo must not be called on the capture path")


# a fake worker: the browser's requests through the real proxy -------------------------------------------------------

def fake_worker(requests, result, write_files=False):
    seen = []

    async def run_worker(args, payload, timeout_s, python=None):
        seen.append(payload)
        for raw in requests:
            r, w = await asyncio.open_unix_connection(payload["proxy_socket"])
            w.write(raw)
            await w.drain()
            with contextlib.suppress(Exception):
                await asyncio.wait_for(r.read(), timeout_s)
            w.close()
        if write_files:
            for name in FILES:
                with open(os.path.join(payload["out_dir"], name), "wb") as f:
                    f.write(name.encode())
        return dict(result)

    run_worker.seen = seen
    return run_worker


def hanging_connector():
    calls = []

    async def connect(ip, port):
        calls.append((ip, port))
        await asyncio.sleep(3600)  # a dropped SYN: no SYN-ACK, ever

    connect.calls = calls
    return connect


def _partial(err):
    m = getattr(err, "manifest", None)
    assert m is not None, f"the error answer {err.code!r} carries no partial manifest"
    return m


# D1: public resolvers -------------------------------------------------------------------------------------------------

def test_d1_default_resolvers_are_public_and_listed_in_settings():
    assert tuple(C.Settings().resolvers) == ("1.1.1.1", "8.8.8.8")
    assert tuple(C.Settings.from_env({}).resolvers) == ("1.1.1.1", "8.8.8.8")
    assert tuple(C.Settings.from_env({"FETCHER_RESOLVERS": "9.9.9.9, 2620:fe::fe"}).resolvers) == ("9.9.9.9",
                                                                                                    "2620:fe::fe")


@pytest.mark.parametrize("env", [{"FETCHER_RESOLVERS": "10.4.3.10"}, {"FETCHER_RESOLVERS": "1.1.1.1,10.4.3.10"},
                                 {"FETCHER_RESOLVERS": "169.254.169.254"}, {"FETCHER_RESOLVERS": "127.0.0.53"},
                                 {"FETCHER_RESOLVERS": "fd00::53"}, {"FETCHER_RESOLVERS": "dns.google"},
                                 {"FETCHER_RESOLVERS": "1.1.1.1", "FETCHER_BLOCKED_CIDRS": "1.1.1.0/24"}])
def test_d1_a_resolver_that_fails_the_address_rules_stops_the_start(env):
    with pytest.raises(ValueError):
        C.Settings.from_env(env)


def test_d1_service_refuses_to_start_with_a_private_resolver(monkeypatch):
    monkeypatch.setenv("FETCHER_RESOLVERS", "10.4.3.10")
    monkeypatch.delenv("FETCHER_BLOCKED_CIDRS", raising=False)
    ran = []
    monkeypatch.setattr(S, "run_selftest", lambda settings: ran.append(1) or {"passed": True})
    assert S.main(["--selftest-only"]) == 2
    assert ran == []


def test_d1_resolver_object_refuses_private_servers():
    dns = _dns()
    for servers in (["10.4.3.10"], ["1.1.1.1", "192.168.1.1"], [], ["not-an-ip"]):
        with pytest.raises(ValueError):
            dns.PublicResolver(servers)
    with pytest.raises(ValueError):
        dns.PublicResolver(["1.1.1.1"], extra=addr.parse_cidrs("1.1.1.0/24"))


def test_d1_queries_a_and_aaaa_at_the_configured_resolver():
    dns = _dns()
    fake = FakeDNS({"example.test": ["93.184.215.14", "2606:2800:21f:cb07:6820:80da:af6b:8b2c"]})
    r = dns.PublicResolver(["9.9.9.9"], udp=fake.udp, tcp=fake.tcp)
    assert r("Example.Test.") == ["93.184.215.14", "2606:2800:21f:cb07:6820:80da:af6b:8b2c"]
    assert {(t, s, n) for t, s, n, _ in fake.calls} == {("udp", "9.9.9.9", "example.test")}
    assert sorted(q for *_, q in fake.calls) == [1, 28]


def test_d1_tcp_fallback_when_the_udp_answer_is_truncated():
    dns = _dns()
    fake = FakeDNS({"big.test": [FIXTURE_IP]}, truncate_udp=True)
    r = dns.PublicResolver(["1.1.1.1"], udp=fake.udp, tcp=fake.tcp)
    assert r("big.test") == [FIXTURE_IP]
    assert ("tcp", "1.1.1.1", "big.test", 1) in fake.calls


def test_d1_next_resolver_when_the_first_does_not_answer():
    dns = _dns()
    fake = FakeDNS({"ok.test": [FIXTURE_IP]}, dead={"1.1.1.1"})
    r = dns.PublicResolver(["1.1.1.1", "8.8.8.8"], udp=fake.udp, tcp=fake.tcp)
    assert r("ok.test") == [FIXTURE_IP]
    assert any(s == "8.8.8.8" for _, s, _, _ in fake.calls)


def test_d1_nxdomain_is_unreachable():
    dns = _dns()
    fake = FakeDNS({"gone.test": "NXDOMAIN"})
    r = dns.PublicResolver(["1.1.1.1", "8.8.8.8"], udp=fake.udp, tcp=fake.tcp)
    with pytest.raises(OSError):
        r("gone.test")
    with pytest.raises(addr.Refused) as e:
        addr.vet_host("gone.test", 443, resolver=r)
    assert e.value.code == "unreachable"
    assert {s for _, s, _, _ in fake.calls} == {"1.1.1.1"}  # an NXDOMAIN is an answer: no second opinion asked


def test_d1_cname_chain_followed_and_unrelated_records_ignored():
    dns = _dns()

    def udp(server, packet, timeout):
        name, qtype, qend = _question(packet)
        if qtype != 1:
            return packet[:2] + struct.pack("!HHHHH", 0x8180, 1, 0, 0, 0) + packet[12:qend]
        target = b"\x04edge\x03cdn\x04test\x00"
        cname = b"\xc0\x0c" + struct.pack("!HHIH", 5, 1, 60, len(target)) + target
        cname_at = 12 + (qend - 12) + 12  # offset of the CNAME's rdata
        a = struct.pack("!H", 0xC000 | cname_at) + struct.pack("!HHIH", 1, 1, 60, 4) + bytes([93, 184, 215, 14])
        evil = b"\x04evil\x04test\x00" + struct.pack("!HHIH", 1, 1, 60, 4) + bytes([10, 0, 0, 1])
        return packet[:2] + struct.pack("!HHHHH", 0x8180, 1, 3, 0, 0) + packet[12:qend] + cname + a + evil

    r = dns.PublicResolver(["1.1.1.1"], udp=udp, tcp=udp)
    assert r("www.site.test") == [FIXTURE_IP]


def test_d1_answer_with_the_wrong_id_or_question_is_not_trusted():
    dns = _dns()

    def wrong_id(server, packet, timeout):
        reply = dns_reply(packet, {"ok.test": ["10.0.0.1"]})
        return bytes([packet[0] ^ 0xFF, packet[1]]) + reply[2:]

    with pytest.raises(OSError):
        dns.PublicResolver(["1.1.1.1"], udp=wrong_id, tcp=wrong_id)("ok.test")


def test_d1_proxy_and_capture_never_use_the_system_resolver(monkeypatch, site_factory):
    """The whole capture path (the pre-check, robots.txt and the page's own request through the proxy) with no
    resolver handed in: DNS goes to the configured public resolvers and socket.getaddrinfo is never called."""
    site = site_factory({"/page": page("<p>hi</p>")})
    fake = _install_fake_dns(monkeypatch, {"fixture.test": [FIXTURE_IP]})
    worker = fake_worker([b"GET http://fixture.test/page HTTP/1.1\r\nHost: fixture.test\r\n\r\n"],
                         {"ok": True, "final_url": "http://fixture.test/page", "status": 200, "redirects": [],
                          "chain": ["http://fixture.test/page"], "browser": "chromium 1", "tls": None,
                          "user_agent": "ua", "mime": "text/html"}, write_files=True)
    monkeypatch.setattr(nsrun, "run_worker", worker)
    spy = GetaddrinfoSpy()
    monkeypatch.setattr(socket, "getaddrinfo", spy)
    conn = seam_connector({(FIXTURE_IP, 80): (site.host, site.port)})
    try:
        result = C.capture_sync("http://fixture.test/page", (1280, 900), C.Settings(), connector=conn)
    except C.CaptureError as e:
        result = e
    assert spy.calls == [], f"getaddrinfo was called for {spy.calls}"
    assert not isinstance(result, C.CaptureError), f"{result.code}: {result.detail}"
    assert result.manifest["resolved_ips"] == [FIXTURE_IP]
    assert {s for _, s, _, _ in fake.calls} == {"1.1.1.1"}
    assert {n for _, _, n, _ in fake.calls} == {"fixture.test"}
    assert [p for p, _ in site.hits] == ["/robots.txt", "/page"]


def test_d1_selftest_lists_the_resolvers(monkeypatch):
    monkeypatch.setattr(nsrun, "run_worker", fake_worker([], {"interfaces": ["lo"], "passed": True, "reasons": [],
                                                              "probes": [{"target": "10.0.0.1:80",
                                                                          "result": "failed"}],
                                                              "proxy_probe": {"result": "refused"}}))
    result = C.run_selftest(C.Settings())
    assert result.get("resolvers") == ["1.1.1.1", "8.8.8.8"], result


# D2 and D4: the partial manifest in error answers -------------------------------------------------------------------

def test_d4_robots_disallowed_carries_the_partial_manifest(monkeypatch, site_factory):
    robots_txt = b"User-agent: *\nDisallow: /search\n"
    site = site_factory({"/robots.txt": (200, {"Content-Type": "text/plain"}, robots_txt)})
    monkeypatch.setattr(nsrun, "run_worker", lambda *a, **k: pytest.fail("the browser must not start"))
    conn = seam_connector({(FIXTURE_IP, 80): (site.host, site.port)})
    with pytest.raises(C.CaptureError) as e:
        C.capture_sync("http://fixture.test/search?q=onedroid", (1280, 900), C.Settings(),
                       resolver=FakeResolver({"fixture.test": [FIXTURE_IP]}), connector=conn)
    assert e.value.code == "robots-disallowed"
    m = _partial(e.value)
    assert m["requested_url"] == "http://fixture.test/search?q=onedroid"
    assert m["robots"] == "disallowed"
    assert m["robots_txt"]["url"] == "http://fixture.test/robots.txt"
    assert m["robots_txt"]["sha256"] == hashlib.sha256(robots_txt).hexdigest()
    assert m["redirects"] == []
    assert m["resolved_ips"] == [FIXTURE_IP]
    assert isinstance(m["fetch_ms"], int) and m["fetch_ms"] >= 0
    assert m["fetched_at"].endswith("Z")


def test_d2_blocked_redirect_keeps_the_first_hop(monkeypatch, site_factory):
    site = site_factory({})
    url = "http://fixture.test/redirect-to?url=http://169.254.169.254/"
    hop = {"url": url, "status": 302, "location": "http://169.254.169.254/"}
    worker = fake_worker([b"GET http://169.254.169.254/ HTTP/1.1\r\nHost: 169.254.169.254\r\n\r\n"],
                         {"ok": False, "code": "navigation", "detail": "net::ERR_EMPTY_RESPONSE",
                          "chain": [url, "http://169.254.169.254/"], "redirects": [hop]})
    monkeypatch.setattr(nsrun, "run_worker", worker)
    conn = seam_connector({(FIXTURE_IP, 80): (site.host, site.port)})
    with pytest.raises(C.CaptureError) as e:
        C.capture_sync(url, (1280, 900), C.Settings(), resolver=FakeResolver({"fixture.test": [FIXTURE_IP]}),
                       connector=conn)
    assert e.value.code == "blocked"
    m = _partial(e.value)
    assert m["requested_url"] == url
    assert m["redirects"] == [hop]
    assert m["resolved_ips"] == [FIXTURE_IP]
    assert m["robots"] == "allowed"  # the fixture has no robots.txt: 404
    assert set(m) >= {"requested_url", "redirects", "fetched_at", "fetch_ms", "resolved_ips", "robots"}
    assert conn.calls == [(FIXTURE_IP, 80)]  # robots.txt only; the metadata address was never dialled


def _api(capture_fn):
    srv = S.make_server("127.0.0.1", 0, b"k", capture_fn, selftest={"passed": True})
    import threading
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _post(srv, url):
    import http.client
    conn = http.client.HTTPConnection("127.0.0.1", srv.server_address[1], timeout=10)
    conn.request("POST", "/v1/capture", body=json.dumps({"url": url}).encode(),
                 headers={"X-Fetcher-Secret": "k", "Content-Type": "application/json"})
    resp = conn.getresponse()
    return resp.status, json.loads(resp.read())


PARTIAL = {"requested_url": "https://r.test/a", "fetched_at": "2026-11-24T10:41:07Z", "fetch_ms": 812,
           "redirects": [{"url": "https://r.test/a", "status": 302, "location": "http://169.254.169.254/"}],
           "resolved_ips": [FIXTURE_IP], "robots": "allowed"}


def test_d2_error_answer_body_and_log_line_carry_the_partial_manifest(caplog):
    def capture_fn(url, viewport):
        err = C.CaptureError("blocked", "blocked 169.254.169.254: address-not-public 169.254.169.254")
        err.manifest = dict(PARTIAL)
        raise err

    srv = _api(capture_fn)
    try:
        with caplog.at_level(logging.INFO, logger="claim_fetcher"):
            status, body = _post(srv, "https://r.test/a")
    finally:
        srv.shutdown()
        srv.server_close()
    assert status == 403
    assert body["error"] == "blocked" and body["detail"].startswith("blocked 169.254.169.254")
    assert body.get("manifest") == PARTIAL
    lines = [json.loads(r.getMessage()) for r in caplog.records if r.getMessage().startswith("{")]
    refused = [x for x in lines if x.get("event") == "capture-refused"]
    assert refused and refused[0].get("redirects") == PARTIAL["redirects"], lines


def test_d2_error_before_any_request_has_no_manifest():
    with pytest.raises(C.CaptureError) as e:
        C.capture_sync("http://priv.test/", (1280, 900), C.Settings(),
                       resolver=FakeResolver({"priv.test": ["10.0.0.1"]}), connector=seam_connector({}))
    assert e.value.code == "blocked"
    assert getattr(e.value, "manifest", None) is None


# D3: a dropped connection is a timeout -------------------------------------------------------------------------------

def test_d3_connect_with_no_syn_ack_is_timeout_at_the_proxy():
    async def body():
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            proxy = P.EgressProxy(os.path.join(tmp, "e.sock"), resolver=FakeResolver({"drop.test": [FIXTURE_IP]}),
                                  connector=hanging_connector(), connect_timeout=0.3)
            await proxy.start()
            try:
                r, w = await asyncio.open_unix_connection(proxy.socket_path)
                w.write(b"CONNECT drop.test:443 HTTP/1.1\r\n\r\n")
                await w.drain()
                head = await asyncio.wait_for(r.readuntil(b"\r\n\r\n"), 5)
                w.close()
                assert head.split(b" ")[1] == b"504", head
                assert b"X-Fetcher-Refused: timeout" in head
                assert proxy.log[-1]["result"] == "timeout"
            finally:
                await proxy.close()
    asyncio.run(body())


def test_d3_refused_on_one_address_and_dropped_on_another_stays_unreachable():
    async def body():
        import tempfile
        calls = []

        async def connector(ip, port):
            calls.append(ip)
            if ip == FIXTURE_IP:
                raise ConnectionRefusedError(111, "refused")
            await asyncio.sleep(3600)

        with tempfile.TemporaryDirectory() as tmp:
            proxy = P.EgressProxy(os.path.join(tmp, "e.sock"),
                                  resolver=FakeResolver({"mix.test": [FIXTURE_IP, "93.184.215.15"]}),
                                  connector=connector, connect_timeout=0.3)
            await proxy.start()
            try:
                r, w = await asyncio.open_unix_connection(proxy.socket_path)
                w.write(b"CONNECT mix.test:443 HTTP/1.1\r\n\r\n")
                await w.drain()
                head = await asyncio.wait_for(r.readuntil(b"\r\n\r\n"), 5)
                w.close()
                assert b"X-Fetcher-Refused: unreachable" in head
                assert calls == [FIXTURE_IP, "93.184.215.15"]
            finally:
                await proxy.close()
    asyncio.run(body())


def test_d3_dropped_main_document_connection_is_a_408_timeout(monkeypatch):
    """http://8.8.4.4/ on the deployed fetcher: robots.txt and the page both meet a dropped SYN."""
    worker = fake_worker([b"GET http://8.8.4.4/ HTTP/1.1\r\nHost: 8.8.4.4\r\n\r\n"],
                         {"ok": False, "code": "navigation", "detail": "net::ERR_EMPTY_RESPONSE at http://8.8.4.4/",
                          "chain": ["http://8.8.4.4/"], "redirects": []})
    monkeypatch.setattr(nsrun, "run_worker", worker)
    settings = C.Settings()
    settings.connect_timeout_s = 0.5
    conn = hanging_connector()
    t0 = time.monotonic()
    with pytest.raises(C.CaptureError) as e:
        C.capture_sync("http://8.8.4.4/", (1280, 900), settings, resolver=FakeResolver({}), connector=conn)
    elapsed = time.monotonic() - t0
    assert e.value.code == "timeout", f"{e.value.code}: {e.value.detail}"
    assert e.value.http_status == 408
    assert elapsed < settings.timeout_s
    assert [c[0] for c in conn.calls] == ["8.8.4.4", "8.8.4.4"]  # robots.txt, then the page
    m = _partial(e.value)
    assert m["robots"] == "unavailable" and m["resolved_ips"] == ["8.8.4.4"]


def test_d3_settings_keep_the_15_s_wall_time():
    s = C.Settings.from_env({})
    assert s.timeout_s == 15.0
    assert s.connect_timeout_s < s.timeout_s


# integration ----------------------------------------------------------------------------------------------------------

@pytest.mark.integration
def test_d2_integration_blocked_redirect_records_the_first_hop(site_factory):
    need_sandbox()
    site = site_factory({"/evil": (302, {"Location": "http://10.0.0.5/"}, b"")})
    conn = seam_connector({(FIXTURE_IP, 80): (site.host, site.port)})
    with pytest.raises(C.CaptureError) as e:
        C.capture_sync("http://fixture.test/evil", (1280, 900), C.Settings(),
                       resolver=FakeResolver({"fixture.test": [FIXTURE_IP]}), connector=conn)
    assert e.value.code == "blocked"
    m = _partial(e.value)
    assert m["redirects"] == [{"url": "http://fixture.test/evil", "status": 302, "location": "http://10.0.0.5/"}]
    assert m["resolved_ips"] == [FIXTURE_IP]
    assert [p for p, _ in site.hits] == ["/robots.txt", "/evil"]


@pytest.mark.integration
def test_d3_integration_dropped_syn_is_timeout_in_the_real_browser():
    need_sandbox()
    settings = C.Settings()
    settings.connect_timeout_s = 1.5
    conn = hanging_connector()
    t0 = time.monotonic()
    with pytest.raises(C.CaptureError) as e:
        C.capture_sync("https://drop.test/", (1280, 900), settings, resolver=FakeResolver({"drop.test": [FIXTURE_IP]}),
                       connector=conn)
    assert e.value.code == "timeout", f"{e.value.code}: {e.value.detail}"
    assert time.monotonic() - t0 < settings.timeout_s + 1


@pytest.mark.integration
def test_d1_integration_real_capture_without_getaddrinfo(monkeypatch, site_factory):
    need_sandbox()
    site = site_factory({"/p.html": page("<p>public resolvers</p>")})
    fake = _install_fake_dns(monkeypatch, {"fixture.test": [FIXTURE_IP]})
    spy = GetaddrinfoSpy()
    monkeypatch.setattr(socket, "getaddrinfo", spy)
    conn = seam_connector({(FIXTURE_IP, 80): (site.host, site.port)})
    try:
        result = C.capture_sync("http://fixture.test/p.html", (1280, 900), C.Settings(), connector=conn)
    except C.CaptureError as e:
        result = e
    assert spy.calls == [], f"getaddrinfo was called for {spy.calls}"
    assert not isinstance(result, C.CaptureError), f"{result.code}: {result.detail}"
    assert result.manifest["status"] == 200 and result.manifest["resolved_ips"] == [FIXTURE_IP]
    assert fake.calls and {s for _, s, _, _ in fake.calls} == {"1.1.1.1"}
