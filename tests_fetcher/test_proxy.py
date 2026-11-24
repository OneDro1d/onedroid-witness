"""The egress proxy (claim_fetcher.proxy): Unix socket only, CONNECT and plain HTTP, resolve once, pin, refuse, cap."""
import asyncio
import os
import socket
import stat
import tempfile

import pytest

from claim_fetcher import proxy as P
from conftest import FIXTURE_IP, FakeResolver, seam_connector

RESOLVER = {"ok.test": [FIXTURE_IP], "127.0.0.1.nip.io": ["127.0.0.1"], "meta.test": ["169.254.169.254"]}


def run(coro):
    return asyncio.run(coro)


async def _open(proxy):
    return await asyncio.open_unix_connection(proxy.socket_path)


async def _head(reader):
    """(status, headers), or (None, {}) when the proxy closed without a byte (its plain-HTTP refusal: page script must
    see a network error, never a response it could take for the origin's)."""
    try:
        data = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 5)
    except asyncio.IncompleteReadError as e:
        assert e.partial == b"", f"a refusal sends nothing or a whole head, got {e.partial!r}"
        return None, {}
    lines = data.decode("latin-1").split("\r\n")
    status = int(lines[0].split()[1])
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return status, headers


def _make(tmp, resolver=None, connector=None, **kw):
    return P.EgressProxy(os.path.join(tmp, "egress.sock"), resolver=resolver or FakeResolver(RESOLVER),
                         connector=connector, **kw)


def test_listens_only_on_a_private_unix_socket():
    async def body():
        with tempfile.TemporaryDirectory() as tmp:
            proxy = _make(tmp)
            await proxy.start()
            try:
                families = {s.family for s in proxy.server.sockets}
                assert families == {socket.AF_UNIX}
                mode = stat.S_IMODE(os.stat(proxy.socket_path).st_mode)
                assert mode & 0o077 == 0
            finally:
                await proxy.close()
            assert not os.path.exists(proxy.socket_path)
    run(body())


@pytest.mark.parametrize("target,code", [("127.0.0.1.nip.io:443", "blocked"), ("meta.test:80", "blocked"),
                                         ("10.0.0.1:443", "blocked"), ("[::1]:443", "blocked"),
                                         ("ok.test:22", "port"), ("ok.test:8080", "port"),
                                         ("nx.test:443", "unreachable"), ("kubernetes.default.svc:443", "blocked")])
def test_connect_refusals(target, code):
    async def body():
        with tempfile.TemporaryDirectory() as tmp:
            conn = seam_connector({})
            proxy = _make(tmp, connector=conn)
            await proxy.start()
            try:
                r, w = await _open(proxy)
                w.write(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode())
                await w.drain()
                status, headers = await _head(r)
                w.close()
                assert status in (403, 502)
                assert headers["x-fetcher-refused"] == code
                assert conn.calls == []
                assert proxy.log[-1]["result"] == code
            finally:
                await proxy.close()
    run(body())


def test_plain_http_forwarded_to_pinned_address_in_origin_form(site_factory):
    site = site_factory({"/hello": (200, {"Content-Type": "text/plain"}, b"hello")})

    async def body():
        with tempfile.TemporaryDirectory() as tmp:
            conn = seam_connector({(FIXTURE_IP, 80): (site.host, site.port)})
            resolver = FakeResolver(RESOLVER)
            proxy = _make(tmp, resolver=resolver, connector=conn)
            await proxy.start()
            try:
                r, w = await _open(proxy)
                w.write(b"GET http://ok.test/hello HTTP/1.1\r\nHost: ok.test\r\nProxy-Connection: keep-alive\r\n"
                        b"Proxy-Authorization: Basic eDp5\r\n\r\n")
                await w.drain()
                status, headers = await _head(r)
                payload = await asyncio.wait_for(r.read(), 5)
                w.close()
                assert status == 200 and payload == b"hello"
                assert conn.calls == [(FIXTURE_IP, 80)]
                assert resolver.calls == ["ok.test"]
                path, seen = site.hits[0]
                assert path == "/hello"
                assert seen.get("Host") == "ok.test"
                assert "Proxy-Authorization" not in seen and "Proxy-Connection" not in seen
                assert proxy.resolved["ok.test"] == [FIXTURE_IP]
                assert proxy.log[-1]["pinned"] == FIXTURE_IP
            finally:
                await proxy.close()
    run(body())


def test_plain_http_absolute_form_with_private_target_refused():
    async def body():
        with tempfile.TemporaryDirectory() as tmp:
            conn = seam_connector({})
            proxy = _make(tmp, connector=conn)
            await proxy.start()
            try:
                r, w = await _open(proxy)
                w.write(b"GET http://169.254.169.254/latest/meta-data/ HTTP/1.1\r\nHost: 169.254.169.254\r\n\r\n")
                await w.drain()
                status, headers = await _head(r)
                w.close()
                assert status is None  # closed with no answer: a fetch() in the page rejects
                assert conn.calls == []
                assert proxy.log[-1]["result"] == "blocked"
            finally:
                await proxy.close()
    run(body())


def test_connect_tunnel_splices_bytes():
    async def body():
        async def echo(reader, writer):
            data = await reader.read(100)
            writer.write(b"echo:" + data)
            await writer.drain()
            writer.close()

        server = await asyncio.start_server(echo, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        with tempfile.TemporaryDirectory() as tmp:
            conn = seam_connector({(FIXTURE_IP, 443): ("127.0.0.1", port)})
            proxy = _make(tmp, connector=conn)
            await proxy.start()
            try:
                r, w = await _open(proxy)
                w.write(b"CONNECT ok.test:443 HTTP/1.1\r\nHost: ok.test:443\r\n\r\n")
                await w.drain()
                status, _ = await _head(r)
                assert status == 200
                w.write(b"ping")
                await w.drain()
                assert await asyncio.wait_for(r.read(100), 5) == b"echo:ping"
                w.close()
            finally:
                await proxy.close()
                server.close()
    run(body())


def test_every_request_resolved_again_so_rebinding_is_refused(site_factory):
    site = site_factory({"/": (200, {}, b"first")})

    async def body():
        with tempfile.TemporaryDirectory() as tmp:
            resolver = FakeResolver({"rebind.test": [[FIXTURE_IP], ["127.0.0.1"]]})
            conn = seam_connector({(FIXTURE_IP, 80): (site.host, site.port)})
            proxy = _make(tmp, resolver=resolver, connector=conn)
            await proxy.start()
            try:
                for expect in (200, None):
                    r, w = await _open(proxy)
                    w.write(b"GET http://rebind.test/ HTTP/1.1\r\nHost: rebind.test\r\n\r\n")
                    await w.drain()
                    status, _ = await _head(r)
                    await r.read()
                    w.close()
                    assert status == expect
                assert resolver.calls == ["rebind.test", "rebind.test"]
                assert conn.calls == [(FIXTURE_IP, 80)]
            finally:
                await proxy.close()
    run(body())


def test_plain_http_response_over_cap_refused(site_factory):
    big = b"x" * 2048
    site = site_factory({"/big": (200, {"Content-Type": "text/plain"}, big)})

    async def body():
        with tempfile.TemporaryDirectory() as tmp:
            conn = seam_connector({(FIXTURE_IP, 80): (site.host, site.port)})
            proxy = _make(tmp, connector=conn, max_response_bytes=1024)
            await proxy.start()
            try:
                r, w = await _open(proxy)
                w.write(b"GET http://ok.test/big HTTP/1.1\r\nHost: ok.test\r\n\r\n")
                await w.drain()
                got = await asyncio.wait_for(r.read(), 5)
                w.close()
                assert len(got) < len(big)
                assert any(e["result"] == "too-large" for e in proxy.log)
                assert proxy.too_large
            finally:
                await proxy.close()
    run(body())


def test_total_budget_cuts_tunnels():
    async def body():
        async def flood(reader, writer):
            await reader.read(10)
            try:
                for _ in range(100):
                    writer.write(b"y" * 1000)
                    await writer.drain()
            except (ConnectionError, OSError):
                pass
            writer.close()

        server = await asyncio.start_server(flood, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        with tempfile.TemporaryDirectory() as tmp:
            conn = seam_connector({(FIXTURE_IP, 443): ("127.0.0.1", port)})
            proxy = _make(tmp, connector=conn, max_total_bytes=5000)
            await proxy.start()
            try:
                r, w = await _open(proxy)
                w.write(b"CONNECT ok.test:443 HTTP/1.1\r\n\r\n")
                await w.drain()
                await _head(r)
                w.write(b"go")
                await w.drain()
                total = 0
                while True:
                    chunk = await asyncio.wait_for(r.read(65536), 5)
                    if not chunk:
                        break
                    total += len(chunk)
                assert total <= 5000
                assert proxy.too_large
            finally:
                await proxy.close()
                server.close()
    run(body())


@pytest.mark.parametrize("line", [b"GET /relative HTTP/1.1", b"NONSENSE", b"GET ftp://ok.test/ HTTP/1.1",
                                  b"CONNECT ok.test HTTP/1.1"])
def test_malformed_or_odd_requests_refused(line):
    async def body():
        with tempfile.TemporaryDirectory() as tmp:
            conn = seam_connector({})
            proxy = _make(tmp, connector=conn)
            await proxy.start()
            try:
                r, w = await _open(proxy)
                w.write(line + b"\r\n\r\n")
                await w.drain()
                status, headers = await _head(r)
                w.close()
                assert status is None or 400 <= status < 500
                assert conn.calls == []
            finally:
                await proxy.close()
    run(body())


def test_connect_failure_is_unreachable():
    async def body():
        with tempfile.TemporaryDirectory() as tmp:
            proxy = _make(tmp, connector=seam_connector({}))  # no route: the connect fails
            await proxy.start()
            try:
                r, w = await _open(proxy)
                w.write(b"CONNECT ok.test:443 HTTP/1.1\r\n\r\n")
                await w.drain()
                status, headers = await _head(r)
                w.close()
                assert status == 502 and headers["x-fetcher-refused"] == "unreachable"
            finally:
                await proxy.close()
    run(body())
