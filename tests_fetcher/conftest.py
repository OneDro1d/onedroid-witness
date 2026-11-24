"""Shared helpers for the claim fetcher tests (pytest).

Unit tests need nothing but the standard library and the package. Integration tests (marked `integration`) also need
`unshare` that can make an unprivileged user + network namespace, Playwright for Python and its Chromium; each one skips
with the reason when something is missing.

The one seam the integration tests use is the egress proxy's outbound connector: a fixture site is given a public
address by a fake resolver, and the connector carries that pinned address to a local test server. Everything between
the page and that last hop (the namespace, the loopback bridge, the Unix socket, the proxy's address rules) is real.
"""
import asyncio
import contextlib
import http.server
import os
import pathlib
import shutil
import socket
import subprocess
import sys
import threading

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

FIXTURE_IP = "93.184.215.14"  # a public address the fake resolver gives fixture hosts; never dialled for real


def pytest_configure(config):
    config.addinivalue_line("markers", "integration: needs unshare, Playwright and Chromium")


class FakeResolver:
    """host -> list of addresses, or an exception to raise; a list of answers is used one per call (rebinding)."""

    def __init__(self, mapping):
        self.mapping = dict(mapping)
        self.calls = []

    def __call__(self, host):
        self.calls.append(host)
        key = host.rstrip(".").lower()
        if key not in self.mapping:
            raise OSError(f"fake resolver: no such host {key}")
        value = self.mapping[key]
        if isinstance(value, BaseException):
            raise value
        if value and isinstance(value[0], list):  # a sequence of answers
            answer = value.pop(0) if len(value) > 1 else value[0]
            return list(answer)
        return list(value)


def seam_connector(routes):
    """An async connector for the proxy: (pinned ip, port) -> a local (host, port). Records every call."""
    calls = []

    async def connect(ip, port):
        calls.append((ip, port))
        target = routes.get((ip, port))
        if target is None:
            raise OSError(f"seam: no route for {ip}:{port}")
        return await asyncio.open_connection(*target)

    connect.calls = calls
    return connect


class Site:
    """A threaded local HTTP server serving a dict path -> (status, headers, body | callable)."""

    def __init__(self, routes, host="127.0.0.1"):
        self.routes = routes
        self.hits = []
        site = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def do_GET(self):
                site.hits.append((self.path, dict(self.headers)))
                route = site.routes.get(self.path.split("?", 1)[0])
                if route is None:
                    status, headers, body = 404, {"Content-Type": "text/plain"}, b"not found"
                else:
                    status, headers, body = route
                if callable(body):
                    body = body(self)
                    if body is None:
                        return
                self.send_response(status)
                for k, v in headers.items():
                    self.send_header(k, v)
                if "Content-Length" not in headers:
                    self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                with contextlib.suppress(OSError):
                    self.wfile.write(body)

        self.server = http.server.ThreadingHTTPServer((host, 0), Handler)
        self.server.daemon_threads = True
        self.host, self.port = self.server.server_address[:2]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def site_factory():
    made = []

    def make(routes, host="127.0.0.1"):
        s = Site(routes, host)
        made.append(s)
        return s

    yield make
    for s in made:
        s.close()


def primary_ip():
    """This machine's own non-loopback IPv4 address (no packet is sent), or None."""
    for probe in ("10.255.255.255", "192.0.2.1"):
        with contextlib.suppress(OSError):
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect((probe, 9))
                ip = s.getsockname()[0]
                if not ip.startswith("127.") and ip != "0.0.0.0":
                    return ip
    return None


def _unshare_ok():
    exe = shutil.which("unshare")
    if not exe:
        return "unshare not installed"
    try:
        out = subprocess.run([exe, "--user", "--net", "--map-root-user", "cat", "/proc/net/dev"],
                             capture_output=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired) as e:
        return f"unshare failed: {e}"
    if out.returncode != 0:
        return "unshare cannot create a user+net namespace: " + out.stderr.decode(errors="replace").strip()
    return None


def _chromium_ok():
    try:
        import playwright  # noqa: F401
    except ImportError:
        return "playwright not installed"
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            path = p.chromium.executable_path
    except Exception as e:  # noqa: BLE001
        return f"playwright chromium unavailable: {e}"
    if not os.path.exists(path):
        return f"chromium not downloaded at {path} (python -m playwright install chromium)"
    return None


_SKIP = {}


def need_sandbox():
    if "sandbox" not in _SKIP:
        _SKIP["sandbox"] = _unshare_ok() or _chromium_ok()
    if _SKIP["sandbox"]:
        pytest.skip(_SKIP["sandbox"])


def online(host="example.com", port=443, timeout=3.0):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False
