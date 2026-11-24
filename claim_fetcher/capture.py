"""One capture, end to end, and the start-up self-test.

capture(): check the URL and its host (no browser starts for a refused target) -> a fresh egress proxy on a Unix
socket in a private temporary directory -> robots.txt through that proxy -> the worker in its namespace -> the manifest
over the files it wrote. The whole capture is bounded by Settings.timeout_s (15 s); the proxy is closed and the
directory removed whatever happens.
"""
import asyncio
import contextlib
import dataclasses
import hashlib
import io
import json
import os
import shutil
import socket
import tarfile
import tempfile
import time
import urllib.parse

from . import FETCHER_ID, VERSION, addr, dnsclient, nsrun, robots
from .proxy import EgressProxy

FILE_ORDER = ("capture.wacz", "response.body", "screenshot.png", "rendered.html", "hidden-nodes.json")
MEDIA = {"capture.wacz": "application/wacz", "screenshot.png": "image/png", "rendered.html": "text/html",
         "hidden-nodes.json": "application/json"}
HTTP_STATUS = {"bad-request": 400, "scheme": 400, "port": 400, "unauthorized": 401, "blocked": 403,
               "robots-disallowed": 403, "timeout": 408, "too-large": 413, "unreachable": 422, "internal": 500,
               "busy": 503}
SERVICE_ACCOUNT_DIR = "/var/run/secrets/kubernetes.io"
user_agent_for = robots.user_agent_for


class CaptureError(Exception):
    """A refusal or failure with one of the API's codes. `manifest` is the partial manifest (partial_manifest) when
    the error came after at least one request was made, else None."""

    def __init__(self, code, detail="", proxy_log=None, manifest=None):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code, self.detail, self.proxy_log = code, detail, list(proxy_log or [])
        self.manifest = manifest

    @property
    def http_status(self):
        return HTTP_STATUS.get(self.code, 422)


@dataclasses.dataclass
class Settings:
    timeout_s: float = 15.0
    max_response_bytes: int = 10 * 1024 * 1024
    max_total_bytes: int = 30 * 1024 * 1024
    blocked_cidrs: tuple = ()
    resolvers: tuple = dnsclient.DEFAULT_RESOLVERS  # public DNS resolvers; each must pass the address rules
    connect_timeout_s: float = 5.0  # per vetted address; no SYN-ACK on every one of them is `timeout`
    max_redirects: int = addr.MAX_REDIRECTS
    settle_ms: int = 5000
    robots_unavailable: str = "allow"
    work_dir: str = None
    python: str = None
    user_agent: str = None  # None: robots.user_agent_for(the browser's version)
    hide_paths: tuple = (SERVICE_ACCOUNT_DIR,)
    require_hidden: bool = False  # True: a path that could not be hidden fails the self-test and every capture

    @classmethod
    def from_env(cls, env=None):
        env = os.environ if env is None else env
        s = cls(blocked_cidrs=addr.parse_cidrs(env.get("FETCHER_BLOCKED_CIDRS", "")))
        # ValueError (the service refuses to start) for a resolver that is not a public address outside the CIDRs
        s.resolvers = dnsclient.parse_resolvers(env.get("FETCHER_RESOLVERS") or ",".join(dnsclient.DEFAULT_RESOLVERS),
                                                s.blocked_cidrs)
        if env.get("FETCHER_CONNECT_TIMEOUT_S"):
            s.connect_timeout_s = float(env["FETCHER_CONNECT_TIMEOUT_S"])
        if env.get("FETCHER_TIMEOUT_S"):
            s.timeout_s = float(env["FETCHER_TIMEOUT_S"])
        if env.get("FETCHER_MAX_RESPONSE_BYTES"):
            s.max_response_bytes = int(env["FETCHER_MAX_RESPONSE_BYTES"])
        if env.get("FETCHER_SETTLE_MS"):
            s.settle_ms = int(env["FETCHER_SETTLE_MS"])
        if env.get("FETCHER_ROBOTS_UNAVAILABLE"):
            s.robots_unavailable = env["FETCHER_ROBOTS_UNAVAILABLE"]
        s.work_dir = env.get("FETCHER_WORK_DIR") or None
        if env.get("FETCHER_USER_AGENT"):
            s.user_agent = env["FETCHER_USER_AGENT"]
        hide = [SERVICE_ACCOUNT_DIR]
        if env.get("FETCHER_SECRET_FILE"):
            hide.insert(0, os.path.dirname(os.path.abspath(env["FETCHER_SECRET_FILE"])))
        hide += [p for p in (env.get("FETCHER_HIDE_PATHS") or "").split(":") if p]
        s.hide_paths = tuple(dict.fromkeys(hide))
        s.require_hidden = env.get("FETCHER_REQUIRE_HIDDEN", "") in ("1", "true", "yes")
        return s


@dataclasses.dataclass
class Result:
    manifest: dict
    files: dict
    proxy_log: list


def _now_iso():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def build_manifest(requested_url, final_url, redirects, fetched_at, fetch_ms, status, resolved_ips, tls, robots,
                   browser, viewport, files, body_media_type=None, user_agent=None):
    entries = []
    for name in [n for n in FILE_ORDER if n in files] + sorted(n for n in files if n not in FILE_ORDER):
        blob = files[name]
        entry = {"name": name, "sha256": hashlib.sha256(blob).hexdigest(), "size": len(blob)}
        if name in MEDIA:
            entry["media_type"] = MEDIA[name]
        elif name == "response.body" and body_media_type:
            entry["media_type"] = body_media_type
        entries.append(entry)
    return {"requested_url": requested_url, "final_url": final_url, "redirects": list(redirects),
            "fetched_at": fetched_at, "fetch_ms": int(fetch_ms), "status": status, "resolved_ips": list(resolved_ips),
            "tls": tls, "robots": robots,
            "fetcher": {"id": FETCHER_ID, "version": VERSION, "browser": browser, "viewport": list(viewport),
                        "user_agent": user_agent,
                        "isolation": "userns+netns(lo only)+mountns, unix-socket egress proxy"},
            "files": entries}


def to_tar(manifest, files):
    out = io.BytesIO()
    mtime = 0
    with tarfile.open(fileobj=out, mode="w", format=tarfile.PAX_FORMAT) as tar:
        blobs = [("manifest.json", json.dumps(manifest, sort_keys=True, indent=1).encode())]
        blobs += [(e["name"], files[e["name"]]) for e in manifest["files"]]
        for name, blob in blobs:
            info = tarfile.TarInfo(name)
            info.size, info.mtime, info.mode = len(blob), mtime, 0o644
            tar.addfile(info, io.BytesIO(blob))
    return out.getvalue()


def _host_of(url):
    try:
        return addr.check_url(url)[1]
    except addr.Refused:
        return (urllib.parse.urlsplit(url).hostname or "").lower()


def _refusal_for(proxy, chain):
    hosts = {_host_of(u) for u in chain}
    for entry in proxy.log:
        if entry.get("host") in hosts and entry.get("result") in ("blocked", "port", "scheme"):
            return entry["result"], f"{entry['result']} {entry.get('host')}: {entry.get('detail', '')}".strip()
    return None


def _connect_timed_out(proxy, chain):
    """The detail when the proxy's last attempt at the main document's current hop (the chain's last URL) was a
    connect timeout on every vetted address, else None."""
    if not chain:
        return None
    try:
        _, host, port = addr.check_url(chain[-1])
    except addr.Refused:
        return None
    for entry in reversed(proxy.log):
        if entry.get("host") == host and entry.get("port") == port:
            if entry.get("result") == "timeout":
                return f"timeout {host}: {entry.get('detail', '')}".strip()
            return None
    return None


def partial_manifest(requested_url, redirects, fetched_at, fetch_ms, resolved_ips, robots, robots_txt=None):
    """What an error answer carries once at least one request was made: the request, the redirect hops recorded so
    far, the addresses vetted so far for the hosts of the chain, and the robots decision (None when not reached).
    `robots_txt` {url, status, sha256} when robots.txt was read."""
    return {"requested_url": requested_url, "redirects": list(redirects), "fetched_at": fetched_at,
            "fetch_ms": int(fetch_ms), "resolved_ips": list(resolved_ips), "robots": robots, "robots_txt": robots_txt}


def _chain_ips(proxy, chain, host, ips):
    out = []
    for u in chain:
        h = _host_of(u)
        for ip in proxy.resolved.get(h) or (ips if h == host else []):
            if ip not in out:
                out.append(ip)
    return out


async def capture(url, viewport=(1280, 900), settings=None, resolver=None, connector=None):
    settings = settings or Settings()
    t0 = time.monotonic()
    deadline = t0 + settings.timeout_s
    fetched_at = _now_iso()
    loop = asyncio.get_running_loop()
    # names are resolved only through the configured public resolvers, never the system resolver (defect D1)
    resolver = resolver or dnsclient.PublicResolver(settings.resolvers, extra=settings.blocked_cidrs)
    try:
        _, host, port, ips = await asyncio.wait_for(
            loop.run_in_executor(None, lambda: addr.check_target(url, resolver=resolver,
                                                                 extra=settings.blocked_cidrs)), 5)
    except addr.Refused as e:
        raise CaptureError(e.code, e.detail) from None
    except asyncio.TimeoutError:
        raise CaptureError("unreachable", "resolve-timeout") from None
    tmp = tempfile.mkdtemp(prefix="claim-fetch-", dir=settings.work_dir)
    os.chmod(tmp, 0o700)
    out_dir = os.path.join(tmp, "out")
    os.mkdir(out_dir, 0o700)
    proxy = EgressProxy(os.path.join(tmp, "egress.sock"), resolver=resolver, connector=connector,
                        extra_cidrs=settings.blocked_cidrs, max_response_bytes=settings.max_response_bytes,
                        max_total_bytes=settings.max_total_bytes, connect_timeout=settings.connect_timeout_s)
    # what is known so far, for the partial manifest of an error answer (defects D2 and D4)
    state = {"redirects": [], "chain": [url], "robots": None, "robots_txt": None}
    await proxy.start()
    try:
        try:
            got = await asyncio.wait_for(robots.fetch_info(proxy.socket_path, url,
                                                           settings.user_agent or robots.user_agent_for()),
                                         max(0.1, deadline - time.monotonic()))
        except asyncio.TimeoutError:
            raise CaptureError("timeout", "robots.txt", proxy.log) from None
        status, body = got["status"], got["body"]
        if status is not None:
            state["robots_txt"] = {"url": got["url"], "status": status,
                                   "sha256": hashlib.sha256(body or b"").hexdigest()}
        decision = robots.decide(status, body, robots.target_of(url))
        state["robots"] = decision
        if decision == "disallowed":
            raise CaptureError("robots-disallowed", robots.target_of(url), proxy.log)
        if decision == "unavailable" and settings.robots_unavailable == "deny":
            raise CaptureError("robots-disallowed", "robots.txt unavailable", proxy.log)
        remaining = deadline - time.monotonic()
        if remaining < 2:
            raise CaptureError("timeout", "no time left after robots.txt", proxy.log)
        payload = {"url": url, "viewport": list(viewport), "proxy_socket": proxy.socket_path, "out_dir": out_dir,
                   "budget_ms": int((remaining - 0.5) * 1000), "max_response_bytes": settings.max_response_bytes,
                   "settle_ms": settings.settle_ms, "user_agent": settings.user_agent, "fetched_at": fetched_at,
                   "max_redirects": settings.max_redirects, "hide_paths": list(settings.hide_paths),
                   "require_hidden": settings.require_hidden}
        try:
            res = await nsrun.run_worker(["capture"], payload, remaining, python=settings.python)
        except asyncio.TimeoutError:
            raise CaptureError("timeout", f"{settings.timeout_s:g} s", proxy.log) from None
        except nsrun.WorkerError as e:
            raise CaptureError("internal", str(e), proxy.log) from None
        state["redirects"] = list(res.get("redirects") or [])
        state["chain"] = list(res.get("chain") or [url])
        if not res.get("ok"):
            code, detail, chain = res.get("code"), res.get("detail", ""), res.get("chain") or [url]
            if code == "too-many-redirects":
                raise CaptureError("blocked", detail, proxy.log)
            if code == "too-large" or proxy.too_large:
                raise CaptureError("too-large", detail, proxy.log)
            refusal = _refusal_for(proxy, chain)
            if refusal:
                raise CaptureError(refusal[0], refusal[1], proxy.log)
            # no SYN-ACK from any vetted address of the main document: a timeout, not unreachable (defect D3)
            dropped = _connect_timed_out(proxy, chain)
            if dropped:
                raise CaptureError("timeout", f"{dropped} ({detail})" if detail else dropped, proxy.log)
            if code == "timeout":
                raise CaptureError("timeout", detail, proxy.log)
            if code in ("isolation", "internal"):
                raise CaptureError("internal", detail, proxy.log)
            raise CaptureError("unreachable", detail, proxy.log)
        if len(res.get("redirects") or []) > settings.max_redirects:
            raise CaptureError("blocked", "too-many-redirects", proxy.log)
        files = {}
        for name in FILE_ORDER:
            with open(os.path.join(out_dir, name), "rb") as f:
                files[name] = f.read()
        final_host = _host_of(res["final_url"])
        manifest = build_manifest(
            requested_url=url, final_url=res["final_url"], redirects=res.get("redirects") or [],
            fetched_at=fetched_at, fetch_ms=(time.monotonic() - t0) * 1000, status=res.get("status"),
            resolved_ips=proxy.resolved.get(final_host) or (ips if final_host == host else []), tls=res.get("tls"),
            robots=decision, browser=res.get("browser"), viewport=viewport, files=files,
            body_media_type=res.get("mime") or None, user_agent=res.get("user_agent"))
        return Result(manifest, files, list(proxy.log))
    except CaptureError as e:
        if e.manifest is None:  # every error after the first request (robots.txt) carries what was seen
            e.manifest = partial_manifest(
                requested_url=url, redirects=state["redirects"], fetched_at=fetched_at,
                fetch_ms=(time.monotonic() - t0) * 1000, resolved_ips=_chain_ips(proxy, state["chain"], host, ips),
                robots=state["robots"], robots_txt=state["robots_txt"])
        raise
    finally:
        await proxy.close()
        shutil.rmtree(tmp, ignore_errors=True)


def capture_sync(url, viewport=(1280, 900), settings=None, resolver=None, connector=None):
    return asyncio.run(capture(url, viewport, settings, resolver=resolver, connector=connector))


def _own_address():
    for target in ("10.255.255.255", "192.0.2.1"):
        with contextlib.suppress(OSError):
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect((target, 9))
                ip = s.getsockname()[0]
                if not ip.startswith("127.") and ip != "0.0.0.0":
                    return ip
    return None


async def selftest(settings=None, extra_probes=()):
    """The start-up self-test. Besides the fixed probes, a listener is opened on this pod's own address outside the
    namespace and probed from inside it: a private address that really answers, which the namespace must not reach."""
    settings = settings or Settings()
    probes = [list(p) for p in extra_probes]
    listener, hits = None, []
    own = _own_address()
    if own:
        with contextlib.suppress(OSError):
            listener = await asyncio.start_server(lambda r, w: (hits.append(1), w.close()), own, 0)
            probes.append([own, listener.sockets[0].getsockname()[1]])
    tmp = tempfile.mkdtemp(prefix="claim-selftest-", dir=settings.work_dir)
    os.chmod(tmp, 0o700)
    resolvers, resolver_problem = list(settings.resolvers), None
    try:
        resolver = dnsclient.PublicResolver(resolvers, extra=settings.blocked_cidrs)
    except ValueError as e:  # Settings.from_env refuses these already; a hand-made Settings may not have
        resolver, resolver_problem = None, f"resolvers: {e}"
    proxy = EgressProxy(os.path.join(tmp, "egress.sock"), resolver=resolver or dnsclient.default_resolver(),
                        extra_cidrs=settings.blocked_cidrs)
    await proxy.start()
    try:
        result = await nsrun.run_worker(["selftest"], {"proxy_socket": proxy.socket_path, "probes": probes,
                                                      "hide_paths": list(settings.hide_paths),
                                                      "require_hidden": settings.require_hidden}, 60,
                                        python=settings.python)
    except (asyncio.TimeoutError, nsrun.WorkerError, OSError) as e:
        result = {"passed": False, "reasons": [f"worker: {type(e).__name__}: {e}"[:500]]}
    finally:
        await proxy.close()
        shutil.rmtree(tmp, ignore_errors=True)
        if listener:
            listener.close()
    if "code" in result and "interfaces" not in result:
        result = {"passed": False, "reasons": [result.get("detail", "worker failed")]}
    if hits:
        result["passed"] = False
        result.setdefault("reasons", []).append("the own-address listener was reached from the namespace")
    result["own_address_probe"] = bool(own and listener)
    # the public DNS resolvers every capture target is resolved through (never the pod's cluster DNS)
    result["resolvers"] = resolvers
    if resolver_problem:
        result["passed"] = False
        result.setdefault("reasons", []).append(resolver_problem)
    return result


def run_selftest(settings=None, extra_probes=()):
    return asyncio.run(selftest(settings, extra_probes))
