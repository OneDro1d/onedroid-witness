"""The worker that runs INSIDE the unprivileged user + network namespace (started by nsrun.run_worker):

    unshare --user --net --map-root-user -- python -m claim_fetcher.sandbox {selftest|capture}

It reads one JSON request on stdin and writes one line "RESULT <json>" on stdout. Inside the namespace the only
interface is `lo`. The worker brings `lo` up (it holds CAP_NET_ADMIN over this namespace only), opens a TCP listener on
127.0.0.1:<random port> that bridges each connection over the Unix socket to the egress proxy outside, and starts
Chromium with that listener as its HTTP proxy. Page script therefore has no route anywhere: WebRTC, QUIC, DNS and
direct sockets all meet a network with no interface but loopback, and loopback holds nothing but the bridge.

selftest: the interface list from /proc/net/dev, direct connect probes to private and public addresses (all must
fail), a CONNECT to a private address through the bridge (the proxy must refuse it), and a page-script fetch() to a
private address in the real browser (must fail). capture: one page, recorded through the Chrome DevTools Protocol.
"""
import asyncio
import base64
import contextlib
import errno
import fcntl
import hashlib
import json
import os
import pathlib
import socket
import struct
import sys
import time

from . import FETCHER_ID, VERSION, robots, wacz

BROWSER_ARGS = [
    "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
    "--webrtc-ip-handling-policy=disable_non_proxied_udp",
    "--disable-quic",
    "--dns-prefetch-disable",
    "--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE 127.0.0.1",
    "--disable-features=NetworkPrediction,DnsOverHttps,Translate,OptimizationHints,MediaRouter,AutofillServerCommunication",
    "--disable-background-networking",
    "--disable-component-update",
    "--disable-domain-reliability",
    "--disable-sync",
    "--no-pings",
    "--no-first-run",
    "--disable-breakpad",
    "--disable-dev-shm-usage",
    "--metrics-recording-only",
    "--mute-audio",
]
DEFAULT_PROBES = [("10.0.0.1", 80), ("169.254.169.254", 80), ("172.16.0.1", 443), ("192.168.0.1", 80),
                  ("100.64.0.1", 80), ("1.1.1.1", 443), ("8.8.8.8", 53), ("2606:4700:4700::1111", 443)]
MAX_SHOT_HEIGHT = 16384
MAX_RESOURCES = 400
HIDDEN_JS = "\n".join(line for line in (pathlib.Path(__file__).with_name("hidden.js")).read_text().splitlines()
                      if not line.lstrip().startswith("//"))
SIOCGIFFLAGS, SIOCSIFFLAGS, IFF_UP = 0x8913, 0x8914, 0x1
MS_RDONLY, MS_NOSUID, MS_NODEV, MS_NOEXEC = 0x1, 0x2, 0x4, 0x8


def emit(obj):
    sys.stdout.write("RESULT " + json.dumps(obj, sort_keys=True) + "\n")
    sys.stdout.flush()


def interfaces(proc_net_dev_text):
    out = []
    for line in proc_net_dev_text.splitlines()[2:]:
        name, sep, _ = line.partition(":")
        if sep and name.strip():
            out.append(name.strip())
    return out


def read_interfaces():
    with open("/proc/net/dev") as f:
        return interfaces(f.read())


def lo_up():
    """Set IFF_UP on lo (a new network namespace starts with lo down)."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        req = struct.pack("16sH22x", b"lo", 0)
        flags = struct.unpack("16sH22x", fcntl.ioctl(s, SIOCGIFFLAGS, req))[1]
        if not flags & IFF_UP:
            fcntl.ioctl(s, SIOCSIFFLAGS, struct.pack("16sH22x", b"lo", flags | IFF_UP))


def hide_paths(paths):
    """Cover each existing directory with an empty read-only tmpfs, in this worker's own mount namespace (nsrun
    starts it with --mount, so the service outside sees nothing change). Returns [{path, result}], result one of
    hidden | absent | readable | failed: <reason>."""
    import ctypes
    import ctypes.util
    out = []
    libc = None
    for path in paths or []:
        if not os.path.isdir(path):
            out.append({"path": path, "result": "absent"})
            continue
        try:
            if libc is None:
                libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)
            rc = libc.mount(b"none", path.encode(), b"tmpfs", MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC,
                            b"size=4k,mode=0500")
            if rc != 0:
                err = ctypes.get_errno()
                out.append({"path": path, "result": f"failed: {errno.errorcode.get(err, err)}"})
                continue
            out.append({"path": path, "result": "hidden" if not os.listdir(path) else "readable"})
        except OSError as e:
            out.append({"path": path, "result": f"failed: {type(e).__name__}"})
    return out


def hide_ok(entry, required):
    """hidden and absent are fine; readable (mounted, yet the contents show) never is; failed only when required."""
    result = entry.get("result") or ""
    if result in ("hidden", "absent"):
        return True
    if result.startswith("failed"):
        return not required
    return False


def probe(host, port, timeout=2.0):
    fam = socket.AF_INET6 if ":" in host else socket.AF_INET
    s = socket.socket(fam, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        return "connected"
    except socket.timeout:
        return "failed: timeout"
    except OSError as e:
        return "failed: " + (errno.errorcode.get(e.errno, str(e.errno)) if e.errno else str(e))
    finally:
        s.close()


def verdict(result):
    """passed only if the namespace shows only lo, at least one probe ran and none connected, and the proxy refused a
    private CONNECT that came through the bridge."""
    reasons = []
    if result.get("interfaces") != ["lo"]:
        reasons.append(f"interfaces {result.get('interfaces')}")
    probes = result.get("probes") or []
    if not probes:
        reasons.append("no probe ran")
    if any(p.get("result") == "connected" for p in probes):
        reasons.append("a probe connected")
    if (result.get("proxy_probe") or {}).get("result") != "refused":
        reasons.append("proxy did not refuse a private CONNECT")
    if (result.get("browser_probe") or {}).get("result") == "reached":
        reasons.append("page script reached a private address")
    for h in result.get("hidden_paths") or []:
        if not hide_ok(h, result.get("hide_required", False)):
            reasons.append(f"path not hidden: {h.get('path')} ({h.get('result')})")
    return dict(result, passed=not reasons, reasons=reasons)


# the bridge -----------------------------------------------------------------------------------------------------------

async def start_bridge(proxy_socket):
    async def pipe(src, dst):
        with contextlib.suppress(Exception):
            while True:
                data = await src.read(65536)
                if not data:
                    break
                dst.write(data)
                await dst.drain()
        with contextlib.suppress(Exception):
            dst.close()

    async def handle(reader, writer):
        try:
            ur, uw = await asyncio.open_unix_connection(proxy_socket)
        except OSError:
            writer.close()
            return
        await asyncio.gather(pipe(reader, uw), pipe(ur, writer))

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    return server, server.sockets[0].getsockname()[1]


async def proxy_probe(port, target="10.0.0.1:443"):
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection("127.0.0.1", port), 3)
        w.write(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode())
        await w.drain()
        head = await asyncio.wait_for(r.readuntil(b"\r\n\r\n"), 5)
        w.close()
        status = head.split(b" ", 2)[1].decode()
        return {"target": target, "status": status, "result": "refused" if status in ("403", "502") else "allowed"}
    except Exception as e:  # noqa: BLE001
        return {"target": target, "result": f"error: {type(e).__name__}"}


# the browser ----------------------------------------------------------------------------------------------------------

async def launch(pw, port):
    return await pw.chromium.launch(headless=True, args=BROWSER_ARGS,
                                    proxy={"server": f"http://127.0.0.1:{port}"})


async def selftest(req):
    from playwright.async_api import async_playwright
    out = {"fetcher": {"id": FETCHER_ID, "version": VERSION}}
    out["hidden_paths"] = hide_paths(req.get("hide_paths"))
    out["hide_required"] = bool(req.get("require_hidden"))
    lo_up()
    out["interfaces"] = read_interfaces()
    probes = [tuple(p) for p in DEFAULT_PROBES] + [tuple(p) for p in req.get("probes") or []]
    out["probes"] = [{"target": (f"[{h}]" if ":" in h else h) + f":{p}", "result": probe(h, p)} for h, p in probes]
    server, port = await start_bridge(req["proxy_socket"])
    try:
        out["proxy_probe"] = await proxy_probe(port)
        async with async_playwright() as pw:
            browser = await launch(pw, port)
            try:
                out["browser"] = f"chromium {browser.version}"
                page = await browser.new_page()
                await page.set_content("<!doctype html><title>selftest</title>")
                got = await page.evaluate("""async () => {
                    const c = new AbortController(); setTimeout(() => c.abort(), 4000);
                    try { await fetch("http://10.0.0.1/", {mode: "no-cors", signal: c.signal}); return "reached"; }
                    catch (e) { return "failed"; } }""")
                out["browser_probe"] = {"target": "http://10.0.0.1/", "result": got}
            finally:
                await browser.close()
    finally:
        server.close()
    return verdict(out)


def _pairs(headers):
    """CDP headers ({name: value}, repeated values joined by newlines) as a list of pairs."""
    out = []
    for k, v in (headers or {}).items():
        for part in str(v).split("\n"):
            out.append((k, part))
    return out


def _iso(ts=None):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


class Recorder:
    """Collects the Network domain events of one page."""

    def __init__(self, max_response_bytes):
        self.max = max_response_bytes
        self.order, self.req = [], {}
        self.main_id = None
        self.main_frame = None
        self.redirects = []
        self.chain = []
        self.too_large = None
        self.raw = {}  # Network requestId -> the exact bytes of a main-frame document (Fetch domain, Response stage)

    def on_request(self, p):
        rid = p["requestId"]
        prev = self.req.get(rid)
        if prev is not None and p.get("redirectResponse"):
            # the same requestId continues after a redirect: the earlier hop is complete, without a body
            r = p["redirectResponse"]
            prev.update(response=r, finished=True, redirect=True)
            if rid == self.main_id:
                self.redirects.append({"url": prev["url"], "status": r.get("status"), "location": p["request"]["url"]})
                self.chain.append(p["request"]["url"])
        entry = {"id": rid, "url": p["request"]["url"], "method": p["request"].get("method", "GET"),
                 "headers": p["request"].get("headers") or {}, "type": p.get("type"), "frame": p.get("frameId"),
                 "wall": p.get("wallTime"), "response": None, "finished": False, "failed": None, "bytes": 0}
        self.req[rid] = entry
        self.order.append(entry)
        if self.main_id is None and p.get("type") == "Document" and (self.main_frame is None
                                                                     or p.get("frameId") == self.main_frame):
            self.main_id = rid
            self.chain.append(entry["url"])

    def on_response(self, p):
        e = self.req.get(p["requestId"])
        if e is not None:
            e["response"] = p["response"]

    def on_data(self, p):
        e = self.req.get(p["requestId"])
        if e is None:
            return
        e["bytes"] += p.get("dataLength", 0)
        if e["bytes"] > self.max and p["requestId"] == self.main_id:
            self.too_large = "main document"

    def on_finished(self, p):
        e = self.req.get(p["requestId"])
        if e is not None:
            e["finished"] = True
            e["encoded"] = p.get("encodedDataLength", 0)
            if p["requestId"] == self.main_id and e["bytes"] > self.max:
                self.too_large = "main document"

    def on_failed(self, p):
        e = self.req.get(p["requestId"])
        if e is not None:
            e["failed"] = p.get("errorText") or "failed"


async def _body(cdp, rec, e, deadline):
    if e.get("failed") or not e.get("finished") or e.get("response") is None or e["bytes"] > rec.max:
        return None
    if time.monotonic() > deadline:
        return None
    try:
        got = await asyncio.wait_for(cdp.send("Network.getResponseBody", {"requestId": e["id"]}), 3)
    except Exception:  # noqa: BLE001 - no body (redirect, 204, evicted): archived without one
        return None
    if got.get("base64Encoded"):
        return base64.b64decode(got["body"])
    return got["body"].encode("utf-8")


async def capture(req):
    from playwright.async_api import async_playwright
    t0 = time.monotonic()
    deadline = t0 + req["budget_ms"] / 1000.0
    reserve = 3.0  # seconds kept for the screenshot, the DOM, the bodies and the WACZ
    out_dir = pathlib.Path(req["out_dir"])
    masked = hide_paths(req.get("hide_paths"))
    bad = [h for h in masked if not hide_ok(h, bool(req.get("require_hidden")))]
    if bad:
        return {"ok": False, "code": "isolation", "detail": f"paths not hidden {bad}"}
    lo_up()
    ifs = read_interfaces()
    if ifs != ["lo"]:
        return {"ok": False, "code": "isolation", "detail": f"interfaces {ifs}"}
    server, port = await start_bridge(req["proxy_socket"])
    rec = Recorder(req["max_response_bytes"])
    try:
        async with async_playwright() as pw:
            browser = await launch(pw, port)
            try:
                vw, vh = req["viewport"]
                user_agent = req.get("user_agent") or robots.user_agent_for(browser.version)
                context = await browser.new_context(viewport={"width": vw, "height": vh}, user_agent=user_agent,
                                                    service_workers="block", accept_downloads=False,
                                                    ignore_https_errors=False)
                page = await context.new_page()
                cdp = await context.new_cdp_session(page)
                tree = await cdp.send("Page.getFrameTree")
                rec.main_frame = tree["frameTree"]["frame"]["id"]

                async def on_paused(p):
                    # a main-frame document paused at the Response stage: read its exact bytes (content-decoded,
                    # never charset-decoded), then let it continue unchanged
                    try:
                        status = p.get("responseStatusCode")
                        if (p.get("frameId") == rec.main_frame and status is not None and not 300 <= status < 400
                                and p.get("networkId")):
                            got = await cdp.send("Fetch.getResponseBody", {"requestId": p["requestId"]})
                            body = got.get("body") or ""
                            raw = base64.b64decode(body) if got.get("base64Encoded") else body.encode("utf-8")
                            if len(raw) > rec.max:
                                rec.too_large = "main document"
                            else:
                                rec.raw[p["networkId"]] = raw
                    except Exception:  # noqa: BLE001 - no body (aborted, 204): the fallback below applies
                        pass
                    finally:
                        with contextlib.suppress(Exception):
                            await cdp.send("Fetch.continueRequest", {"requestId": p["requestId"]})

                cdp.on("Fetch.requestPaused", lambda p: asyncio.ensure_future(on_paused(p)))
                await cdp.send("Fetch.enable", {"patterns": [{"urlPattern": "*", "resourceType": "Document",
                                                              "requestStage": "Response"}]})
                cdp.on("Network.requestWillBeSent", rec.on_request)
                cdp.on("Network.responseReceived", rec.on_response)
                cdp.on("Network.dataReceived", rec.on_data)
                cdp.on("Network.loadingFinished", rec.on_finished)
                cdp.on("Network.loadingFailed", rec.on_failed)
                await cdp.send("Network.enable", {"maxTotalBufferSize": 200 * 1024 * 1024,
                                                  "maxResourceBufferSize": req["max_response_bytes"] + 1024 * 1024})
                nav_error = None
                try:
                    nav_ms = max(1000, int((deadline - time.monotonic() - reserve) * 1000))
                    await page.goto(req["url"], wait_until="domcontentloaded", timeout=nav_ms)
                except Exception as e:  # noqa: BLE001
                    nav_error = str(e).splitlines()[0][:300]
                if len(rec.redirects) > req["max_redirects"]:
                    return {"ok": False, "code": "too-many-redirects", "chain": rec.chain,
                            "detail": f"too-many-redirects ({len(rec.redirects)} > {req['max_redirects']})"}
                if rec.too_large:
                    return {"ok": False, "code": "too-large", "detail": rec.too_large, "chain": rec.chain}
                main = rec.req.get(rec.main_id) if rec.main_id else None
                if nav_error or main is None or main.get("response") is None:
                    code = "timeout" if nav_error and "Timeout" in nav_error else "navigation"
                    return {"ok": False, "code": code, "detail": nav_error or "no main document", "chain": rec.chain}
                with contextlib.suppress(Exception):
                    await page.wait_for_load_state("load", timeout=max(1, int((deadline - time.monotonic() - reserve)
                                                                              * 1000)))
                settle = min(req["settle_ms"] / 1000.0, deadline - time.monotonic() - reserve)
                if settle > 0:
                    await asyncio.sleep(settle)
                if rec.too_large:
                    return {"ok": False, "code": "too-large", "detail": rec.too_large, "chain": rec.chain}
                # screenshot, full page at the viewport width
                height = await page.evaluate("() => Math.max(document.documentElement.scrollHeight,"
                                             " document.body ? document.body.scrollHeight : 0)")
                shot_args = {"full_page": True, "type": "png", "timeout": 5000}
                if height > MAX_SHOT_HEIGHT:
                    shot_args["clip"] = {"x": 0, "y": 0, "width": vw, "height": MAX_SHOT_HEIGHT}
                shot = await page.screenshot(**shot_args)
                # hidden elements, then the DOM
                hidden = await page.evaluate(HIDDEN_JS)
                rendered = await page.evaluate("""() => {
                    const d = document.doctype;
                    const dt = d ? "<!DOCTYPE " + d.name + (d.publicId ? ' PUBLIC "' + d.publicId + '"' : "")
                                   + (!d.publicId && d.systemId ? " SYSTEM" : "")
                                   + (d.systemId ? ' "' + d.systemId + '"' : "") + ">\\n" : "";
                    return dt + document.documentElement.outerHTML; }""")
                title = await page.title()
                # bodies
                body_deadline = deadline - 1.0
                if rec.raw.get(rec.main_id) is not None:
                    main_body, body_source = rec.raw[rec.main_id], "fetch-intercept"
                else:
                    main_body, body_source = await _body(cdp, rec, main, body_deadline), "getResponseBody"
                exchanges = []
                for e in rec.order[:MAX_RESOURCES]:
                    r = e.get("response")
                    if r is None:
                        continue
                    if e is main:
                        body = main_body
                    elif e.get("redirect"):
                        body = None  # a redirect hop
                    else:
                        body = await _body(cdp, rec, e, body_deadline)
                    exchanges.append({
                        "url": e["url"], "method": e["method"], "request_headers": _pairs(e["headers"]),
                        "status": r.get("status"), "status_text": r.get("statusText", ""),
                        "http_version": (r.get("protocol") or "http/1.1").upper(),
                        "response_headers": _pairs(r.get("headers")), "body": body, "mime": r.get("mimeType", ""),
                        "date": _iso(e["wall"]) if e.get("wall") else req["fetched_at"]})
                # TLS of the main document
                tls = None
                sec = main["response"].get("securityDetails")
                if sec:
                    leaf = None
                    with contextlib.suppress(Exception):
                        origin = main["url"].split("/", 3)
                        certs = await asyncio.wait_for(cdp.send("Network.getCertificate",
                                                                {"origin": origin[0] + "//" + origin[2]}), 3)
                        if certs.get("tableNames"):
                            leaf = hashlib.sha256(base64.b64decode(certs["tableNames"][0])).hexdigest()
                    tls = {"version": (sec.get("protocol") or "").replace(" ", ""), "leaf_sha256": leaf}
                browser_version = f"chromium {browser.version}"
            finally:
                await browser.close()
    finally:
        server.close()
    nodes = [{"xpath": n["xpath"], "excerpt": n["text"][:200],
              "sha256": hashlib.sha256(n["text"].encode("utf-8")).hexdigest(), "reason": n["reason"]} for n in hidden]
    files = {
        "capture.wacz": wacz.build_wacz(exchanges, main_url=main["url"], fetched_at=req["fetched_at"], title=title,
                                        software=f"{FETCHER_ID} {VERSION} ({browser_version})"),
        "response.body": main_body if main_body is not None else b"",
        "screenshot.png": shot,
        "rendered.html": rendered.encode("utf-8"),
        "hidden-nodes.json": json.dumps(nodes, ensure_ascii=False, sort_keys=True, indent=1).encode("utf-8"),
    }
    for name, blob in files.items():
        (out_dir / name).write_bytes(blob)
    return {"ok": True, "final_url": main["url"], "status": main["response"].get("status"), "redirects": rec.redirects,
            "chain": rec.chain, "browser": browser_version, "tls": tls,
            "main_body_source": body_source, "user_agent": user_agent,
            "mime": main["response"].get("mimeType") or None,
            "requests": len(rec.order)}


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    mode = argv[0] if argv else ""
    req = json.loads(sys.stdin.read() or "{}")
    try:
        if mode == "selftest":
            emit(asyncio.run(selftest(req)))
        elif mode == "capture":
            emit(asyncio.run(capture(req)))
        else:
            emit({"ok": False, "code": "internal", "detail": f"unknown mode {mode!r}"})
            return 2
    except Exception as e:  # noqa: BLE001
        emit({"ok": False, "passed": False, "code": "internal", "detail": f"{type(e).__name__}: {e}"[:500]})
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
