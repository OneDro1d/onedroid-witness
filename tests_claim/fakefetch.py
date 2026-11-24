"""A fake claim_fetcher for the witness tests: a local HTTP server speaking the fetcher API of README_FETCHER.md (POST
/v1/capture with X-Fetcher-Secret; 200 application/x-tar with manifest.json first, or 4xx JSON {error, detail, manifest?}),
answering prepared captures per URL. Times come from the test clock, so the signer's 300 s window holds.

    ff = FakeFetcher(clock)
    ff.set("https://a.example/", page(b"<p>Hello</p>"))            # every call answers this
    ff.set("https://b.example/", page(status=404), page(status=404))  # answers in order, the last one repeats
    ff.set("https://c.example/", error("unreachable", "host-not-found c.example"))
    client = ff.client()                                            # a claim_witness.fetcher.FetcherClient
"""
import hashlib
import http.server
import io
import json
import pathlib
import shutil
import tarfile
import tempfile
import threading
import time

SECRET = "fetcher-secret-for-tests-0123456789"
PNG = b"\x89PNG\r\n\x1a\n"
FETCHER = {"id": "onedroid-fetcher", "version": "1.0.0", "browser": "chromium 159.0.8154.6", "viewport": [1280, 900],
           "user_agent": "Mozilla/5.0 test OneDroidWitness/1.0", "isolation": "userns+netns(lo only)+mountns, unix-socket egress proxy"}


def iso(t):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(int(t)))


def page(html=b"<html><body><h1>Example</h1><p>This page is live.</p></body></html>", status=200, rendered=None, hidden=None,
         final_url=None, redirects=None, media_type="text/html", screenshot=None, robots="allowed", tamper=None):
    """A capture: response.body = html, rendered.html = rendered (default: html), hidden-nodes.json = hidden (default [])."""
    return {"kind": "page", "html": html if isinstance(html, bytes) else html.encode("utf-8"), "status": status,
            "rendered": rendered if rendered is None or isinstance(rendered, bytes) else rendered.encode("utf-8"),
            "hidden": hidden, "final_url": final_url, "redirects": redirects or [], "media_type": media_type,
            "screenshot": screenshot, "robots": robots, "tamper": tamper}


PLATFORM_FIELDS = ("name", "post_uri", "author_did", "handle", "handle_resolution", "did_doc_sha256", "signature",
                   "commit_cid", "created_at_claimed")


def post_page(platform, html=b"<html><body><p>Bluesky</p><p>v1.138 is live!</p></body></html>", **kw):
    """A `capture: post` answer (B5a): the page capture plus platform.json (the whole dict given) and manifest.platform (its
    SPEC §2.3 fields), as claim_fetcher's capture_post builds them."""
    spec = page(html, **kw)
    spec["platform"] = dict(platform)
    return spec


def error(code, detail="", status=None, manifest=None):
    """A fetcher error answer; manifest is the optional partial manifest the newer fetcher adds."""
    statuses = {"bad-request": 400, "scheme": 400, "port": 400, "unauthorized": 401, "blocked": 403, "robots-disallowed": 403,
                "timeout": 408, "too-large": 413, "unreachable": 422, "internal": 500, "busy": 503}
    return {"kind": "error", "code": code, "detail": detail, "status": status or statuses.get(code, 422), "manifest": manifest}


def drop():
    """Close the connection without an answer."""
    return {"kind": "drop"}


def build_capture(url, spec, fetched_at):
    files = {"capture.wacz": b"PK\x03\x04fake-wacz:" + url.encode("utf-8"), "response.body": spec["html"],
             "screenshot.png": spec["screenshot"] or (PNG + b"OCR:" + spec["html"]),
             "rendered.html": spec["rendered"] if spec["rendered"] is not None else spec["html"],
             "hidden-nodes.json": json.dumps(spec["hidden"] or [], sort_keys=True).encode("utf-8")}
    if spec["media_type"] != "text/html" and spec["rendered"] is None:
        del files["rendered.html"]
    media = {"capture.wacz": "application/wacz", "response.body": spec["media_type"], "screenshot.png": "image/png",
             "rendered.html": "text/html", "hidden-nodes.json": "application/json", "platform.json": "application/json",
             "post.car": "application/vnd.ipld.car", "did-document.json": "application/did+json"}
    if spec.get("platform") is not None:
        files["platform.json"] = json.dumps(spec["platform"], sort_keys=True, indent=1).encode("utf-8")
        files["post.car"] = b"fake-car:" + url.encode("utf-8")
        files["did-document.json"] = b'{"id": "did:plc:fake"}'
    entries = [{"name": n, "sha256": hashlib.sha256(b).hexdigest(), "size": len(b), "media_type": media[n]} for n, b in files.items()]
    manifest = {"requested_url": url, "final_url": spec["final_url"] or url, "redirects": list(spec["redirects"]),
                "fetched_at": fetched_at, "fetch_ms": 1234, "status": spec["status"], "resolved_ips": ["93.184.215.14"],
                "tls": {"version": "TLS1.3", "leaf_sha256": "c" * 64} if url.startswith("https:") else None,
                "robots": spec["robots"], "fetcher": dict(FETCHER), "files": entries}
    if spec.get("platform") is not None:
        manifest["platform"] = {k: spec["platform"].get(k) for k in PLATFORM_FIELDS}
    if spec["tamper"]:
        files[spec["tamper"]] = files[spec["tamper"]] + b"tampered"
    return manifest, files


def to_tar(manifest, files):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w", format=tarfile.PAX_FORMAT) as tar:
        blobs = [("manifest.json", json.dumps(manifest, sort_keys=True, indent=1).encode())]
        blobs += [(e["name"], files[e["name"]]) for e in manifest["files"]]
        for name, blob in blobs:
            info = tarfile.TarInfo(name)
            info.size, info.mtime, info.mode = len(blob), 0, 0o644
            tar.addfile(info, io.BytesIO(blob))
    return out.getvalue()


class FakeFetcher:
    def __init__(self, clock, secret=SECRET):
        self.clock, self.secret = clock, secret
        self.routes, self.calls, self.lock = {}, [], threading.Lock()
        self.dir = pathlib.Path(tempfile.mkdtemp(prefix="cw-fakefetch-"))
        self.secret_file = self.dir / "secret"
        self.secret_file.write_text(secret + "\n")
        fake = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def _send(self, status, body, ctype):
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):
                raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                if self.path != "/v1/capture":
                    return self._send(404, b'{"error": "not-found"}', "application/json")
                if self.headers.get("X-Fetcher-Secret") != fake.secret:
                    return self._send(401, b'{"error": "unauthorized", "detail": ""}', "application/json")
                req = json.loads(raw)
                spec = fake._next(req["url"])
                with fake.lock:
                    fake.calls.append({"url": req["url"], "capture": req.get("capture"), "handle": req.get("handle"),
                                       "at": int(fake.clock())})
                if spec["kind"] == "drop":
                    self.close_connection = True
                    return
                if spec["kind"] == "error":
                    body = {"error": spec["code"], "detail": spec["detail"]}
                    if spec["manifest"] is not None:
                        body["manifest"] = spec["manifest"]
                    return self._send(spec["status"], json.dumps(body).encode(), "application/json")
                manifest, files = build_capture(req["url"], spec, iso(fake.clock()))
                self._send(200, to_tar(manifest, files), "application/x-tar")

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def set(self, url, *answers):
        with self.lock:
            self.routes[url] = list(answers)

    def _next(self, url):
        with self.lock:
            q = self.routes.get(url)
            if not q:
                return error("unreachable", "connect-failed ConnectionRefusedError")
            return q.pop(0) if len(q) > 1 else q[0]

    def urls_called(self):
        with self.lock:
            return [c["url"] for c in self.calls]

    def client(self, **kw):
        from claim_witness import fetcher
        kw.setdefault("busy_delay_s", 0)
        return fetcher.FetcherClient(self.url, self.secret, **kw)

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        shutil.rmtree(self.dir, ignore_errors=True)


class Resolver:
    """A stand-in for one DNS resolver: answers 'nxdomain', 'exists' or 'error' per host."""

    def __init__(self, answers=None, default="nxdomain"):
        self.answers, self.default, self.asked = dict(answers or {}), default, []

    def query(self, host):
        self.asked.append(host)
        return self.answers.get(host, self.default)


class Sleeper:
    """The witness's sleep for the not-live confirmation: records each wait, blocks while the gate is closed, then moves the
    test clock on by the waited seconds."""

    def __init__(self, clock):
        self.clock, self.calls, self.gate = clock, [], threading.Event()
        self.gate.set()

    def __call__(self, seconds):
        self.calls.append(seconds)
        self.gate.wait(20)
        self.clock.advance(seconds)


def stack(clock=None, ff=None, storage=None, resolvers=None, **overrides):
    """(Stack, FakeFetcher, Sleeper): an in-process witness wired to a fake fetcher, two fake resolvers and a sleeper."""
    from tests_claim import helpers as h
    clock = clock or h.Clock()
    ff = ff or FakeFetcher(clock)
    sleeper = Sleeper(clock)
    cfg = {"fetcher": ff.client(), "resolvers": resolvers if resolvers is not None else [Resolver(), Resolver()],
           "sleep": sleeper, "confirm_delay_s": 60, "host_fetches_per_minute": 1000}
    cfg.update(overrides)
    s = h.Stack(storage=storage, clock=clock, config_overrides=cfg)
    return s, ff, sleeper


def url_item(url, slot="page", max_age=None, capture="page"):
    item = {"slot": slot, "kind": "url", "url": url, "capture": capture}
    if max_age is not None:
        item["max_age"] = max_age
    return item


def wait_job(s, job_id, timeout=20, key="dev-key-a-0123456789abcdef"):
    deadline = time.time() + timeout
    while time.time() < deadline:
        code, out, _ = s.call("GET", f"/v1/jobs/{job_id}", key=key)
        if out.get("state") in ("done", "failed"):
            return out
        time.sleep(0.05)
    raise AssertionError(f"job {job_id} did not finish")
