"""The fetcher's HTTP API (standard library), called by the claim witness only.

    POST /v1/capture   {"url": "...", "capture": "page", "viewport": [1280, 900]}   header X-Fetcher-Secret
        200 application/x-tar: manifest.json first, then the files it lists
        4xx application/json {"error": <code>, "detail": ...}: bad-request, unauthorized, scheme, port, blocked,
            robots-disallowed, too-large, timeout, unreachable; 503 busy; 500 internal. An error that came after at
            least one request (robots.txt counts) also carries "manifest": the partial manifest (capture.partial_manifest)
    GET /healthz       {"ok": true, "selftest": {...}}

The secret is read from the file named by FETCHER_SECRET_FILE and compared with hmac.compare_digest. The service does
not start serving unless the start-up self-test passed (README_FETCHER.md, "Self-test").
"""
import argparse
import hmac
import http.server
import json
import logging
import os
import sys
import threading

from . import FETCHER_ID, VERSION, addr, atproto, post
from .capture import CaptureError, HTTP_STATUS, Settings, capture_sync, run_selftest, to_tar

MAX_BODY = 64 * 1024
MAX_URL = 4096
DEFAULT_VIEWPORT = (1280, 900)
log = logging.getLogger("claim_fetcher")


def load_secret(path):
    if not path:
        raise ValueError("FETCHER_SECRET_FILE is not set")
    with open(path, "rb") as f:
        secret = f.read().strip()
    if not secret:
        raise ValueError("the secret file is empty")
    return secret


def set_non_dumpable():
    """prctl(PR_SET_DUMPABLE, 0): the worker runs under this process's uid, so without it a browser escape could
    ptrace this process or read /proc/<pid>/mem, where the secret lives. True when set."""
    try:
        import ctypes
        import ctypes.util
        libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)
        return libc.prctl(4, 0, 0, 0, 0) == 0  # PR_SET_DUMPABLE = 4
    except (OSError, AttributeError):
        return False


def _viewport(value):
    if value is None:
        return DEFAULT_VIEWPORT
    if (not isinstance(value, list) or len(value) != 2
            or not all(isinstance(v, int) and not isinstance(v, bool) for v in value)):
        raise ValueError("viewport must be [width, height]")
    w, h = value
    if not (320 <= w <= 3840 and 240 <= h <= 4320):
        raise ValueError("viewport out of range")
    return (w, h)


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = f"{FETCHER_ID}/{VERSION}"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        log.info("%s %s", self.address_string(), fmt % args)

    def _send(self, status, body, ctype):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _error(self, code, detail="", status=None, manifest=None):
        answer = {"error": code, "detail": detail}
        if manifest is not None:  # the partial manifest of an error that came after at least one request
            answer["manifest"] = manifest
        self._send(status or HTTP_STATUS.get(code, 422), json.dumps(answer).encode(), "application/json")

    def do_GET(self):
        if self.path == "/healthz":
            st = self.server.selftest or {}
            ok = bool(st.get("passed"))
            self._send(200 if ok else 503, json.dumps({"ok": ok, "selftest": st}, sort_keys=True).encode(),
                       "application/json")
            return
        self._error("not-found", self.path, 404)

    def do_POST(self):
        length = self.headers.get("Content-Length", "0")
        length = int(length) if length.isdigit() else -1
        if length < 0 or length > MAX_BODY:
            self.close_connection = True
            self._error("bad-request", "body size")
            return
        raw = self.rfile.read(length) if length else b""
        if self.path != "/v1/capture":
            self._error("not-found", self.path, 404)
            return
        given = (self.headers.get("X-Fetcher-Secret") or "").encode("utf-8", "replace")
        if not hmac.compare_digest(given, self.server.secret):
            self._error("unauthorized")
            return
        try:
            req = json.loads(raw)
            if not isinstance(req, dict):
                raise ValueError("a JSON object is expected")
            url = req.get("url")
            if not isinstance(url, str) or not url or len(url) > MAX_URL:
                raise ValueError("url")
            kind = req.get("capture", "page")
            if kind not in ("page", "post"):
                raise ValueError("capture must be 'page' or 'post'")
            handle = req.get("handle")
            if kind == "page" and handle is not None:
                raise ValueError("handle goes with capture 'post' only")
            if kind == "post":
                atproto.parse_post_url(url)  # a bsky.app post URL, else bad-request before any request
                handle = atproto.normalize_handle(handle) if handle is not None else None
            viewport = _viewport(req.get("viewport"))
        except (ValueError, TypeError) as e:
            self._error("bad-request", str(e)[:200])
            return
        try:
            addr.check_url(url)
        except addr.Refused as e:
            self._error(e.code, e.detail)
            return
        if not self.server.slots.acquire(blocking=False):
            self._error("busy", "too many captures in progress")
            return
        try:
            if kind == "post":
                manifest, files = self.server.capture_fn(url, viewport, kind="post", handle=handle)
            else:
                manifest, files = self.server.capture_fn(url, viewport)
        except CaptureError as e:
            m = e.manifest or {}
            log.info(json.dumps({"event": "capture-refused", "url": url, "code": e.code, "detail": e.detail,
                                 "redirects": m.get("redirects"), "robots": m.get("robots"),
                                 "fetch_ms": m.get("fetch_ms")}))
            self._error(e.code, e.detail, manifest=e.manifest)
            return
        except Exception as e:  # noqa: BLE001
            log.exception("capture failed")
            self._error("internal", type(e).__name__)
            return
        finally:
            self.server.slots.release()
        log.info(json.dumps({"event": "capture", "url": url, "final_url": manifest.get("final_url"),
                             "redirects": manifest.get("redirects"), "status": manifest.get("status"),
                             "fetch_ms": manifest.get("fetch_ms")}))
        self._send(200, to_tar(manifest, files), "application/x-tar")


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True


def make_server(host, port, secret, capture_fn, selftest, max_concurrent=2):
    srv = Server((host, port), Handler)
    srv.secret, srv.capture_fn, srv.selftest = secret, capture_fn, selftest
    srv.slots = threading.BoundedSemaphore(max_concurrent)
    return srv


def main(argv=None):
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s", stream=sys.stderr)
    ap = argparse.ArgumentParser(prog="claim_fetcher")
    ap.add_argument("--host", default=os.environ.get("FETCHER_HOST", "0.0.0.0"))
    ap.add_argument("--port", type=int, default=int(os.environ.get("FETCHER_PORT", "8090")))
    ap.add_argument("--selftest-only", action="store_true", help="run the self-test, print it, exit 0 if it passed")
    ap.add_argument("--capture", metavar="URL", help="capture one URL through the isolation path, print the manifest")
    ap.add_argument("--out", metavar="DIR", help="with --capture: also write manifest.json and the files here")
    ap.add_argument("--post", action="store_true", help="with --capture: capture: post (a bsky.app post URL)")
    ap.add_argument("--handle", help="with --capture --post: the handle to resolve both ways")
    args = ap.parse_args(argv)
    try:
        settings = Settings.from_env()
    except ValueError as e:
        log.error("refusing to start: bad configuration: %s", e)
        return 2
    if args.capture:
        try:
            if args.post:
                r = post.capture_post_sync(args.capture, args.handle, DEFAULT_VIEWPORT, settings)
            else:
                r = capture_sync(args.capture, DEFAULT_VIEWPORT, settings)
        except CaptureError as e:
            answer = {"error": e.code, "detail": e.detail}
            if e.manifest is not None:
                answer["manifest"] = e.manifest
            print(json.dumps(answer, sort_keys=True, indent=1))
            return 4
        if args.out:
            os.makedirs(args.out, exist_ok=True)
            with open(os.path.join(args.out, "manifest.json"), "w") as f:
                json.dump(r.manifest, f, sort_keys=True, indent=1)
            for name, blob in r.files.items():
                with open(os.path.join(args.out, name), "wb") as f:
                    f.write(blob)
        print(json.dumps(r.manifest, sort_keys=True, indent=1))
        return 0
    if not args.selftest_only:
        try:
            secret = load_secret(os.environ.get("FETCHER_SECRET_FILE"))
        except (OSError, ValueError) as e:
            log.error("refusing to start: %s", e)
            return 2
        log.info("non-dumpable: %s", set_non_dumpable())
    result = run_selftest(settings)
    log.info("selftest %s", json.dumps(result, sort_keys=True))
    if args.selftest_only:
        print(json.dumps(result, sort_keys=True, indent=1))
        return 0 if result.get("passed") else 3
    if not result.get("passed"):
        log.error("refusing to serve: the namespace self-test failed: %s", result.get("reasons"))
        return 3

    def capture_fn(url, viewport, kind="page", handle=None):
        if kind == "post":
            r = post.capture_post_sync(url, handle, viewport, settings)
        else:
            r = capture_sync(url, viewport, settings)
        return r.manifest, r.files

    srv = make_server(args.host, args.port, secret, capture_fn, result,
                      max_concurrent=int(os.environ.get("FETCHER_MAX_CONCURRENT", "2")))
    log.info("serving on %s:%s", args.host, args.port)
    try:
        srv.serve_forever()
    finally:
        srv.server_close()
    return 0
