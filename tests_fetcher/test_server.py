"""The HTTP API (claim_fetcher.server): shared secret in constant time, request checks, error codes, the tar answer."""
import hashlib
import http.client
import io
import json
import tarfile
import threading

import pytest

from claim_fetcher import capture as C
from claim_fetcher import server as S

SECRET = b"s3cret-for-tests-only"
FILES = {"capture.wacz": b"PK-wacz", "response.body": b"<html>hi</html>", "screenshot.png": b"\x89PNG",
         "rendered.html": b"<html data-x>hi</html>", "hidden-nodes.json": b"[]"}


def fake_capture(calls):
    def capture(url, viewport):
        calls.append((url, tuple(viewport)))
        if "blocked" in url:
            raise C.CaptureError("blocked", "host-not-public")
        if "robots" in url:
            raise C.CaptureError("robots-disallowed", "/x")
        if "large" in url:
            raise C.CaptureError("too-large", "main document")
        if "slow" in url:
            raise C.CaptureError("timeout", "15 s")
        if "gone" in url:
            raise C.CaptureError("unreachable", "dns")
        manifest = C.build_manifest(
            requested_url=url, final_url=url, redirects=[], fetched_at="2026-11-24T10:41:07Z", fetch_ms=12,
            status=200, resolved_ips=["93.184.215.14"], tls={"version": "TLS1.3", "leaf_sha256": "ab" * 32},
            robots="allowed", browser="chromium 131.0.6778.33", viewport=list(viewport), files=FILES)
        return manifest, FILES
    return capture


@pytest.fixture
def api():
    calls = []
    srv = S.make_server("127.0.0.1", 0, SECRET, fake_capture(calls), selftest={"passed": True, "interfaces": ["lo"]})
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield srv, calls
    srv.shutdown()
    srv.server_close()


def call(srv, method, path, body=None, secret=SECRET, raw=None):
    conn = http.client.HTTPConnection("127.0.0.1", srv.server_address[1], timeout=10)
    headers = {"Content-Type": "application/json"}
    if secret is not None:
        headers["X-Fetcher-Secret"] = secret.decode() if isinstance(secret, bytes) else secret
    data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
    conn.request(method, path, body=data, headers=headers)
    resp = conn.getresponse()
    return resp.status, resp.getheader("Content-Type"), resp.read()


def test_healthz(api):
    srv, _ = api
    status, ctype, body = call(srv, "GET", "/healthz", secret=None)
    assert status == 200
    assert json.loads(body)["selftest"]["passed"] is True


@pytest.mark.parametrize("secret", [None, "", "wrong", SECRET.decode() + "x", SECRET.decode()[:-1]])
def test_missing_or_wrong_secret_is_401_and_never_captures(api, secret):
    srv, calls = api
    status, _, body = call(srv, "POST", "/v1/capture", {"url": "https://ok.test/", "capture": "page"}, secret=secret)
    assert status == 401
    assert json.loads(body)["error"] == "unauthorized"
    assert calls == []


def test_secret_compared_in_constant_time(api, monkeypatch):
    srv, _ = api
    seen = []
    real = S.hmac.compare_digest

    def spy(a, b):
        seen.append((a, b))
        return real(a, b)

    monkeypatch.setattr(S.hmac, "compare_digest", spy)
    call(srv, "POST", "/v1/capture", {"url": "https://ok.test/", "capture": "page"}, secret="nope")
    assert seen, "the secret check must go through hmac.compare_digest"


@pytest.mark.parametrize("body,raw", [(None, b"{not json"), ({"url": 5}, None), ({"capture": "page"}, None),
                                      ({"url": "https://ok.test/", "capture": "post"}, None),
                                      ({"url": "https://ok.test/", "viewport": [1280]}, None),
                                      ({"url": "https://ok.test/", "viewport": [10, 10]}, None),
                                      ({"url": "https://ok.test/", "viewport": ["a", 900]}, None),
                                      ({"url": "https://ok.test/" + "a" * 5000}, None)])
def test_bad_requests_are_400(api, body, raw):
    srv, calls = api
    status, _, out = call(srv, "POST", "/v1/capture", body, raw=raw)
    assert status == 400
    assert json.loads(out)["error"] == "bad-request"
    assert calls == []


@pytest.mark.parametrize("url,status,code", [
    ("ftp://ok.test/", 400, "scheme"), ("https://ok.test:8443/", 400, "port"),
    ("https://blocked.test/", 403, "blocked"), ("https://robots.test/", 403, "robots-disallowed"),
    ("https://large.test/", 413, "too-large"), ("https://slow.test/", 408, "timeout"),
    ("https://gone.test/", 422, "unreachable")])
def test_error_answers(api, url, status, code):
    srv, calls = api
    got, ctype, out = call(srv, "POST", "/v1/capture", {"url": url, "capture": "page", "viewport": [1280, 900]})
    assert got == status
    assert ctype.startswith("application/json")
    assert json.loads(out)["error"] == code


def test_scheme_and_port_checked_before_any_capture(api):
    srv, calls = api
    call(srv, "POST", "/v1/capture", {"url": "file:///etc/passwd", "capture": "page"})
    call(srv, "POST", "/v1/capture", {"url": "http://ok.test:22/", "capture": "page"})
    assert calls == []


def test_success_is_a_tar_with_manifest_and_files(api):
    srv, calls = api
    status, ctype, out = call(srv, "POST", "/v1/capture", {"url": "https://ok.test/", "capture": "page",
                                                            "viewport": [1280, 900]})
    assert status == 200
    assert ctype == "application/x-tar"
    assert calls == [("https://ok.test/", (1280, 900))]
    tar = tarfile.open(fileobj=io.BytesIO(out))
    names = tar.getnames()
    assert names[0] == "manifest.json"
    assert set(names) == {"manifest.json", *FILES}
    manifest = json.loads(tar.extractfile("manifest.json").read())
    for entry in manifest["files"]:
        blob = tar.extractfile(entry["name"]).read()
        assert entry["sha256"] == hashlib.sha256(blob).hexdigest()
        assert entry["size"] == len(blob)
    for key in ("requested_url", "final_url", "redirects", "fetched_at", "fetch_ms", "status", "resolved_ips", "tls",
                "robots", "fetcher", "files"):
        assert key in manifest
    assert manifest["fetcher"]["viewport"] == [1280, 900]
    assert set(manifest["fetcher"]) >= {"id", "version", "browser", "viewport"}


def test_default_viewport(api):
    srv, calls = api
    call(srv, "POST", "/v1/capture", {"url": "https://ok.test/", "capture": "page"})
    assert calls == [("https://ok.test/", (1280, 900))]


def test_unknown_paths(api):
    srv, _ = api
    assert call(srv, "GET", "/v1/capture")[0] in (404, 405)
    assert call(srv, "POST", "/nope", {})[0] == 404


def test_load_secret(tmp_path):
    p = tmp_path / "secret"
    p.write_bytes(b"abc\n")
    assert S.load_secret(str(p)) == b"abc"
    p.write_bytes(b"\n")
    with pytest.raises(ValueError):
        S.load_secret(str(p))
    with pytest.raises(ValueError):
        S.load_secret(None)
    with pytest.raises((ValueError, OSError)):
        S.load_secret(str(tmp_path / "missing"))


def test_refuses_to_serve_when_selftest_fails(monkeypatch, tmp_path):
    p = tmp_path / "secret"
    p.write_bytes(b"abc")
    monkeypatch.setenv("FETCHER_SECRET_FILE", str(p))
    monkeypatch.setattr(S, "run_selftest", lambda settings: {"passed": False, "reason": "eth0 visible"})
    served = []
    monkeypatch.setattr(S, "make_server", lambda *a, **k: served.append(1))
    assert S.main(["--port", "0"]) != 0
    assert served == []
