"""robots.txt decisions (claim_fetcher.robots) and the WACZ package (claim_fetcher.wacz)."""
import gzip
import hashlib
import io
import json
import zipfile

import pytest

from claim_fetcher import robots, wacz

AGENT = robots.AGENT


@pytest.mark.parametrize("status,body,path,expect", [
    (200, b"User-agent: *\nDisallow: /private", "/private/x", "disallowed"),
    (200, b"User-agent: *\nDisallow: /private", "/public", "allowed"),
    (200, f"User-agent: {AGENT}\nDisallow: /\n\nUser-agent: *\nAllow: /".encode(), "/a", "disallowed"),
    (200, f"User-agent: {AGENT.lower()}/1.0\nDisallow: /x".encode(), "/x/y", "disallowed"),
    (200, b"User-agent: *\nAllow: /private/ok\nDisallow: /private", "/private/ok/x", "allowed"),
    (200, b"User-agent: *\nDisallow: /*.pdf$", "/a/b.pdf", "disallowed"),
    (200, b"User-agent: *\nDisallow: /*.pdf$", "/a/b.pdf?x", "allowed"),
    (200, b"User-agent: *\nDisallow: /search", "/search?q=1", "disallowed"),
    (200, b"", "/", "allowed"),
    (200, b"User-agent: otherbot\nDisallow: /", "/", "allowed"),
    (404, b"", "/", "allowed"),
    (401, b"", "/", "allowed"),
    (403, b"", "/", "allowed"),
    (500, b"", "/", "unavailable"),
    (503, b"", "/", "unavailable"),
    (None, None, "/", "unavailable"),
])
def test_decide(status, body, path, expect):
    assert robots.decide(status, body, path) == expect


def test_robots_target_is_path_and_query():
    assert robots.target_of("https://ok.test/a/b?c=1#frag") == "/a/b?c=1"
    assert robots.target_of("https://ok.test") == "/"


EXCHANGES = [
    {"url": "https://ok.test/", "method": "GET", "request_headers": [("User-Agent", "t"), ("Accept", "*/*")],
     "status": 200, "status_text": "OK", "http_version": "HTTP/1.1",
     "response_headers": [("Content-Type", "text/html; charset=utf-8"), ("Content-Encoding", "gzip")],
     "body": b"<html><body>hello</body></html>", "mime": "text/html", "date": "2026-11-24T10:41:07Z"},
    {"url": "https://ok.test/app.js", "method": "GET", "request_headers": [], "status": 200, "status_text": "OK",
     "http_version": "HTTP/1.1", "response_headers": [("Content-Type", "application/javascript")],
     "body": b"console.log(1)", "mime": "application/javascript", "date": "2026-11-24T10:41:08Z"},
    {"url": "https://ok.test/failed.png", "method": "GET", "request_headers": [], "status": 302, "status_text": "Found",
     "http_version": "HTTP/1.1", "response_headers": [("Location", "/x")], "body": None, "mime": "",
     "date": "2026-11-24T10:41:08Z"},
]


def _build():
    data = wacz.build_wacz(EXCHANGES, main_url="https://ok.test/", fetched_at="2026-11-24T10:41:07Z",
                           title="hello", software="claim-fetcher test")
    return data, zipfile.ZipFile(io.BytesIO(data))


def test_wacz_layout_and_datapackage_digests():
    data, z = _build()
    names = set(z.namelist())
    assert {"datapackage.json", "archive/data.warc.gz", "indexes/index.cdx", "pages/pages.jsonl"} <= names
    pkg = json.loads(z.read("datapackage.json"))
    assert pkg["profile"] == "data-package"
    assert pkg["wacz_version"] == "1.1.1"
    assert pkg["mainPageUrl"] == "https://ok.test/"
    assert pkg["mainPageDate"] == "2026-11-24T10:41:07Z"
    paths = {r["path"] for r in pkg["resources"]}
    assert paths == names - {"datapackage.json", "datapackage-digest.json"}
    for res in pkg["resources"]:
        blob = z.read(res["path"])
        assert res["hash"] == "sha256:" + hashlib.sha256(blob).hexdigest()
        assert res["bytes"] == len(blob)
    digest = json.loads(z.read("datapackage-digest.json"))
    assert digest["hash"] == "sha256:" + hashlib.sha256(z.read("datapackage.json")).hexdigest()


def test_warc_records_readable_and_index_offsets_point_at_them():
    from warcio.archiveiterator import ArchiveIterator
    _, z = _build()
    warc = z.read("archive/data.warc.gz")
    records = []
    for rec in ArchiveIterator(io.BytesIO(warc)):
        records.append((rec.rec_type, rec.rec_headers.get_header("WARC-Target-URI"), rec.content_stream().read()))
    kinds = [k for k, _, _ in records]
    assert kinds[0] == "warcinfo"
    resp = [(u, b) for k, u, b in records if k == "response"]
    assert ("https://ok.test/", b"<html><body>hello</body></html>") in resp
    assert ("https://ok.test/app.js", b"console.log(1)") in resp
    assert "request" in kinds
    lines = z.read("indexes/index.cdx").decode().splitlines()
    assert lines == sorted(lines)
    for line in lines:
        key, ts, js = line.split(" ", 2)
        meta = json.loads(js)
        chunk = warc[int(meta["offset"]):int(meta["offset"]) + int(meta["length"])]
        rec = next(iter(ArchiveIterator(io.BytesIO(chunk))))
        assert rec.rec_headers.get_header("WARC-Target-URI") == meta["url"]
        assert ts == "20261124104107" or ts.startswith("2026112410410")
    pages = [json.loads(x) for x in z.read("pages/pages.jsonl").decode().splitlines()]
    assert pages[0]["format"] == "json-pages-1.0"
    assert pages[1]["url"] == "https://ok.test/"


def test_decoded_body_drops_encoding_headers_but_keeps_the_original():
    from warcio.archiveiterator import ArchiveIterator
    _, z = _build()
    for rec in ArchiveIterator(io.BytesIO(z.read("archive/data.warc.gz"))):
        if rec.rec_type == "response" and rec.rec_headers.get_header("WARC-Target-URI") == "https://ok.test/":
            h = rec.http_headers
            assert h.get_header("Content-Encoding") is None
            assert h.get_header("X-Archive-Orig-Content-Encoding") == "gzip"
            assert h.get_header("Content-Length") == str(len(b"<html><body>hello</body></html>"))


def test_wacz_is_deterministic_for_the_same_input():
    a, _ = _build()
    b, _ = _build()
    assert hashlib.sha256(a).hexdigest() == hashlib.sha256(b).hexdigest()


@pytest.mark.parametrize("url,key", [("https://www.Example.com:443/a?b=1", "com,example)/a?b=1"),
                                     ("http://example.com/", "com,example)/"),
                                     ("https://sub.example.org:8443/x", "org,example,sub:8443)/x")])
def test_surt(url, key):
    assert wacz.surt(url) == key


def test_gzip_members_per_record():
    _, z = _build()
    warc = z.read("archive/data.warc.gz")
    assert gzip.decompress(warc).startswith(b"WARC/1.1")
