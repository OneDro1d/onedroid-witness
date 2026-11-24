"""WARC records (warcio) packaged as a WACZ 1.1.1 by hand: archive/data.warc.gz, indexes/index.cdx (CDXJ),
pages/pages.jsonl, datapackage.json with every file's sha256 and size, and datapackage-digest.json.

The output is a pure function of its input: record ids are UUIDv5 of the content, dates come from the exchanges, and
zip entries carry a fixed time, so the same exchanges always give the same bytes (and the same sha256 in the manifest).

Bodies are the decoded bodies the browser received (no transfer or content encoding). A response record therefore
drops Content-Encoding, Transfer-Encoding and Content-Length, keeps each as X-Archive-Orig-<name> (the pywb
convention), and states the decoded Content-Length.
"""
import hashlib
import io
import json
import urllib.parse
import uuid
import zipfile

from warcio.archiveiterator import ArchiveIterator
from warcio.statusandheaders import StatusAndHeaders
from warcio.warcwriter import WARCWriter

WACZ_VERSION = "1.1.1"
WARC_NAME = "data.warc.gz"
DROP_ON_DECODED = ("content-encoding", "transfer-encoding", "content-length")
_NS = uuid.UUID("6f1b2a59-3c55-4d43-9c1b-0e4a7c1c9a11")


def surt(url):
    p = urllib.parse.urlsplit(url)
    host = (p.hostname or "").lower()
    if host.startswith("www."):
        host = host[4:]
    key = ",".join(reversed(host.split(".")))
    try:
        port = p.port
    except ValueError:
        port = None
    if port and port != {"http": 80, "https": 443}.get(p.scheme.lower()):
        key += f":{port}"
    key += ")" + (p.path or "/")
    if p.query:
        key += "?" + p.query
    return key


def _ts14(iso):
    return "".join(c for c in iso if c.isdigit())[:14].ljust(14, "0")


def _warc_date(iso):
    return iso if iso.endswith("Z") else iso + "Z"


def _rid(*parts):
    return f"<urn:uuid:{uuid.uuid5(_NS, '|'.join(str(p) for p in parts))}>"


def _sha(b):
    return hashlib.sha256(b).hexdigest()


def _warc(exchanges, fetched_at, software):
    buf = io.BytesIO()
    w = WARCWriter(buf, gzip=True, warc_version="1.1")
    info = f"software: {software}\r\nformat: WARC File Format 1.1\r\n".encode()
    w.write_record(w.create_warc_record("", "warcinfo", payload=io.BytesIO(info), length=len(info),
                                        warc_content_type="application/warc-fields",
                                        warc_headers_dict={"WARC-Record-ID": _rid("warcinfo", fetched_at),
                                                           "WARC-Date": _warc_date(fetched_at),
                                                           "WARC-Filename": WARC_NAME}))
    for i, ex in enumerate(exchanges):
        url, date = ex["url"], _warc_date(ex.get("date") or fetched_at)
        body = ex.get("body") or b""
        resp_id = _rid("response", i, url, _sha(body))
        req_id = _rid("request", i, url)
        # response
        headers = []
        for k, v in ex.get("response_headers") or []:
            if k.lower() in DROP_ON_DECODED:
                headers.append((f"X-Archive-Orig-{k}", v))
            else:
                headers.append((k, v))
        headers.append(("Content-Length", str(len(body))))
        version = ex.get("http_version") or "HTTP/1.1"
        if not version.upper().startswith("HTTP/1"):
            version = "HTTP/1.1"  # h2/h3 exchanges are written in HTTP/1.1 form, as every web archiver does
        status_line = f"{ex.get('status') or 200} {ex.get('status_text') or ''}".strip()
        http_headers = StatusAndHeaders(status_line, headers, protocol=version)
        w.write_record(w.create_warc_record(url, "response", payload=io.BytesIO(body), length=len(body),
                                            http_headers=http_headers,
                                            warc_headers_dict={"WARC-Record-ID": resp_id, "WARC-Date": date}))
        # request
        p = urllib.parse.urlsplit(url)
        path = (p.path or "/") + (f"?{p.query}" if p.query else "")
        req_headers = StatusAndHeaders(f"{ex.get('method') or 'GET'} {path}", list(ex.get("request_headers") or []),
                                       protocol="HTTP/1.1", is_http_request=True)
        w.write_record(w.create_warc_record(url, "request", payload=io.BytesIO(b""), length=0,
                                            http_headers=req_headers,
                                            warc_headers_dict={"WARC-Record-ID": req_id, "WARC-Date": date,
                                                               "WARC-Concurrent-To": resp_id}))
    return buf.getvalue()


def _index(warc, exchanges):
    mimes = {ex["url"]: ex.get("mime") or "" for ex in exchanges}
    lines = []
    it = ArchiveIterator(io.BytesIO(warc))
    for rec in it:
        if rec.rec_type != "response":
            continue
        url = rec.rec_headers.get_header("WARC-Target-URI")
        payload = rec.content_stream().read()
        status = rec.http_headers.get_statuscode() if rec.http_headers else ""
        offset, length = it.get_record_offset(), it.get_record_length()
        date = rec.rec_headers.get_header("WARC-Date")
        meta = {"url": url, "mime": mimes.get(url, ""), "status": str(status), "digest": "sha256:" + _sha(payload),
                "length": str(length), "offset": str(offset), "filename": WARC_NAME}
        lines.append(f"{surt(url)} {_ts14(date)} {json.dumps(meta, sort_keys=True)}")
    return ("\n".join(sorted(lines)) + "\n").encode()


def build_wacz(exchanges, main_url, fetched_at, title="", software="claim-fetcher"):
    """The WACZ bytes for a list of exchanges {url, method, request_headers, status, status_text, http_version,
    response_headers, body, mime, date}."""
    warc = _warc(exchanges, fetched_at, software)
    files = {
        f"archive/{WARC_NAME}": warc,
        "indexes/index.cdx": _index(warc, exchanges),
        "pages/pages.jsonl": (json.dumps({"format": "json-pages-1.0", "id": "pages", "title": "All Pages"}) + "\n"
                              + json.dumps({"id": str(uuid.uuid5(_NS, main_url + fetched_at)), "url": main_url,
                                            "ts": fetched_at, "title": title or main_url}) + "\n").encode(),
    }
    resources = [{"name": path.rsplit("/", 1)[-1], "path": path, "hash": "sha256:" + _sha(blob), "bytes": len(blob)}
                 for path, blob in files.items()]
    pkg = {"profile": "data-package", "wacz_version": WACZ_VERSION, "resources": resources, "created": fetched_at,
           "modified": fetched_at, "software": software, "title": title or main_url, "mainPageUrl": main_url,
           "mainPageDate": fetched_at}
    pkg_bytes = json.dumps(pkg, indent=2, sort_keys=True).encode()
    digest = json.dumps({"path": "datapackage.json", "hash": "sha256:" + _sha(pkg_bytes)}, sort_keys=True).encode()
    out = io.BytesIO()
    stamp = tuple(int(x) for x in (_ts14(fetched_at)[0:4], _ts14(fetched_at)[4:6], _ts14(fetched_at)[6:8],
                                   _ts14(fetched_at)[8:10], _ts14(fetched_at)[10:12], _ts14(fetched_at)[12:14]))
    if stamp[0] < 1980:
        stamp = (1980, 1, 1, 0, 0, 0)
    with zipfile.ZipFile(out, "w") as z:
        for path, blob in list(files.items()) + [("datapackage.json", pkg_bytes),
                                                 ("datapackage-digest.json", digest)]:
            info = zipfile.ZipInfo(path, date_time=stamp)
            info.compress_type = zipfile.ZIP_STORED  # WACZ: stored, so a replayer can seek into the WARC
            info.external_attr = 0o644 << 16
            z.writestr(info, blob)
    return out.getvalue()
