"""Observations (SPEC §2.3, §2.6): a fetcher capture becomes a signed observation.

- text.canonical.txt is computed here, by the witness, from rendered.html with canon/1 at the rendered layer, so every element
  the fetcher marked data-witness-hidden is left out with its text (§9.1 step 1). A page with no rendered.html (not HTML)
  takes its text from response.body. hidden-nodes.json is kept exactly as the fetcher wrote it.
- The manifest is the §2.3 predicate, with exactly its fields; `fetcher` keeps {id, version, browser, viewport} (the fetcher's
  extra user_agent and isolation fields are not signed). Each file entry keeps the fetcher's name, sha256, size and media type.
- Public: subject [{name: final URL, digest: H(canonical manifest)}], predicate = the manifest.
- Private: the body is the manifest with visibility "private"; the payload holds only {visibility, body_commitment,
  fetched_at, fetcher: {id, version}}, subject [{name: "observation", digest: body_commitment}]; the owner gets {salt, body}.
"""
import hashlib
import os

from . import canon, ids, jcs
from .dsse import STATEMENT_TYPE
from .schemas import OBSERVATION_TYPE

TEXT_FILE = "text.canonical.txt"
COPIED = ("requested_url", "final_url", "redirects", "fetched_at", "fetch_ms", "status", "resolved_ips", "tls", "robots")


def text_canonical(data, media_type="text/html"):
    """The rendered-layer canon/1 text of a page as UTF-8 bytes (b"" when it is not readable text)."""
    try:
        return canon.canon1(data, media_type, layer="rendered").encode("utf-8")
    except ValueError:
        return b""


def _media(manifest, name):
    for e in manifest.get("files") or []:
        if e.get("name") == name:
            return e.get("media_type")
    return None


def _int(v, default=0):
    return v if isinstance(v, int) and not isinstance(v, bool) else default


PLATFORM_FIELDS = ("name", "post_uri", "author_did", "handle", "handle_resolution", "did_doc_sha256", "signature", "commit_cid",
                   "created_at_claimed")
RESOLUTION_FIELDS = ("method", "result_did", "at", "bidirectional")


def _short(v, n=512):
    return v if isinstance(v, str) and len(v) <= n else None


def platform_of(p):
    """The §2.3 `platform` of a `capture: post` (B5a): exactly its fields, strings or null (bidirectional a boolean),
    anything else dropped to null; None for a page capture."""
    if not isinstance(p, dict):
        return None
    hr = p.get("handle_resolution") if isinstance(p.get("handle_resolution"), dict) else {}
    out = {k: _short(p.get(k)) for k in PLATFORM_FIELDS if k != "handle_resolution"}
    out["signature"] = p.get("signature") if p.get("signature") in ("verified", "not-available", "failed") else "failed"
    out["handle_resolution"] = {"method": hr.get("method") if hr.get("method") in ("dns-txt", "well-known") else None,
                                "result_did": _short(hr.get("result_did")), "at": _short(hr.get("at"), 64),
                                "bidirectional": hr.get("bidirectional") is True}
    return {k: out[k] for k in PLATFORM_FIELDS}


def from_capture(manifest, files, visibility):
    """(the §2.3 manifest predicate, the files with text.canonical.txt added)."""
    out = {k: v for k, v in files.items() if k != TEXT_FILE}
    if "rendered.html" in out:
        text = text_canonical(out["rendered.html"], "text/html")
    elif "response.body" in out:
        text = text_canonical(out["response.body"], _media(manifest, "response.body") or "text/plain")
    else:
        text = b""
    out[TEXT_FILE] = text
    entries = []
    for e in manifest.get("files") or []:
        if e.get("name") in out and e.get("name") != TEXT_FILE:
            entry = {"name": e["name"], "sha256": hashlib.sha256(out[e["name"]]).hexdigest(), "size": len(out[e["name"]])}
            if isinstance(e.get("media_type"), str):
                entry["media_type"] = e["media_type"]
            entries.append(entry)
    entries.append({"name": TEXT_FILE, "sha256": hashlib.sha256(text).hexdigest(), "size": len(text),
                    "media_type": "text/plain; charset=utf-8"})
    f = manifest.get("fetcher") or {}
    pred = {k: manifest.get(k) for k in COPIED}
    pred["fetch_ms"] = _int(pred["fetch_ms"])
    pred["status"] = _int(pred["status"])
    pred["redirects"] = list(pred["redirects"] or [])
    pred["resolved_ips"] = list(pred["resolved_ips"] or [])
    pred.update(fetcher={"id": f.get("id"), "version": f.get("version"), "browser": f.get("browser"),
                         "viewport": list(f.get("viewport") or [])},
                files=entries, canonicaliser=canon.CANON_ID, platform=platform_of(manifest.get("platform")),
                visibility=visibility)
    jcs.canonical(pred)  # integers only (BD9): a float from the fetcher stops here
    return pred, out


def manifest_digest(pred):
    return ids.sha256_hex(jcs.canonical(pred))


def statement(pred, salt=None):
    """(in-toto statement, disclosure or None) for a manifest predicate; private when pred["visibility"] is "private"."""
    if pred["visibility"] == "public":
        return {"_type": STATEMENT_TYPE, "subject": [{"name": pred["final_url"], "digest": {"sha256": manifest_digest(pred)}}],
                "predicateType": OBSERVATION_TYPE, "predicate": pred}, None
    salt = os.urandom(16) if salt is None else salt
    body = dict(pred, visibility="private")
    commitment = ids.body_commitment(salt, body)
    stmt = {"_type": STATEMENT_TYPE, "subject": [{"name": "observation", "digest": {"sha256": commitment}}],
            "predicateType": OBSERVATION_TYPE,
            "predicate": {"visibility": "private", "body_commitment": commitment, "fetched_at": pred["fetched_at"],
                          "fetcher": {"id": pred["fetcher"]["id"], "version": pred["fetcher"]["version"]}}}
    return stmt, {"salt": ids.b64url(salt), "body": body}


def files_match(pred, files):
    """True when every file the manifest lists is present and hashes to its fingerprint."""
    for e in pred.get("files") or []:
        data = files.get(e.get("name"))
        if data is None or hashlib.sha256(data).hexdigest() != e.get("sha256"):
            return False
    return True
