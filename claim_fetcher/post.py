"""`capture: post` (slice B5a, SPEC §2.2, §2.3): a Bluesky post, captured as a page and proven from AT Protocol.

capture_post(url, handle) runs two things side by side, both bounded and both through an egress proxy with the
address rules (README_FETCHER.md, "capture: post"):
- the page: the normal page capture of the bsky.app URL (Chromium in its namespace), so a person can see the post;
- the platform part (run_platform): outside the namespace, like robots.txt, every HTTPS request through its own
  EgressProxy (resolve once, vet every address, dial the vetted address), and DNS TXT through the public resolvers:
  1. the repository's DID: the URL's DID, or the URL's handle resolved (DNS TXT `_atproto.<handle>`, else
     `https://<handle>/.well-known/atproto-did`);
  2. its DID document (plc.directory for did:plc, the domain for did:web);
  3. `com.atproto.sync.getRecord` from the PDS the document names: the CAR with the signed commit, the MST path and
     the record, checked by claim_fetcher.atproto against the document's #atproto key;
  4. the claimed handle (the request's `handle`, else the URL's handle, else the document's first) resolved to a DID,
     and that DID's document read back: `bidirectional` when it lists at://<handle>.

platform.json holds the SPEC §2.3 fields (platform_fields) and a few more for a reader (README_FETCHER.md); the
manifest's `platform` is exactly the §2.3 fields. A network failure reading the DID document or the PDS is the
capture's error with the fetcher's codes; a PDS that will not give the record, or a document without a usable key, is
`signature: not-available`; a proof that does not check is `failed`. Handle resolution never fails the capture.
"""
import asyncio
import contextlib
import hashlib
import json
import os
import re
import shutil
import ssl
import tempfile
import time
import urllib.parse

from . import addr, atproto, dnsclient, robots
from . import capture as capture_mod
from .proxy import EgressProxy

SPEC_FIELDS = ("name", "post_uri", "author_did", "handle", "handle_resolution", "did_doc_sha256", "signature",
               "commit_cid", "created_at_claimed")
MAX_DOC_BYTES = atproto.MAX_DID_DOC
MAX_CAR_BYTES = 2 * 1024 * 1024
MAX_WELL_KNOWN = 2048
REQUEST_TIMEOUT_S = 8.0
PLATFORM_TIMEOUT_S = 15.0
CREATED_AT_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?(Z|[+-]\d{2}:\d{2})$")
CODES = {"blocked", "timeout", "unreachable", "too-large"}


class FetchError(Exception):
    """A platform request that failed: code is one of the fetcher's codes (blocked, timeout, unreachable, too-large)."""

    def __init__(self, code, detail=""):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code if code in CODES else "unreachable"
        self.detail = str(detail)[:300]


def _now_iso():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def platform_fields(pj):
    """The SPEC §2.3 `platform` object from a platform.json dict: exactly its fields, in its order."""
    return {k: pj.get(k) for k in SPEC_FIELDS}


# requests through the egress proxy ------------------------------------------------------------------------------------

class ProxyGetter:
    """GET through the egress proxy's Unix socket: CONNECT host:port (the proxy vets the host's every address and
    dials the vetted one; a refusal carries X-Fetcher-Refused), TLS with certificate checks for https, then one
    HTTP/1.1 request. Follows up to 5 redirects, each a new CONNECT. (status, content type, body) or FetchError."""

    def __init__(self, proxy_socket, user_agent, ssl_context=None, max_redirects=addr.MAX_REDIRECTS,
                 timeout=REQUEST_TIMEOUT_S):
        self.proxy_socket, self.user_agent = proxy_socket, user_agent
        self.ssl_context = ssl_context or ssl.create_default_context()
        self.max_redirects, self.timeout = max_redirects, timeout
        self.log = []

    async def __call__(self, url, accept, max_bytes):
        for hop in range(self.max_redirects + 1):
            try:
                status, headers, body = await asyncio.wait_for(self._once(url, accept, max_bytes), self.timeout)
            except asyncio.TimeoutError:
                raise FetchError("timeout", urllib.parse.urlsplit(url).hostname or "") from None
            self.log.append({"url": url, "status": status})
            if status in (301, 302, 303, 307, 308) and headers.get("location"):
                try:
                    url = addr.next_hop(url, headers["location"], hop + 1, self.max_redirects)
                except addr.Refused as e:
                    raise FetchError("blocked", f"{e.code} {e.detail}") from None
                continue
            return status, headers.get("content-type", ""), body
        raise FetchError("blocked", "too-many-redirects")

    async def _once(self, url, accept, max_bytes):
        try:
            scheme, host, port = addr.check_url(url)
        except addr.Refused as e:
            raise FetchError("blocked", f"{e.code} {e.detail}") from None
        parts = urllib.parse.urlsplit(url)
        path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
        authority = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
        host_header = f"[{host}]" if ":" in host else host
        if port != (443 if scheme == "https" else 80):
            host_header += f":{port}"
        try:
            reader, writer = await asyncio.open_unix_connection(self.proxy_socket)
        except OSError as e:
            raise FetchError("unreachable", f"egress proxy: {e}") from None
        try:
            writer.write(f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n".encode())
            await writer.drain()
            head = await reader.readuntil(b"\r\n\r\n")
            status_line, _, rest = head.decode("latin-1").partition("\r\n")
            code = status_line.split(" ")[1] if len(status_line.split(" ")) > 1 else ""
            if code != "200":
                refused = ""
                for line in rest.split("\r\n"):
                    k, _, v = line.partition(":")
                    if k.strip().lower() == "x-fetcher-refused":
                        refused = v.strip()
                mapped = {"timeout": "timeout", "unreachable": "unreachable"}.get(refused, "blocked" if code == "403"
                                                                               else "unreachable")
                raise FetchError(mapped, f"{host}: {refused or code}")
            if scheme == "https":
                await writer.start_tls(self.ssl_context, server_hostname=host)
            writer.write((f"GET {path} HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: {self.user_agent}\r\n"
                          f"Accept: {accept}\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n").encode())
            await writer.drain()
            head = await reader.readuntil(b"\r\n\r\n")
            lines = head.decode("latin-1").split("\r\n")
            status = int(lines[0].split(" ")[1])
            headers = {}
            for h in lines[1:]:
                k, sep, v = h.partition(":")
                if sep:
                    headers[k.strip().lower()] = v.strip()
            length = headers.get("content-length")
            if length and length.isdigit() and int(length) > max_bytes:
                raise FetchError("too-large", f"{host}: {length} bytes")
            body = bytearray()
            while True:
                chunk = await reader.read(65536)
                if not chunk:
                    break
                body += chunk
                if len(body) > max_bytes + 65536:
                    raise FetchError("too-large", f"{host}: over {max_bytes} bytes")
            body = bytes(body)
            if "chunked" in headers.get("transfer-encoding", "").lower():
                body = robots._dechunk(body)
            elif length and length.isdigit():
                body = body[:int(length)]
            if len(body) > max_bytes:
                raise FetchError("too-large", f"{host}: over {max_bytes} bytes")
            return status, headers, body
        except FetchError:
            raise
        except ssl.SSLError as e:
            raise FetchError("unreachable", f"{host}: tls {type(e).__name__}") from None
        except (OSError, asyncio.IncompleteReadError, asyncio.LimitOverrunError, ValueError, IndexError) as e:
            raise FetchError("unreachable", f"{host}: {type(e).__name__}") from None
        finally:
            with contextlib.suppress(Exception):
                writer.close()


# the platform part (pure over a getter and a TXT lookup) ---------------------------------------------------------------

async def _doc(get, did):
    """(bytes, info or None) of a DID's document. FetchError for a network failure or an answer that is not 200."""
    status, _, body = await get(atproto.did_doc_url(did), "application/did+json, application/json", MAX_DOC_BYTES)
    if status != 200:
        raise FetchError("unreachable", f"DID document of {did}: status {status}")
    try:
        return body, atproto.did_doc_info(body, did)
    except ValueError:
        return body, None


async def _resolve_handle(handle, get, txt, now):
    """{method, result_did, at} for a handle: DNS TXT first; HTTPS well-known when DNS gives no did= record. Two
    different did= records resolve to nothing (AT Protocol: ambiguous). Never raises."""
    at = now()
    try:
        answers = await txt(f"_atproto.{handle}")
    except (OSError, FetchError):
        answers = []
    dids = sorted({a[4:].strip() for a in answers or [] if isinstance(a, str) and a.startswith("did=")})
    if len(dids) == 1:
        return {"method": "dns-txt", "result_did": dids[0] if atproto.valid_did(dids[0]) else None, "at": at}
    if len(dids) > 1:
        return {"method": "dns-txt", "result_did": None, "at": at}
    try:
        status, _, body = await get(f"https://{handle}/.well-known/atproto-did", "text/plain", MAX_WELL_KNOWN)
    except FetchError:
        return {"method": "well-known", "result_did": None, "at": at}
    did = body.decode("utf-8", "replace").strip().split("\n", 1)[0].strip() if status == 200 else ""
    return {"method": "well-known", "result_did": did if atproto.valid_did(did) else None, "at": at}


def _pds_ok(pds):
    try:
        u = urllib.parse.urlsplit(pds)
        atproto.normalize_handle(u.hostname or "")
        return u.scheme == "https" and u.port is None and not u.query and u.path in ("", "/") and "@" not in u.netloc
    except ValueError:
        return False


async def platform_capture(url, handle, get, txt, now=_now_iso):
    """(platform.json dict, extra files {name: bytes}) for a bsky.app post URL. `get(url, accept, max_bytes)` and
    `txt(name)` are the network (through the egress proxy and the public resolvers in run_platform; recorded answers in
    the tests). FetchError when the DID document or the PDS cannot be reached."""
    actor, rkey = atproto.parse_post_url(url)
    claimed = atproto.normalize_handle(handle) if handle else None
    files = {}
    resolved = {}

    async def resolve(h):
        if h not in resolved:
            resolved[h] = await _resolve_handle(h, get, txt, now)
        return resolved[h]

    pj = {"name": "bluesky", "post_uri": None, "author_did": None, "handle": None,
          "handle_resolution": {"method": None, "result_did": None, "at": None, "bidirectional": False},
          "did_doc_sha256": None, "signature": "not-available", "commit_cid": None, "created_at_claimed": None,
          "url_actor": actor, "record_cid": None, "commit_rev": None, "pds": None, "key_type": None,
          "author_handles": [], "signature_reason": None, "handle_did_doc_sha256": None}
    if actor.startswith("did:"):
        did = actor
    else:
        did = (await resolve(actor))["result_did"]
        if did is None:
            pj["signature_reason"] = "url-handle-unresolved"
    info = None
    if did is not None:
        pj["author_did"] = did
        pj["post_uri"] = f"at://{did}/{atproto.POST_COLLECTION}/{rkey}"
        doc, info = await _doc(get, did)
        files["did-document.json"] = doc
        pj["did_doc_sha256"] = hashlib.sha256(doc).hexdigest()
        if info is None:
            pj["signature_reason"] = "did-document-unreadable"
        else:
            pj["author_handles"] = list(info["handles"])
            if not info["pds"] or not _pds_ok(info["pds"]):
                pj["signature_reason"] = "no-pds"
            else:
                pj["pds"] = info["pds"].rstrip("/")
                q = urllib.parse.urlencode({"did": did, "collection": atproto.POST_COLLECTION, "rkey": rkey},
                                           quote_via=urllib.parse.quote)
                status, _, car = await get(f"{pj['pds']}/xrpc/com.atproto.sync.getRecord?{q}",
                                           "application/vnd.ipld.car", MAX_CAR_BYTES)
                if status != 200:
                    pj["signature_reason"] = f"pds-status-{status}"
                else:
                    files["post.car"] = car
                    got = atproto.verify_record(car, did, atproto.POST_COLLECTION, rkey, info["key"])
                    pj.update(signature=got["signature"], signature_reason=got["reason"], commit_cid=got["commit_cid"],
                              record_cid=got["record_cid"], commit_rev=got["rev"], key_type=got.get("key_type"))
                    created = (got["record"] or {}).get("createdAt")
                    if isinstance(created, str) and CREATED_AT_RE.match(created):
                        pj["created_at_claimed"] = created
    if claimed is None:
        claimed = actor if not actor.startswith("did:") else (pj["author_handles"][0] if pj["author_handles"] else None)
    pj["handle"] = claimed
    if claimed is not None:
        r = dict(await resolve(claimed))
        bidirectional = False
        if r["result_did"] is not None and r["result_did"] == did and info is not None:
            bidirectional = claimed in info["handles"]
        elif r["result_did"] is not None:
            try:
                hdoc, hinfo = await _doc(get, r["result_did"])
            except (FetchError, ValueError):
                hdoc, hinfo = None, None
            if hdoc is not None:
                files["handle-did-document.json"] = hdoc
                pj["handle_did_doc_sha256"] = hashlib.sha256(hdoc).hexdigest()
                bidirectional = hinfo is not None and claimed in hinfo["handles"]
        r["bidirectional"] = bool(bidirectional)
        pj["handle_resolution"] = {"method": r["method"], "result_did": r["result_did"], "at": r["at"],
                                   "bidirectional": r["bidirectional"]}
    return pj, files


# the real network: an egress proxy of its own, the public resolvers ----------------------------------------------------

async def run_platform(url, handle, settings, resolver, connector=None):
    """platform_capture through a fresh EgressProxy (Unix socket in a private directory) and the public resolvers,
    bounded by settings.post_timeout_s (15 s)."""
    tmp = tempfile.mkdtemp(prefix="claim-post-", dir=settings.work_dir)
    os.chmod(tmp, 0o700)
    proxy = EgressProxy(os.path.join(tmp, "egress.sock"), resolver=resolver, connector=connector,
                        extra_cidrs=settings.blocked_cidrs, max_response_bytes=settings.max_response_bytes,
                        max_total_bytes=settings.max_total_bytes, connect_timeout=settings.connect_timeout_s)
    await proxy.start()
    loop = asyncio.get_running_loop()

    async def txt(name):
        return await loop.run_in_executor(None, resolver.txt, name)

    try:
        get = ProxyGetter(proxy.socket_path, settings.user_agent or robots.user_agent_for())
        return await asyncio.wait_for(platform_capture(url, handle, get, txt),
                                      getattr(settings, "post_timeout_s", PLATFORM_TIMEOUT_S))
    except asyncio.TimeoutError:
        raise FetchError("timeout", "the platform requests ran out of time") from None
    finally:
        await proxy.close()
        shutil.rmtree(tmp, ignore_errors=True)


def platform_json_bytes(pj):
    return json.dumps(pj, sort_keys=True, indent=1, ensure_ascii=False).encode("utf-8")


async def capture_post(url, handle=None, viewport=(1280, 900), settings=None, resolver=None, connector=None):
    """The page capture of the post URL plus the platform part: a capture.Result whose files add platform.json (and
    post.car, did-document.json, handle-did-document.json when read) and whose manifest has `platform`. A URL that is
    not a bsky.app post, or a bad handle, is refused (bad-request) before any request."""
    try:
        atproto.parse_post_url(url)
        handle = atproto.normalize_handle(handle) if handle else None
    except ValueError as e:
        raise capture_mod.CaptureError("bad-request", str(e)) from None
    settings = settings or capture_mod.Settings()
    resolver = resolver or dnsclient.PublicResolver(settings.resolvers, extra=settings.blocked_cidrs)
    page, plat = await asyncio.gather(capture_mod.capture(url, viewport, settings, resolver=resolver, connector=connector),
                                      run_platform(url, handle, settings, resolver, connector),
                                      return_exceptions=True)
    if isinstance(page, BaseException):
        raise page
    if isinstance(plat, FetchError):
        raise capture_mod.CaptureError(plat.code, f"platform: {plat.detail}", page.proxy_log) from None
    if isinstance(plat, BaseException):
        raise plat
    pj, extra = plat
    files = dict(page.files)
    files["platform.json"] = platform_json_bytes(pj)
    files.update(extra)
    manifest = dict(page.manifest)
    body_type = next((f.get("media_type") for f in manifest.get("files") or [] if f.get("name") == "response.body"), None)
    manifest["files"] = capture_mod.file_entries(files, body_type)
    manifest["platform"] = platform_fields(pj)
    return capture_mod.Result(manifest, files, page.proxy_log)


def capture_post_sync(url, handle=None, viewport=(1280, 900), settings=None, resolver=None, connector=None):
    return asyncio.run(capture_post(url, handle, viewport, settings, resolver=resolver, connector=connector))
