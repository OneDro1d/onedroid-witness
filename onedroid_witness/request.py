"""The request (contract section 4): the manifest, audit.jsonl byte for byte, its signature and the auditor's allowed_signers line, the
audited text, the model list and the cost bound. Everything is checked before any model is called: the auditor signature, the hashes,
the profile (read from the manifest, never chosen by the caller), the size cap, and in public mode that the part is published.

The published check fetches a caller-named URL, so it is an SSRF surface (3c.8): https only, the host resolved first and refused when
any address is private, loopback or link-local, no redirect followed, 10 s, a size cap.
"""
import hashlib
import ipaddress
import json
import pathlib
import socket
import urllib.parse
import urllib.request

MAX_CLAIMS = 1000
FETCH_TIMEOUT_S = 10
FETCH_MAX_BYTES = 8 * 1024 * 1024


class Refused(ValueError):
    """A request refused before any model call; the message is what the caller sees."""


def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


def profile_of(manifest):
    p = (manifest.get("profile") or (manifest.get("subject") or {}).get("profile") or "cited-sources")
    return p


class Request:
    """A loaded, checked request. `root` is the folder holding the parts (a job's request/ folder or a snapshot folder)."""

    def __init__(self, root, private_mode=False, verify_signature=None):
        self.root = pathlib.Path(root)
        self.private_mode = private_mode
        self.manifest = self._json("manifest.json")
        self.audit_bytes = self._bytes("audit.jsonl")
        self.audit_sha256 = sha256_bytes(self.audit_bytes)
        self.audit = [json.loads(l) for l in self.audit_bytes.decode("utf-8").splitlines() if l.strip()]
        if not self.audit:
            raise Refused("audit.jsonl holds no rows")
        if len(self.audit) > MAX_CLAIMS:
            raise Refused(f"{len(self.audit)} claims exceed the cap of {MAX_CLAIMS} per request; split by surface and merge by claim id")
        ids = [r.get("id") for r in self.audit]
        if len(set(ids)) != len(ids) or any(not i for i in ids):
            raise Refused("audit.jsonl ids must be present and unique")
        for r in self.audit:
            for f in ("verdict", "confidence", "graded_by", "graded_at"):
                if f in r:
                    raise Refused(f"audit.jsonl row {r.get('id')} carries a decision field ({f}); the auditor part carries no verdicts (K11)")
        self.profile = profile_of(self.manifest)
        self.page = self._text_optional("page.txt") or ""
        self._check_manifest_hash()
        self._check_auditor_signature(verify_signature)
        self.primary = next((w for w in (self.manifest.get("grading") or {}).get("witnesses", []) if w.get("primary")), None)

    def _bytes(self, name):
        p = self.root / name
        if not p.is_file():
            raise Refused(f"{name} is missing from the request")
        return p.read_bytes()

    def _json(self, name):
        try:
            return json.loads(self._bytes(name).decode("utf-8"))
        except ValueError as e:
            raise Refused(f"{name} is not JSON: {e}")

    def _text_optional(self, name):
        p = self.root / name
        return p.read_text(encoding="utf-8") if p.is_file() else None

    def _check_manifest_hash(self):
        want = ((self.manifest.get("grading") or {}).get("auditor") or {}).get("sha256") or self.manifest.get("audit_sha256")
        if want and want != self.audit_sha256:
            raise Refused(f"audit.jsonl sha256 {self.audit_sha256} does not match the manifest's {want}")

    def _check_auditor_signature(self, verify):
        """audit.jsonl.sig over the prescribed line, against the auditor's allowed_signers line; refused when unsigned or broken."""
        sig = self.root / "audit.jsonl.sig"
        signers = self.root / "allowed_signers"
        if not sig.is_file() or not signers.is_file():
            raise Refused("the auditor part is unsigned: audit.jsonl.sig and allowed_signers are both required")
        fmt = self.manifest.get("format", "claims-snapshot/0.4")
        line = f"{fmt} auditor audit.jsonl sha256:{self.audit_sha256}"
        identity = None
        sigs = self._text_optional("signatures.json")
        if sigs:
            try:
                for e in json.loads(sigs):
                    if e.get("role") == "auditor" and e.get("file") == "audit.jsonl":
                        identity = (e.get("signer") or {}).get("name")
                        line = e.get("line") or line
            except ValueError:
                pass
        if identity is None:
            first = signers.read_text(encoding="utf-8").strip().splitlines()
            identity = first[0].split()[0] if first else None
        if not identity:
            raise Refused("no auditor identity: signatures.json names none and allowed_signers is empty")
        if verify is None:
            from .signing import verify as _verify
            verify = _verify
        ok, out = verify(signers, identity, line, sig)
        if not ok:
            raise Refused(f"the auditor signature does not verify for {identity}: {out[:200]}")
        self.auditor_identity = identity
        self.auditor_line = line


def _refuse_private_host(host):
    try:
        infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        raise Refused(f"the host {host} does not resolve: {e}")
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
            raise Refused(f"the host {host} resolves to {ip}, a private, loopback or link-local address; refused before any fetch")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise Refused(f"the published URL redirects ({code}); redirects are not followed")


def fetch_published(url, opener_factory=None):
    """Fetch a caller-named public URL under the SSRF rules and return its bytes; every refusal happens before the fetch."""
    u = urllib.parse.urlparse(url)
    if u.scheme != "https":
        raise Refused("the published URL must be https")
    if not u.hostname:
        raise Refused("the published URL has no host")
    _refuse_private_host(u.hostname)
    opener = (opener_factory or (lambda: urllib.request.build_opener(_NoRedirect)))()
    req = urllib.request.Request(url, headers={"User-Agent": "onedroid-witness/0.1 (published-check)"})
    with opener.open(req, timeout=FETCH_TIMEOUT_S) as r:
        data = r.read(FETCH_MAX_BYTES + 1)
    if len(data) > FETCH_MAX_BYTES:
        raise Refused(f"the published copy is larger than {FETCH_MAX_BYTES} bytes")
    return data


def check_published(request, published_url=None, catalogue_lookup=None, fetch=fetch_published):
    """Public mode: the auditor part must be published, as a catalogue record (preferred) or at a public URL whose audit.jsonl matches
    byte for byte. Private mode skips this: the caller's own estate, the caller's own key."""
    if request.private_mode:
        return {"mode": "private", "published": None}
    if catalogue_lookup is not None:
        rec = catalogue_lookup(request.audit_sha256)
        if rec:
            return {"mode": "public", "published": {"catalogue": rec}}
    if not published_url:
        raise Refused("the public service takes published parts only: name the catalogue record or the public URL of audit.jsonl")
    data = fetch(published_url)
    if sha256_bytes(data) != request.audit_sha256:
        raise Refused(f"the published copy at {published_url} has sha256 {sha256_bytes(data)}, not the request's {request.audit_sha256}")
    return {"mode": "public", "published": {"url": published_url, "sha256": request.audit_sha256}}
