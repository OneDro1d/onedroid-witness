"""The request (contract section 4): the manifest, audit.jsonl byte for byte, its signature and the auditor's allowed_signers line, the
audited text, the model list and the cost bound. Everything is checked before any model is called: the auditor signature, the hashes,
the profile (read from the manifest, never chosen by the caller), the size cap, and in public mode that the part is published.

The published check fetches a caller-named URL, so it is an SSRF surface (3c.8): https only, the host resolved first and refused when
any address is private, loopback or link-local, no redirect followed, 10 s, a size cap.
"""
import hashlib
import http.client
import ipaddress
import json
import pathlib
import re
import socket
import ssl
import urllib.parse

MAX_CLAIMS = 1000
FETCH_TIMEOUT_S = 10
FETCH_MAX_BYTES = 8 * 1024 * 1024


class Refused(ValueError):
    """A request refused before any model call; the message is what the caller sees."""


def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


PROFILES = ("cited-sources", "publisher-surfaces", "agent-work", "test-run")  # check.py PROFILES; the prompts module names the same four

# check.py's K9 patterns (the format's own rule): a credential-shaped string in any part is refused before any model call (gate D10)
SECRET_PATTERNS = [
    re.compile(r"\b(?:sk|pk|rk)-[A-Za-z0-9_-]{20,}"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bxox[abpr]-[A-Za-z0-9-]{10,}"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}"),
]


def profile_of(manifest):
    """The profile is grading.profile (SPEC 3; check.py reads it there). The older manifest.profile and subject.profile are read only
    when grading.profile is absent (gate D2: a publisher-surfaces snapshot was witnessed with the cited-sources prompt)."""
    g = manifest.get("grading") if isinstance(manifest.get("grading"), dict) else {}
    p = g.get("profile") or manifest.get("profile") or (manifest.get("subject") or {}).get("profile") or "cited-sources"
    if p not in PROFILES:
        raise Refused(f"grading.profile {p!r} is not one of {PROFILES}")
    return p


def refuse_credentials(name, text):
    """A credential-shaped string in a part is refused by the part's name and the pattern's shape; the value is never repeated."""
    for pat in SECRET_PATTERNS:
        if pat.search(text):
            raise Refused(f"a credential-shaped string in {name} (K9 shape {pat.pattern[:14]}...): refused before any model call; the value is not repeated here")


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
        refuse_credentials("audit.jsonl", self.audit_bytes.decode("utf-8", "replace"))
        refuse_credentials("page.txt", self.page)
        refuse_credentials("manifest.json", json.dumps(self.manifest, ensure_ascii=False))
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
        # The signed line is REBUILT from the bytes received (SPEC 3a: `claims-snapshot/0.4 auditor audit.jsonl sha256:<hex>`, the prefix
        # names the signing rule and never changes). It is never taken from the caller's signatures.json: a part changed after signing
        # with the old line kept would otherwise verify (gate D1). signatures.json supplies the identity, and its entry must agree.
        line = f"claims-snapshot/0.4 auditor audit.jsonl sha256:{self.audit_sha256}"
        identity = None
        sigs = self._text_optional("signatures.json")
        if sigs:
            try:
                entries = json.loads(sigs)
            except ValueError:
                raise Refused("signatures.json is not JSON")
            for e in (entries if isinstance(entries, list) else []):
                if isinstance(e, dict) and e.get("role") == "auditor" and e.get("file") == "audit.jsonl":
                    identity = (e.get("signer") or {}).get("name")
                    if e.get("sha256") not in (None, self.audit_sha256):
                        raise Refused(f"signatures.json names audit.jsonl sha256 {str(e.get('sha256'))[:12]}..., the part received is {self.audit_sha256[:12]}...: the auditor signature does not cover these bytes")
                    if e.get("line") not in (None, line):
                        raise Refused("signatures.json carries a signed line that is not the prescribed line over the bytes received: the auditor signature does not cover these bytes")
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


# Addresses a fetch never reaches, beyond what ipaddress classifies as private, loopback, link-local, reserved or multicast (gate D8):
# the Azure instance metadata WireServer (this service runs on AKS; estate rule, Engram 0a1fac7d), the carrier-grade NAT space, the
# "this network" block, the IETF protocol assignments block, the benchmarking range, class E, the NAT64 well-known prefix.
REFUSED_NETWORKS = [ipaddress.ip_network(n) for n in (
    "168.63.129.16/32", "169.254.0.0/16", "100.64.0.0/10", "0.0.0.0/8", "192.0.0.0/24", "198.18.0.0/15", "224.0.0.0/4", "240.0.0.0/4",
    "::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8", "64:ff9b::/96", "::ffff:0:0/96")]


def _refuse_address(host, ip):
    ip = ipaddress.ip_address(ip)
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified or any(ip in n for n in REFUSED_NETWORKS):
        raise Refused(f"the host {host} resolves to {ip}, an address a published copy is never fetched from (private, loopback, link-local, metadata or reserved); refused before any fetch")
    return str(ip)


def _resolve_once(host):
    """One resolution; every address the name has is checked, the first is the one connected to (so a name that rebinds between the check
    and the connection cannot steer the fetch, gate D8)."""
    try:
        infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        raise Refused(f"the host {host} does not resolve: {e}")
    if not infos:
        raise Refused(f"the host {host} does not resolve")
    for info in infos:
        _refuse_address(host, info[4][0])
    return infos[0][4][0]


def _refuse_private_host(host):
    """A literal address or a name: refused before any fetch when any address it has is one the fetch never reaches."""
    try:
        return _refuse_address(host, ipaddress.ip_address(host.strip("[]")))
    except ValueError:
        return _resolve_once(host)


class _PinnedHTTPS(http.client.HTTPSConnection):
    """TLS to the address already checked, with the URL's host name for the certificate and the Host header: no second resolution."""

    def __init__(self, host, ip, timeout):
        super().__init__(host, 443, timeout=timeout, context=ssl.create_default_context())
        self._pinned_ip = ip

    def connect(self):
        sock = socket.create_connection((self._pinned_ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


def _connect_and_get(host, ip, path, timeout):
    """GET over a pinned connection: (status, body up to the cap plus one byte). Redirects are not followed (the status is returned)."""
    c = _PinnedHTTPS(host, ip, timeout)
    try:
        c.request("GET", path, headers={"Host": host, "User-Agent": "onedroid-witness/0.1 (published-check)", "Accept": "*/*"})
        r = c.getresponse()
        return r.status, r.read(FETCH_MAX_BYTES + 1)
    finally:
        c.close()


def fetch_published(url, opener_factory=None, resolve=None, connect=None):
    """Fetch a caller-named public URL under the SSRF rules and return its bytes; every refusal happens before the fetch. The name is
    resolved once, every address checked, and the connection made to the checked address with the host name for TLS (3c.8, gate D8).
    `resolve(host) -> ip` and `connect(host, ip, path, timeout) -> (status, body)` are injectable for tests."""
    u = urllib.parse.urlparse(url)
    if u.scheme != "https":
        raise Refused("the published URL must be https")
    if not u.hostname:
        raise Refused("the published URL has no host")
    if u.port not in (None, 443):
        raise Refused("the published URL must use port 443")
    if u.username or u.password:
        raise Refused("the published URL carries credentials; refused")
    ip = _refuse_address(u.hostname, (resolve or _resolve_once)(u.hostname)) if resolve else _refuse_private_host(u.hostname)
    path = (u.path or "/") + (("?" + u.query) if u.query else "")
    status, data = (connect or _connect_and_get)(u.hostname, ip, path, FETCH_TIMEOUT_S)
    if 300 <= status < 400:
        raise Refused(f"the published URL redirects ({status}); redirects are not followed")
    if status != 200:
        raise Refused(f"the published URL answered {status}")
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
