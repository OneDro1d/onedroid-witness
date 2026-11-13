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

from .render import safe_relative

MAX_CLAIMS = 1000
CARRIED_PREFIXES = ("sources/", "sessions/")  # the folders of a snapshot a request may carry beside the fixed parts (S-1, D1)
TEST_RUN_ROWS = ("C-001", "C-002", "C-003")  # SPEC 13: a test-run auditor part has exactly these three rows, in this order (S-2)
FETCH_TIMEOUT_S = 10
FETCH_MAX_BYTES = 8 * 1024 * 1024


class Refused(ValueError):
    """A request refused before any model call; the message is what the caller sees."""


def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


PROFILES = ("cited-sources", "publisher-surfaces", "agent-work", "test-run")  # check.py PROFILES; the prompts module names the same four
# The profiles the SERVICE runs model witnesses on (second re-gate N1, 13 Nov 2026): publisher-surfaces is out until the format carries a
# candidate kind (restatement | artefact) from the auditor and a gate passes on it (NEXT-REVISION 23). With the publisher relation rendered
# and named in the prompt, chat models still answered EVIDENCED on 3 of 6 restatements on the publisher's own surface, and no row rule can
# tell a restatement from an artefact (a terms page is own-surface AND the artefact). A configuration may widen this list; the default is here.
# Third re-gate F1 (13 Nov 2026 02:1xZ): agent-work and test-run are out too. A request carries only the fixed parts, so a model deciding
# one of their claims never sees the file line, the handed-in output, the artefact or run.json the claim points at (39 of 39 live answers
# were NO EVIDENCE PUBLISHED, including claims whose evidence showed them and claims whose evidence showed the opposite). Served again since
# service item S-1 (13 Nov 2026): a request carries the files the manifest lists under sources[].file and grading.sessions[].file, each
# hash-checked (_check_carried), render.py resolves every pointer of an `evidence` row from them, a pointer that cannot be read is said so by
# name and never carries a verdict (normalise.apply_row_rules), and `on` indexes the row's `evidence` list (SPEC 4b, check.py 872-890).
PROFILES_SERVED = ("cited-sources", "agent-work", "test-run")
PROFILES_NOT_SERVED_WHY = {"publisher-surfaces": "model witnesses do not apply the restatement rule reliably; out of scope until the auditor marks each candidate "
                                                 "restatement or artefact (NEXT-REVISION 23) and a gate passes on it"}


def is_carried_part(name):
    """A part name the request accepts beside the fixed parts: a normalised relative path (no leading /, no `..` component, no backslash,
    no NUL) under sources/ or sessions/ with at least one more component (S-1, D1). Any other unknown name stays refused."""
    return safe_relative(name) and name.startswith(CARRIED_PREFIXES) and "/" in name.rstrip("/") and not name.endswith("/")

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


def check_manifest_shape(manifest):
    """Second re-gate P1 (the claims session, 13 Nov 2026): the parts of the manifest the service reads after the request checks
    (source_index, render, the estimate, the worker's add_witness and check.py) have the shapes SPEC.md gives them, or the request is
    refused here, by name, before anything runs on them. Absent keys stay allowed where the renderer tolerates their absence; a key that
    is present has to have its shape (null is not absent: `sources: null` would be iterated)."""
    def list_of_objects(key, value):
        if not isinstance(value, list):
            raise Refused(f"manifest {key} is not a list")
        for i, entry in enumerate(value):
            if not isinstance(entry, dict):
                raise Refused(f"manifest {key}[{i}] is not an object")
    if "sources" in manifest:
        list_of_objects("sources", manifest["sources"])
        for i, s in enumerate(manifest["sources"]):
            if s.get("url") is not None and not isinstance(s.get("url"), str):
                raise Refused(f"manifest sources[{i}].url is not a string")
    if "pages" in manifest:
        list_of_objects("pages", manifest["pages"])
    if "subject" in manifest and not isinstance(manifest["subject"], dict):
        raise Refused("manifest subject is not an object")
    if "grading" in manifest:
        g = manifest["grading"]
        if not isinstance(g, dict):
            raise Refused("manifest grading is not an object")
        if "witnesses" in g:
            list_of_objects("grading.witnesses", g["witnesses"])
        if "auditor" in g and not isinstance(g["auditor"], dict):
            raise Refused("manifest grading.auditor is not an object")


def refuse_credentials(name, text):
    """A credential-shaped string in a part is refused by the part's name and the pattern's shape; the value is never repeated."""
    for pat in SECRET_PATTERNS:
        if pat.search(text):
            raise Refused(f"a credential-shaped string in {name} (K9 shape {pat.pattern[:14]}...): refused before any model call; the value is not repeated here")


class Request:
    """A loaded, checked request. `root` is the folder holding the parts (a job's request/ folder or a snapshot folder)."""

    def __init__(self, root, private_mode=False, verify_signature=None, profiles_served=None):
        """profiles_served: the profiles this caller runs model witnesses on (the service passes PROFILES_SERVED or its configuration's
        list); None reads every profile the format has, for the library's own readers."""
        self.root = pathlib.Path(root)
        self.private_mode = private_mode
        # 0.1.6 (fifth re-gate H1): the manifest's bytes as received and their sha256 are kept, so every answer can record which manifest
        # the models' evidence was resolved from (answer.run) and public mode can bind it to the published snapshot (check_published)
        self.manifest_bytes = self._bytes("manifest.json")
        self.manifest_sha256 = sha256_bytes(self.manifest_bytes)
        self.manifest = self._json("manifest.json", self.manifest_bytes)
        self.audit_bytes = self._bytes("audit.jsonl")
        self.audit_sha256 = sha256_bytes(self.audit_bytes)
        # re-gate N3: a part that does not read is a refusal with an answer, never an exception past the handler; rows are split on \n
        # only, because a raw U+2028 or U+2029 inside a JSON string is valid JSON and str.splitlines() would cut the row in two
        try:
            text = self.audit_bytes.decode("utf-8")
        except UnicodeDecodeError as e:
            raise Refused(f"audit.jsonl is not UTF-8 (byte {e.start})")
        if text.startswith("﻿"):  # second re-gate note: said by name rather than as "line 1 is not JSON"; the format's reader takes none
            raise Refused("audit.jsonl starts with a UTF-8 BOM (bytes EF BB BF); the format's reader takes none: remove it and sign the bytes again")
        self.audit = []
        for n, l in enumerate(text.split("\n"), 1):
            if not l.strip():
                continue
            try:
                row = json.loads(l)
            except ValueError:
                raise Refused(f"audit.jsonl line {n} is not JSON")
            if not isinstance(row, dict):
                raise Refused(f"audit.jsonl line {n} is not a JSON object")
            self.audit.append(row)
        if not self.audit:
            raise Refused("audit.jsonl holds no rows")
        if not isinstance(self.manifest, dict):
            raise Refused("manifest.json is not a JSON object")
        check_manifest_shape(self.manifest)
        if len(self.audit) > MAX_CLAIMS:
            raise Refused(f"{len(self.audit)} claims exceed the cap of {MAX_CLAIMS} per request; split by surface and merge by claim id")
        ids = [r.get("id") for r in self.audit]
        if len(set(ids)) != len(ids) or any(not i for i in ids):
            raise Refused("audit.jsonl ids must be present and unique")
        for r in self.audit:
            if not isinstance(r.get("text"), str):
                raise Refused(f"audit.jsonl row {r.get('id')} has no claim text")
        for r in self.audit:
            for f in ("verdict", "confidence", "graded_by", "graded_at"):
                if f in r:
                    raise Refused(f"audit.jsonl row {r.get('id')} carries a decision field ({f}); the auditor part carries no verdicts (K11)")
        self.profile = profile_of(self.manifest)
        if profiles_served is not None and self.profile not in profiles_served:
            why = PROFILES_NOT_SERVED_WHY.get(self.profile, "not in this service's configuration")
            raise Refused(f"the {self.profile} profile is not served by this service ({why}); profiles served: {', '.join(profiles_served)}")
        if self.profile == "test-run" and tuple(ids) != TEST_RUN_ROWS:  # S-2, before any model call; the ids named (0.1.6, the first ten)
            raise Refused(f"a test-run auditor part has exactly the three rows C-001, C-002, C-003 (SPEC 13); this one has {len(ids)} row(s): "
                          + ", ".join(str(i) for i in ids[:10]))
        self.page = self._text_optional("page.txt") or ""
        self.page_sha256 = None  # 0.1.7 (sixth re-gate J1): the sha256 of the page.txt BYTES as received, None when absent
        refuse_credentials("audit.jsonl", self.audit_bytes.decode("utf-8", "replace"))
        refuse_credentials("page.txt", self.page)
        refuse_credentials("manifest.json", json.dumps(self.manifest, ensure_ascii=False))
        self._check_page()  # after the credential rule (gate D10 keeps the first word on a planted page), before the carried files
        self._check_manifest_hash()
        self._check_auditor_signature(verify_signature)
        self.carried = {}  # manifest path -> bytes, the files this request carries for the evidence pointers (S-1)
        self._check_carried()
        self.primary = next((w for w in (self.manifest.get("grading") or {}).get("witnesses", []) if w.get("primary")), None)

    def _check_page(self):
        """0.1.7 (sixth re-gate J1): the audited page a model reads is bound like every other carried file. When page.txt is present
        (non-empty bytes) the manifest's `pages` must hold an entry whose `file` is page.txt, and that entry's sha256, when present, must
        equal the sha256 of the bytes received; refused by name otherwise (B15b: a forged page with the manifest unchanged was accepted).
        An absent or empty page.txt checks nothing. page.txt is NOT put in self.carried (render.evidence_index iterates it as evidence
        files); answer.run records page_sha256 under "page.txt" in `carried` beside them."""
        p = self.root / "page.txt"
        page_bytes = p.read_bytes() if p.is_file() else b""
        pages = self.manifest.get("pages")
        entry = next((e for e in pages if isinstance(e, dict) and e.get("file") == "page.txt"), None) if isinstance(pages, list) else None
        if not page_bytes:
            if entry is not None:
                if not p.is_file():  # 0.1.8 (seventh re-gate H2, J4): the manifest names the page the models would read and the request did not send it
                    raise Refused("part page.txt is named by the manifest's pages and was not sent")
                # 0.1.8 (J4, the owner's holdout v9a): an EMPTY page.txt sent under a pages entry is held to the entry's hash like any other
                # bytes, so a caller cannot blank the page the models read by sending zero bytes
                self.page_sha256 = sha256_bytes(page_bytes)
                if entry.get("sha256") and entry["sha256"] != self.page_sha256:
                    raise Refused("part page.txt sha256 differs from the manifest's")
            return
        self.page_sha256 = sha256_bytes(page_bytes)
        if entry is None:
            raise Refused("part page.txt is named by no page of the manifest")
        if entry.get("sha256") and entry["sha256"] != self.page_sha256:
            raise Refused("part page.txt sha256 differs from the manifest's")

    def _check_carried(self):
        """S-1, D1: every file under sources/ or sessions/ of the folder is a carried part. One that no manifest entry (sources[].file,
        grading.sessions[].file) names is refused by name; one whose sha256 differs from its entry's sha256 (a session's record_sha256) is
        refused by name. The named files present are kept in self.carried. A manifest path outside those two folders, or one that could
        leave the folder, is never read. check_published is untouched: it covers audit.jsonl."""
        named = {}
        for s in self.manifest.get("sources") or []:
            if isinstance(s.get("file"), str):
                named.setdefault(s["file"], s.get("sha256"))
        for s in (self.manifest.get("grading") or {}).get("sessions") or []:
            if isinstance(s, dict) and isinstance(s.get("file"), str):
                named.setdefault(s["file"], s.get("record_sha256"))
        for sub in ("sources", "sessions"):
            d = self.root / sub
            if not d.is_dir():
                continue
            for p in sorted(d.rglob("*")):
                if p.is_file():
                    rel = p.relative_to(self.root).as_posix()
                    if rel not in named:
                        raise Refused(f"part {rel} is named by no source of the manifest")
        for rel, want in named.items():
            if not is_carried_part(rel):
                continue
            p = self.root / rel
            if not p.is_file():
                continue
            b = p.read_bytes()
            if want and sha256_bytes(b) != want:
                raise Refused(f"part {rel} sha256 differs from the manifest's")
            refuse_credentials(rel, b.decode("utf-8", "replace"))
            self.carried[rel] = b

    def _bytes(self, name):
        p = self.root / name
        if not p.is_file():
            raise Refused(f"{name} is missing from the request")
        return p.read_bytes()

    def _json(self, name, data=None):
        try:
            return json.loads((self._bytes(name) if data is None else data).decode("utf-8"))
        except UnicodeDecodeError as e:
            raise Refused(f"{name} is not UTF-8 (byte {e.start})")
        except ValueError as e:
            raise Refused(f"{name} is not JSON: {e.msg if hasattr(e, 'msg') else 'parse error'} (line {getattr(e, 'lineno', '?')})")

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


# The parts of the manifest public mode binds to the published snapshot (0.1.6, fifth re-gate H1): what the carried evidence is checked
# against (sources[].file + sha256, grading.sessions[].record_sha256), the profile the prompt is chosen by, and the subject; since 0.1.7
# (sixth re-gate J1) `pages` too, so the audited page's hash (pages[].sha256, which _check_page holds page.txt to) is the published one and
# a forged page.txt with a manifest changed to match is refused against the genuine publication. grading.witnesses, files and signatures
# are NOT compared: inserting a witness changes them.
BOUND_MANIFEST_SECTIONS = ("subject", "sources", "pages", "grading.profile", "grading.sessions")


def _canonical(x):
    return json.dumps(x, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _section(manifest, dotted):
    """The value at a dotted path of a manifest, None when absent (so a section absent on both sides is equal)."""
    cur = manifest
    for k in dotted.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(k)
    return cur


def check_published(request, published_url=None, catalogue_lookup=None, fetch=fetch_published):
    """Public mode: the auditor part must be published, as a catalogue record (preferred) or at a public URL whose audit.jsonl matches
    byte for byte; and since 0.1.6 (fifth re-gate H1) the request's manifest is bound to the published snapshot's: a catalogue record
    must carry the request manifest's sha256; by URL, the published manifest.json is fetched beside the published audit.jsonl (the same
    `fetch`, so the same SSRF rules) and its subject, sources, pages (0.1.7), grading.profile and grading.sessions must equal the request's,
    section by section in canonical JSON. Without this, the carried files a model reads are hash-checked against the caller's own, unpublished manifest
    only (the X01 case: a forged carried file with a matching manifest hash, witnessed over the genuine audit part). Private mode skips all
    of it, with no fetch at all: the caller's own estate, the caller's own key."""
    if request.private_mode:
        return {"mode": "private", "published": None}
    if catalogue_lookup is not None:
        rec = catalogue_lookup(request.audit_sha256)
        if rec:
            want = rec.get("manifest_sha256") if isinstance(rec, dict) else None
            if not want:
                raise Refused("the catalogue record carries no manifest hash")
            if want != request.manifest_sha256:
                raise Refused("the catalogue record's manifest sha256 differs from the request's")
            return {"mode": "public", "published": {"catalogue": rec}}
    if not published_url:
        raise Refused("the public service takes published parts only: name the catalogue record or the public URL of audit.jsonl")
    if not published_url.endswith("/audit.jsonl"):
        raise Refused("the published URL must name the snapshot's audit.jsonl")
    data = fetch(published_url)
    if sha256_bytes(data) != request.audit_sha256:
        raise Refused(f"the published copy at {published_url} has sha256 {sha256_bytes(data)}, not the request's {request.audit_sha256}")
    manifest_url = published_url[:-len("audit.jsonl")] + "manifest.json"
    mdata = fetch(manifest_url)
    try:
        published_manifest = json.loads(mdata.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        published_manifest = None
    if not isinstance(published_manifest, dict):
        # 0.1.7 (the sixth re-gate's gist note): the bytes fetched are named, and when they are the audit part's own bytes the cause is said:
        # a raw gist URL (gist.githubusercontent.com/<user>/<id>/raw/<file>) names ONE blob under any file name, so manifest.json beside
        # audit.jsonl answers the audit bytes; the gist's revision URL (raw/<revision>/manifest.json) names each file
        same = sha256_bytes(mdata) == request.audit_sha256
        raise Refused(f"the published manifest.json is not a JSON object ({len(mdata)} bytes, sha256 {sha256_bytes(mdata)[:16]}..., at {manifest_url})"
                      + (" and is byte-equal to the published audit.jsonl: a raw gist URL names one blob under any file name, use the gist's revision URL "
                         "(raw/<revision>/manifest.json)" if same else ""))
    for section in BOUND_MANIFEST_SECTIONS:
        if _canonical(_section(published_manifest, section)) != _canonical(_section(request.manifest, section)):
            raise Refused(f"the manifest's {section} differs from the published snapshot's at {manifest_url}")
    return {"mode": "public", "published": {"url": published_url, "sha256": request.audit_sha256,
                                            "manifest": {"url": manifest_url, "sha256": sha256_bytes(mdata)}}}
