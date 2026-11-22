#!/usr/bin/env python3
"""check.py: the mechanical checker for a claims snapshot (SPEC.md section 5). Standard library only, no model.

usage: python3 -I check.py SNAPSHOT_DIR [--copies DIR] [--fetch] [--strict] [--json] [--keys FILE] [--links ROOT] [--export DIR]
  --copies DIR  a private folder holding NNN.txt (or NNN.pdf-text.txt) copies of hash-only sources, to verify quotes offline
  --fetch       fetch every source live (GET, browser user-agent) and check the quotes are still there (K10)
  --strict      a quote gone from a live page fails K10 instead of warning
  --json        also write CHECK.json into the snapshot folder: the run as data (SPEC.md section 5)
  --keys FILE   0.6: the published key list (keys/model-keys.jsonl of the public repository) a model witness's principal is
                checked against; a broken binding FAILs. Without it the snapshot's own keys/model-keys.jsonl is used (a broken
                binding there is a WARN), and without either the checker warns.
  --links ROOT  0.7: a local directory (a clone or mirror of the publisher's repository) under which K16 looks up link targets by the
                sha256 of their manifest.json; without it only a link's relative `path` is followed. Offline, never the network.
  --export DIR  0.7: verify an export of this version (statement.intoto.json, statement.dsse.json, credential.vc.json, written by
                export.py outside the folder) against the folder: the KX line. Any format; without the flag nothing changes.
Prints one line per check (PASS / WARN / FAIL) with details, then a summary; exit 0 when nothing failed.
A 0.4 snapshot (audit.jsonl + witness/) gets K11 to K15 as well; K13 verifies SSH signatures when ssh-keygen is on PATH.
0.5 adds the agent-work profile (an agent's claims about its own work, OneDroid Indie's bundle; SPEC.md section 12):
K5/K6 check its evidence pointers from the folder, K7 does not apply to them, K11 reads its MISSING CLAIM rows,
K13 fails a witness signed with the auditor's key.
0.5 adds the test-run profile (a scenario run as a claim record: three claims, evidence by artefact hash; SPEC.md section 13).
0.6 adds witnesses of kind human | agent | model, the method classify, the witness verdict UNDECIDED, per-witness scores without
undecided rows, split lines across model witnesses, the key list, the manifest signature role (SPEC.md section 14).
0.6 (12 Nov 2026) also names the pre-witness stage: grading.kind "pre-witness" is the auditor's part published alone (no claims.jsonl,
no score, no claims_sha256, no grader or model; witnesses may be listed, none primary); K1 reads the declaration, K5 tests the
auditor's pointers and candidate quotes without a verdict, K8 and K12 WARN that no score exists yet, K11 asks for no primary.
0.7 (14 Nov 2026, SPEC 15): every rule keyed on 0.6 reads "0.6 or later" (fmt_at_least), so a 0.7 folder inherits them all; the manifest
field `links` and K16; the auditor's `sources` signature over six sections (links too); K14 reads an armarium ref's `signer` and a
`gvui`; --export verifies the in-toto/DSSE and VC 2.0 exports with a standard-library Ed25519. A 0.6 or older folder never reaches a 0.7
rule, so its output is byte-identical to the 0.6 checker's.
0.8 (16 Nov 2026, SPEC 16): the format claims-snapshot/0.8 and the decision profile (a decision on one item under one rule set: three
claims, evidence by artefact hash, a private record). Its K1 and K11 rules, its witness methods read and classify, and K5/K6 for artefact
pointers (section 13, unchanged) run on a 0.8 folder of that profile only (fmt_at_least), so a 0.2 to 0.7 folder gives byte-identical output.
0.9 (17 Nov 2026, SPEC 16): the format claims-snapshot/0.9 and a third decider, `decision.by.kind` `agent`, which must carry
`decision.by.enrolled_by` (the person who enrolled the agent, never the agent itself); `enrolled_by` on a person or a pipeline fails. Both
rules run on 0.9 and later only, so a 0.2 to 0.8 folder gives byte-identical output (a 0.8 folder naming `agent` still fails K1)."""
import traceback
import base64, datetime, fractions, hashlib, html, json, os, pathlib, re, shutil, stat, subprocess, sys, tempfile, urllib.error, urllib.request

FORMATS = {"claims-snapshot/0.2", "claims-snapshot/0.3", "claims-snapshot/0.4", "claims-snapshot/0.5", "claims-snapshot/0.6", "claims-snapshot/0.7", "claims-snapshot/0.8", "claims-snapshot/0.9"}
FORMAT_RE = re.compile(r"^claims-snapshot/0\.([0-9]{1,3})$")


def fmt_at_least(M, minor):
    """True when the manifest's format is claims-snapshot/0.N with N at least the minor of `minor` ("0.6"), else False (a missing,
    non-string or foreign format included). 0.7 (14 Nov 2026): every rule that was keyed on the format being exactly 0.6 reads
    "0.6 or later" through this one helper, so a 0.7 folder inherits every 0.6 rule; the new 0.7 rules read "0.7 or later"."""
    f_ = M.get("format") if isinstance(M, dict) else None
    m_ = FORMAT_RE.match(f_) if isinstance(f_, str) else None
    return m_ is not None and int(m_.group(1)) >= int(str(minor).split(".")[1])
WITNESS_VERDICTS = {"EVIDENCED", "NO EVIDENCE PUBLISHED", "CONTRADICTED", "EVIDENCE AVAILABLE ON REQUEST", "WITHDRAWN", "MISSING CLAIM", "UNDECIDED"}  # UNDECIDED: 0.6, a witness never the primary; never in VERDICTS, so never in claims.jsonl
WITNESS_KINDS = {"human", "agent", "model"}  # the witness header `kind` (0.6); absent means human
KEY_LIST = "keys/model-keys.jsonl"
SIGN_NAMESPACE = "claims-snapshot"
ANCHOR_METHODS = {"ots", "argus-commitment", "armarium"}
# the structural files of a folder: never named by hash in the manifest's `files` (K2 refuses it, NEXT-REVISION 22, 13 Nov 2026)
STRUCTURAL_FILES = ("manifest.json", "signatures.json", "allowed_signers", "anchors.json", "CHECK.json", "CHECK.txt")
# the order of keys in a merged claims.jsonl row (SPEC.md 4b): the auditor's row with the witness's decision in the 0.3 places
MERGE_ORDER = ["id", "text", "location", "kind", "checkable", "verdict", "confidence", "proofs", "counter", "located", "consulted",
               "searched", "note", "history", "graded_by", "graded_at", "witness", "evidence_missing", "carried_from", "on_request",
               "other_pass_note", "lister", "audited_by", "audited_at"]
DECISION_KEYS = ("verdict", "confidence", "graded_by", "graded_at")
VERDICTS = {"EVIDENCED", "NO EVIDENCE PUBLISHED", "CONTRADICTED", "EVIDENCE AVAILABLE ON REQUEST", "WITHDRAWN"}
KINDS = {"figure", "arithmetic", "quote", "citation", "negative", "comparison", "process", "rule", "promise", "page-internal", "other"}
PAGE_PROVES = {"page-internal", "arithmetic"}  # kinds a quote from the audited page itself can prove
GRADED_BY = {"grader", "author"}
PROFILES = {"cited-sources", "publisher-surfaces", "agent-work", "test-run"}  # agent-work: 0.5, an agent's claims about its own work (SPEC 12); test-run: 0.5, a scenario run as a claim record (SPEC 13)
HEX64 = re.compile(r"^[0-9a-f]{64}$")
TIME_Z = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
HELD_BY = {"folder", "fleet", "blob", "subject-org"}
# 0.8 (SPEC 16): the decision profile. Known from claims-snapshot/0.8 only, so PROFILES (what a 0.2 to 0.7 folder is checked against) is unchanged.
DECISION_PROFILE = "decision"
EVIDENCE_PROFILES = ("agent-work", "test-run", DECISION_PROFILE)  # profiles whose auditor part is evidence-shaped and whose auditor signature is a promise
ARTEFACT_PROFILES = ("test-run", DECISION_PROFILE)  # profiles whose evidence pointers may be {"artefact", "sha256"} (SPEC 13, 16)
DECISION_REF_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
DECISION_VALUE_RE = re.compile(r"^[A-Za-z0-9_-]+$")
DECISION_DECIDERS = {"person", "pipeline"}
DECISION_DECIDERS_09 = DECISION_DECIDERS | {"agent"}  # 0.9 (SPEC 16): an agent decides too (a break-glass re-identification), from claims-snapshot/0.9 only
# 0.9 (SPEC 17): the document profile, a document as the subject. Known from claims-snapshot/0.9 only, so PROFILES is unchanged; every rule below
# is keyed on the profile (and the format 0.9 or later), never on the format alone.
DOCUMENT_PROFILE = "document"
DOCX_MEDIA = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
DOCUMENT_MEDIA = ("text/plain", "text/markdown", "text/html", "application/pdf", DOCX_MEDIA, "application/zip", "application/x-git")
DOCUMENT_MEMBER_MEDIA = ("application/zip", "application/x-git")  # a subject made of members; never the media type of one page
DOCUMENT_EXTRACTED_MEDIA = ("application/pdf", DOCX_MEDIA)  # a page of these types is an extraction: its extractor is named
DOCUMENT_VERDICTS = ("EVIDENCED", "NO EVIDENCE PUBLISHED", "CONTRADICTED")
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX_ANY = re.compile(r"^[0-9a-f]{7,64}$")
# the typographic fold (SPEC 17), after norm(), exactly these 16 code points and nothing else
DOCUMENT_FOLD = str.maketrans({0x2018: "'", 0x2019: "'", 0x201A: "'", 0x201B: "'", 0x2032: "'",
                               0x201C: '"', 0x201D: '"', 0x201E: '"', 0x201F: '"', 0x2033: '"',
                               0x2010: "-", 0x2011: "-", 0x2012: "-", 0x2013: "-", 0x2014: "-", 0x2212: "-"})


def document_norm(t):
    """norm() and then the typographic fold: what K4, K5, K6 and the quote-check recomputation compare in the document profile."""
    return norm(t).translate(DOCUMENT_FOLD)


def parse_time(t):
    """A 'YYYY-MM-DDTHH:MM:SSZ' time as a datetime, else None."""
    if not isinstance(t, str) or not TIME_Z.match(t):
        return None
    try:
        return datetime.datetime.strptime(t, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return None

def parse_rfc3339(t):
    """An RFC3339 time (Z or an offset, optional fraction) as an aware datetime, else None."""
    if not isinstance(t, str):
        return None
    try:
        d = datetime.datetime.fromisoformat(t.strip().replace("Z", "+00:00") if t.strip().endswith("Z") else t.strip())
    except ValueError:
        return None
    return d if d.tzinfo else None


def key_of(fields):
    """The key of an allowed_signers line or a key-list value as `type base64` (a trailing comment is not part of it), else None."""
    kt = [i for i, x in enumerate(fields) if x.startswith(("ssh-", "ecdsa-", "sk-"))]
    if not kt or kt[0] + 1 >= len(fields):
        return None
    return fields[kt[0]] + " " + fields[kt[0] + 1]


RECORD_PTR = re.compile(r"^([^#\s]{1,128})#([0-9]{1,18})$")
BANDS = [(90, "A"), (75, "B"), (50, "C"), (25, "D"), (0, "E")]
SECRET_PATTERNS = [
    re.compile(r"\b(?:sk|pk|rk)-[A-Za-z0-9_-]{20,}"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bxox[abpr]-[A-Za-z0-9-]{10,}"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}"),
]


def norm(t):
    """Markers and end punctuation out, whitespace collapsed, straight quotes, lower case."""
    t = re.sub(r"\[\d+\]", " ", t)
    t = t.replace("’", "'").replace("‘", "'").replace("“", '"').replace("”", '"')
    t = re.sub(r"\s+", " ", t).strip()
    t = re.sub(r"\s+([,.;:])", r"\1", t)
    return t.strip(" .,;:").lower()


def sha256(p):
    return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()


def html_to_text(raw):
    """Rendered text of an HTML body: scripts, styles and tags gone, entities decoded. JSON-LD blocks are kept as text,
    because a page's structured data is a claim-bearing surface the lister reads (e.g. "foundingDate": "2025")."""
    kept = []

    def hold(m):
        kept.append(m.group(1))
        return f" \x00{len(kept) - 1}\x00 "

    def blank(m):
        # keep the newlines of what is removed, so line N of the rendered text is line N of the raw body
        return "\n" * m.group(0).count("\n") + " "

    raw = re.sub(r"(?is)<script[^>]*application/ld\+json[^>]*>(.*?)</script>", hold, raw)
    raw = re.sub(r"(?is)<(script|style|noscript)[^>]*>.*?</\1>", blank, raw)
    raw = re.sub(r"(?s)<!--.*?-->", blank, raw)
    raw = re.sub(r"(?s)<[^>]+>", blank, raw)
    raw = html.unescape(raw)
    for i, k in enumerate(kept):
        raw = raw.replace(f"\x00{i}\x00", k)
    return raw


def is_html(name, raw):
    return str(name).lower().endswith((".html", ".htm")) or raw.lstrip()[:15].lower().startswith(("<!doctype html", "<html"))


def page_text_of(name, raw):
    """An audited page as the lister read it: an HTML surface as its rendered text (tags gone, entities decoded),
    anything else as served."""
    return html_to_text(raw) if is_html(name, raw) else raw


def evidence_score(rows):
    """evidence-score/1 (the claims session's evidence_score.py, unchanged): over the checkable, non-withdrawn rows,
    coverage = evidenced + on request, contradiction = contradicted, both rounded half to even; band by thresholds,
    capped at C by any high-confidence contradiction and at D by contradiction above 5%."""
    k = [r for r in rows if r.get("verdict") != "WITHDRAWN" and r.get("checkable", True) and r.get("kind") != "promise"]
    e = sum(r["verdict"] == "EVIDENCED" for r in k)
    on_req = sum(r["verdict"] == "EVIDENCE AVAILABLE ON REQUEST" for r in k)
    c = [r for r in k if r["verdict"] == "CONTRADICTED"]
    c_high = sum(r.get("confidence") == "high" for r in c)
    n = sum(r["verdict"] == "NO EVIDENCE PUBLISHED" for r in k)
    if not k:
        return {"checkable": 0, "coverage_pct": None, "contradiction_pct": None, "band": None}
    cov = round(100 * (e + on_req) / len(k))
    con = round(100 * len(c) / len(k))
    band = next(b for lo, b in BANDS if cov >= lo)
    if c_high and band in ("A", "B"):
        band = "C"
    if con > 5 and band in ("A", "B", "C"):
        band = "D"
    return {"claims": len(rows), "checkable": len(k), "evidenced": e, "on_request": on_req, "no_evidence": n,
            "contradicted": len(c), "contradicted_high": c_high,
            "withdrawn": sum(r.get("verdict") == "WITHDRAWN" for r in rows),
            "author_read": sum(r.get("graded_by") == "author" for r in rows),
            "coverage_pct": cov, "contradiction_pct": con, "band": band}


class Report:
    def __init__(self):
        self.rows = []

    def add(self, k, status, msg, details=()):
        self.rows.append((k, status, msg, list(details)))

    def failed(self):
        return any(s == "FAIL" for _, s, _, _ in self.rows)

    def text(self):
        self.printed = True  # V2h: main's net never prints a second report after this one
        out = []
        for k, s, m, d in self.rows:
            out.append(f"{k} {s}: {m}")
            for line in d[:40]:
                out.append(f"    {line}")
            if len(d) > 40:
                out.append(f"    ... and {len(d) - 40} more")
        n_fail = sum(1 for _, s, _, _ in self.rows if s == "FAIL")
        n_warn = sum(1 for _, s, _, _ in self.rows if s == "WARN")
        out.append(f"SUMMARY: {len(self.rows)} checks, {n_fail} failed, {n_warn} warnings: " + ("FAIL" if n_fail else "PASS"))
        return "\n".join(out)

    def result(self):
        if self.failed():
            return "FAIL"
        return "WARN" if any(s == "WARN" for _, s, _, _ in self.rows) else "PASS"

    def as_json(self, snap, fmt, flags):
        """CHECK.json (SPEC.md section 5): what ran, over which bytes, when, with what result."""
        return {"engine": "check.py", "checker_sha256": sha256(__file__), "format_read": fmt,
                "ran_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "manifest_sha256": sha256(snap / "manifest.json") if (snap / "manifest.json").is_file() else None, "flags": flags,
                "checks": [{"id": k, "status": s, "text": m, "details": d} for k, s, m, d in self.rows], "result": self.result()}


def load_jsonl(p):
    """JSON lines, split on "\\n" ONLY (a trailing "\\r" is stripped, so a CRLF file still reads; empty and whitespace lines skipped).
    Never str.splitlines(): it also cuts a line at U+2028, U+2029, U+0085, \\v, \\f and \\x1c to \\x1e, which are valid inside a JSON
    string and which dump_jsonl (ensure_ascii=False) writes as is, so a claim text holding one was cut in two on read (13 Nov 2026)."""
    return [json.loads(l.rstrip("\r")) for l in pathlib.Path(p).read_text(encoding="utf-8").split("\n") if l.strip()]


def signed_line(role, file, h, over=None):
    """The one line a signature covers (SPEC.md 3a); a witness line also names the auditor part it decided on."""
    line = f"claims-snapshot/0.4 {role} {file} sha256:{h}"
    if role == "witness":
        line += f" over audit.jsonl sha256:{over}"
    return line


def load_witness(p):
    """A witness file: its header (first line) and its rows."""
    rows = load_jsonl(p)
    if not rows or "witness" not in rows[0]:
        return None, rows
    return rows[0], rows[1:]


def carried_inventory(M):
    """The paths a witness header's `carried` may name, with the manifest's hash for each (the carried cut, 13 Nov 2026, NEXT-REVISION 25):
    the pages by `file` and `sha256` (the page the models read is a carried file too: the sixth re-gate's J1, 13 Nov 2026), the sources by
    `file` and `sha256`, the session records by `file` and `record_sha256`. Nothing else: not the witness files, not the structural files. One helper for K11 and add_witness.py, so the two rules cannot drift."""
    inv = {}
    for p_ in (M.get("pages") or []) if isinstance(M.get("pages"), list) else []:
        if isinstance(p_, dict) and p_.get("file") and p_.get("sha256"):
            inv[p_["file"]] = p_["sha256"]
    for s_ in (M.get("sources") or []) if isinstance(M.get("sources"), list) else []:
        if isinstance(s_, dict) and s_.get("file") and s_.get("sha256"):
            inv[s_["file"]] = s_["sha256"]
    g_ = M.get("grading") if isinstance(M.get("grading"), dict) else {}
    for s_ in (g_.get("sessions") or []) if isinstance(g_.get("sessions"), list) else []:
        if isinstance(s_, dict) and s_.get("file") and s_.get("record_sha256"):
            inv[s_["file"]] = s_["record_sha256"]
    return inv


BOUND_SECTIONS = ("subject", "sources", "pages", "grading.profile", "grading.sessions")


def service_json_version(snap, M):
    """service.json's `service_version` (a string) when the manifest's `files`, in either shape, lists service.json and the file parses as a
    JSON object, else None. K11's 30(a) rule reads it last, after the witness header and the manifest witness entry (13 Nov 2026)."""
    fl_ = M.get("files")
    names_ = [e_.get("file") for e_ in fl_ if isinstance(e_, dict)] if isinstance(fl_, list) else (list(fl_) if isinstance(fl_, dict) else [])
    if "service.json" not in names_:
        return None
    try:
        sj_ = json.loads((snap / "service.json").read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeDecodeError):
        return None
    v_ = sj_.get("service_version") if isinstance(sj_, dict) else None
    return v_ if isinstance(v_, str) else None


def _section(manifest, dotted):
    """The value at a dotted path of a manifest, None when absent (so a section absent on both sides is equal)."""
    cur = manifest
    for k in dotted.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(k)
    return cur


def bound_sections(M):
    """The sha256 of each bound manifest section in canonical JSON (the bound cut, 13 Nov 2026, the seventh re-gate's U1): reproduces the
    witness service's `_canonical` (onedroid_witness/request.py: json.dumps sort_keys, separators (",", ":"), ensure_ascii False, UTF-8; an
    absent section hashes as null) over its BOUND_MANIFEST_SECTIONS. The five sections are the ones add_witness.py never touches, so they are
    the same before and after any insertion. One helper for K11 and add_witness.py, like carried_inventory, so the two rules cannot drift."""
    return {s: hashlib.sha256(json.dumps(_section(M, s), sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest() for s in BOUND_SECTIONS}


def bound_digest(M):
    """One sha256 over bound_sections(M) in canonical JSON (the sources cut, 13 Nov 2026, NEXT-REVISION 25b): what the auditor's `sources`
    signature covers (`claims-snapshot/0.4 sources manifest.json sha256:<this>`). The five sections never change under an allowed change, so
    the signature holds through every witness insertion where a `manifest` signature cannot. One helper for K13, sign.py and add_witness.py."""
    return hashlib.sha256(json.dumps(bound_sections(M), sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest()


def _canon_sha(v):
    return hashlib.sha256(json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest()


def sources_digest(M):
    """What the auditor's `sources` signature covers (0.7, 14 Nov 2026): on 0.7 and later the bound digest over SIX sections, the five
    bound sections plus `links` (its sha256 in canonical JSON, null when absent), so a link is the auditor's statement and holds through
    every witness insertion as the sources list does; before 0.7 exactly bound_digest(M), byte for byte. The witness header's `bound`
    stays at the five sections (K11). One helper for K13, sign.py and add_witness.py."""
    if not fmt_at_least(M, "0.7"):
        return bound_digest(M)
    secs = bound_sections(M)
    secs["links"] = _canon_sha(_section(M, "links"))
    return _canon_sha(secs)


LINK_RELS = ("supersedes", "reaudits", "wasDerivedFrom", "partOf")
SIGNER_RE = re.compile(r"0x[0-9a-fA-F]{40}")
GVUI_NS = "claims-snapshot"


def gvui_of(a):
    """The gv1 string an anchors.json entry's `gvui` must equal (0.7, SPEC 3a), else None when the entry lacks what it needs: "gv1", then
    the unpadded standard base32 of the namespace "claims-snapshot", of "anchor/<chain>/<block>", of the correlation id and of the
    signer, then the anchor time as Unix seconds, joined by ":" (gvuid 7311ea9, gvuid.go:30-33 and :73-82)."""
    ref_ = a.get("ref") if isinstance(a, dict) else None
    if not (isinstance(ref_, dict) and a.get("method") == "armarium"):
        return None
    chain_, blk_, corr_, sg_ = ref_.get("chain"), ref_.get("block"), ref_.get("correlation_id"), ref_.get("signer")
    t_ = parse_time(a.get("time"))
    if not (isinstance(chain_, str) and isinstance(blk_, int) and not isinstance(blk_, bool) and isinstance(corr_, str) and isinstance(sg_, str) and t_):
        return None
    b32 = lambda s: base64.b32encode(s.encode("utf-8")).decode("ascii").rstrip("=")  # noqa: E731
    secs = int((t_ - datetime.datetime(1970, 1, 1)).total_seconds())
    return ":".join(["gv1", b32(GVUI_NS), b32(f"anchor/{chain_}/{blk_}"), b32(corr_), b32(sg_), str(secs)])


def subject_key(M):
    """The subject a supersedes or reaudits link must share (K16): a test-run's scenario.id, else subject.url, else subject.title."""
    sub = M.get("subject") if isinstance(M, dict) and isinstance(M.get("subject"), dict) else {}
    if sub.get("kind") == "test-run":
        sc_ = sub.get("scenario") if isinstance(sub.get("scenario"), dict) else {}
        return "subject.scenario.id", sc_.get("id")
    if isinstance(sub.get("url"), str) and sub["url"]:
        return "subject.url", sub["url"]
    return "subject.title", sub.get("title")


def _manifest_hash_at(folder):
    """sha256 of folder/manifest.json when it is a regular file reached through no symbolic link, else None."""
    mp = os.path.join(folder, "manifest.json")
    if os.path.islink(folder) or os.path.islink(mp) or not os.path.isfile(mp):
        return None
    return sha256(mp)


def links_check(snap, M, root):
    """K16 (0.7, 14 Nov 2026, SPEC 3 and 5): the manifest's `links`, offline. Shape first (every fault by index and field, never a
    traceback); a duplicate (rel, manifest_sha256) FAILs; an unknown rel WARNs and is still resolved; a target is looked up at its `path`
    (relative to this folder, inside this folder's parent directory, or inside ROOT with --links ROOT, through no symbolic link) and then
    under ROOT by the sha256 of each manifest.json there; not found is a WARN. A resolved target FAILs on a differing signatures.json
    hash, an anchor its anchors.json does not list, and for supersedes and reaudits another subject or a taken_at not earlier than this
    record's. The target itself is never checked here (check.py <target> does that). Returns (status, text, details)."""
    if "links" not in M:
        return "PASS", "no links", []
    L_ = M["links"]
    if not isinstance(L_, list):
        return "FAIL", "links: not a list", [f"links is a JSON {json_kind(L_)}, not a list"]
    bad, warn, ok = [], [], []
    boundary = os.path.abspath(root) if root is not None else os.path.abspath(snap.parent if snap.name else snap.absolute().parent)
    where = "the --links ROOT" if root is not None else "this folder's parent directory"
    index = {}

    def root_index():
        if not index and root is not None and os.path.isdir(root):
            for dp, dns, fns in os.walk(root, followlinks=False):
                if "manifest.json" in fns:
                    h_ = _manifest_hash_at(dp)
                    if h_:
                        index.setdefault(h_, dp)
            index.setdefault(None, None)
        return index

    seen, valid = {}, []
    for i, e in enumerate(L_):
        p_ = f"links[{i}]"
        if not isinstance(e, dict):
            bad.append(f"{p_} is a JSON {json_kind(e)}, not an object")
            continue
        n_bad = len(bad)
        if "rel" not in e:
            bad.append(f"{p_}.rel is missing")
        elif not isinstance(e["rel"], str):
            bad.append(f"{p_}.rel is a JSON {json_kind(e['rel'])}, not a string")
        for k_ in ("note",):
            if e.get(k_) is not None and not isinstance(e[k_], str):
                bad.append(f"{p_}.{k_} is a JSON {json_kind(e[k_])}, not a string or null")
        t_ = e.get("target")
        full = None
        if "target" not in e:
            bad.append(f"{p_}.target is missing")
        elif not isinstance(t_, dict):
            bad.append(f"{p_}.target is a JSON {json_kind(t_)}, not an object")
        else:
            h_ = t_.get("manifest_sha256")
            if "manifest_sha256" not in t_:
                bad.append(f"{p_}.target.manifest_sha256 is missing")
            elif not (isinstance(h_, str) and HEX64.fullmatch(h_)):
                bad.append(f"{p_}.target.manifest_sha256 is not 64 lower-case hex: {h_!r}"[:200])
            s_ = t_.get("signatures_sha256")
            if s_ is not None and not (isinstance(s_, str) and HEX64.fullmatch(s_)):
                bad.append(f"{p_}.target.signatures_sha256 is not 64 lower-case hex or null: {s_!r}"[:200])
            for k_ in ("location",):
                if t_.get(k_) is not None and not isinstance(t_[k_], str):
                    bad.append(f"{p_}.target.{k_} is a JSON {json_kind(t_[k_])}, not a string or null")
            if t_.get("anchor") is not None and not isinstance(t_["anchor"], dict):
                bad.append(f"{p_}.target.anchor is a JSON {json_kind(t_['anchor'])}, not an object or null")
            pth = t_.get("path")
            if pth is not None:
                if not isinstance(pth, str):
                    bad.append(f"{p_}.target.path is a JSON {json_kind(pth)}, not a string or null")
                elif not pth:
                    bad.append(f"{p_}.target.path is empty")
                elif os.path.isabs(pth) or pth.startswith(("/", "\\")):
                    bad.append(f"{p_}.target.path is absolute: a link names its target relative to this folder")
                else:
                    full = os.path.normpath(os.path.join(os.path.abspath(snap), pth))
                    if full == boundary or os.path.commonpath([full, boundary]) != boundary:
                        bad.append(f"{p_}.target.path leaves {where}")
                        full = None
                    else:
                        cur = boundary
                        for part in os.path.relpath(full, boundary).split(os.sep):
                            cur = os.path.join(cur, part)
                            if os.path.islink(cur):
                                bad.append(f"{p_}.target.path passes through a symbolic link: the checker follows none")
                                full = None
                                break
        if len(bad) > n_bad:
            continue
        key_ = (e["rel"], t_["manifest_sha256"])
        if key_ in seen:
            bad.append(f"{p_}: a duplicate of links[{seen[key_]}] (rel {e['rel']!r}, manifest sha256:{key_[1][:12]}…)")
            continue
        seen[key_] = i
        valid.append((i, e, full))

    for i, e, full in valid:
        p_, rel, t_ = f"links[{i}]", e["rel"], e["target"]
        want = t_["manifest_sha256"]
        if rel not in LINK_RELS:
            warn.append(f"{p_}: rel {rel!r} is not one of {', '.join(LINK_RELS)}: read as a relation this checker does not know, the target still resolved")
        found, via, other = None, None, None
        if full is not None:
            h_ = _manifest_hash_at(full)
            if h_ == want:
                found, via = full, f"at its path {t_['path']}"
            elif h_ is not None:
                other = h_
        if found is None and root is not None:
            dp = root_index().get(want)
            if dp:
                found, via = dp, "under --links ROOT"
        if found is None:
            warn.append(f"{p_}: target manifest sha256:{want[:12]}… not at hand, hash recorded, not resolved"
                        + (f" (the folder at its path holds another manifest, sha256:{other[:12]}…)" if other else ""))
            continue
        n_bad = len(bad)
        try:
            TM = json.loads(pathlib.Path(found, "manifest.json").read_text(encoding="utf-8"))
        except (OSError, ValueError, UnicodeDecodeError):
            TM = None
        if not isinstance(TM, dict) or TM.get("format") not in FORMATS:
            warn.append(f"{p_}: the target's format {(TM.get('format') if isinstance(TM, dict) else None)!r} is not one this checker reads; the hash still holds")
        s_ = t_.get("signatures_sha256")
        if s_ is not None:
            sp = os.path.join(found, "signatures.json")
            got = sha256(sp) if os.path.isfile(sp) and not os.path.islink(sp) else None
            if got != s_:
                bad.append(f"{p_}: the target's signatures.json sha256 {str(got)[:12]}… is not the link's {s_[:12]}…")
        if t_.get("anchor") is not None:
            ap = os.path.join(found, "anchors.json")
            # like signatures.json and the link path: a symbolic link is never followed, wherever it points, inside the target or
            # out (gate H2, then gate-h2 F2, 14 Nov 2026)
            if os.path.islink(ap):
                bad.append(f"{p_}: the target's anchors.json is a symbolic link, not followed: the checker follows none")
            else:
                try:
                    ta = json.loads(pathlib.Path(ap).read_text(encoding="utf-8"))
                except (OSError, ValueError, UnicodeDecodeError):
                    ta = None
                if not (isinstance(ta, list) and any(isinstance(a_, dict) and a_.get("ref") == t_["anchor"] for a_ in ta)):
                    bad.append(f"{p_}: the target's anchors.json has no entry whose ref is the link's anchor")
        if rel in ("supersedes", "reaudits") and isinstance(TM, dict):
            kf, kv = subject_key(M)
            tf, tv = subject_key(TM)
            if (kf, kv) != (tf, tv):
                bad.append(f"{p_}: {rel} a target whose {tf} is {tv!r} and this record's {kf} is {kv!r}: a re-audit of another subject")
            t0, t1 = parse_rfc3339(TM.get("taken_at")), parse_rfc3339(M.get("taken_at"))
            if t0 is None or t1 is None:
                bad.append(f"{p_}: {rel} needs both taken_at as times (the target's {TM.get('taken_at')!r}, this record's {M.get('taken_at')!r})")
            elif not t0 < t1:
                bad.append(f"{p_}: {rel} a target taken at {TM.get('taken_at')}, which is not earlier than this record's {M.get('taken_at')}")
        if len(bad) == n_bad:
            kf, kv = subject_key(TM if isinstance(TM, dict) else {})
            ok.append(f"{p_}: {rel} manifest sha256:{want[:12]}… resolved {via}: {kf} {kv!r}, taken_at {(TM or {}).get('taken_at') if isinstance(TM, dict) else None}")
    status = "FAIL" if bad else ("WARN" if warn else "PASS")
    return status, f"{len(L_)} link(s): {len(ok)} resolved, {len(warn)} note(s), {len(bad)} broken", bad + warn + ok


def allowed_keys(path):
    """principal -> {"<type> <base64>", ...} from an allowed_signers file: the key is the key-type field and the one after it, wherever options
    put them; a trailing comment is not part of the key (ssh-keygen ignores it, so must every comparison). K13's auditor-key rule and the
    sources rule read keys through this, as does sign.py --role sources."""
    keys = {}
    for l in pathlib.Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
        f_ = l.split()
        if len(f_) >= 3 and not l.lstrip().startswith("#"):
            kt = [i for i, x in enumerate(f_[1:], 1) if x.startswith(("ssh-", "ecdsa-", "sk-"))]
            if not kt or kt[0] + 1 >= len(f_):
                continue
            key_ = f_[kt[0]] + " " + f_[kt[0] + 1]
            for p_ in f_[0].split(","):
                keys.setdefault(p_, set()).add(key_)
    return keys


JSON_KIND = {dict: "object", list: "array", str: "string", bool: "boolean", int: "number", float: "number", type(None): "null"}
SIGNER_FIELDS = ("name", "key_id", "kind")


def json_kind(v):
    return JSON_KIND.get(type(v), type(v).__name__)


def manifest_shape_faults(M):
    """V2f (the twelfth cut, 13 Nov 2026, NEXT-REVISION 33; the sixteenth re-gate's checker finding): every part of manifest.json that a
    reader uses as an object, a list, a path or a hash, checked by JSON kind, as lines "manifest.json: <path> is a JSON <kind>, not <want>",
    every fault (none dropped), in the order listed here, which is not the order of the keys in the file. V2g (the seventeenth re-gate's
    finding B): format, taken_at and grading.profile are strings; counts and score objects; grading.sessions and grading.gates lists of
    objects (null reads as absent), a session's file and record_sha256 strings; a source's path a string or null; a witness entry's score
    an object (null reads as absent). The document is an object; grading an object (null included); grading.auditor an object
    and its file, sha256 and name strings; grading.witnesses a list of objects whose name, file and sha256 are strings; pages and sources
    lists of objects whose file and sha256 are strings (a source's may be null: a hash-only or no-copy source). An ABSENT field is not a fault here (K1 and the later checks say what a missing field
    means); grading.auditor and grading.witnesses null read as absent (sign.py's rule since V2e). check.py fails K1 on any line; sign.py and
    add_witness.py refuse by the same rule before writing."""
    if not isinstance(M, dict):
        return [f"manifest.json: a JSON {json_kind(M)} is not an object"]
    out = []
    for k_, want_ in (("format", str), ("taken_at", str), ("counts", dict), ("score", dict)):
        if k_ in M and not isinstance(M[k_], want_):
            out.append(f"manifest.json: {k_} is a JSON {json_kind(M[k_])}, not {'a string' if want_ is str else 'an object'}")

    def fault(path, v, want):
        out.append(f"manifest.json: {path} is a JSON {json_kind(v)}, not {want}")

    def strings(path, e, keys, nullable=False):
        for k in keys:
            if k in e and not isinstance(e[k], str) and not (nullable and e[k] is None):
                fault(f"{path}.{k}", e[k], "a string or null" if nullable else "a string")

    def object_list(path, v, keys, nullable=False):
        if not isinstance(v, list):
            fault(path, v, "a list")
            return
        for i, e in enumerate(v):
            if isinstance(e, dict):
                strings(f"{path}[{i}]", e, keys, nullable)
            else:
                fault(f"{path}[{i}]", e, "an object")
    for k in ("pages", "sources"):
        if k in M:
            object_list(k, M[k], ("file", "sha256", "path") if k == "sources" else ("file", "sha256"), nullable=(k == "sources"))
    if "grading" in M:
        g = M["grading"]
        if not isinstance(g, dict):
            fault("grading", g, "an object")
        else:
            au = g.get("auditor")
            if au is not None:
                if isinstance(au, dict):
                    strings("grading.auditor", au, ("file", "sha256", "name"))
                else:
                    fault("grading.auditor", au, "an object")
            if g.get("witnesses") is not None:
                object_list("grading.witnesses", g["witnesses"], ("name", "file", "sha256"))
                for i, w in enumerate(g["witnesses"] if isinstance(g["witnesses"], list) else []):
                    if isinstance(w, dict) and w.get("score") is not None and not isinstance(w["score"], dict):
                        fault(f"grading.witnesses[{i}].score", w["score"], "an object")
            if "profile" in g and not isinstance(g["profile"], str):
                fault("grading.profile", g["profile"], "a string")
            if g.get("sessions") is not None:
                object_list("grading.sessions", g["sessions"], ("file", "record_sha256"))
            if g.get("gates") is not None:
                object_list("grading.gates", g["gates"], ())
    return out


def entry_shape_fault(e):
    """V2b and V2c (the twelfth cut, 13 Nov 2026, NEXT-REVISION 33; the twelfth re-gate's Q06 and the thirteenth's R05): the first wrong-shaped
    field of an OBJECT signature entry, as (field, JSON kind, what it should be), else None. role, file, sha256, line and signature are strings;
    signer is an object whose name, key_id and kind are strings. An absent field is not a fault here (the rules say what a missing field
    means); a present field of the wrong JSON kind is, null included. sign.py and add_witness.py refuse a file by this same rule."""
    for k in ("role", "file", "sha256", "line", "signature"):
        if k in e and not isinstance(e[k], str):
            return k, json_kind(e[k]), "a string"
    if "signer" in e and not isinstance(e["signer"], dict):
        return "signer", json_kind(e["signer"]), "an object"
    if isinstance(e.get("signer"), dict):
        for k in SIGNER_FIELDS:
            if k in e["signer"] and not isinstance(e["signer"][k], str):
                return "signer." + k, json_kind(e["signer"][k]), "a string"
    return None


def shape_fault_line(i, fault):
    """The K13 line for entry_shape_fault's answer, at the entry's index in the file."""
    k, kind, want = fault
    why = "(a signer's name, key_id and kind are strings)" if k.startswith("signer.") else "(role, file, sha256, line and signature are strings, signer an object)"
    return f"signatures[{i}]: field {k} is a JSON {kind}, not {want} {why}: the entry is not checked"


def entry_not_object_line(i, e):
    """The K13 line for an entry that is not an object (V2), at its index in the file."""
    return f"signatures[{i}]: entry {e!r} is not an object (role, file, sha256, signer, signature)"


def sshsig_public_key(path):
    """The signer's public key inside an SSH signature file, as `<type> <base64>` (the form allowed_keys and key_of use), else None.
    An SSHSIG blob carries it: magic SSHSIG, uint32 version, string publickey (its first string the key type), string namespace, string
    reserved, string hash_algorithm, string signature. The armour is read with any line endings, text after END ignored (as ssh-keygen
    tolerates); text before BEGIN, a bad base64 body, a wrong magic, a short or over-long blob are None. Standard library only.
    The auditor-key cut (13 Nov 2026, NEXT-REVISION 31): a name in allowed_signers is not a key; the key inside the signature is."""
    try:
        text = pathlib.Path(path).read_bytes().decode("ascii")
    except (OSError, UnicodeDecodeError):
        return None
    lines = text.splitlines()
    if not lines or lines[0].strip() != "-----BEGIN SSH SIGNATURE-----":
        return None
    end = next((i for i, l in enumerate(lines) if i > 0 and l.strip() == "-----END SSH SIGNATURE-----"), None)
    if end is None:
        return None
    try:
        blob = base64.b64decode("".join(l.strip() for l in lines[1:end]), validate=True)
    except (ValueError, TypeError):
        return None
    if len(blob) < 10 or blob[:6] != b"SSHSIG":
        return None

    def rd(off):
        if off + 4 > len(blob):
            raise ValueError("short")
        n = int.from_bytes(blob[off:off + 4], "big")
        if off + 4 + n > len(blob):
            raise ValueError("short")
        return blob[off + 4:off + 4 + n], off + 4 + n
    try:
        pk, off = rd(10)
        for _ in range(4):
            _, off = rd(off)
    except ValueError:
        return None
    if off != len(blob) or len(pk) < 4 or 4 + int.from_bytes(pk[:4], "big") > len(pk):
        return None
    kt = pk[4:4 + int.from_bytes(pk[:4], "big")].decode("ascii", errors="replace")
    if not kt.startswith(("ssh-", "ecdsa-", "sk-")):
        return None
    return kt + " " + base64.b64encode(pk).decode("ascii")


def sshsig_fingerprint(key):
    """`SHA256:<base64, no padding>` of a `<type> <base64>` key: what ssh-keygen -lf prints and signatures.json's key_id records."""
    return "SHA256:" + base64.b64encode(hashlib.sha256(base64.b64decode(key.split()[1])).digest()).decode("ascii").rstrip("=")


# ---- 0.7 exports (14 Nov 2026, SPEC 15): an in-toto Statement v1 in a DSSE envelope and a W3C VC 2.0 credential (eddsa-jcs-2022), written
# OUTSIDE the folder by export.py and verified here by --export DIR. Everything below is standard library: the Ed25519 verification is RFC
# 8032's (5.1.7, cofactorless, S < L and canonical point encodings required), so the CI pin of this file covers the verifier too.
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PRED_TYPE = "https://github.com/OneDro1d/onedroid-claims/blob/main/SPEC.md#claims-snapshot-v0.7"
DSSE_PAYLOAD_TYPE = "application/vnd.in-toto+json"
VC_CONTEXT = ["https://www.w3.org/ns/credentials/v2", "https://www.w3.org/ns/credentials/undefined-terms/v2"]
VC_TYPE = ["VerifiableCredential", "ClaimsSnapshotCredential"]
EXPORT_FILES = ("statement.intoto.json", "statement.dsse.json", "credential.vc.json")

_ED_P = 2 ** 255 - 19
_ED_L = 2 ** 252 + 27742317777372353535851937790883648493
_ED_D = -121665 * pow(121666, _ED_P - 2, _ED_P) % _ED_P
_ED_I = pow(2, (_ED_P - 1) // 4, _ED_P)


def _ed_add(P, Q):
    A = (P[1] - P[0]) * (Q[1] - Q[0]) % _ED_P
    B = (P[1] + P[0]) * (Q[1] + Q[0]) % _ED_P
    C = 2 * P[3] * Q[3] * _ED_D % _ED_P
    D = 2 * P[2] * Q[2] % _ED_P
    E, F, G, H = B - A, D - C, D + C, B + A
    return (E * F % _ED_P, G * H % _ED_P, F * G % _ED_P, E * H % _ED_P)


def _ed_mul(s, P):
    Q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            Q = _ed_add(Q, P)
        P = _ed_add(P, P)
        s >>= 1
    return Q


def _ed_x(y, sign):
    if y >= _ED_P:
        return None
    x2 = (y * y - 1) * pow(_ED_D * y * y + 1, _ED_P - 2, _ED_P) % _ED_P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_ED_P + 3) // 8, _ED_P)
    if (x * x - x2) % _ED_P:
        x = x * _ED_I % _ED_P
    if (x * x - x2) % _ED_P:
        return None
    if (x & 1) != sign:
        x = _ED_P - x
    return x


def _ed_point(b):
    if len(b) != 32:
        return None
    y = int.from_bytes(b, "little")
    sign, y = y >> 255, y & ((1 << 255) - 1)
    x = _ed_x(y, sign)
    return None if x is None else (x, y, 1, x * y % _ED_P)


_ED_G = _ed_point((4 * pow(5, _ED_P - 2, _ED_P) % _ED_P).to_bytes(32, "little"))


def ed25519_verify(pub, msg, sig):
    """RFC 8032 5.1.7 Ed25519 verification (pure, cofactorless): True or False, never an exception for wrong-shaped input."""
    if not (isinstance(pub, bytes) and isinstance(sig, bytes) and isinstance(msg, bytes)) or len(pub) != 32 or len(sig) != 64:
        return False
    A, R = _ed_point(pub), _ed_point(sig[:32])
    s = int.from_bytes(sig[32:], "little")
    if A is None or R is None or s >= _ED_L:
        return False
    h = int.from_bytes(hashlib.sha512(sig[:32] + pub + msg).digest(), "little") % _ED_L
    sB, Rh = _ed_mul(s, _ED_G), _ed_add(R, _ed_mul(h, A))
    return (sB[0] * Rh[2] - Rh[0] * sB[2]) % _ED_P == 0 and (sB[1] * Rh[2] - Rh[1] * sB[2]) % _ED_P == 0


def dsse_pae(payload_type, body):
    """DSSE v1 pre-authentication encoding (dsse protocol.md): "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body, lengths in bytes."""
    return b"DSSEv1 %d %s %d %s" % (len(payload_type), payload_type, len(body), body)


_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58encode(b):
    n, out = int.from_bytes(b, "big"), ""
    while n:
        n, r = divmod(n, 58)
        out = _B58[r] + out
    return "1" * (len(b) - len(b.lstrip(b"\0"))) + out


def b58decode(s):
    """base58-btc to bytes, else None."""
    if not isinstance(s, str) or any(c not in _B58 for c in s):
        return None
    n = 0
    for c in s:
        n = n * 58 + _B58.index(c)
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\0" * (len(s) - len(s.lstrip("1"))) + body


def jcs(v):
    """RFC 8785 JSON Canonicalization Scheme for the values these exports hold: objects with members sorted by UTF-16 code units, no
    whitespace, strings escaped as ECMAScript JSON.stringify does, integers as decimals. A non-integer or out-of-range number raises."""
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, int):
        if abs(v) > 2 ** 53:
            raise ValueError("JCS: an integer beyond 2^53 is not used in this format")
        return str(v)
    if isinstance(v, float):
        if v.is_integer() and abs(v) <= 2 ** 53:
            return str(int(v))
        raise ValueError("JCS: a non-integer number is not used in this format")
    if isinstance(v, str):
        v.encode("utf-8")  # a lone surrogate raises
        return json.dumps(v, ensure_ascii=False)
    if isinstance(v, list):
        return "[" + ",".join(jcs(x) for x in v) + "]"
    if isinstance(v, dict):
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + jcs(v[k]) for k in sorted(v, key=lambda k: k.encode("utf-16-be"))) + "}"
    raise ValueError(f"JCS: a {type(v).__name__} is not JSON")


def ssh_ed25519_raw(key):
    """The 32 raw bytes of an `ssh-ed25519 <base64>` key, else None."""
    try:
        kt, b64 = key.split()[:2]
        blob = base64.b64decode(b64, validate=True)
    except (ValueError, AttributeError):
        return None
    if kt != "ssh-ed25519" or len(blob) != 51 or blob[:15] != b"\0\0\0\x0bssh-ed25519" or blob[15:19] != b"\0\0\0\x20":
        return None
    return blob[19:]


def did_key(pub32):
    """did:key of an Ed25519 key: multibase base58-btc ("z") of the Multikey header 0xed01 and the 32 bytes (vc-di-eddsa, Multikey)."""
    return "did:key:z" + b58encode(b"\xed\x01" + pub32)


def _sig_entries(snap):
    try:
        s_ = json.loads((snap / "signatures.json").read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeDecodeError):
        return []
    return [e for e in s_ if isinstance(e, dict) and entry_shape_fault(e) is None] if isinstance(s_, list) else []


def version_key(snap):
    """(key, signature file, signed_at or None) of whoever last stood behind this version (SPEC 15): the key inside manifest.json.sig when
    signatures.json has a manifest entry naming it, else the key inside audit.jsonl.sig; None when neither is readable."""
    sigs = _sig_entries(snap)
    man = next((e for e in sigs if e.get("role") == "manifest" and e.get("signature") == "manifest.json.sig"), None)
    if man is not None:
        k_ = sshsig_public_key(snap / "manifest.json.sig")
        return (k_, "manifest.json.sig", man.get("signed_at")) if k_ else None
    k_ = sshsig_public_key(snap / "audit.jsonl.sig") if (snap / "audit.jsonl.sig").is_file() else None
    return (k_, "audit.jsonl.sig", None) if k_ else None


def export_subjects(snap, M):
    """The statement's subjects: manifest.json, signatures.json, the auditor's part, claims.jsonl when there is one, every page file."""
    g_ = M.get("grading") if isinstance(M.get("grading"), dict) else {}
    au_ = g_.get("auditor") if isinstance(g_.get("auditor"), dict) else {}
    names = ["manifest.json", "signatures.json", au_.get("file") or "audit.jsonl", "claims.jsonl"] + [p_.get("file") for p_ in (M.get("pages") or []) if isinstance(p_, dict)]
    out, seen = [], set()
    for n_ in names:
        if isinstance(n_, str) and n_ not in seen and (snap / n_).is_file() and not (snap / n_).is_symlink():
            seen.add(n_)
            out.append({"name": n_, "digest": {"sha256": sha256(snap / n_)}})
    return out


def export_predicate(snap, M, check_block, location):
    """The predicate: a summary copied from the folder or recomputed from it, never a claim row (SPEC 15)."""
    g_ = M.get("grading") if isinstance(M.get("grading"), dict) else {}
    sigs = _sig_entries(snap)
    fp_ = lambda p_: (lambda k_: sshsig_fingerprint(k_) if k_ else None)(sshsig_public_key(p_) if p_.is_file() else None)  # noqa: E731
    a_ent = next((e for e in sigs if e.get("role") == "auditor"), None)
    auditor = {"principal": (a_ent.get("signer") or {}).get("name") if a_ent else None, "key_fingerprint": fp_(snap / "audit.jsonl.sig")}
    witnesses = []
    for w in (g_.get("witnesses") or []) if isinstance(g_.get("witnesses"), list) else []:
        if not isinstance(w, dict):
            continue
        kind_ = w.get("kind") if w.get("kind") in WITNESS_KINDS else "human"
        try:
            hdr_, _ = load_witness(snap / w["file"]) if isinstance(w.get("file"), str) and (snap / w["file"]).is_file() else (None, None)
        except (ValueError, UnicodeDecodeError):
            hdr_ = None
        if isinstance(hdr_, dict) and hdr_.get("kind") in WITNESS_KINDS:
            kind_ = hdr_["kind"]
        se_ = next((e for e in sigs if e.get("role") == "witness" and e.get("file") == w.get("file") and isinstance(e.get("signature"), str)), None)
        witnesses.append({"name": w.get("name"), "kind": kind_, "primary": bool(w.get("primary")),
                          "key_fingerprint": fp_(snap / se_["signature"]) if se_ else None, "score": w.get("score")})
    try:
        anc_ = json.loads((snap / "anchors.json").read_text(encoding="utf-8")) if (snap / "anchors.json").is_file() else []
    except (OSError, ValueError, UnicodeDecodeError):
        anc_ = []
    anchors = [{"over": a_.get("over"), "method": a_.get("method"), "ref": a_.get("ref")} for a_ in (anc_ if isinstance(anc_, list) else []) if isinstance(a_, dict)]
    return {"format": M.get("format"), "location": location, "subject": M.get("subject"), "profile": g_.get("profile"), "grading_kind": g_.get("kind"),
            "taken_at": M.get("taken_at"), "counts": M.get("counts"), "score": M.get("score"), "auditor": auditor, "witnesses": witnesses,
            "anchors": anchors, "links": M.get("links", []), "check": check_block}


def export_statement(snap, M, check_block, location):
    return {"_type": STATEMENT_TYPE, "subject": export_subjects(snap, M), "predicateType": PRED_TYPE, "predicate": export_predicate(snap, M, check_block, location)}


def export_credential_subject(M, manifest_sha, check_block):
    g_ = M.get("grading") if isinstance(M.get("grading"), dict) else {}
    cb_ = check_block if isinstance(check_block, dict) else {}
    return {"id": f"urn:sha256:{manifest_sha}", "type": "ClaimsSnapshotVersion", "format": M.get("format"), "documentSubject": M.get("subject"),
            "profile": g_.get("profile"), "gradingKind": g_.get("kind"), "counts": M.get("counts"), "score": M.get("score"), "links": M.get("links", []),
            "check": {"checkerSha256": cb_.get("checker_sha256"), "result": cb_.get("result")}}


def export_related(snap, M, location):
    """relatedResource: manifest.json, signatures.json and the auditor's part with their digestSRI (VC 2.0 section 5.3)."""
    g_ = M.get("grading") if isinstance(M.get("grading"), dict) else {}
    au_ = g_.get("auditor") if isinstance(g_.get("auditor"), dict) else {}
    base_ = location.rstrip("/") if isinstance(location, str) and location else f"urn:sha256:{sha256(snap / 'manifest.json')}"
    out = []
    for n_ in ("manifest.json", "signatures.json", au_.get("file") or "audit.jsonl"):
        if isinstance(n_, str) and (snap / n_).is_file():
            r_ = {"id": f"{base_}/{n_}", "digestSRI": "sha256-" + base64.b64encode(hashlib.sha256((snap / n_).read_bytes()).digest()).decode("ascii")}
            if n_.endswith(".json"):
                r_["mediaType"] = "application/json"
            out.append(r_)
    return out


def export_credential(snap, M, check_block, location, pub32, valid_from):
    """The VC 2.0 credential without its proof (export.py adds the eddsa-jcs-2022 proof)."""
    did_ = did_key(pub32)
    vc = {"@context": list(VC_CONTEXT), "type": list(VC_TYPE), "issuer": did_, "validFrom": valid_from,
          "credentialSubject": export_credential_subject(M, sha256(snap / "manifest.json"), check_block), "relatedResource": export_related(snap, M, location)}
    if isinstance(location, str) and location:
        vc["evidence"] = [{"id": location.rstrip("/") + "/CHECK.json", "type": ["ClaimsSnapshotCheck"]}]
    return vc


def eddsa_jcs_hash_data(unsecured, proof_options):
    """eddsa-jcs-2022 hashData (vc-di-eddsa 3.3.4): sha256(JCS(proof configuration)) followed by sha256(JCS(the document))."""
    return hashlib.sha256(jcs(proof_options).encode("utf-8")).digest() + hashlib.sha256(jcs(unsecured).encode("utf-8")).digest()


def _b64any(s):
    """Standard or URL-safe base64 (DSSE: a verifier MUST accept either), padding optional; None when it does not decode."""
    if not isinstance(s, str):
        return None
    try:
        s_ = s.replace("-", "+").replace("_", "/")
        return base64.b64decode(s_ + "=" * (-len(s_) % 4), validate=True)
    except (ValueError, TypeError):
        return None


def export_check(snap, M, d):
    """KX (0.7, check.py --export DIR): the three export files against THIS version of the folder. The DSSE signature must verify, over
    PAE, under the version's key (the key inside manifest.json.sig, else audit.jsonl.sig); the statement file is the signed payload; the
    subjects are this version's files by sha256; the predicate equals the folder (format, subject, profile, grading kind, taken_at, counts,
    score, auditor, witnesses, anchors, links); the credential's issuer is that key's did:key, its subject and relatedResource digests
    equal the folder, and its eddsa-jcs-2022 proof verifies. Returns (status, text, details)."""
    d = pathlib.Path(d)
    bad, ok = [], []
    for n_ in EXPORT_FILES:
        if (d / n_).is_symlink() or not (d / n_).is_file():
            bad.append(f"{n_}: missing from the export folder or not a regular file")
    try:
        if snap.resolve() == d.resolve() or snap.resolve() in d.resolve().parents:
            bad.append("the export folder lies inside the snapshot folder: an export is written outside it")
    except OSError:
        pass
    vk = version_key(snap)
    raw = ssh_ed25519_raw(vk[0]) if vk else None
    if vk is None:
        bad.append("no readable manifest.json.sig or audit.jsonl.sig: no version key to verify the export against")
    elif raw is None:
        bad.append(f"the version's key ({vk[1]}) is not Ed25519: an export is signed with an Ed25519 key")
    if bad:
        return "FAIL", f"export: {len(bad)} problem(s)", bad
    fp = sshsig_fingerprint(vk[0])
    msha = sha256(snap / "manifest.json")
    try:
        env = json.loads((d / "statement.dsse.json").read_text(encoding="utf-8"))
        vc = json.loads((d / "credential.vc.json").read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeDecodeError) as e:
        return "FAIL", "export: 1 problem(s)", [f"an export file is not JSON: {type(e).__name__}"]
    if not isinstance(env, dict) or not isinstance(vc, dict):
        return "FAIL", "export: 1 problem(s)", ["statement.dsse.json and credential.vc.json must each be a JSON object"]
    # DSSE
    pt = env.get("payloadType")
    if pt != DSSE_PAYLOAD_TYPE:
        bad.append(f"statement.dsse.json: payloadType {str(pt)[:60]!r} is not {DSSE_PAYLOAD_TYPE}")
    payload = _b64any(env.get("payload"))
    if payload is None:
        bad.append("statement.dsse.json: payload is not base64")
        payload = b""
    if payload != (d / "statement.intoto.json").read_bytes():
        bad.append("statement.intoto.json is not the signed payload of statement.dsse.json")
    sigs_ = env.get("signatures") if isinstance(env.get("signatures"), list) else []
    pae_ = dsse_pae(str(pt).encode("utf-8"), payload) if isinstance(pt, str) else None
    if pae_ is not None and any(isinstance(s_, dict) and ed25519_verify(raw, pae_, _b64any(s_.get("sig")) or b"") for s_ in sigs_):
        ok.append(f"statement.dsse.json: the DSSE signature verifies under the version's key {fp} (the key inside {vk[1]})")
    else:
        bad.append(f"statement.dsse.json: no signature verifies under the version's key {fp} (the key inside {vk[1]})")
    # the statement, read from the signed bytes
    try:
        stmt = json.loads(payload.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        stmt = None
    if not isinstance(stmt, dict):
        bad.append("the signed payload is not a JSON object")
        stmt = {}
    if stmt and stmt.get("_type") != STATEMENT_TYPE:
        bad.append(f"statement: _type {str(stmt.get('_type'))[:60]!r} is not {STATEMENT_TYPE}")
    if stmt and stmt.get("predicateType") != PRED_TYPE:
        bad.append(f"statement: predicateType {str(stmt.get('predicateType'))[:80]!r} is not {PRED_TYPE}")
    want_s = {s_["name"]: s_["digest"]["sha256"] for s_ in export_subjects(snap, M)}
    got_s = {}
    for s_ in stmt.get("subject") if isinstance(stmt.get("subject"), list) else []:
        if isinstance(s_, dict) and isinstance(s_.get("name"), str):
            got_s[s_["name"]] = (s_.get("digest") or {}).get("sha256") if isinstance(s_.get("digest"), dict) else None
    if stmt:
        for n_, h_ in want_s.items():
            if n_ not in got_s:
                bad.append(f"subject {n_}: missing from the statement")
            elif got_s[n_] != h_:
                bad.append(f"subject {n_}: sha256 {str(got_s[n_])[:12]}… differs from the folder's {h_[:12]}…")
        for n_ in got_s:
            if n_ not in want_s:
                bad.append(f"subject {n_}: not a file of this version")
    pred = stmt.get("predicate") if isinstance(stmt.get("predicate"), dict) else {}
    want_p = export_predicate(snap, M, None, None)
    if stmt:
        for k_ in want_p:
            if k_ not in ("location", "check") and pred.get(k_) != want_p[k_]:
                bad.append(f"predicate.{k_} differs from the folder")
    cb = pred.get("check") if isinstance(pred.get("check"), dict) else {}
    if stmt and not (cb.get("result") in ("PASS", "WARN") and isinstance(cb.get("checker_sha256"), str) and HEX64.fullmatch(cb["checker_sha256"]) and parse_time(cb.get("ran_at"))):
        bad.append("predicate.check: result PASS or WARN, checker_sha256 64 hex and ran_at a time are required")
    # the credential
    did_ = did_key(raw)
    if vc.get("@context") != VC_CONTEXT:
        bad.append("credential: @context is not the VC 2.0 context and the undefined-terms context")
    if not (isinstance(vc.get("type"), list) and all(t_ in vc["type"] for t_ in VC_TYPE)):
        bad.append(f"credential: type does not hold {VC_TYPE}")
    if vc.get("issuer") != did_:
        bad.append(f"credential: issuer {str(vc.get('issuer'))[:40]!r}… is not the version key's did:key")
    want_cs = export_credential_subject(M, msha, None)
    cs = vc.get("credentialSubject") if isinstance(vc.get("credentialSubject"), dict) else {}
    for k_ in want_cs:
        if k_ != "check" and cs.get(k_) != want_cs[k_]:
            bad.append(f"credentialSubject.{k_} differs from the folder")
    if cs.get("check") != {"checkerSha256": cb.get("checker_sha256"), "result": cb.get("result")}:
        bad.append("credentialSubject.check differs from the statement's check")
    rr = vc.get("relatedResource") if isinstance(vc.get("relatedResource"), list) else []
    for w_ in export_related(snap, M, None):
        n_ = w_["id"].rsplit("/", 1)[1]
        got_ = next((r_ for r_ in rr if isinstance(r_, dict) and isinstance(r_.get("id"), str) and r_["id"].endswith("/" + n_)), None)
        if got_ is None:
            bad.append(f"relatedResource {n_}: missing")
        elif got_.get("digestSRI") != w_["digestSRI"]:
            bad.append(f"relatedResource {n_}: digestSRI differs from the folder's file")
    proof = vc.get("proof") if isinstance(vc.get("proof"), dict) else {}
    opts = {k_: v_ for k_, v_ in proof.items() if k_ != "proofValue"}
    pv = proof.get("proofValue")
    sig_ = b58decode(pv[1:]) if isinstance(pv, str) and pv.startswith("z") else None
    vm_ok = proof.get("verificationMethod") == did_ + "#" + did_[len("did:key:"):]
    ctx_ok = isinstance(opts.get("@context"), list) and vc.get("@context", [])[:len(opts["@context"])] == opts["@context"] if "@context" in opts else True
    try:
        unsecured = {k_: v_ for k_, v_ in vc.items() if k_ != "proof"}
        if "@context" in opts:
            unsecured["@context"] = opts["@context"]
        hd = eddsa_jcs_hash_data(unsecured, opts)
    except ValueError:
        hd = None
    if not (proof.get("type") == "DataIntegrityProof" and proof.get("cryptosuite") == "eddsa-jcs-2022" and proof.get("proofPurpose") == "assertionMethod"
            and vm_ok and ctx_ok and hd is not None and sig_ is not None and ed25519_verify(raw, hd, sig_)):
        bad.append("credential.vc.json: the credential's proof does not verify (DataIntegrityProof, eddsa-jcs-2022, assertionMethod, the version key's did:key)")
    else:
        ok.append(f"credential.vc.json: the eddsa-jcs-2022 proof verifies under {did_[:24]}…, the version key's did:key")
    if bad:
        return "FAIL", f"export: {len(bad)} problem(s) against this version (manifest sha256:{msha[:12]}…)", bad + ok
    return "PASS", f"export: the DSSE envelope, the statement and the credential hold for this version (manifest sha256:{msha[:12]}…)", ok


def merge_rows(audit, wrows, witness_name):
    """claims.jsonl from the auditor's rows and one witness's decisions (SPEC.md 4b). MISSING CLAIM rows are not merged.
    A claim the witness did not decide gets verdict None, which K3 then rejects."""
    by_id = {w["id"]: w for w in wrows if w.get("verdict") != "MISSING CLAIM"}
    out = []
    for a in audit:
        w = by_id.get(a.get("id"))
        row = dict(a)
        if w is None:
            row.update({"verdict": None, "confidence": None, "graded_by": None, "graded_at": None, "witness": witness_name})
        else:
            row.update({"verdict": w.get("verdict"), "confidence": w.get("confidence"), "note": w.get("note"), "history": w.get("history"),
                        "graded_by": w.get("graded_by", "grader"), "graded_at": w.get("graded_at"), "witness": witness_name})
            if w.get("evidence_missing"):
                row["evidence_missing"] = w["evidence_missing"]
        ordered = {k: row[k] for k in MERGE_ORDER if k in row}
        for k, v in row.items():
            if k not in ordered:
                ordered[k] = v
        out.append(ordered)
    return out


def dump_jsonl(rows):
    return "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows)


def copy_text(snap, copies, src):
    """The text copy of a source if one is at hand: in the snapshot, or in --copies under the source's copy_name
    (a site run's fetched/NNN.txt, numbered by fetch order) or as NNN.pdf-text.txt / NNN.txt by the snapshot's n."""
    if src.get("file"):
        p = snap / src["file"]
        if p.exists():
            return p.read_text(encoding="utf-8", errors="replace")
    if copies:
        names = ([src["copy_name"]] if src.get("copy_name") else []) + [f"{src['n']:03d}.pdf-text.txt", f"{src['n']:03d}.txt"]
        for name in names:
            p = copies / name
            if p.exists() and p.stat().st_size > 0:
                return p.read_text(encoding="utf-8", errors="replace")
    return None


class CheckJsonRefused(OSError):
    """An existing CHECK.json the checker will not write over (V2i): a symbolic link, a pipe, a directory, anything but a regular file."""


def write_check_json(R, snap, argv, fmt):
    """V2i (the nineteenth re-gate's J05, J03, J04, U, 13 Nov 2026): CHECK.json is written on EVERY exit of a --json run, the early K1 and
    K0 stops included, so a stale CHECK.json saying PASS never outlives a run that FAILed. It is written to a temporary file in the folder
    and moved into place, so a write that stops half-way leaves the old file whole, never a truncated one. An existing CHECK.json that is
    a symbolic link (it could point outside the folder and the run would overwrite that file), a named pipe, a directory or anything but a
    regular file is refused, and so is one the user may not write (mode 444 stays a FAIL, as before). A refusal or a failed write is a K0
    FAIL inside the one report. Text the folder supplies that UTF-8 cannot encode (a lone surrogate) is written backslash-escaped."""
    p = snap / "CHECK.json"
    flags = [a for a in argv[2:] if a.startswith("--") and a != "--json"]
    tmpname = None
    try:
        try:
            st = os.lstat(p)
        except FileNotFoundError:
            st = None
        if st is not None:
            if stat.S_ISLNK(st.st_mode):
                raise CheckJsonRefused("a symbolic link, refused: the checker never writes through one")
            if not stat.S_ISREG(st.st_mode):
                raise CheckJsonRefused("not a regular file, refused")
            if not os.access(p, os.W_OK):
                raise PermissionError("not writable")
        data = (json.dumps(R.as_json(snap, fmt, flags), ensure_ascii=False, indent=1) + "\n").encode("utf-8", "backslashreplace")
        fd, tmpname = tempfile.mkstemp(prefix=".CHECK.json.", dir=snap)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        mask = os.umask(0)
        os.umask(mask)
        os.chmod(tmpname, 0o666 & ~mask)
        os.replace(tmpname, p)
        tmpname = None
        return R.result()
    except Exception as e:
        why = f": {e.args[0]}" if isinstance(e, (CheckJsonRefused, PermissionError)) and len(e.args) == 1 and isinstance(e.args[0], str) else ""
        R.add("K0", "FAIL", f"CHECK.json could not be written ({type(e).__name__}{why}): the checks ran, their record did not land; not a PASS")
        return None
    finally:
        if tmpname is not None:
            try:
                os.unlink(tmpname)
            except OSError:
                pass


def finish(R, snap, argv, fmt):
    """The one way a run ends (V2i): CHECK.json first when --json asks for it, then the one report, then the written line."""
    written = write_check_json(R, snap, argv, fmt) if snap is not None and "--json" in argv else None
    print(R.text())
    if written:
        print(f"CHECK.json written ({written})")
    return 1 if R.failed() else 0


def main(argv):
    """V2g (the seventeenth re-gate's finding B, 13 Nov 2026): the checker never ends in a traceback. A part of the folder that no rule
    names and that still stops a check is a K0 FAIL, with the exception's type and the checker line, and the SUMMARY line the reader
    keys on; the folder is not checked further and is never a PASS. A named rule (K1's shape lines, K13's entry lines) is the fix for
    each such part; this line is the net under the ones not named yet."""
    R = Report()
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="backslashreplace")
        except (AttributeError, ValueError):
            pass
    try:
        return _main(argv, R)
    except Exception as e:
        where = next((fr.lineno for fr in reversed(traceback.extract_tb(e.__traceback__)) if fr.filename == __file__), None)
        msg = str(e)
        if len(argv) > 1 and argv[1]:
            # V2h: the folder is named <folder>, never by its absolute path (a report is published; the path is the machine's)
            for form in sorted({str(pathlib.Path(argv[1]).resolve()), str(pathlib.Path(argv[1]).absolute()), argv[1]}, key=len, reverse=True):
                msg = msg.replace(form, "<folder>")
        if getattr(R, "printed", False):
            print(f"check.py: stopped after the report was printed ({type(e).__name__} at check.py:{where}); exit 1", file=sys.stderr)
            return 1
        R.add("K0", "FAIL", f"the checker stopped on a part of the folder it does not read ({type(e).__name__} at check.py:{where}: {msg[:160]}): "
                            "the folder is not checked further and is not a PASS")
        finish(R, pathlib.Path(argv[1]) if len(argv) > 1 and argv[1] else None, argv, getattr(R, "fmt", None))
        return 1


def locator_faults(M, snap):
    """The evidence locator rules of SPEC 13, shared by the test-run profile (0.5) and the decision profile (0.8, SPEC 16): the locator is
    present with `held_by`, `where`, `expires_at` and `note`; `held_by` is in its vocabulary; `expires_at` is null or a time; a holder other than
    the folder names `where`; with `held_by: folder` every artefact source has its copy in the folder. The problems, as text, in the order found."""
    bad = []
    loc_ = M.get("evidence_locator")
    if not isinstance(loc_, dict):
        bad.append("evidence_locator missing")
    else:
        for k_ in ("held_by", "where", "expires_at", "note"):
            if k_ not in loc_:
                bad.append(f"evidence_locator.{k_}")
        if "held_by" in loc_ and loc_["held_by"] not in HELD_BY:
            bad.append(f"evidence_locator.held_by={loc_['held_by']!r} not in {sorted(HELD_BY)}")
        if loc_.get("expires_at") is not None and parse_time(loc_.get("expires_at")) is None:
            bad.append(f"evidence_locator.expires_at={loc_.get('expires_at')!r} is not null or a time")
        if loc_.get("held_by") in HELD_BY and loc_.get("held_by") != "folder" and not (isinstance(loc_.get("where"), str) and loc_["where"].strip()):
            # trilix, adoption of section 13 (WB): the writer refuses a holder without `where`; the checker holds the same rule
            bad.append(f"evidence_locator.held_by is {loc_['held_by']} but where is {loc_.get('where')!r}: a holder other than the folder is named by its url or path")
        if loc_.get("held_by") == "folder":
            for s_ in (M.get("sources") or []):
                if isinstance(s_, dict) and s_.get("role") == "artefact" and not (s_.get("file") and (snap / s_["file"]).exists()):
                    bad.append(f"evidence_locator.held_by is folder but artefact {s_.get('name') or s_.get('path')!r} has no copy in the folder (file {s_.get('file')!r})")
    return bad


def decision_subject_faults(M):
    """K1 for the decision profile (SPEC 16, 0.8), the subject only (the locator is locator_faults): every field present with its type
    (a string field non-empty, `basis.recommendation` and `basis.ruleset.digest` strings that may be empty, a sha256 64 lower-case hex,
    `decision.override` a boolean, `decision.at` a time, `ledger` null or an object); `title` is `decision on ` and `item.ref`; `item.ref`
    matches `[A-Za-z0-9_.-]{1,64}`; `decision.value` is a token of letters, digits, `_` and `-`; `decision.by.kind` is person or pipeline;
    `decision.override` equals (`decision.value` != `basis.recommendation`); `taken_at` equals `decision.at`; `ledger` carries a `stream`, an
    integer `n` of 1 or more (a boolean is no integer) and an `event` with an artefact name and a sha256. The problems, as text."""
    bad = []
    sub = M.get("subject")
    if not isinstance(sub, dict):
        return ["subject must be an object"]

    def at(path):
        cur = sub
        for k_ in path:
            cur = cur.get(k_, KeyError) if isinstance(cur, dict) else KeyError
        return cur

    def text(path, may_be_empty=False, hexed=False):
        v_, label = at(path), "subject." + ".".join(path)
        if v_ is KeyError:
            bad.append(label)
        elif not isinstance(v_, str):
            bad.append(label + " must be a string")
        elif not v_.strip() and not may_be_empty:
            bad.append(label + " empty")
        elif hexed and not HEX64.match(v_):
            bad.append(label + " not 64 hex")
        return v_ if isinstance(v_, str) else None

    if sub.get("kind") != DECISION_PROFILE:
        bad.append(f"subject.kind={sub.get('kind')!r} must be {DECISION_PROFILE!r}")
    title = text(("title",))
    ref = text(("item", "ref"))
    text(("item", "sha256"), hexed=True)
    value = text(("decision", "value"))
    text(("decision", "by", "principal"))
    kind = text(("decision", "by", "kind"))
    when = text(("decision", "at"))
    rec = text(("basis", "recommendation"), may_be_empty=True)
    text(("basis", "on", "artefact"))
    text(("basis", "on", "sha256"), hexed=True)
    text(("basis", "ruleset", "id"))
    text(("basis", "ruleset", "version"))
    text(("basis", "ruleset", "digest"), may_be_empty=True)
    ov = at(("decision", "override"))
    if ov is KeyError:
        bad.append("subject.decision.override")
    elif not isinstance(ov, bool):
        bad.append("subject.decision.override must be a boolean")
    if ref is not None and ref.strip() and not DECISION_REF_RE.match(ref):
        bad.append(f"subject.item.ref {ref[:70]!r} is not 1 to 64 of letters, digits, '-', '_' and '.' (an opaque reference)")
    if title is not None and ref is not None and title != "decision on " + ref:
        bad.append(f"subject.title {title[:80]!r} is not 'decision on ' followed by item.ref (a free title is how a name leaks)")
    if value is not None and value.strip() and not DECISION_VALUE_RE.match(value):
        bad.append(f"subject.decision.value {value[:40]!r} is not a token of letters, digits, '_' and '-'")
    deciders = DECISION_DECIDERS_09 if fmt_at_least(M, "0.9") else DECISION_DECIDERS
    if kind is not None and kind.strip() and kind not in deciders:
        bad.append(f"subject.decision.by.kind={kind!r} not in {sorted(deciders)}")
    if fmt_at_least(M, "0.9"):
        # 0.9: an agent's decision names the person who enrolled the agent; nobody else's decider carries that field
        by_ = at(("decision", "by"))
        has_eb = isinstance(by_, dict) and "enrolled_by" in by_
        if kind == "agent":
            eb = text(("decision", "by", "enrolled_by"))
            pr = at(("decision", "by", "principal"))
            if eb is not None and eb.strip() and eb == pr:
                bad.append("subject.decision.by.enrolled_by is the agent's own principal: it names the person who enrolled the agent")
        elif has_eb and kind in DECISION_DECIDERS:
            bad.append(f"subject.decision.by.enrolled_by is set on a {kind} decider: only an agent's decider names who enrolled it")
    if when is not None and when.strip() and parse_time(when) is None:
        bad.append(f"subject.decision.at={when!r} is not a time (YYYY-MM-DDTHH:MM:SSZ)")
    if isinstance(ov, bool) and value is not None and rec is not None and ov != (value != rec):
        bad.append(f"subject.decision.override is {ov!r} but value {value!r} and basis.recommendation {rec!r} make it {value != rec!r}")
    if when is not None and M.get("taken_at") != when:
        bad.append(f"taken_at {M.get('taken_at')!r} is not subject.decision.at {when!r}")
    led = at(("ledger",))
    if led is KeyError:
        bad.append("subject.ledger (null, or an object with stream, n and event)")
    elif led is not None:
        if not isinstance(led, dict):
            bad.append("subject.ledger must be null or an object")
        else:
            text(("ledger", "stream"))
            n_ = led.get("n", KeyError)
            if n_ is KeyError:
                bad.append("subject.ledger.n")
            elif not isinstance(n_, int) or isinstance(n_, bool) or n_ < 1:
                bad.append(f"subject.ledger.n={n_!r} must be an integer of 1 or more")
            text(("ledger", "event", "artefact"))
            text(("ledger", "event", "sha256"), hexed=True)
    return bad


def document_member_fault(m):
    """Why a page's `member` (the path inside a zip or a repository) is not allowed (SPEC 17), else None."""
    if not isinstance(m, str) or not m.strip():
        return "must be a non-empty string"
    if m.startswith("/"):
        return "must be relative: no leading /"
    if "\\" in m:
        return "must not hold a backslash"
    if any(part == ".." for part in m.split("/")):
        return "must not hold a .. component"
    return None


def document_faults(M):
    """K1 for the document profile (SPEC 17, 0.9): the subject (six keys, the media types, sha256, url, commit), the pages (their own media
    type, `member` for a zip or a repository, `extractor` for an extraction) and the stage (always pre-witness, no primary, no gates). The
    problems, as text, in the order found."""
    bad = []
    sub = M.get("subject")
    if not isinstance(sub, dict):
        return ["subject must be an object"]
    for k_ in ("kind", "title", "media_type", "sha256", "url", "commit"):
        if k_ not in sub:
            bad.append(f"subject.{k_}")
    if "kind" in sub and sub["kind"] != DOCUMENT_PROFILE:
        bad.append(f"subject.kind={sub['kind']!r} must be {DOCUMENT_PROFILE!r}")
    if "title" in sub and not (isinstance(sub["title"], str) and sub["title"].strip()):
        bad.append("subject.title must be a non-empty string")
    mt = sub.get("media_type")
    mt_ok = isinstance(mt, str) and mt in DOCUMENT_MEDIA
    if "media_type" in sub and not mt_ok:
        bad.append(f"subject.media_type={mt!r} is not one of {list(DOCUMENT_MEDIA)}")
    if "sha256" in sub and not (isinstance(sub["sha256"], str) and HEX64.match(sub["sha256"])):
        bad.append("subject.sha256 is not 64 lower-case hex")
    if "url" in sub and sub["url"] is not None and not (isinstance(sub["url"], str) and sub["url"].startswith(("https://", "http://"))):
        bad.append(f"subject.url={str(sub['url'])[:60]!r} is not null or a string starting https:// or http://")
    if "commit" in sub:
        cm = sub["commit"]
        if mt == "application/x-git":
            if not (isinstance(cm, str) and HEX40.match(cm)):
                bad.append("subject.commit must be 40 lower-case hex when the media type is application/x-git")
        elif cm is not None:
            bad.append("subject.commit must be null unless the media type is application/x-git")
    members = []
    pages = M.get("pages") if isinstance(M.get("pages"), list) else []
    multi = mt in DOCUMENT_MEMBER_MEDIA
    for i, p in enumerate(pages):
        if not isinstance(p, dict):
            continue
        pm = p.get("media_type", KeyError)
        if pm is KeyError:
            bad.append(f"pages[{i}].media_type")
        elif not (isinstance(pm, str) and pm in DOCUMENT_MEDIA and pm not in DOCUMENT_MEMBER_MEDIA):
            bad.append(f"pages[{i}].media_type={pm!r} is not a single-file media type of the list (a page is never application/zip or application/x-git)")
        elif mt_ok and not multi and pm != mt:
            bad.append(f"pages[{i}].media_type={pm!r} must equal subject.media_type {mt!r} for a single-file subject")
        mem = p.get("member")
        if multi:
            why = document_member_fault(mem)
            if why:
                bad.append(f"pages[{i}].member {why} (a {mt} subject names each page's path inside it)")
            else:
                members.append(mem)
        elif mem is not None:
            bad.append(f"pages[{i}].member must be null or absent unless the subject is application/zip or application/x-git")
        ex = p.get("extractor")
        if isinstance(pm, str) and pm in DOCUMENT_EXTRACTED_MEDIA:
            if not (isinstance(ex, dict) and isinstance(ex.get("name"), str) and ex["name"].strip() and isinstance(ex.get("sha256"), str) and HEX64.match(ex["sha256"])):
                bad.append(f"pages[{i}].extractor must be an object with a name and a 64 hex sha256 (a {pm} page is an extraction)")
        elif ex is not None:
            bad.append(f"pages[{i}].extractor must be null or absent on a page that is not an extraction")
    for m_ in sorted({m_ for m_ in members if members.count(m_) > 1}):
        bad.append(f"pages: member {m_!r} is used by more than one page")
    g = M.get("grading") if isinstance(M.get("grading"), dict) else {}
    if g.get("kind") != "pre-witness":
        bad.append(f"grading.kind={g.get('kind')!r} must be 'pre-witness': the document profile has no primary witness and no merge")
    if g.get("gates"):
        bad.append("grading.gates must be absent or empty in the document profile")
    for i, w in enumerate(g.get("witnesses") if isinstance(g.get("witnesses"), list) else []):
        if isinstance(w, dict) and w.get("primary"):
            bad.append(f"grading.witnesses[{i}] is marked primary: the document profile names no primary (the result is the auditor's claimed verdicts and each witness's agreement with them)")
    return bad


def document_audit_faults(audit, M):
    """K11 for the document profile (SPEC 17): every candidate of every row (`where`, `kind`, `quote`, and for `external` exactly one source),
    and the auditor's `claimed` verdict on every checkable row. Returns (faults, warnings) as text."""
    bad, warn = [], []
    page_files = {p.get("file") for p in (M.get("pages") or []) if isinstance(p, dict)}
    srcs = [s for s in (M.get("sources") or []) if isinstance(s, dict)]
    for a in audit:
        rid = a.get("id")
        for side in ("proofs", "counter"):
            lst = a.get(side) or []
            if not isinstance(lst, list):
                bad.append(f"{rid}: {side} is not a list")
                continue
            for i, c in enumerate(lst):
                lab = f"{rid}: {side}[{i}]"
                if not isinstance(c, dict):
                    bad.append(f"{lab} is not an object")
                    continue
                w = c.get("where", KeyError)
                if w is KeyError:
                    bad.append(f"{lab}.where missing (document or external)")
                elif w not in ("document", "external"):
                    bad.append(f"{lab}.where={w!r} is not 'document' or 'external'")
                k_ = c.get("kind", KeyError)
                if k_ is KeyError:
                    bad.append(f"{lab}.kind missing (artefact or restatement)")
                elif k_ not in ("artefact", "restatement"):
                    bad.append(f"{lab}.kind={k_!r} is not 'artefact' or 'restatement'")
                if not (isinstance(c.get("quote"), str) and c["quote"].strip()):
                    bad.append(f"{lab}.quote must be a non-empty string (no existence or status proofs in this profile)")
                if w == "document":
                    if c.get("file") not in page_files:
                        bad.append(f"{lab}.file {c.get('file')!r} is not one of pages[].file")
                elif w == "external":
                    u = c.get("url")
                    held = [s for s in srcs if isinstance(u, str) and s.get("url") == u]
                    if len(held) != 1:
                        bad.append(f"{lab}.url {str(u)[:80]!r} is held by {len(held)} source(s): where external needs exactly one source with that url")
                        continue
                    s = held[0]
                    n_ = s.get("n")
                    if not (isinstance(s.get("sha256"), str) and HEX64.match(s["sha256"])):
                        bad.append(f"{lab}: source {n_}: sha256 is not 64 hex")
                    if not s.get("fetched_at"):
                        bad.append(f"{lab}: source {n_}: fetched_at is missing")
                    if s.get("copy") not in ("text", "hash-only"):
                        bad.append(f"{lab}: source {n_}: copy {s.get('copy')!r} is not text or hash-only")
                    elif s.get("copy") == "text" and c.get("file") != s.get("file"):
                        bad.append(f"{lab}.file {c.get('file')!r} is not the file of source {n_} ({s.get('file')!r}): a text source's candidate names its copy")
    for a in audit:
        rid = a.get("id")
        checkable = bool(a.get("checkable", True)) and a.get("kind") != "promise"
        cl = a.get("claimed", KeyError)
        if not checkable:
            if cl is not KeyError:
                bad.append(f"{rid}: claimed on a row that is not checkable (checkable false or kind promise): only a checkable row carries claimed")
            continue
        if cl is KeyError:
            bad.append(f"{rid}: claimed missing: every checkable row carries the auditor's claimed verdict")
            continue
        if not isinstance(cl, dict):
            bad.append(f"{rid}: claimed is not an object")
            continue
        v = cl.get("verdict")
        if v not in DOCUMENT_VERDICTS:
            bad.append(f"{rid}: claimed.verdict={v!r} is not one of {list(DOCUMENT_VERDICTS)}")
        if "confidence" in cl and cl["confidence"] not in ("high", "low"):
            bad.append(f"{rid}: claimed.confidence={cl['confidence']!r} is not high or low")
        elif v == "CONTRADICTED" and "confidence" not in cl:
            bad.append(f"{rid}: claimed.confidence is required on CONTRADICTED (high or low)")
        if not (isinstance(cl.get("note"), str) and cl["note"].strip()):
            bad.append(f"{rid}: claimed.note must be a non-empty string")
        on = cl.get("on")
        if not isinstance(on, dict):
            bad.append(f"{rid}: claimed.on must be an object with proofs and counter (lists of indices)")
            on = {}
        valid = {}
        for key in ("proofs", "counter"):
            lst = on.get(key, [])
            n_have = len(a.get(key) or []) if isinstance(a.get(key) or [], list) else 0
            if not (isinstance(lst, list) and all(isinstance(i, int) and not isinstance(i, bool) for i in lst)):
                bad.append(f"{rid}: claimed.on.{key} must be a list of integers")
                valid[key] = []
                continue
            valid[key] = [i for i in lst if 0 <= i < n_have]
            for i in lst:
                if not 0 <= i < n_have:
                    bad.append(f"{rid}: claimed.on.{key} index {i} is outside the row's {n_have} candidate(s)")
        art = [i for i in valid.get("proofs", []) if isinstance((a.get("proofs") or [])[i], dict) and (a.get("proofs") or [])[i].get("kind") == "artefact"]
        if v == "EVIDENCED" and not art:
            bad.append(f"{rid}: claimed EVIDENCED names no artefact proof in claimed.on.proofs (a restatement does not count)")
        if v == "CONTRADICTED" and not valid.get("counter"):
            bad.append(f"{rid}: claimed CONTRADICTED names no counter in claimed.on.counter")
        if v == "NO EVIDENCE PUBLISHED" and art:
            warn.append(f"{rid}: claimed NO EVIDENCE PUBLISHED but on.proofs names an artefact: the auditor saw an artefact and did not count it")
    return bad, warn


def _main(argv, R):
    if len(argv) < 2:
        print(__doc__)
        return 2
    snap = pathlib.Path(argv[1])
    copies = pathlib.Path(argv[argv.index("--copies") + 1]) if "--copies" in argv else None
    fetch = "--fetch" in argv
    strict = "--strict" in argv
    want_json = "--json" in argv
    keys_arg = pathlib.Path(argv[argv.index("--keys") + 1]) if "--keys" in argv and argv.index("--keys") + 1 < len(argv) else None
    links_root = pathlib.Path(argv[argv.index("--links") + 1]) if "--links" in argv and argv.index("--links") + 1 < len(argv) else None

    # K1 manifest
    try:
        M = json.loads((snap / "manifest.json").read_text(encoding="utf-8"))
    except Exception as e:
        R.add("K1", "FAIL", f"manifest.json unreadable: {e}")
        return finish(R, snap, argv, None)
    R.fmt = M.get("format") if isinstance(M, dict) else None
    shape_ = manifest_shape_faults(M)
    if shape_:
        # V2f: a manifest of another shape fails here by name, never a traceback further down
        R.add("K1", "FAIL", f"manifest shape: {len(shape_)} part(s) of the wrong JSON kind, the folder is not checked further", shape_)
        return finish(R, snap, argv, M.get("format") if isinstance(M, dict) else None)
    # 0.6, the pre-witness stage (12 Nov 2026, SPEC 14): grading.kind "pre-witness" declares the auditor's part alone, no primary
    # witness named yet: no claims.jsonl, no score, no claims_sha256, no grading.grader or grading.model; witnesses may be listed, none
    # primary. The declaration is required: an undeclared folder missing those fields fails K1 as before.
    pre = isinstance(M.get("grading"), dict) and M["grading"].get("kind") == "pre-witness"
    top_fields = ("format", "subject", "taken_at", "pages", "sources", "grading", "counts") if pre else ("format", "subject", "taken_at", "pages", "sources", "grading", "counts", "score", "claims_sha256")
    missing = [k for k in top_fields if k not in M]
    if M.get("format") not in FORMATS:
        missing.append(f"format={M.get('format')!r} unknown")
    pages = M.get("pages") or []
    if not isinstance(pages, list) or not pages:
        missing.append("pages must be a non-empty list")
    for i, pg in enumerate(pages if isinstance(pages, list) else []):
        for k in ("file", "sha256"):
            if k not in pg:
                missing.append(f"pages[{i}].{k}")
    g = M.get("grading", {})
    for k in (("kind", "profile") if pre else ("kind", "grader", "model", "profile")):
        if k not in g:
            missing.append(f"grading.{k}")
    profiles_ = PROFILES | {DECISION_PROFILE} if fmt_at_least(M, "0.8") else PROFILES  # 0.8: the decision profile exists from claims-snapshot/0.8
    if fmt_at_least(M, "0.9"):
        profiles_ = profiles_ | {DOCUMENT_PROFILE}  # 0.9: the document profile (SPEC 17)
    if g.get("profile") not in profiles_:
        missing.append(f"grading.profile={g.get('profile')!r} not in {sorted(profiles_)}")
    pre_bad = []  # pre-witness (SPEC 14): what the stage forbids, said as such
    if pre:
        if not fmt_at_least(M, "0.6"):  # 0.7: "0.6 or later" (was: exactly 0.6)
            pre_bad.append(f"format {M.get('format')!r}: the stage exists from claims-snapshot/0.6")
        for k in ("score", "claims_sha256"):
            if k in M:
                pre_bad.append(f"carries {k}: the score comes with the primary witness")
        for k in ("grader", "model"):
            if k in g:
                pre_bad.append(f"carries grading.{k}: they name the primary witness")
        if (snap / "claims.jsonl").exists():
            pre_bad.append("holds claims.jsonl: the merge comes with the primary witness")
        if not (snap / "audit.jsonl").exists():
            pre_bad.append("has no audit.jsonl: nothing is published")
        if not isinstance(g.get("witnesses"), list):
            pre_bad.append("grading.witnesses must be a list (empty before the first witness)")
        elif any(isinstance(w, dict) and w.get("primary") for w in g["witnesses"]):
            pre_bad.append("marks a witness primary: naming the primary ends the stage (grading.kind self-audit | split, claims.jsonl, score)")
    tr_bad = []  # test-run (SPEC 13): problems that are not missing fields, said as such
    if g.get("profile") == "test-run":
        # 0.5, the test-run profile (SPEC 13): the subject's fields, the evidence locator, the times
        sub = M.get("subject") if isinstance(M.get("subject"), dict) else {}
        if not sub:
            tr_bad.append("subject must be an object")
        if sub.get("kind") != "test-run":
            tr_bad.append(f"subject.kind={sub.get('kind')!r} must be 'test-run'")
        for path in (("scenario", "id"), ("scenario", "sha256"), ("environment", "name"), ("environment", "sha256"),
                     ("system_under_test", "repository"), ("system_under_test", "commit"), ("system_under_test", "image_digest"),
                     ("runner", "id"), ("runner", "machine_id"), ("started_at",), ("finished_at",)):
            cur, label = sub, "subject." + ".".join(path)
            for k_ in path:
                cur = cur.get(k_, KeyError) if isinstance(cur, dict) else KeyError
            if cur is KeyError:
                tr_bad.append(label)
            elif path[-1] == "image_digest":
                if cur is not None and not isinstance(cur, str):
                    tr_bad.append(label + " must be a string or null")
            elif not isinstance(cur, str) or not cur.strip():
                tr_bad.append(label + " empty")
            elif path[-1] == "sha256" and not HEX64.match(cur):
                tr_bad.append(label + " not 64 hex")
        t0, t1 = parse_time(sub.get("started_at")), parse_time(sub.get("finished_at"))
        for k_, t_ in (("started_at", t0), ("finished_at", t1)):
            if k_ in sub and t_ is None:
                tr_bad.append(f"subject.{k_}={sub.get(k_)!r} is not a time (YYYY-MM-DDTHH:MM:SSZ)")
        if t0 and t1 and t0 > t1:
            tr_bad.append(f"subject.started_at {sub.get('started_at')} is after finished_at {sub.get('finished_at')}")
        if "finished_at" in sub and M.get("taken_at") != sub.get("finished_at"):
            tr_bad.append(f"taken_at {M.get('taken_at')!r} is not subject.finished_at {sub.get('finished_at')!r}")
        tr_bad.extend(locator_faults(M, snap))
    dc_bad = []  # decision (SPEC 16, 0.8): the subject's fields and rules, the evidence locator
    if g.get("profile") == DECISION_PROFILE and fmt_at_least(M, "0.8"):
        dc_bad = decision_subject_faults(M)
        dc_bad.extend(locator_faults(M, snap))
    doc_bad = []  # document (SPEC 17, 0.9): the subject, the pages, the stage
    is_doc = g.get("profile") == DOCUMENT_PROFILE and fmt_at_least(M, "0.9")
    if is_doc:
        doc_bad = document_faults(M)
    for i, gate in enumerate(g.get("gates", []) or []):
        for k in ("run", "size", "sealed_sha256", "sealed_at", "first_gate", "final"):
            if k not in gate:
                missing.append(f"grading.gates[{i}].{k}")
    k1_text = "manifest fields" + (": missing " + ", ".join(missing) if missing else (" present" if tr_bad or pre_bad or dc_bad or doc_bad else f" present, format {M.get('format')}, profile {g.get('profile')}, {len(g.get('gates', []) or [])} holdout gate(s) recorded"))
    if tr_bad:
        k1_text += "; test-run subject or locator: " + ", ".join(tr_bad)
    if dc_bad:
        k1_text += "; decision subject or locator: " + ", ".join(dc_bad)
    if doc_bad:
        k1_text += "; document subject, pages or stage: " + ", ".join(doc_bad)
    if pre_bad:
        k1_text += "; pre-witness folder " + ", ".join(pre_bad)
    elif pre and not missing:
        k1_text += "; pre-witness: the auditor's part alone, no primary witness named yet"
    if is_doc and not (missing or pre_bad or doc_bad):
        k1_text += "; document profile (0.9): subject, pages and stage in order"
    R.add("K1", "FAIL" if missing or tr_bad or pre_bad or dc_bad or doc_bad else "PASS", k1_text)
    if missing or tr_bad or pre_bad or dc_bad or doc_bad:
        return finish(R, snap, argv, M.get("format"))

    # K2 files and hashes: every content file the manifest names, wherever it names it, each once (13 Nov 2026, NEXT-REVISION 20 and 22):
    # pages, sources, claims.jsonl (not pre-witness), the auditor part through grading.auditor.sha256 (0.4 and later), every witness
    # file through its grading.witnesses entry, and `files` in both shapes, a list of {file, sha256} (the examples, add_witness.py) or
    # an object file -> sha256 (the kit's writer). A file named twice with one hash counts once; two different hashes is a FAIL detail.
    # A `files` entry naming a STRUCTURAL file is refused and its hash is not checked: signatures.json and allowed_signers grow with
    # every signature, anchors.json with every anchor, and the manifest's own signature lands in signatures.json after the manifest
    # is hashed, so such a hash is stale the moment the folder is signed or witnessed.
    bad = []
    files = [(pg["file"], pg["sha256"]) for pg in pages] + [(s["file"], s["sha256"]) for s in M["sources"] if s.get("file")]
    if not pre:
        files.append(("claims.jsonl", M["claims_sha256"]))
    au_ = g.get("auditor") if isinstance(g.get("auditor"), dict) else {}
    if au_.get("file") and au_.get("sha256"):
        files.append((au_["file"], au_["sha256"]))
    for w_ in (g.get("witnesses") or []) if isinstance(g.get("witnesses"), list) else []:
        if isinstance(w_, dict) and w_.get("file") and w_.get("sha256"):
            files.append((w_["file"], w_["sha256"]))
    fl_ = M.get("files")
    if isinstance(fl_, list):
        listed = [(e_["file"], e_.get("sha256")) for e_ in fl_ if isinstance(e_, dict) and e_.get("file")]
    elif isinstance(fl_, dict):
        listed = [(f_, h_) for f_, h_ in fl_.items() if isinstance(f_, str) and f_]
    else:
        listed = []
        if fl_ is not None:  # present but of a shape nobody writes: said by name, not skipped
            bad.append("files: neither a list of {file, sha256} nor an object file -> sha256")
    for f, h in listed:
        if f in STRUCTURAL_FILES:
            bad.append(f"{f}: a structural file named by hash in files (NEXT-REVISION 22: signatures.json and allowed_signers grow with every "
                       "signature, anchors.json with every anchor, the manifest's own signature lands in signatures.json after the manifest is hashed)")
        else:
            files.append((f, h))
    named = {}
    for f, h in files:
        named.setdefault(f, [])
        if h and h not in named[f]:
            named[f].append(h)
    for f, hs in named.items():
        p = snap / f
        if len(hs) > 1:
            bad.append(f"{f}: named with two different sha256")
        elif not p.exists():
            bad.append(f"{f}: missing")
        elif hs and sha256(p) != hs[0]:
            bad.append(f"{f}: sha256 {sha256(p)[:12]}… differs from manifest {hs[0][:12]}…")
    R.add("K2", "FAIL" if bad else "PASS", f"{len(named)} files named, hashes " + ("differ" if bad else "match"), bad)

    claims = load_jsonl(snap / "audit.jsonl") if pre else load_jsonl(snap / "claims.jsonl")  # pre-witness: the auditor's rows stand in, no verdicts
    page_files = [pg["file"] for pg in pages]
    page_text = {pg["file"]: page_text_of(pg["file"], (snap / pg["file"]).read_text(encoding="utf-8", errors="replace")) for pg in pages if (snap / pg["file"]).exists()}
    N = document_norm if is_doc else norm  # 0.9 document profile: the typographic fold after norm() on both sides of K4, K5, K6 and quote-check
    pages_norm = N(" ".join(page_text.values()))
    by_n = {s["n"]: s for s in M["sources"]}
    by_file = {s["file"]: s for s in M["sources"] if s.get("file")}

    # K3 vocabulary
    bad = []
    ids = [c.get("id") for c in claims]
    dup = {i for i in ids if ids.count(i) > 1}
    if dup:
        bad.append("duplicate ids: " + ", ".join(sorted(dup)))
    for c in claims:
        if not pre and c.get("verdict") not in VERDICTS:
            bad.append(f"{c.get('id')}: verdict {c.get('verdict')!r}")
        if c.get("kind") not in KINDS:
            bad.append(f"{c.get('id')}: kind {c.get('kind')!r}")
        if c.get("verdict") == "CONTRADICTED" and c.get("confidence") not in ("high", "low"):
            bad.append(f"{c.get('id')}: CONTRADICTED without confidence")
        if not pre and c.get("graded_by") not in GRADED_BY:
            bad.append(f"{c.get('id')}: graded_by {c.get('graded_by')!r}")
        if not pre and not c.get("graded_at"):
            bad.append(f"{c.get('id')}: no graded_at")
        if not isinstance(c.get("checkable", True), bool):
            bad.append(f"{c.get('id')}: checkable not a boolean")
        if not c.get("text", "").strip():
            bad.append(f"{c.get('id')}: empty text")
        # the carried cut (13 Nov 2026, NEXT-REVISION 24): `on_request`, when present, is an object; `true` or any other non-object is a
        # violation by name, never a traceback (absent or null on an ON REQUEST row keeps the message below)
        orq = c.get("on_request")
        if c.get("verdict") == "EVIDENCE AVAILABLE ON REQUEST":
            if orq is not None and not isinstance(orq, dict):
                bad.append(f"{c.get('id')}: on_request is not an object (holder, sha256, …)")
            elif not (isinstance(orq, dict) and orq.get("holder") and orq.get("sha256")):
                bad.append(f"{c.get('id')}: EVIDENCE AVAILABLE ON REQUEST without on_request.holder and on_request.sha256")
        elif orq is not None and not isinstance(orq, dict):
            bad.append(f"{c.get('id')}: on_request is not an object")
        if c.get("verdict") == "WITHDRAWN" and not (c.get("history") or c.get("note")):
            bad.append(f"{c.get('id')}: WITHDRAWN without a history or note saying so")
    R.add("K3", "FAIL" if bad else "PASS", ("pre-witness: " if pre else "") + f"{len(claims)} claims; " + (f"{len(bad)} id, vocabulary or provenance violation(s)" if bad else ("ids unique; kinds and texts in order (no verdicts yet)" if pre else "ids unique; verdicts, kinds, confidence, graded_by and graded_at in order")), bad)

    # K4 claim text on the pages
    bad = []
    for c in claims:
        if c.get("verdict") == "WITHDRAWN":
            continue
        frags = [N(f) for f in c.get("text", "").split("[...]")]
        frags = [f for f in frags if f]
        if not frags or not all(f in pages_norm for f in frags):
            miss = [f for f in frags if f not in pages_norm]
            bad.append(f"{c['id']}: not on the page: " + " | ".join(m[:80] for m in miss))
    R.add("K4", "FAIL" if bad else "PASS", "every claim text on the audited page(s)" if not bad else f"{len(bad)} claims not on the page", bad)

    # K5 / K6 / K7 quotes against copies
    texts = {}
    def norm_text_for(file):
        if file in texts:
            return texts[file]
        if file in page_text:
            texts[file] = N(page_text[file])
        else:
            src = by_file.get(file)
            if src is None:
                m = re.search(r"(\d{3})(?:\.pdf-text)?\.txt$", file or "")
                src = by_n.get(int(m.group(1))) if m else None
            raw = copy_text(snap, copies, src) if src else None
            texts[file] = N(raw) if raw is not None else None
        return texts[file]

    profile = g.get("profile")
    pages_prove = profile == "publisher-surfaces"  # a site's pages ARE its surfaces: the grader judged which quote is the artefact

    def test_quote(c, p, what):
        """verified | untestable | failed for one proof-shaped dict. A quote-less proof with a file is an existence
        proof (the file at hand, hash-checked by K2, is the artefact); a quote-less proof with expect_status is a
        status proof, testable only live (K10)."""
        f = p.get("file")
        if not f:
            p["verified"] = False
            return "untestable"
        t = norm_text_for(f)
        if t is None:
            p["verified"] = False
            return "untestable"
        if p.get("quote") is None:
            if f in page_text:
                p["verified"] = False   # the publisher's own page existing proves nothing: a locator, not a proof
                bad_quotes.append(f"{c['id']}: {what} names a page of the publisher's own with no quote: {f}")
                return "failed"
            p["verified"] = True
            return "verified"
        if N(p.get("quote", "")) and N(p["quote"]) in t:
            p["verified"] = True
            return "verified"
        p["verified"] = False
        if f in page_text or (f in by_file and (snap / f).exists()):
            # the copy is published in the snapshot itself: every quote taken from it must be there, no tolerance
            published_misses.append(f"{c['id']}: {what} quote not found in the published copy {f}: {p.get('quote', '')[:60]}")
        else:
            bad_quotes.append(f"{c['id']}: {what} quote not found in {f}: {p.get('quote', '')[:60]}")
        return "failed"

    # 0.5, the agent-work shape (SPEC 12): a row with one `evidence` list of pointers instead of proofs and counter.
    # A pointer is verified from the folder alone: a file and line by the published copy of that file holding the
    # line; a command or test by a published output whose sha256 is the one named; record rows by the published
    # session record holding that sequence. Not in the folder = untestable (WARN), never verified.
    sess_records = {}
    for s_ in (g.get("sessions") or []):
        f = s_.get("file")
        if f and (snap / f).exists() and sha256(snap / f) == s_.get("record_sha256"):
            seqs = set()
            for l in (snap / f).read_text(encoding="utf-8", errors="replace").split("\n"):  # JSON lines: "\n" only, as load_jsonl
                try:
                    e = json.loads(l.rstrip("\r"))
                except Exception:
                    continue
                if isinstance(e, dict) and isinstance(e.get("sequence"), int):
                    seqs.add((str(e.get("session_id", "")), e["sequence"]))
            sess_records[str(s_.get("session_id", ""))] = seqs
    by_path = {s_["path"]: s_ for s_ in M["sources"] if s_.get("path")}
    by_sha = {s_["sha256"]: s_ for s_ in M["sources"] if s_.get("sha256") and s_.get("file") and (snap / s_["file"]).exists()}

    def test_pointer(c, p, i):
        """verified | untestable | failed for one evidence pointer of the agent-work shape."""
        if not isinstance(p, dict):
            return "failed"
        if "file" in p and "line" in p:
            src = by_path.get(p["file"])
            if not src or not src.get("file") or not (snap / src["file"]).exists():
                return "untestable"
            lines = (snap / src["file"]).read_text(encoding="utf-8", errors="replace").splitlines()
            if isinstance(p["line"], int) and 1 <= p["line"] <= len(lines):
                return "verified"
            bad_quotes.append(f"{c['id']}: evidence {i + 1}: {p['file']} has {len(lines)} line(s), no line {p['line']}")
            return "failed"
        if "output_sha256" in p and ("command" in p or "test" in p):
            return "verified" if p["output_sha256"] in by_sha else "untestable"
        if "artefact" in p and profile in ARTEFACT_PROFILES:
            # 0.5, test-run (SPEC 13), and 0.8, decision (SPEC 16, K5/K6 unchanged): an artefact of the run by name and hash, verified from the folder's copy
            h_, nm_ = p.get("sha256"), p.get("artefact")
            if not (isinstance(h_, str) and HEX64.match(h_)) or not nm_:
                return "failed"
            held = [s_ for s_ in M["sources"] if s_.get("sha256") == h_ and s_.get("file") and (snap / s_["file"]).exists()]
            if not held:
                if not any(s_.get("sha256") == h_ for s_ in M["sources"]):
                    # trilix, adoption of section 13 (WA): the sources are the record's inventory; a pointer to a hash no source lists fails, whoever holds the bytes
                    bad_quotes.append(f"{c['id']}: evidence {i + 1}: artefact {nm_!r} sha256 {h_[:12]}... is listed by no source: the record's inventory does not cover the auditor's evidence")
                    return "failed"
                return "untestable"
            src = held[0]
            if any(nm_ in (s_.get("name"), s_.get("path")) for s_ in held):
                return "verified"
            bad_quotes.append(f"{c['id']}: evidence {i + 1}: artefact {nm_!r} names sha256 {h_[:12]}..., which the folder holds under another name: {src.get('name') or src.get('path')!r}")
            return "failed"
        if "record" in p:
            m = RECORD_PTR.match(str(p["record"]))
            if not m:
                return "failed"
            for sid, seqs in sess_records.items():
                if sid.startswith(m.group(1)):
                    if (sid, int(m.group(2))) in seqs:
                        return "verified"
                    bad_quotes.append(f"{c['id']}: evidence {i + 1}: the published record of {sid} has no row #{m.group(2)}")
                    return "failed"
            return "untestable"
        return "failed"

    def agent_shape(c):
        return isinstance(c.get("evidence"), list) and not c.get("proofs") and not c.get("counter")

    def doc_hold(p):
        """0.9 document profile (SPEC 17): (holds | untestable | fails, published) for one candidate. A `document` candidate is tested against
        its page, an `external` one against the copy of the source that holds its url: the text copy in the folder, else --copies (as K5 does),
        else it is untestable here. Both sides go through the fold. No side effect."""
        q = N(p["quote"]) if isinstance(p.get("quote"), str) else ""
        if not q:
            return "fails", False
        if p.get("where") == "document":
            t = norm_text_for(p.get("file")) if p.get("file") in page_text else None
            pub = True
        else:
            held = [s_ for s_ in M["sources"] if isinstance(p.get("url"), str) and s_.get("url") == p.get("url")]
            if len(held) != 1:
                return "untestable", False
            raw = copy_text(snap, copies, held[0])
            t = N(raw) if raw is not None else None
            pub = bool(held[0].get("file") and (snap / held[0]["file"]).exists())
        if t is None:
            return "untestable", False
        return ("holds" if q in t else "fails"), pub

    def doc_test(c, p, what):
        """K5 for a candidate of the document profile: verified | untestable | failed, saying where a miss lands (the published copy: a FAIL)."""
        r_, pub = doc_hold(p)
        if r_ == "holds":
            return "verified"
        if r_ == "untestable":
            return "untestable"
        quote_ = p.get("quote") if isinstance(p.get("quote"), str) else ""
        if pub:
            published_misses.append(f"{c['id']}: {what} quote not found in the published copy {p.get('file')}: {quote_[:60]}")
        else:
            bad_quotes.append(f"{c['id']}: {what} quote not found in the copy of {p.get('url')}: {quote_[:60]}")
        return "failed"

    k5_fail, k5_warn, k6_fail, k6_warn, k7_fail, page_only, bad_quotes, existence, published_misses = [], [], [], [], [], [], [], [], []
    pre_tally = {"verified": 0, "untestable": 0, "failed": 0}  # pre-witness: every pointer or candidate quote of the auditor's rows, tested without a verdict
    for c in claims:
        v = c.get("verdict")
        if pre:
            if is_doc:
                for p in (c.get("proofs") or []) + (c.get("counter") or []):
                    if isinstance(p, dict):
                        pre_tally[doc_test(c, p, "candidate")] += 1
            elif agent_shape(c):
                for i, p in enumerate(c["evidence"]):
                    pre_tally[test_pointer(c, p, i)] += 1
            else:
                for p in c.get("proofs", []) + c.get("counter", []):
                    pre_tally[test_quote(c, p, "candidate")] += 1
            continue
        if agent_shape(c) and v in ("EVIDENCED", "CONTRADICTED"):
            # EVIDENCED and CONTRADICTED both rest on the agent's pointers (SPEC 4b, Indie shape): at least one must hold
            rs = [test_pointer(c, p, i) for i, p in enumerate(c["evidence"])]
            fail_l, warn_l = (k5_fail, k5_warn) if v == "EVIDENCED" else (k6_fail, k6_warn)
            if "verified" not in rs:
                if "untestable" in rs:
                    warn_l.append(f"{c['id']}: no evidence pointer checkable from the folder ({rs.count('untestable')} not in it: output, record or file held by hash)")
                else:
                    fail_l.append(f"{c['id']}: no evidence pointer holds in the folder")
            continue
        if agent_shape(c):
            continue  # K7 does not apply: a pointer that resolves shows where the agent looked, not that the claim holds
        if v == "EVIDENCED":
            ok, untestable, pageq, nonpage_ok = 0, 0, 0, 0
            for p in c.get("proofs", []):
                f = p.get("file")
                if f in page_text:
                    pageq += 1
                    if not pages_prove and c.get("kind") not in PAGE_PROVES:
                        continue
                r = test_quote(c, p, "proof")
                if r == "verified":
                    ok += 1
                    if f not in page_text:
                        nonpage_ok += 1
                    if p.get("quote") is None:
                        existence.append(c["id"])
                elif r == "untestable":
                    untestable += 1
            if ok == 0:
                if untestable:
                    k5_warn.append(f"{c['id']}: no checkable proof ({untestable} proof(s) without a copy at hand)")
                else:
                    k5_fail.append(f"{c['id']}: no proof quote found in a source" + (f" (kind {c.get('kind')}: quotes from the page itself do not count)" if pageq and not pages_prove else ""))
            elif pageq and nonpage_ok == 0:
                page_only.append(c["id"])
        elif v == "CONTRADICTED":
            ok, untestable = 0, 0
            for p in c.get("counter", []):
                r = test_quote(c, p, "counter")
                if r == "verified":
                    ok += 1
                elif r == "untestable":
                    untestable += 1
            if ok == 0:
                (k6_warn if untestable else k6_fail).append(f"{c['id']}: no counter quote found" + (" (copy not at hand)" if untestable else ""))
        elif v in ("NO EVIDENCE PUBLISHED", "EVIDENCE AVAILABLE ON REQUEST", "WITHDRAWN"):
            for p in c.get("proofs", []):
                f = p.get("file")
                if f and f not in page_text:
                    t = norm_text_for(f)
                    if t is not None and (p.get("quote") is None or (N(p.get("quote", "")) and N(p["quote"]) in t)):
                        k7_fail.append(f"{c['id']}: {v} but a source proof verifies: {f}")
    n_e = sum(1 for c in claims if c.get("verdict") == "EVIDENCED")
    if pre:
        # pre-witness: no verdict to test; the auditor's pointers and candidate quotes are tested from the folder and reported.
        # A quote missing from a copy published in this very snapshot still fails: the folder must carry what it quotes.
        n_p = sum(pre_tally.values())
        R.add("K5", "FAIL" if published_misses else ("WARN" if (pre_tally["failed"] or bad_quotes) else "PASS"),
              f"pre-witness: {len(claims)} auditor rows, {n_p} evidence pointer(s) or candidate quote(s): {pre_tally['verified']} hold in the folder, {pre_tally['untestable']} not testable from it, {pre_tally['failed']} do not hold; no verdicts to test yet"
              + (f"; {len(published_misses)} quote(s) missing from a copy published in this snapshot (a published copy must carry every quote taken from it)" if published_misses else ""),
              published_misses + (bad_quotes if len(bad_quotes) <= 10 else bad_quotes[:10] + [f"... and {len(bad_quotes) - 10} more quotes not found"]))
    else:
      R.add("K5", "FAIL" if (k5_fail or published_misses) else ("WARN" if (k5_warn or bad_quotes or (page_only and pages_prove)) else "PASS"),
          f"{n_e} EVIDENCED rows: {n_e - len(k5_fail) - len(k5_warn)} with a verified proof, {len(k5_warn)} untestable without copies, {len(k5_fail)} with none"
          + (f"; {len(published_misses)} quote(s) missing from a copy published in this snapshot (a published copy must carry every quote taken from it)" if published_misses else "")
          + ((f"; {len(page_only)} rows verified only by quotes from the publisher's own pages (their other proofs, if any, are untestable offline; the grader judged the surface itself the artefact): " + ", ".join(page_only[:12]) + ("…" if len(page_only) > 12 else "")) if page_only and pages_prove else
             (f"; {len(page_only)} page-internal or arithmetic rows rest on the page itself" if page_only else ""))
          + (f"; {len(set(existence))} rows hold on a file's presence (a quote-less proof: the copy is the artefact)" if existence else "")
          + (f"; {len(bad_quotes)} individual quote(s) not found in their source (the row still holds on another proof)" if bad_quotes else ""),
          k5_fail + published_misses + (k5_warn if len(k5_warn) <= 10 else [f"{len(k5_warn)} rows untestable without copies (pass --copies or --fetch)"])
          + (bad_quotes if len(bad_quotes) <= 10 else bad_quotes[:10] + [f"... and {len(bad_quotes) - 10} more quotes not found"]))
    n_c = sum(1 for c in claims if c.get("verdict") == "CONTRADICTED")
    if pre:
        if is_doc:
            # 0.9 document (SPEC 17): there is no verdict, but the auditor CLAIMED some: each claimed CONTRADICTED row needs a named counter that holds
            c_ok, c_warn, c_fail = 0, [], []
            n_cc = 0
            for c in claims:
                cl_ = c.get("claimed")
                if not (isinstance(cl_, dict) and cl_.get("verdict") == "CONTRADICTED"):
                    continue
                n_cc += 1
                side_ = c.get("counter") or []
                named_ = [i for i in ((cl_.get("on") or {}).get("counter") or []) if isinstance(i, int) and not isinstance(i, bool) and 0 <= i < len(side_) and isinstance(side_[i], dict)]
                st_ = [doc_hold(side_[i])[0] for i in named_]
                if "holds" in st_:
                    c_ok += 1
                elif "untestable" in st_:
                    c_warn.append(f"{c['id']}: no named counter checkable from the folder (copy not at hand)")
                else:
                    c_fail.append(f"{c['id']}: no named counter holds")
            R.add("K6", "FAIL" if c_fail else ("WARN" if c_warn else "PASS"),
                  f"document: {n_cc} claimed CONTRADICTED row(s): {c_ok} with a counter that holds, {len(c_warn)} not testable here, {len(c_fail)} with none", c_fail + c_warn)
        else:
            R.add("K6", "PASS", "pre-witness: no verdicts yet, no counter quote to test")
        R.add("K7", "PASS", "pre-witness: no verdicts yet, nothing to contradict")
    else:
        R.add("K6", "FAIL" if k6_fail else ("WARN" if k6_warn else "PASS"), f"{n_c} CONTRADICTED rows: {n_c - len(k6_fail) - len(k6_warn)} with a verified counter quote", k6_fail + k6_warn)
        R.add("K7", "FAIL" if k7_fail else "PASS", "no NO EVIDENCE PUBLISHED, ON REQUEST or WITHDRAWN row carries a verified source proof" if not k7_fail else f"{len(k7_fail)} rows", k7_fail)

    # K8 counts and score, recomputed by evidence-score/1
    if pre:
        # pre-witness: no score yet (it comes with the primary witness); counts.claims and counts.checkable are recomputed from
        # the auditor's rows the way evidence-score/1 counts them (checkable true or absent, kind not promise)
        n_chk = sum(1 for c in claims if c.get("checkable", True) and c.get("kind") != "promise")
        s = {"author_read": 0}
        bad = []
        for k, v_ in (("claims", len(claims)), ("checkable", n_chk)):
            if M["counts"].get(k) != v_:
                bad.append(f"counts.{k}: manifest {M['counts'].get(k)} vs {v_} from audit.jsonl")
        if is_doc:
            # 0.9 document: no primary and no score by design (SPEC 17); the auditor's own score is recomputed by K12
            R.add("K8", "FAIL" if bad else "PASS", f"document: {len(claims)} claims, {n_chk} checkable" + (" (counts agree)" if not bad else "; manifest differs") + "; no top-level score by design: the auditor's score is K12's", bad)
        else:
            R.add("K8", "FAIL" if bad else "WARN", f"pre-witness: {len(claims)} claims, {n_chk} checkable" + (" (counts agree)" if not bad else "; manifest differs") + "; no score yet: it comes with the primary witness", bad)
    else:
        s = evidence_score(claims)
        bad = []
        for k in ("claims", "checkable", "evidenced", "on_request", "no_evidence", "contradicted", "contradicted_high", "withdrawn", "author_read"):
            if M["counts"].get(k) != s.get(k):
                bad.append(f"counts.{k}: manifest {M['counts'].get(k)} vs {s.get(k)}")
        for k in ("coverage_pct", "contradiction_pct", "band"):
            if M["score"].get(k) != s.get(k):
                bad.append(f"score.{k}: manifest {M['score'].get(k)} vs {s.get(k)}")
        if M["score"].get("formula") != "evidence-score/1":
            bad.append(f"score.formula {M['score'].get('formula')!r}: this checker knows evidence-score/1")
        R.add("K8", "FAIL" if bad else "PASS", f"{s['evidenced']} evidenced, {s['on_request']} on request, {s['no_evidence']} no evidence, {s['contradicted']} contradicted ({s['contradicted_high']} high) of {s['checkable']} checkable: {s['coverage_pct']}% backed, {s['contradiction_pct']}% contradicted, band {s['band']} (recomputed)" + ("" if not bad else "; manifest differs"), bad)

    # K9 secrets
    bad = []
    for p in sorted(snap.rglob("*")):
        if p.is_file() and p.suffix in (".json", ".jsonl", ".txt", ".md"):
            raw = p.read_text(encoding="utf-8", errors="replace")
            for pat in SECRET_PATTERNS:
                if pat.search(raw):
                    bad.append(f"{p.relative_to(snap)}: matches {pat.pattern[:30]}")
                    break
    R.add("K9", "FAIL" if bad else "PASS", "no credential-shaped strings" if not bad else f"{len(bad)} files match", bad)

    # provenance summary
    none_copy = [s_["n"] for s_ in M["sources"] if s_.get("copy") == "none"]
    hash_only = [s_["n"] for s_ in M["sources"] if s_.get("copy") == "hash-only"]
    notes = []
    if s["author_read"]:
        notes.append(f"{s['author_read']} row(s) carry the author's reading, not a grader's verdict (graded_by author)")
    gates = g.get("gates", []) or []
    for gate in gates:
        if str(gate.get("first_gate", "")).lower().startswith("fail") or gate.get("holdout_amended"):
            notes.append(f"gate {gate.get('run')}: first gate {gate.get('first_gate')}; re-graded {gate.get('regraded_ids') or 'none'}; holdout amended: {gate.get('holdout_amended', False)}")
    R.add("K2b", "WARN" if (none_copy or notes or (hash_only and not copies and not fetch)) else "PASS",
          f"{len(M['sources'])} sources: {sum(1 for s_ in M['sources'] if s_.get('copy') == 'text')} with a text copy, {len(hash_only)} hash-only, {len(none_copy)} none"
          + ("; pass --copies or --fetch to test quotes from hash-only sources" if hash_only and not copies and not fetch else ""), notes)

    # 0.4: the auditor's part, the witness files, the merge, signatures, anchors, session records (SPEC.md 3a, 4a, 4b, K11 to K15)
    is_04 = M.get("format") == "claims-snapshot/0.4" or (snap / "audit.jsonl").exists()
    if is_04:
        bad, witnesses, w_rows_by_name, primary = [], g.get("witnesses") or [], {}, None
        k11_warn = []  # test-run (SPEC 13): a re-run result the folder does not hold
        fmt06 = fmt_at_least(M, "0.6")  # 0.7: "0.6 or later" (was: exactly 0.6), read at K1 kind, K12 undecided and K13 file name
        w_hdr, w_kind, w_kind_file, w_und = {}, {}, {}, {}  # 0.6: header, effective kind, kind by file, UNDECIDED count, per witness
        kind_bad = []   # a `kind` outside human | agent | model, said on K1 (FAIL in 0.6, WARN before)
        doc_hdr_bad = []  # 0.9 document (SPEC 17): the witness header's shape (kind script, method quote-check), said on K1
        kinds_ok = (WITNESS_KINDS | {"script"}) if is_doc else WITNESS_KINDS
        try:
            sigs_pre = json.loads((snap / "signatures.json").read_text(encoding="utf-8")) if (snap / "signatures.json").exists() else []
        except Exception:
            sigs_pre = []
        if not isinstance(sigs_pre, list):
            sigs_pre = []
        audit_p = snap / "audit.jsonl"
        if not audit_p.exists():
            bad.append("audit.jsonl missing")
            audit, audit_h, audit_ids = [], None, set()
        else:
            audit = load_jsonl(audit_p)
            audit_h = sha256(audit_p)
            a_ids = [a.get("id") for a in audit]
            audit_ids = set(a_ids)
            if len(audit_ids) != len(a_ids):
                bad.append("audit.jsonl: duplicate ids")
            for a in audit:
                found = [k for k in DECISION_KEYS if k in a]
                if found:
                    bad.append(f"audit.jsonl {a.get('id')}: carries decision field(s) {', '.join(found)}")
            if profile == "test-run":
                # 0.5, test-run (SPEC 13): exactly three claims, C-003 names the commit
                want_ = [("C-001", "process"), ("C-002", "figure"), ("C-003", "other")]
                got_ = [(a.get("id"), a.get("kind")) for a in audit]
                if got_ != want_:
                    bad.append(f"audit.jsonl: test-run needs exactly {want_}, found {got_}")
                commit_ = ((M.get("subject") or {}).get("system_under_test") or {}).get("commit")
                c3 = next((a for a in audit if a.get("id") == "C-003"), None)
                if c3 is not None:
                    if not isinstance(commit_, str) or len(commit_) < 7:
                        bad.append(f"C-003: subject.system_under_test.commit {commit_!r} is shorter than 7 characters")
                    elif commit_[:7].lower() not in str(c3.get("text", "")).lower():
                        bad.append(f"C-003: text does not name the commit of the system under test (a prefix of {commit_[:12]}, 7 characters or more)")
            if profile == DECISION_PROFILE and fmt_at_least(M, "0.8"):
                # 0.8, decision (SPEC 16): exactly three claims with those kinds; C-003 names the rule set as <id>@<version>; an override's
                # C-003 holds a letter beyond that string; with a ledger C-002's evidence names the ledger event (artefact name and sha256)
                want_ = [("C-001", "process"), ("C-002", "figure"), ("C-003", "other")]
                got_ = [(a.get("id"), a.get("kind")) for a in audit]
                if got_ != want_:
                    bad.append(f"audit.jsonl: decision needs exactly {want_}, found {got_}")
                sub_ = M.get("subject") if isinstance(M.get("subject"), dict) else {}
                rs_ = (sub_.get("basis") or {}).get("ruleset") or {}
                tag_ = f"{rs_.get('id')}@{rs_.get('version')}"
                c3 = next((a for a in audit if a.get("id") == "C-003"), None)
                if c3 is not None:
                    t3_ = str(c3.get("text", ""))
                    if tag_ not in t3_:
                        bad.append(f"C-003: text does not contain the rule set as {tag_!r} (basis.ruleset.id@basis.ruleset.version)")
                    elif (sub_.get("decision") or {}).get("override") is True and not any(ch_.isalpha() for ch_ in t3_.replace(tag_, "")):
                        bad.append(f"C-003: an override (subject.decision.override true) needs the decider's reason in words beyond {tag_!r}: the text holds no letter once the rule set is removed")
                ev_ = (sub_.get("ledger") or {}).get("event") if isinstance(sub_.get("ledger"), dict) else None
                c2 = next((a for a in audit if a.get("id") == "C-002"), None)
                if isinstance(ev_, dict) and c2 is not None:
                    names_ = [p_ for p_ in (c2.get("evidence") if isinstance(c2.get("evidence"), list) else []) if isinstance(p_, dict)
                              and p_.get("artefact") == ev_.get("artefact") and p_.get("sha256") == ev_.get("sha256")]
                    if not names_:
                        bad.append(f"C-002: the evidence does not name the decision event (subject.ledger.event {ev_.get('artefact')!r} sha256 {str(ev_.get('sha256'))[:12]}...): with a ledger C-002 rests on that event")
                # 0.8 amendment (the format's owner, 16 Nov 2026, at the gate of Indie #83): C-001 names the item and the judgement; without a
                # ledger C-002 names the judgement; C-003 names the decision event when there is a ledger (the reason is recorded in it), else
                # the judgement. "Names" = an artefact pointer with that artefact name AND that sha256.
                def names_ptr(row_, ptr_):
                    return isinstance(ptr_, dict) and any(isinstance(p_, dict) and p_.get("artefact") == ptr_.get("artefact") and p_.get("sha256") == ptr_.get("sha256")
                                                          for p_ in (row_.get("evidence") if isinstance(row_.get("evidence"), list) else []))
                on_ = (sub_.get("basis") or {}).get("on")
                it_ = sub_.get("item") if isinstance(sub_.get("item"), dict) else {}
                c1 = next((a for a in audit if a.get("id") == "C-001"), None)
                if c1 is not None:
                    if not any(isinstance(p_, dict) and p_.get("sha256") == it_.get("sha256") for p_ in (c1.get("evidence") if isinstance(c1.get("evidence"), list) else [])):
                        bad.append(f"C-001: the evidence does not name the item (subject.item.sha256 {str(it_.get('sha256'))[:12]}...)")
                    if not names_ptr(c1, on_):
                        bad.append("C-001: the evidence does not name the judgement (subject.basis.on)")
                if c2 is not None and not isinstance(ev_, dict) and not names_ptr(c2, on_):
                    bad.append("C-002: the evidence does not name the judgement (subject.basis.on): without a ledger C-002 rests on it")
                if c3 is not None:
                    if isinstance(ev_, dict) and not names_ptr(c3, ev_):
                        bad.append(f"C-003: the evidence does not name the decision event (subject.ledger.event {ev_.get('artefact')!r}): with a ledger the reason is recorded in that event")
                    elif not isinstance(ev_, dict) and not names_ptr(c3, on_):
                        bad.append("C-003: the evidence does not name the judgement (subject.basis.on): without a ledger C-003 rests on it")
            if is_doc:
                d_bad_, d_warn_ = document_audit_faults(audit, M)
                bad.extend(d_bad_)
                k11_warn.extend(d_warn_)
            au = g.get("auditor") or {}
            if au.get("file", "audit.jsonl") != "audit.jsonl" or (au.get("sha256") and au["sha256"] != audit_h):
                bad.append(f"grading.auditor: file {au.get('file')!r} / sha256 {str(au.get('sha256'))[:12]}… does not match audit.jsonl {audit_h[:12]}…")
            if not au.get("name"):
                bad.append("grading.auditor.name missing")
        if not pre:  # pre-witness (0.6, SPEC 14): no witness yet, or witnesses with none primary; K1 refused a primary mark
            if not witnesses:
                bad.append("grading.witnesses: none listed")
            if sum(1 for w in witnesses if w.get("primary")) != 1:
                bad.append(f"grading.witnesses: {sum(1 for w in witnesses if w.get('primary'))} marked primary, need exactly 1")
        by_audit_id = {a.get("id"): a for a in audit}
        for w in witnesses:
            name, wf = w.get("name"), w.get("file")
            wp = snap / (wf or "")
            if not wf or not wf.startswith("witness/") or not wp.exists():
                bad.append(f"witness {name!r}: file {wf!r} missing")
                continue
            if w.get("sha256") != sha256(wp):
                bad.append(f"witness {name!r}: {wf} sha256 {sha256(wp)[:12]}… differs from manifest {str(w.get('sha256'))[:12]}…")
            try:
                header, rows = load_witness(wp)
            except (ValueError, UnicodeDecodeError) as e:
                # 0.5: a witness file that is not JSON lines fails here, by name, instead of stopping the checker
                bad.append(f"witness {name!r}: {wf} unreadable: {e}")
                continue
            if header is None:
                bad.append(f"witness {name!r}: {wf} has no header line")
                continue
            over = header.get("over") or {}
            if header.get("witness") != name:
                bad.append(f"witness {name!r}: header names {header.get('witness')!r}")
            if over.get("file") != "audit.jsonl" or over.get("sha256") != audit_h:
                bad.append(f"witness {name!r}: header is over {over.get('file')!r} sha256 {str(over.get('sha256'))[:12]}…, audit.jsonl is {str(audit_h)[:12]}…")
            ek = "human"
            for src_, kv in (("header", header.get("kind")), ("manifest entry", w.get("kind"))):
                if kv is None:
                    continue
                if isinstance(kv, str) and kv in kinds_ok:
                    if src_ == "header" or "kind" not in header:
                        ek = kv
                else:
                    kind_bad.append(f"witness {name!r}: {src_} kind {kv!r} is not human, agent or model" + (" or script" if is_doc else ""))
            if is_doc:
                m_ = header.get("method")
                if ek == "script":
                    s_ = header.get("script", KeyError)
                    if not isinstance(s_, dict):
                        doc_hdr_bad.append(f"witness {name!r}: kind script needs a `script` object {{name, sha256, commit}}")
                    else:
                        if not (isinstance(s_.get("name"), str) and s_["name"].strip()):
                            doc_hdr_bad.append(f"witness {name!r}: script.name must be a non-empty string")
                        if not (isinstance(s_.get("sha256"), str) and HEX64.match(s_["sha256"])):
                            doc_hdr_bad.append(f"witness {name!r}: script.sha256 is not 64 lower-case hex")
                        if "commit" not in s_:
                            doc_hdr_bad.append(f"witness {name!r}: script.commit is missing (hex or null)")
                        elif s_["commit"] is not None and not (isinstance(s_["commit"], str) and HEX_ANY.match(s_["commit"])):
                            doc_hdr_bad.append(f"witness {name!r}: script.commit {str(s_['commit'])[:20]!r} is not hex or null")
                    if header.get("model") is not None:
                        doc_hdr_bad.append(f"witness {name!r}: model must be absent or null on a script witness (a script has no model id)")
                    if m_ != "quote-check":
                        doc_hdr_bad.append(f"witness {name!r}: kind script runs the method 'quote-check' only (this one says {m_!r})")
                else:
                    if "script" in header:
                        doc_hdr_bad.append(f"witness {name!r}: script is set on a {ek} witness: only kind script carries it")
                    if m_ == "quote-check":
                        doc_hdr_bad.append(f"witness {name!r}: the method 'quote-check' is for kind script only (this one is {ek!r})")
            # the carried cut (13 Nov 2026, NEXT-REVISION 25a): a model witness header's `carried` {path: sha256} names what the models were
            # shown; every path must be a page, source or session record the manifest lists, with the manifest's hash (a witness that read other
            # bytes than the record holds is broken, by name). A bound path prints no line, so a published folder's output does not change.
            # `manifest_sha256` is the hash of the manifest the SERVICE was given, shape-checked only: insertion changed the folder's since.
            if "carried" in header:
                carried_ = header["carried"]
                if not isinstance(carried_, dict):
                    bad.append(f"witness {name!r}: header carried is not an object of path to sha256")
                else:
                    inv_ = carried_inventory(M)
                    for cpath_ in sorted(carried_):
                        ch_ = carried_[cpath_]
                        if cpath_ not in inv_:
                            bad.append(f"witness {name!r}: carried {cpath_!r} is not a page, source or session record the manifest lists")
                        elif not (isinstance(ch_, str) and HEX64.match(ch_)):
                            bad.append(f"witness {name!r}: carried {cpath_!r}: sha256 {ch_!r} is not 64 hex characters")
                        elif ch_ != inv_[cpath_]:
                            bad.append(f"witness {name!r}: carried {cpath_!r} sha256 {ch_[:12]}… differs from the manifest's {inv_[cpath_][:12]}…: the witness read other bytes than the record holds")
            elif ek == "model" and (profile in EVIDENCE_PROFILES or any(isinstance(a_.get("evidence"), list) for a_ in audit)):
                # evidence-shaped auditor part (SPEC 12 and 13): the decisive input is the carried files, so a model witness must say what it read
                k11_warn.append(f"witness {name!r}: a model witness over an evidence-shaped auditor part records no `carried`: what the models read is not on record (0.1.6 of the witness service writes it)")
            # the bound cut (13 Nov 2026, the seventh re-gate's U1): `carried` binds bytes, not which source entry a pointer resolved through, so
            # the header's `bound` {section: sha256} names the five bound manifest sections with the sha256 of each in canonical JSON; K11
            # recomputes them from THIS record's manifest (bound_sections) and fails a mismatch by name. A matching section prints no line.
            if "bound" in header:
                bound_ = header["bound"]
                if not isinstance(bound_, dict):
                    bad.append(f"witness {name!r}: header bound is not an object of section to sha256")
                else:
                    if set(bound_) != set(BOUND_SECTIONS):
                        bad.append(f"witness {name!r}: header bound names {sorted(bound_)!r}, not the five bound sections {list(BOUND_SECTIONS)!r}")
                    want_ = bound_sections(M)
                    for sec_ in BOUND_SECTIONS:
                        if sec_ not in bound_:
                            continue
                        bv_ = bound_[sec_]
                        if not (isinstance(bv_, str) and HEX64.match(bv_)):
                            bad.append(f"witness {name!r}: bound {sec_!r}: sha256 {bv_!r} is not 64 hex characters")
                        elif bv_ != want_[sec_]:
                            bad.append(f"witness {name!r}: bound {sec_!r} sha256 {bv_[:12]}… differs from this record's {want_[sec_][:12]}…: the witness read a manifest whose {sec_} is not this record's")
            elif "carried" in header and ek == "model" and (profile in EVIDENCE_PROFILES or any(isinstance(a_.get("evidence"), list) for a_ in audit)):
                # 30(a) (the one-auditor cut, 13 Nov 2026): since 0.1.10 every witness header and service.json carry `service_version`, and
                # 0.1.8 and later always write `bound`, so a header that names such a version and has no `bound` was not written by that
                # service: FAIL. The version is the header's `service_version`, else the manifest witness entry's, else service.json's when
                # the manifest's `files` lists it (the first string found wins); `^(\d+)\.(\d+)\.(\d+)` at its start, anything after
                # (`-dev` included) ignored. No version anywhere: the WARN alone (the 0.1.6 and 0.1.7 example folders keep their line);
                # a string that is not a version: a WARN beside the existing one.
                # V1 (the twelfth cut, 13 Nov 2026, NEXT-REVISION 33; the eleventh re-gate's O14): every record is read, not the first string
                # found. A header saying 0.1.7-dev beside a service.json saying 0.1.10-dev got the WARN alone; the promise was "any recorded
                # version of 0.1.8 or later FAILs". The first such version in record order is the one named; every string that is not a
                # version WARNs, FAIL or not.
                recs_ = [v_ for v_ in (header.get("service_version"), w.get("service_version"), service_json_version(snap, M)) if isinstance(v_, str)]
                parsed_ = [(v_, re.match(r"(\d+)\.(\d+)\.(\d+)", v_)) for v_ in recs_]
                sv_ = next((v_ for v_, m_ in parsed_ if m_ is not None and tuple(int(x_) for x_ in m_.groups()) >= (0, 1, 8)), None)
                for v_, m_ in parsed_:
                    if m_ is None:
                        k11_warn.append(f"witness {name!r}: service_version '{v_}' is not a version (major.minor.patch)")
                if sv_ is not None:
                    bad.append(f"witness {name!r}: a model witness of service version {sv_} records `carried` but no `bound`: 0.1.8 and later of the witness service write it; this header was not written by that service")
                else:
                    k11_warn.append(f"witness {name!r}: a model witness records `carried` but no `bound`: which manifest its pointers resolved through is not on record (0.1.8 of the witness service writes it)")
            if "manifest_sha256" in header and not (isinstance(header["manifest_sha256"], str) and HEX64.match(header["manifest_sha256"])):
                bad.append(f"witness {name!r}: header manifest_sha256 {header['manifest_sha256']!r} is not 64 hex characters")
            w_hdr[name], w_kind[name], w_kind_file[wf] = header, ek, ek
            if header.get("method") == "classify" and ek != "model":
                bad.append(f"witness {name!r}: method 'classify' is for a witness of kind 'model' only (this one is {ek!r})")
            if profile == DECISION_PROFILE and fmt_at_least(M, "0.8"):
                # 0.8, decision (SPEC 16): `read` or `classify`, and anything else fails; there is no `re-run` (a decision is not run again)
                if header.get("method") not in ("read", "classify"):
                    bad.append(f"witness {name!r}: method {header.get('method')!r} must be 'read' or 'classify' (a decision has no re-run: a second run is a new decision with its own record)")
            if profile == "test-run":
                if header.get("method") not in ("read", "re-run", "classify"):
                    bad.append(f"witness {name!r}: method {header.get('method')!r} must be 'read', 're-run' or 'classify'")
                elif header.get("method") == "re-run":
                    rr = header.get("rerun_result")
                    if not (isinstance(rr, dict) and isinstance(rr.get("artefact"), str) and rr["artefact"].strip()
                            and isinstance(rr.get("sha256"), str) and HEX64.match(rr["sha256"])):
                        bad.append(f"witness {name!r}: a re-run header needs rerun_result with an artefact name and a 64-hex sha256")
                    elif not any(s_.get("sha256") == rr["sha256"] for s_ in M["sources"]):
                        # trilix, adoption of section 13 (WI): a re-run result no source holds is a comparison nobody can check
                        k11_warn.append(f"witness {name!r}: rerun_result {rr['artefact']!r} sha256 {rr['sha256'][:12]}... is held by no source in this folder: the re-run's comparison cannot be checked here")
            w_rows_by_name[name] = rows
            if w.get("primary"):
                primary = (name, rows)
            seen, decided, und_ids = set(), set(), []
            for r in rows:
                rid, v = r.get("id"), r.get("verdict")
                if rid in seen:
                    bad.append(f"witness {name!r} {rid}: decided twice")
                seen.add(rid)
                if v not in WITNESS_VERDICTS:
                    bad.append(f"witness {name!r} {rid}: verdict {v!r}")
                    continue
                if is_doc and "live" in r and not isinstance(r["live"], dict):
                    bad.append(f"witness {name!r} {rid}: live is not an object (what the script saw at the source live)")
                if is_doc and v in ("EVIDENCE AVAILABLE ON REQUEST", "WITHDRAWN"):
                    bad.append(f"witness {name!r} {rid}: verdict {v!r} is not a document-profile verdict (the three verdicts and UNDECIDED)")
                    continue
                if v == "MISSING CLAIM" and profile == "agent-work":
                    # 0.5: the agent's reply is not in the folder (the kit keeps the block), so a claim the block left
                    # out cannot be found on a page: it needs its text and the witness's note saying where it was made
                    if not (r.get("text") or "").strip() or not (r.get("note") or "").strip():
                        bad.append(f"witness {name!r} {rid}: MISSING CLAIM needs the claim's text and a note saying where the agent made it")
                    if rid in audit_ids:
                        bad.append(f"witness {name!r} {rid}: MISSING CLAIM with an id the auditor listed")
                    continue
                if v == "MISSING CLAIM":
                    frags = [N(f) for f in (r.get("text") or "").split("[...]") if N(f)]
                    if not frags or not all(f in pages_norm for f in frags):
                        bad.append(f"witness {name!r} {rid}: MISSING CLAIM text not on the page")
                    if not r.get("location"):
                        bad.append(f"witness {name!r} {rid}: MISSING CLAIM without a location")
                    if rid in audit_ids:
                        bad.append(f"witness {name!r} {rid}: MISSING CLAIM with an id the auditor listed")
                    continue
                if rid not in audit_ids:
                    bad.append(f"witness {name!r} {rid}: not in audit.jsonl")
                    continue
                if v == "UNDECIDED":
                    # 0.6: a witness's "do not know": counted, never merged, never a primary's; it must say why
                    und_ids.append(rid)
                    if not (isinstance(r.get("note"), str) and r["note"].strip()):
                        bad.append(f"witness {name!r} {rid}: UNDECIDED without a note saying why")
                    continue
                decided.add(rid)
                a = by_audit_id[rid]
                on = r.get("on") or {}
                # An auditor row with one `evidence` list and no proofs/counter (the OneDroid Indie shape, SPEC 4b and 12):
                # both on.proofs and on.counter index that list; CONTRADICTED names the opposite-showing pointer in on.counter.
                n_proofs, n_counter = len(a.get("proofs") or []), len(a.get("counter") or [])
                if isinstance(a.get("evidence"), list) and not a.get("proofs") and not a.get("counter"):
                    n_proofs = n_counter = len(a["evidence"])
                for kind_, n_have in (("proofs", n_proofs), ("counter", n_counter)):
                    for i in on.get(kind_, []) or []:
                        if not isinstance(i, int) or i < 0 or i >= n_have:
                            bad.append(f"witness {name!r} {rid}: on.{kind_} index {i!r} outside the auditor's {n_have} candidate(s)")
                if v == "EVIDENCED" and not on.get("proofs"):
                    bad.append(f"witness {name!r} {rid}: EVIDENCED names no proof candidate")
                if is_doc and v == "EVIDENCED":
                    props_ = a.get("proofs") or []
                    if not any(isinstance(i, int) and not isinstance(i, bool) and 0 <= i < len(props_) and isinstance(props_[i], dict) and props_[i].get("kind") == "artefact"
                               for i in (on.get("proofs") or [])):
                        bad.append(f"witness {name!r} {rid}: EVIDENCED names no artefact proof (document profile: a restatement does not evidence a claim)")
                if v == "CONTRADICTED" and not on.get("counter"):
                    bad.append(f"witness {name!r} {rid}: CONTRADICTED names no counter candidate")
                if v == "CONTRADICTED" and r.get("confidence") not in ("high", "low"):
                    bad.append(f"witness {name!r} {rid}: CONTRADICTED without confidence")
                # the bound cut (13 Nov 2026, the seventh re-gate's U1): a decision rests on a carried file. For a witness with `carried`, a
                # file pointer the decision names resolves by `path` through THIS manifest's sources (as test_pointer does); a source whose
                # `file` the witness did not carry is a file the models never read under that name. Other pointer shapes, a hash-only source
                # and an unresolved path: nothing (K11's other rules and the service's own UNDECIDED-by-rule cover them).
                if isinstance(header.get("carried"), dict) and v in ("EVIDENCED", "CONTRADICTED") and isinstance(a.get("evidence"), list):
                    for i in on.get("proofs" if v == "EVIDENCED" else "counter", []) or []:
                        if not (isinstance(i, int) and 0 <= i < len(a["evidence"])):
                            continue
                        p_ = a["evidence"][i]
                        if not (isinstance(p_, dict) and "file" in p_ and "line" in p_):
                            continue
                        src_ = by_path.get(p_["file"])
                        if src_ and src_.get("file") and src_["file"] not in header["carried"]:
                            bad.append(f"witness {name!r} {rid}: decided {v} on pointer [{i}] file {p_['file']!r}, which this record holds at {src_['file']!r}, a file the witness did not carry")
                if r.get("graded_by", "grader") not in GRADED_BY:
                    bad.append(f"witness {name!r} {rid}: graded_by {r.get('graded_by')!r}")
                if not r.get("graded_at"):
                    bad.append(f"witness {name!r} {rid}: no graded_at")
            w_und[name] = len(und_ids)
            if w.get("primary") and und_ids:
                bad.append(f"primary witness {name!r} has {len(und_ids)} UNDECIDED row(s): a primary leaves nothing undecided: " + ", ".join(sorted(und_ids)[:8]) + ("…" if len(und_ids) > 8 else ""))
            if w.get("primary") and audit_ids - decided - set(und_ids):
                und = sorted(audit_ids - decided - set(und_ids))
                bad.append(f"primary witness {name!r} left {len(und)} claim(s) undecided: " + ", ".join(und[:8]) + ("…" if len(und) > 8 else ""))
            if w.get("primary") and ek == "model":
                # 0.6: a model may be primary only when a named principal signed the manifest saying so
                pnb = g.get("primary_named_by")
                if not (isinstance(pnb, str) and pnb.strip()):
                    bad.append(f"primary witness {name!r} is of kind model: grading.primary_named_by must name the principal who chose it")
                elif not any(isinstance(e_, dict) and e_.get("role") == "manifest" and (e_.get("signer") or {}).get("name") == pnb for e_ in sigs_pre):
                    bad.append(f"primary witness {name!r} is of kind model: no manifest signature by primary_named_by {pnb!r} in signatures.json")
        R.add("K11", "FAIL" if bad else ("WARN" if k11_warn else "PASS"), f"audit.jsonl {len(audit)} rows without decisions; {len(witnesses)} witness file(s) over its hash, every decision on a listed claim and a candidate it names" + (f"; {len(k11_warn)} note(s)" if k11_warn else "") if not bad else f"{len(bad)} violation(s)", bad + k11_warn)
        if kind_bad:
            for i_, (k_, st_, m_, d_) in enumerate(R.rows):
                if k_ == "K1":
                    R.rows[i_] = (k_, "FAIL" if fmt06 else "WARN", m_ + "; witness kind: " + ", ".join(kind_bad), d_)
                    break
        if doc_hdr_bad:
            for i_, (k_, st_, m_, d_) in enumerate(R.rows):
                if k_ == "K1":
                    R.rows[i_] = (k_, "FAIL", m_ + "; witness header (document profile): " + ", ".join(doc_hdr_bad), d_)
                    break

        # K12 the merge and the per-witness scores
        bad, info, k12_warn = [], [], []
        if (primary or pre) and audit:
            if primary:
                merged = merge_rows(audit, primary[1], primary[0])
                published = load_jsonl(snap / "claims.jsonl")  # as published: K5 has set proofs[].verified on the rows in memory
                if merged != published:
                    diff = [m.get("id") for m, c in zip(merged, published) if m != c]
                    if len(merged) != len(published):
                        diff.append(f"{len(merged)} merged rows vs {len(published)} in claims.jsonl")
                    bad.append("claims.jsonl is not the merge of audit.jsonl and the primary witness: " + ", ".join(str(d) for d in diff[:10]) + ("…" if len(diff) > 10 else ""))
                p_verdicts = {r["id"]: r.get("verdict") for r in primary[1] if r.get("verdict") != "MISSING CLAIM"}
            else:
                # pre-witness (0.6, SPEC 14): no primary named yet, so no merge and no score; each listed witness is still recomputed
                if not is_doc:  # the document profile has no primary by design (SPEC 17): nothing to warn about
                    k12_warn.append(f"pre-witness: no primary witness named yet, so no claims.jsonl and no score; {len([w for w in witnesses if w.get('name') in w_rows_by_name])} witness file(s) recomputed below")
                p_verdicts = {}
            for w in witnesses:
                rows = w_rows_by_name.get(w.get("name"))
                if rows is None:
                    continue
                # 0.6: this witness's UNDECIDED rows are not checkable for this witness's score (its denominator only)
                sc = evidence_score([m_ for m_ in merge_rows(audit, rows, w.get("name")) if m_.get("verdict") != "UNDECIDED"])
                want = w.get("score") or {}
                for k in ("coverage_pct", "contradiction_pct", "band"):
                    if want.get(k) != sc.get(k):
                        bad.append(f"witness {w.get('name')!r} score.{k}: manifest {want.get(k)} vs {sc.get(k)} recomputed")
                n_missing = sum(1 for r in rows if r.get("verdict") == "MISSING CLAIM")
                if w.get("missing_claims", 0) != n_missing:
                    bad.append(f"witness {w.get('name')!r} missing_claims: manifest {w.get('missing_claims')} vs {n_missing} rows")
                n_und = sum(1 for r in rows if r.get("verdict") == "UNDECIDED")
                if "undecided" in w:
                    if w["undecided"] != n_und or isinstance(w["undecided"], bool):
                        bad.append(f"witness {w.get('name')!r} undecided: manifest {w.get('undecided')} vs {n_und} UNDECIDED rows")
                elif n_und:
                    (bad if fmt06 else k12_warn).append(f"witness {w.get('name')!r} has {n_und} UNDECIDED row(s) and its manifest entry has no `undecided` count")
                h_ = w_hdr.get(w.get("name"))
                if h_ is not None and "kind" in h_ and "kind" in w and h_["kind"] != w["kind"]:
                    bad.append(f"witness {w.get('name')!r} kind: manifest entry {w['kind']!r} vs header {h_['kind']!r}")
                if not w.get("primary"):
                    both = [r for r in rows if r.get("id") in p_verdicts and r.get("verdict") != "UNDECIDED"]  # the agreement counts the rows the witness decided
                    agree = sum(1 for r in both if r.get("verdict") == p_verdicts[r["id"]])
                    info.append(f"witness {w.get('name')!r}: {sc.get('coverage_pct')}% / {sc.get('contradiction_pct')}% band {sc.get('band')}, {n_missing} missing-claim row(s)" + ("" if pre else f"; agrees with the primary on {agree} of {len(both)} claims both decided"))
                else:
                    info.append(f"primary witness {w.get('name')!r}: {sc.get('coverage_pct')}% / {sc.get('contradiction_pct')}% band {sc.get('band')}, {n_missing} missing-claim row(s)")
            if is_doc:
                # 0.9 document (SPEC 17): the auditor's kind, model, score and counts, each witness's agreement with the auditor's claimed verdicts,
                # and every row of a quote-check witness recomputed from the folder's copies (the fold applies); no majority line
                au_ = g.get("auditor") if isinstance(g.get("auditor"), dict) else {}
                if au_.get("kind") != "model":
                    bad.append(f"grading.auditor.kind {au_.get('kind')!r} must be 'model' (the auditor of a document is a model)")
                if not (isinstance(au_.get("model"), str) and au_["model"].strip()):
                    bad.append("grading.auditor.model must name the model (the provider's id with its version)")
                cl_rows = [(a_, a_["claimed"]) for a_ in audit if bool(a_.get("checkable", True)) and a_.get("kind") != "promise"
                           and isinstance(a_.get("claimed"), dict) and a_["claimed"].get("verdict") in DOCUMENT_VERDICTS]
                asc = evidence_score([{"verdict": c_["verdict"], "confidence": c_.get("confidence"), "checkable": True, "kind": a_.get("kind")} for a_, c_ in cl_rows])
                ms_ = au_.get("score")
                if not isinstance(ms_, dict):
                    bad.append("grading.auditor.score is missing or not an object ({coverage_pct, contradiction_pct, band})")
                else:
                    for k_ in ("coverage_pct", "contradiction_pct", "band"):
                        if ms_.get(k_) != asc.get(k_):
                            bad.append(f"grading.auditor.score.{k_}: manifest {ms_.get(k_)} vs {asc.get(k_)} recomputed from the claimed verdicts")
                mc_ = au_.get("counts")
                if not isinstance(mc_, dict):
                    bad.append("grading.auditor.counts is missing or not an object ({evidenced, no_evidence, contradicted, contradicted_high})")
                else:
                    for k_ in ("evidenced", "no_evidence", "contradicted", "contradicted_high"):
                        if mc_.get(k_) != asc.get(k_, 0) or isinstance(mc_.get(k_), bool):
                            bad.append(f"grading.auditor.counts.{k_}: manifest {mc_.get(k_)} vs {asc.get(k_, 0)} recomputed from the claimed verdicts")
                cv_ = {a_.get("id"): c_["verdict"] for a_, c_ in cl_rows}
                by_claim_ = {a_.get("id"): (a_, c_) for a_, c_ in cl_rows}

                def ints_(x):
                    return sorted({i_ for i_ in x if isinstance(i_, int) and not isinstance(i_, bool) and i_ >= 0}) if isinstance(x, list) else []
                for w in witnesses:
                    name_, rows_ = w.get("name"), w_rows_by_name.get(w.get("name"))
                    if rows_ is None:
                        continue
                    dec_, seen_ = [], set()
                    for r_ in rows_:
                        if r_.get("id") in cv_ and r_.get("verdict") in DOCUMENT_VERDICTS and r_["id"] not in seen_:
                            seen_.add(r_["id"])
                            dec_.append(r_)
                    same_ = sum(1 for r_ in dec_ if r_["verdict"] == cv_[r_["id"]])
                    want_ag = {"with": "auditor", "decided": len(dec_), "same": same_,
                               "pct": None if not dec_ else int(round(fractions.Fraction(100 * same_, len(dec_))))}
                    ag_ = w.get("agreement")
                    if not isinstance(ag_, dict):
                        bad.append(f"witness {name_!r} has no agreement object ({{with, decided, same, pct}})")
                    else:
                        for k_ in ("with", "decided", "same", "pct"):
                            if ag_.get(k_) != want_ag[k_] or isinstance(ag_.get(k_), bool):
                                bad.append(f"witness {name_!r} agreement.{k_}: manifest {ag_.get(k_)!r} vs {want_ag[k_]!r} recomputed from the claimed verdicts")
                    info.append(f"witness {name_!r} agrees with the auditor's claimed verdict on {same_} of {len(dec_)} checkable claims it decided")
                    for r_ in dec_:
                        if r_["verdict"] != cv_[r_["id"]]:
                            info.append(f"{r_['id']}: witness {name_!r} says {r_['verdict']}, the auditor claimed {cv_[r_['id']]}")
                    if (w_hdr.get(name_) or {}).get("method") != "quote-check":
                        continue
                    for r_ in rows_:
                        rid_, rv_ = r_.get("id"), r_.get("verdict")
                        if rid_ not in by_claim_ or rv_ == "MISSING CLAIM":
                            continue
                        a_, c_ = by_claim_[rid_]
                        v_ = c_["verdict"]
                        on_c = c_.get("on") if isinstance(c_.get("on"), dict) else {}
                        r_on = r_.get("on") if isinstance(r_.get("on"), dict) else {}
                        rp_, rc_ = ints_(r_on.get("proofs")), ints_(r_on.get("counter"))
                        shown_ = f"the row says {rv_} on proofs {rp_} counter {rc_}" + (f" with confidence {r_.get('confidence')}" if rv_ == "CONTRADICTED" else "")
                        if v_ == "NO EVIDENCE PUBLISHED":
                            if rv_ != "NO EVIDENCE PUBLISHED" or rp_ or rc_:
                                bad.append(f"witness {name_!r} {rid_}: quote-check recomputes NO EVIDENCE PUBLISHED with an empty on, {shown_}")
                            continue
                        key_ = "proofs" if v_ == "EVIDENCED" else "counter"
                        side_ = a_.get(key_) or []
                        named_ = [i_ for i_ in ints_(on_c.get(key_)) if i_ < len(side_) and isinstance(side_[i_], dict) and (v_ == "CONTRADICTED" or side_[i_].get("kind") == "artefact")]
                        st_ = {i_: doc_hold(side_[i_])[0] for i_ in named_}
                        held_ = [i_ for i_ in named_ if st_[i_] == "holds"]
                        unt_ = [i_ for i_ in named_ if st_[i_] == "untestable"]
                        r_key, r_other = (rp_, rc_) if key_ == "proofs" else (rc_, rp_)
                        conf_ok = v_ == "EVIDENCED" or r_.get("confidence") == c_.get("confidence")
                        if held_:
                            exact_ = rv_ == v_ and r_key == held_ and not r_other and conf_ok
                            loose_ = rv_ == v_ and set(held_) <= set(r_key) <= set(held_) | set(unt_) and not r_other and conf_ok
                            if exact_:
                                pass
                            elif unt_ and loose_:
                                k12_warn.append(f"witness {name_!r} {rid_}: quote-check cannot be recomputed in full here: candidate(s) {unt_} have no copy at hand (pass --copies); {shown_}")
                            else:
                                bad.append(f"witness {name_!r} {rid_}: quote-check recomputes {v_} on {key_} {held_}" + (f" with confidence {c_.get('confidence')}" if v_ == "CONTRADICTED" else "") + f", {shown_}")
                        elif unt_:
                            k12_warn.append(f"witness {name_!r} {rid_}: quote-check cannot be recomputed here: the named candidate(s) {unt_} have no copy at hand (pass --copies); {shown_}")
                        elif not (rv_ == "NO EVIDENCE PUBLISHED" and not rp_ and not rc_):
                            bad.append(f"witness {name_!r} {rid_}: quote-check recomputes NO EVIDENCE PUBLISHED (no named candidate holds), {shown_}")
            # 0.6: one line per claim on which witnesses of kind model split (UNDECIDED is a side); no majority rule, no verdict change
            model_ws = [w.get("name") for w in witnesses if w_kind.get(w.get("name")) == "model" and w.get("name") in w_rows_by_name]
            if len(model_ws) >= 2:
                for a_ in audit:
                    sides = []
                    for n_ in model_ws:
                        rv = next((r.get("verdict") for r in w_rows_by_name[n_] if r.get("id") == a_.get("id") and r.get("verdict") != "MISSING CLAIM"), None)
                        if rv is not None:
                            sides.append((n_, rv))
                    if len({v_ for _, v_ in sides}) > 1:
                        info.append(f"split on {a_.get('id')}: " + ", ".join(f"{n_} {v_}" for n_, v_ in sides))
        else:
            bad.append("no primary witness or no audit rows to merge")
        R.add("K12", "FAIL" if bad else ("WARN" if k12_warn else "PASS"), (("document: the auditor's score and counts, each witness's score and agreement, and every quote-check row recomputed" if is_doc else "pre-witness: no merge yet; per-witness scores and missing-claim counts recomputed" if pre else "claims.jsonl equals the merge; per-witness scores and missing-claim counts recomputed") if not bad else f"{len(bad)} difference(s)"), bad + k12_warn + info)

        # K13 signatures over the prescribed line, verified with ssh-keygen when it is on PATH
        parts = {"audit.jsonl": "auditor"} | {w.get("file"): "witness" for w in witnesses if w.get("file")} | {"manifest.json": "manifest"}  # manifest: 0.6, optional
        sig_p = snap / "signatures.json"
        allowed = snap / "allowed_signers"
        bad, warn, ok, covered, bind_ok = [], [], [], set(), []
        # A1 (the auditor-key cut, 13 Nov 2026, NEXT-REVISION 31; the ninth re-gate's S13): one principal, one key. A second line under a
        # name is a second key, not a second signer: ssh-keygen -Y verify -I <name> accepts any key listed under the name, so a forger's
        # line under the auditor's principal made its signatures "verified". A repeated identical line is one key (allowed_keys holds
        # sets); a comma-joined principal field lists each name once; one line per offending principal, in file order.
        if allowed.exists():
            for p_, ks_ in allowed_keys(allowed).items():
                if len(ks_) > 1:
                    bad.append(f"allowed_signers: principal '{p_}' holds {len(ks_)} keys: one principal, one key in a record (a second line under a name is a second key, not a second signer)")
                # V2d (the fourteenth re-gate's C09, 13 Nov 2026): ssh-keygen -Y verify reads a principal as a PATTERN, so a line `* <key>` makes
                # any name verify with that key; the checker reads principals as plain names (A3 caught the forgery) and now says so by name.
                if any(ch_ in p_ for ch_ in "*?!"):
                    bad.append(f"allowed_signers: principal '{p_}' is a pattern (ssh-keygen reads *, ? and ! in a principal as a pattern; a record names its principals plainly)")
        if not sig_p.exists():
            warn.append("no signatures.json: the parts are unsigned")
        else:
            try:
                sigs = json.loads(sig_p.read_text(encoding="utf-8"))
            except Exception as e:
                sigs, bad = [], bad + [f"signatures.json unreadable: {e}"]
            # V2 (the twelfth cut, 13 Nov 2026, NEXT-REVISION 33; the eleventh re-gate's O20): a reader gets a verdict, never a traceback. A
            # document that is not a list FAILs by its JSON kind and nothing is verified; an entry that is not an object FAILs by index and
            # value (the loop below) and the object entries are still checked; every later rule reads the object entries alone (sigs_d).
            if not isinstance(sigs, list):
                bad.append(f"signatures.json: a JSON {json_kind(sigs)} is not a list of signature entries")
                sigs = []
            # V2b (the twelfth re-gate's sealed Q06, 13 Nov 2026 10:3xZ): an object entry whose role, file, sha256, line or signature is not a
            # string, or whose signer is not an object, FAILs by field and JSON kind and is not checked further (5573fee2 crashed on a string
            # signer and on a list signature). sigs_d holds the object entries of the right shape; every later rule reads it alone.
            # V2c (the thirteenth re-gate's sealed R05, 13 Nov 2026 10:4xZ): a signer that IS an object whose name, key_id or kind is not a
            # string FAILs the same way (2966678b crashed at the key-list lookup and at the ssh-keygen spawn on a numeric or list name). The
            # rule is entry_shape_fault, shared with sign.py and add_witness.py, which refuse such a file by name before writing anything.
            sigs_d, shape_bad_ = [], set()
            for i_, e_ in enumerate(sigs):
                if not isinstance(e_, dict):
                    continue
                fault_ = entry_shape_fault(e_)
                if fault_:
                    bad.append(shape_fault_line(i_, fault_))
                    shape_bad_.add(i_)
                else:
                    sigs_d.append(e_)
            tool = shutil.which("ssh-keygen")
            listed_keys = allowed_keys(allowed) if allowed.exists() else {}
            # O1 (the one-auditor cut, 13 Nov 2026, NEXT-REVISION 32; the tenth re-gate's K16): one entry per fixed role. A second `auditor`
            # entry over audit.jsonl is a second auditor, not a co-signer (the forger's door: its own principal, its own key, its own file,
            # a genuine signature over the prescribed line, then the sources role under that key); the sources list is signed once, the
            # manifest once. The entries are still verified below, the FAIL stands beside them; names in entry order.
            if isinstance(sigs, list):
                for role_ in ("auditor", "sources", "manifest"):
                    ents_ = [e_ for e_ in sigs_d if e_.get("role") == role_]
                    if len(ents_) > 1:
                        why_ = {"auditor": "a second entry over audit.jsonl is a second auditor, not a co-signer",
                                "sources": "the auditor signs the sources list once",
                                "manifest": "the manifest is signed once, by whoever last changed the folder"}[role_]
                        bad.append(f"signatures.json: {len(ents_)} {role_} entries ({', '.join(str((e_.get('signer') or {}).get('name')) for e_ in ents_)}): one {role_} signature in a record; {why_}")
            for i, e in enumerate(sigs):
                if not isinstance(e, dict):
                    bad.append(entry_not_object_line(i, e))
                    continue
                if i in shape_bad_:
                    continue  # V2b: its FAIL line is already written
                role, f = e.get("role"), e.get("file")
                # the sources cut (13 Nov 2026, NEXT-REVISION 25b): manifest.json takes two roles, `manifest` (over its bytes, by whoever last
                # changed the folder) and `sources` (the AUDITOR's, over the bound digest of the five bound sections; R1 to R6 of the cut)
                if f not in parts or role not in (("manifest", "sources") if f == "manifest.json" else (parts[f],)):
                    bad.append(f"signatures[{i}]: {role!r} over {f!r} is not a part of this snapshot")
                    continue
                fp = snap / f
                if role == "sources":
                    # R2: the entry's sha256 is the bound digest of THIS record's manifest, never the manifest's own hash: the five sections
                    # never change under an allowed change, so the auditor's word holds through every witness insertion
                    h = sources_digest(M)  # 0.7: six sections (links too); before 0.7 exactly bound_digest
                    if e.get("sha256") != h:
                        bad.append(f"manifest.json: the sources signature is over bound sections sha256 {str(e.get('sha256'))[:12]}… and this record's are {h[:12]}…: "
                                   + ("subject, sources, pages, profile, sessions or links changed under the auditor" if fmt_at_least(M, "0.7") else "subject, sources, pages, profile or sessions changed under the auditor"))
                        continue
                else:
                    h = sha256(fp) if fp.exists() else None
                    if e.get("sha256") != h:
                        bad.append(f"signatures[{i}]: sha256 {str(e.get('sha256'))[:12]}… is not {f}'s {str(h)[:12]}…")
                        continue
                line = signed_line(role, f, h, audit_h)
                if e.get("line") != line:
                    bad.append(f"signatures[{i}]: line differs from the prescribed one: {e.get('line')!r}")
                    continue
                sf = snap / (e.get("signature") or "")
                if not e.get("signature"):
                    bad.append(f"signatures[{i}]: signature file {e.get('signature')!r} missing")
                    continue
                # O2 (the one-auditor cut): the signature file is the prescribed one, manifest.sources.sig for the sources role and <file>.sig
                # for every other role; an entry under another name is not verified (the K16 forger's audit.jsonl.forger.sig)
                prescribed_ = "manifest.sources.sig" if role == "sources" else f"{f}.sig"
                if e.get("signature") != prescribed_:
                    bad.append(f"signatures[{i}]: signature file '{e.get('signature')}' is not the prescribed '{prescribed_}'")
                    continue
                if not sf.exists():
                    bad.append(f"signatures[{i}]: signature file {e.get('signature')!r} missing")
                    continue
                name = (e.get("signer") or {}).get("name")
                covered.add(f)
                # the auditor-key cut: the key INSIDE the signature file, read without ssh-keygen (None: not an SSHSIG, said by name; the
                # ssh-keygen line below follows where the tool is on PATH)
                emb = sshsig_public_key(sf)
                if emb is None:
                    bad.append(f"{f}: signature file {e.get('signature')} is not an SSH signature")
                if role == "sources":
                    # R4: the sources role is the auditor's. The signer's key (by type and base64 from allowed_signers, a trailing comment
                    # ignored, as the auditor-key rule below reads keys) is one of the keys of the `auditor` entries; no auditor entry, no match.
                    a_names = [(e_.get("signer") or {}).get("name") for e_ in sigs_d if e_.get("role") == "auditor"]
                    if not a_names:
                        bad.append("manifest.json: a sources signature with no auditor signature to match")
                        continue
                    if allowed.exists():
                        keys_ = allowed_keys(allowed)
                        if not (keys_.get(name, set()) & set().union(*[keys_.get(n_, set()) for n_ in a_names])):
                            bad.append(f"manifest.json: the sources signature by {name!r} is not the auditor's key: the sources list is bound to the auditor alone")
                            continue
                    # A2 (the auditor-key cut): the sources key IS the audit's key. R4 compared names; the ninth re-gate's S13 put a forger's
                    # key under the auditor's name and R4 passed it. The key embedded in manifest.sources.sig must equal the key embedded in
                    # the auditor's signature file; with or without ssh-keygen.
                    # O3 (the one-auditor cut, NEXT-REVISION 32): audit.jsonl has one signature file, audit.jsonl.sig, and A2 reads that one
                    # and no other (the tenth re-gate's K16 added a second auditor entry with its own file and A2 matched the sources key
                    # against it); no auditor entry names it, or it is missing or not an SSHSIG: no readable auditor signature.
                    if emb is not None:
                        a_emb = sshsig_public_key(snap / "audit.jsonl.sig") if any(e_.get("role") == "auditor" and e_.get("signature") == "audit.jsonl.sig" for e_ in sigs_d) else None
                        if a_emb is None:
                            bad.append("manifest.json: a sources signature with no readable auditor signature to match")
                            continue
                        if emb != a_emb:
                            bad.append(f"manifest.json: the sources signature was made with key {sshsig_fingerprint(emb)} and audit.jsonl with {sshsig_fingerprint(a_emb)}: the sources list is bound to the key that signed the audit, not to a name in allowed_signers")
                            continue
                # A3 (the auditor-key cut): every signature's embedded key is its principal's listed key. ssh-keygen refuses such a file too
                # (its line follows); the checker says it by name, and says it without ssh-keygen.
                a3_bad_ = emb is not None and allowed.exists() and bool(name) and emb not in listed_keys.get(name, set())
                if a3_bad_:
                    bad.append(f"{f}: the signature's key {sshsig_fingerprint(emb)} is not the key allowed_signers lists for '{name}'")
                # O4 (the one-auditor cut, NEXT-REVISION 32): the manifest names the auditor who signed. `grading.auditor.signer` is exactly
                # "<principal> <SHA256:fp>" of the key inside audit.jsonl.sig (what sign.py writes); another name or fingerprint, or no field,
                # FAILs by name: a reader of the manifest must not be told of an auditor other than the one whose key made the signature.
                if role == "auditor" and e.get("signature") == "audit.jsonl.sig" and emb is not None and name:
                    want_signer_ = f"{name} <{sshsig_fingerprint(emb)}>"
                    got_signer_ = ((M.get("grading") or {}).get("auditor") or {}).get("signer") if isinstance(M.get("grading"), dict) and isinstance((M.get("grading") or {}).get("auditor"), dict) else None
                    if got_signer_ != want_signer_:
                        shown_signer_ = repr(got_signer_) if got_signer_ is not None else "missing"
                        bad.append(f"manifest.json: grading.auditor.signer is {shown_signer_} and audit.jsonl.sig was made by '{name}' {sshsig_fingerprint(emb)}: the manifest names another auditor than the one who signed")
                if tool and allowed.exists() and name:
                    r = subprocess.run([tool, "-Y", "verify", "-f", str(allowed), "-I", name, "-n", SIGN_NAMESPACE, "-s", str(sf)],
                                       input=line.encode(), capture_output=True)
                    if r.returncode == 0 and a3_bad_:
                        pass  # V2d (C09): ssh-keygen accepted the key under a pattern principal; the A3 line above stands alone, the entry is neither verified nor counted
                    elif r.returncode == 0:
                        ok.append(f"{f}: sources bound by {name}, verified" if role == "sources" else f"{f}: signed by {name}, verified")
                    else:
                        bad.append(f"{f}: signature by {name!r} does NOT verify: {r.stderr.decode(errors='replace').strip()[:120]}")
                else:
                    warn.append(f"{f}: signature by {name!r} present, not verified here (" + ("ssh-keygen not on PATH" if not tool else "no allowed_signers in the snapshot" if not allowed.exists() else "no signer name") + ")")
            for f in parts:
                if f not in covered:
                    if f == "manifest.json":
                        continue  # 0.6: the manifest signature is optional (K11 asks for it when primary_named_by is set)
                    if profile in ARTEFACT_PROFILES and f == "audit.jsonl":
                        continue  # judged below: FAIL for this profile
                    warn.append(f"{f}: unsigned")
            # R5 (the sources cut): a model witness over an evidence-shaped auditor part (SPEC 12 and 13, or any audit row with an `evidence`
            # list) and no `sources` signature: the sources list rests on the published copy and the service's key alone. Nothing is printed
            # otherwise, so every 0.2 to 0.5 folder and every pre-witness folder without a model witness stays byte-identical.
            if (any(k_ == "model" for k_ in w_kind.values()) and (profile in EVIDENCE_PROFILES or any(isinstance(a_.get("evidence"), list) for a_ in audit))
                    and not any(e.get("role") == "sources" for e in sigs_d)):
                warn.append("manifest.json: no sources signature: the sources list rests on the published copy and the witness service's key alone (sign.py --role sources, the auditor's key)")
            # 0.5, agent-work: the witness is never the auditor (OneDroid Indie VR-I11). The agent signs with the key its
            # machine enrolled; a witness signed by the same key, under any name, is the agent judging itself.
            # 0.6: the same rule for a witness of kind agent or model in every profile (a human self-audit keeps one signer).
            # 0.6 erratum 1 (12 Nov 2026): in the page profiles a self-audit by an AGENT keeps one signer too, when the manifest
            # declares it: the witness is the primary, grading.kind is "self-audit" and grading.gates records the holdout
            # (section 1); K13 reports it instead of failing. A model witness never shares the auditor's key (a model is nobody's
            # self), a non-primary agent witness never does, and in agent-work and test-run no witness does (VR-I11).
            ma_files = {f_ for f_, k_ in w_kind_file.items() if k_ in ("model", "agent", "script")}  # script: 0.9 document (SPEC 17), a script is never signed with the auditor's key
            prim_file = next((w.get("file") for w in witnesses if w.get("primary")), None)
            gates_ = g.get("gates")
            declared_self_audit = g.get("kind") == "self-audit" and isinstance(gates_, list) and len(gates_) > 0
            if (profile in EVIDENCE_PROFILES or ma_files) and allowed.exists() and isinstance(sigs, list):
                keys = allowed_keys(allowed)  # the key by type and base64; a trailing comment is not part of it (ssh-keygen ignores it, so must this comparison)
                # A4 (the auditor-key cut): the key sets hold the listed keys AND the key embedded in each entry's signature file, so a
                # witness file signed with the auditor's key is caught by the key itself, whatever allowed_signers lists under the name
                emb_of = lambda e_: sshsig_public_key(snap / e_["signature"]) if e_.get("signature") else None  # noqa: E731
                a_keys = set().union(*[keys.get((e.get("signer") or {}).get("name"), set()) for e in sigs_d if e.get("role") == "auditor"] or [set()])
                a_keys |= {k_ for k_ in (emb_of(e) for e in sigs_d if e.get("role") == "auditor") if k_}
                for e in sigs_d:
                    w_keys = keys.get((e.get("signer") or {}).get("name"), set()) | ({emb_of(e)} if e.get("role") == "witness" and emb_of(e) else set())
                    if e.get("role") == "witness" and w_keys & a_keys:
                        if profile in EVIDENCE_PROFILES:
                            bad.append(f"{e.get('file')}: signed with the auditor's key: the witness is never the auditor ({profile}, VR-I11)")
                        elif e.get("file") in ma_files:
                            k_ = w_kind_file[e.get("file")]
                            if k_ == "agent" and e.get("file") == prim_file and declared_self_audit:
                                ok.append(f"{e.get('file')}: self-audit by an agent: one signer for the auditor part and the primary witness, grading.kind self-audit, {len(gates_)} holdout gate(s) recorded (0.6 erratum 1)")
                            else:
                                bad.append(f"{e.get('file')}: signed with the auditor's key: the witness is never the auditor (kind {k_}, {profile})"
                                           + ("; an agent keeps one signer only as the primary of a declared self-audit (grading.kind self-audit, grading.gates recorded)" if k_ == "agent" else ""))
        if profile in ARTEFACT_PROFILES and "audit.jsonl" not in covered:
            if profile == DECISION_PROFILE:
                bad.append("audit.jsonl: unsigned: the decision record is a claim nobody stands behind (decision needs the deciding system's signature)")
            else:
                bad.append("audit.jsonl: unsigned: the run record is a claim nobody stands behind (test-run needs the auditor's signature)")
        # 0.6: a witness of kind model: its file is named for its manifest entry, and its principal is in the key list,
        # bound to the header's model for the witness's started_at. --keys FILE is the published list (a broken binding fails);
        # the snapshot's own keys/model-keys.jsonl is a copy of it (a broken binding there warns); neither at hand warns.
        model_ws = [w for w in witnesses if w_kind.get(w.get("name")) == "model" and w.get("file") in w_kind_file]
        agent_ws = [w for w in witnesses if w_kind.get(w.get("name")) == "agent" and w.get("file") in w_kind_file]
        script_ws = [w for w in witnesses if w_kind.get(w.get("name")) == "script" and w.get("file") in w_kind_file]  # 0.9 document only: no other profile reads kind script
        for w in model_ws + agent_ws + script_ws:
            if w.get("file") != f"witness/{w.get('name')}.jsonl":
                (bad if fmt06 else warn).append(f"{w.get('file')}: the witness file's name is not its manifest name {w.get('name')!r} (witness/<name>.jsonl)")
        if model_ws:
            auth = keys_arg is not None
            prob = bad if auth else warn
            lst_p = keys_arg if auth else ((snap / KEY_LIST) if (snap / KEY_LIST).exists() else None)
            label = f"--keys {keys_arg}" if auth else f"the snapshot's {KEY_LIST}"
            entries = []
            if lst_p is not None:
                try:
                    for ln in lst_p.read_text(encoding="utf-8").split("\n"):  # JSON lines: "\n" only, as load_jsonl
                        if ln.strip():
                            e_ = json.loads(ln.rstrip("\r"))
                            if not isinstance(e_, dict):
                                raise ValueError("a line is not an object")
                            entries.append(e_)
                except (OSError, ValueError, UnicodeDecodeError) as e:
                    prob.append(f"key list {lst_p} unreadable: {e}")
                    lst_p = None
            shipped = {}
            if (snap / "allowed_signers").exists():
                for l in (snap / "allowed_signers").read_text(encoding="utf-8", errors="replace").splitlines():
                    f_ = l.split()
                    if len(f_) >= 3 and not l.lstrip().startswith("#") and key_of(f_[1:]):
                        for p_ in f_[0].split(","):
                            shipped.setdefault(p_, set()).add(key_of(f_[1:]))
            sig_list = sigs_d if sig_p.exists() else []
            for w in model_ws:
                wf_, hdr = w.get("file"), w_hdr[w.get("name")]
                principal = next(((e.get("signer") or {}).get("name") for e in sig_list if isinstance(e, dict) and e.get("role") == "witness" and e.get("file") == wf_), None)
                if lst_p is None:
                    if not auth:
                        warn.append(f"{wf_}: model principal {principal!r} not in a published key list (no --keys FILE and no {KEY_LIST} in the snapshot)")
                    continue
                if principal is None:
                    prob.append(f"{wf_}: a model witness with no signature entry has no principal to look up in the key list")
                    continue
                cand = [e for e in entries if e.get("principal") == principal]
                if not cand:
                    prob.append(f"{wf_}: model principal {principal!r} not in a published key list ({label})")
                    continue
                best = None
                for e in cand:
                    why = []
                    if e.get("model") != hdr.get("model"):
                        why.append(f"the list binds it to model {e.get('model')!r}, the header says {hdr.get('model')!r}")
                    st_, vf_, vt_ = parse_rfc3339(hdr.get("started_at")), parse_rfc3339(e.get("valid_from")), e.get("valid_to")
                    if st_ is None:
                        why.append(f"header started_at {hdr.get('started_at')!r} is not an RFC3339 time")
                    elif vf_ is None:
                        why.append(f"valid_from {e.get('valid_from')!r} is not an RFC3339 time")
                    elif st_ < vf_:
                        why.append(f"started_at {hdr.get('started_at')} is before valid_from {e.get('valid_from')}")
                    elif vt_ is not None and parse_rfc3339(vt_) is None:
                        why.append(f"valid_to {vt_!r} is neither null nor an RFC3339 time")
                    elif vt_ is not None and st_ > parse_rfc3339(vt_):
                        why.append(f"started_at {hdr.get('started_at')} is after valid_to {vt_}")
                    listed = key_of(str(e.get("key", "")).split())
                    if (snap / "allowed_signers").exists() and (listed is None or listed not in shipped.get(principal, set())):
                        why.append("the key in the list is not the key of this principal in the shipped allowed_signers")
                    if best is None or len(why) < len(best):
                        best = why
                    if not why:
                        break
                if best:
                    prob.append(f"{wf_}: model principal {principal!r} ({label}): " + "; ".join(best))
                else:
                    bind_ok.append(f"{wf_}: principal {principal} bound to {hdr.get('model')} in {label}, window covers {hdr.get('started_at')}")
        R.add("K13", "FAIL" if bad else ("WARN" if warn else "PASS"), f"{len(ok)} signature(s) verified, {len(warn)} note(s), {len(bad)} broken", bad + warn + ok + bind_ok)

        # K14 anchors: each over the hash of a file in the folder
        anc_p = snap / "anchors.json"
        bad, warn, info, g_info = [], [], [], []  # g_info: 0.7 gvui lines, printed after the bindings and not counted as one
        if fmt_at_least(M, "0.7") and anc_p.is_symlink():
            # gate-h2 F1 (14 Nov 2026): this folder's own anchors.json, as K16 treats a target's: a symbolic link is never followed.
            # 0.7 and later only, so every older folder's output is unchanged
            bad.append("anchors.json is a symbolic link, not followed: the checker follows none")
        elif not anc_p.exists():
            warn.append("no anchors.json: nothing fixes the signatures in time" + (f"; no anchor exists yet ({profile}: an anchor over the signatures file is optional until armarium ships)" if profile in ARTEFACT_PROFILES else ""))
        else:
            try:
                anchors = json.loads(anc_p.read_text(encoding="utf-8"))
            except Exception as e:
                anchors, bad = [], [f"anchors.json unreadable: {e}"]
            hashes = {sha256(p): str(p.relative_to(snap)) for p in snap.rglob("*") if p.is_file() and p.name not in ("anchors.json", "CHECK.json", "CHECK.txt")}
            ots = shutil.which("ots")
            for i, a in enumerate(anchors if isinstance(anchors, list) else []):
                over = str(a.get("over", "")).removeprefix("sha256:")
                if over not in hashes:
                    bad.append(f"anchors[{i}]: over sha256:{over[:12]}… is no file in this folder")
                    continue
                if a.get("method") not in ANCHOR_METHODS:
                    bad.append(f"anchors[{i}]: method {a.get('method')!r} unknown")
                if fmt_at_least(M, "0.7"):
                    # 0.7 (14 Nov 2026, SPEC 3a): an armarium ref keeps the signer the service recovered from the transaction; a `gvui`, when
                    # present, is derived from the anchor and recomputed here (no second chain write). Older folders print nothing new.
                    ref_ = a.get("ref")
                    if a.get("method") == "armarium":
                        sg_ = ref_.get("signer") if isinstance(ref_, dict) else None
                        if not isinstance(ref_, dict):
                            bad.append(f"anchors[{i}]: an armarium ref is a JSON {json_kind(ref_)}, not an object")
                        elif sg_ is None:
                            warn.append(f"anchors[{i}]: the armarium ref names no signer: who wrote the anchor is not on record (0.7 keeps the signer the service recovered)")
                        elif not (isinstance(sg_, str) and SIGNER_RE.fullmatch(sg_)):
                            bad.append(f"anchors[{i}]: the armarium ref's signer {str(sg_)[:60]!r} is not 0x and 40 hex")
                    if a.get("gvui") is not None:
                        want_g = gvui_of(a)
                        if want_g is None or a.get("gvui") != want_g:
                            bad.append(f"anchors[{i}]: gvui does not recompute from the ref (gv1 of namespace {GVUI_NS}, anchor/<chain>/<block>, the correlation id, the signer and the anchor time)"
                                       + ("" if want_g is not None else ": the ref lacks a field it needs"))
                        else:
                            g_info.append(f"anchors[{i}]: gvui recomputes from the ref ({want_g[:24]}…)")
                pf = a.get("proof_file")
                if pf and not (snap / pf).exists():
                    bad.append(f"anchors[{i}]: proof_file {pf!r} missing")
                    continue
                if a.get("method") == "ots" and pf:
                    if fetch and ots:
                        r = subprocess.run([ots, "verify", str(snap / pf)], capture_output=True)
                        (info if r.returncode == 0 else bad).append(f"anchors[{i}]: ots verify exit {r.returncode}: {(r.stdout + r.stderr).decode(errors='replace').strip()[:120]}")
                    else:
                        warn.append(f"anchors[{i}]: {hashes[over]} anchored by ots at {a.get('time')}, proof not verified here (" + ("pass --fetch" if not fetch else "ots not on PATH") + ")")
                else:
                    info.append(f"anchors[{i}]: {hashes[over]} anchored by {a.get('method')} ({a.get('ref')}) at {a.get('time')}: binding holds, the anchor itself is not checked by this script")
        if profile in ARTEFACT_PROFILES and anc_p.exists() and not (info or warn or bad):
            warn.append(f"no anchor exists yet: anchors.json lists none ({profile}: an anchor over the signatures file is optional until armarium ships)")
        R.add("K14", "FAIL" if bad else ("WARN" if warn else "PASS"), f"{len(info)} anchor binding(s) hold, {len(warn)} note(s), {len(bad)} broken", bad + warn + info + g_info)

        # K15 session records, by hash
        sess = g.get("sessions")
        bad, warn = [], []
        if not sess:
            warn.append("no recorded sessions listed: how the parts were produced is not on record")
        for i, s_ in enumerate(sess or []):
            miss = [k for k in ("role", "recorder", "session_id", "record_sha256", "complete", "gaps", "held_by") if k not in s_]
            if miss:
                bad.append(f"sessions[{i}]: missing {', '.join(miss)}")
            if s_.get("file") and (snap / s_["file"]).exists() and sha256(snap / s_["file"]) != s_.get("record_sha256"):
                bad.append(f"sessions[{i}]: {s_['file']} does not have the stated record_sha256")
            if s_.get("complete") is False or (s_.get("gaps") or 0):
                warn.append(f"sessions[{i}] ({s_.get('role')}): the recorder says the record is incomplete ({s_.get('gaps')} gap(s))")
        R.add("K15", "FAIL" if bad else ("WARN" if warn else "PASS"), f"{len(sess or [])} session record(s) listed by hash" if not bad else f"{len(bad)} incomplete", bad + warn)

    # K16 links (0.7, 14 Nov 2026, SPEC 3 and 5): only for a 0.7 or later folder, so every older folder's output is unchanged
    if fmt_at_least(M, "0.7"):
        R.add("K16", *links_check(snap, M, links_root))

    # KX exports (0.7, SPEC 15): only when --export DIR is given, so a run without it is unchanged; any format (an export is outside the folder)
    if "--export" in argv:
        i_ = argv.index("--export")
        if i_ + 1 < len(argv) and not argv[i_ + 1].startswith("--"):
            R.add("KX", *export_check(snap, M, pathlib.Path(argv[i_ + 1])))
        else:
            R.add("KX", "FAIL", "--export needs the export folder (statement.intoto.json, statement.dsse.json, credential.vc.json)")

    # K10 live fetch: every source a proof or counter uses, by file or by url; status proofs compared live;
    # audited pages with a url re-fetched and every claim fragment looked for again
    if fetch:
        drift, gone, errs, unchecked, status_bad, page_gone = [], [], [], [], [], []
        by_url = {s_["url"]: s_ for s_ in M["sources"] if s_.get("url")}

        def source_of(p):
            f = p.get("file")
            if f and f in by_file:
                return by_file[f]
            m = re.search(r"(\d{3})(?:\.pdf-text)?\.txt$", f or "")
            if m and int(m.group(1)) in by_n:
                return by_n[int(m.group(1))]
            if p.get("url") and p["url"] in by_url:
                return by_url[p["url"]]
            return None

        quotes_by_n, status_by_n = {}, {}
        for c in claims:
            for p in c.get("proofs", []) + c.get("counter", []):
                s_ = source_of(p)
                if s_ is None:
                    continue
                if p.get("expect_status") is not None:
                    status_by_n.setdefault(s_["n"], []).append((c["id"], p["expect_status"]))
                if p.get("quote") is not None:
                    quotes_by_n.setdefault(s_["n"], []).append((c["id"], p["quote"]))
                elif p.get("expect_status") is None:
                    quotes_by_n.setdefault(s_["n"], [])  # existence proof: fetch and expect a body

        def get(url):
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (claims-snapshot check.py)"})
            try:
                with urllib.request.urlopen(req, timeout=30) as r:
                    return r.status, r.read(), (r.headers.get_content_type() or "")
            except urllib.error.HTTPError as e:
                return e.code, b"", ""

        def live_text(body, ctype):
            """HTML is stripped to its text; code, Markdown, JSON and plain text are taken as they are (the HTML
            stripper would eat every `<…>` comparison in code and every `<name>` placeholder in Markdown)."""
            raw = body.decode("utf-8", errors="replace")
            is_html = ctype == "text/html" or raw.lstrip()[:15].lower().startswith(("<!doctype html", "<html"))
            return norm(html_to_text(raw) if is_html else raw)

        for s_ in M["sources"]:
            n = s_["n"]
            if n not in quotes_by_n and n not in status_by_n:
                continue
            if not s_.get("url"):
                unchecked.append(f"[{n}] no url to fetch ({len(quotes_by_n.get(n, []))} quote(s) unchecked)")
                continue
            try:
                code, body, ctype = get(s_["url"])
            except Exception as e:
                errs.append(f"[{n}] {s_['url']}: {e}")
                continue
            for cid, want in status_by_n.get(n, []):
                if code != want:
                    status_bad.append(f"[{n}] {cid}: {s_['url']} answered {code}, the grader saw {want}")
            if n not in quotes_by_n:
                continue
            if code != 200:
                gone.append(f"[{n}] {s_['url']} answered {code}: {len(quotes_by_n[n])} quote(s) could not be checked live")
                continue
            if s_.get("body_sha256") and hashlib.sha256(body).hexdigest() != s_["body_sha256"]:
                drift.append(f"[{n}] body changed since the snapshot")
            if body[:5] == b"%PDF-":
                unchecked.append(f"[{n}] is a PDF: the live text is not extracted here, {len(quotes_by_n[n])} quote(s) unchecked")
                continue
            live = live_text(body, ctype)
            for cid, q in quotes_by_n[n]:
                if norm(q) and norm(q) not in live:
                    gone.append(f"[{n}] {cid}: quote not on the live page: {q[:70]}")
        live_pages = [pg for pg in pages if pg.get("url")]
        for pg in live_pages:
            try:
                code, body, ctype = get(pg["url"])
            except Exception as e:
                errs.append(f"page {pg['file']}: {e}")
                continue
            if code != 200:
                page_gone.append(f"page {pg['file']}: {pg['url']} answered {code}")
                continue
            # an audited page is compared as the lister read it: HTML as rendered text, anything else as served
            live = live_text(body, ctype)
            for c in claims:
                if c.get("verdict") == "WITHDRAWN" or not any(l.get("file") == pg["file"] for l in c.get("location", [])):
                    continue
                frags = [norm(f) for f in c.get("text", "").split("[...]") if norm(f)]
                if frags and not all(f in live for f in frags):
                    page_gone.append(f"page {pg['file']}: {c['id']} no longer on the live page")
        status = "FAIL" if ((gone or status_bad or page_gone) and strict) else ("WARN" if (gone or drift or errs or unchecked or status_bad or page_gone) else "PASS")
        R.add("K10", status, f"live fetch: {len(quotes_by_n)} sources with quotes or existence proofs, {len(status_by_n)} with status proofs, {len(live_pages)} audited pages; "
              f"{len(drift)} bodies changed, {len(gone)} quotes gone, {len(status_bad)} statuses differ, {len(page_gone)} claims or pages gone from the live pages, {len(unchecked)} unchecked, {len(errs)} fetch errors",
              gone + status_bad + page_gone + unchecked + drift + errs)

    # V2h (the eighteenth re-gate's X): CHECK.json is written BEFORE the one print, so a failed write is a FAIL line inside the report,
    # never a PASS SUMMARY followed by a second one; V2i: the same finish on every exit
    return finish(R, snap, argv, M.get("format"))


if __name__ == "__main__":
    sys.exit(main(sys.argv))
