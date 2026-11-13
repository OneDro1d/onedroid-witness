#!/usr/bin/env python3
"""check.py: the mechanical checker for a claims snapshot (SPEC.md section 5). Standard library only, no model.

usage: python3 -I check.py SNAPSHOT_DIR [--copies DIR] [--fetch] [--strict] [--json] [--keys FILE]
  --copies DIR  a private folder holding NNN.txt (or NNN.pdf-text.txt) copies of hash-only sources, to verify quotes offline
  --fetch       fetch every source live (GET, browser user-agent) and check the quotes are still there (K10)
  --strict      a quote gone from a live page fails K10 instead of warning
  --json        also write CHECK.json into the snapshot folder: the run as data (SPEC.md section 5)
  --keys FILE   0.6: the published key list (keys/model-keys.jsonl of the public repository) a model witness's principal is
                checked against; a broken binding FAILs. Without it the snapshot's own keys/model-keys.jsonl is used (a broken
                binding there is a WARN), and without either the checker warns.
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
auditor's pointers and candidate quotes without a verdict, K8 and K12 WARN that no score exists yet, K11 asks for no primary."""
import datetime, hashlib, html, json, pathlib, re, shutil, subprocess, sys, urllib.error, urllib.request

FORMATS = {"claims-snapshot/0.2", "claims-snapshot/0.3", "claims-snapshot/0.4", "claims-snapshot/0.5", "claims-snapshot/0.6"}
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
                "manifest_sha256": sha256(snap / "manifest.json"), "flags": flags,
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


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    snap = pathlib.Path(argv[1])
    copies = pathlib.Path(argv[argv.index("--copies") + 1]) if "--copies" in argv else None
    fetch = "--fetch" in argv
    strict = "--strict" in argv
    want_json = "--json" in argv
    keys_arg = pathlib.Path(argv[argv.index("--keys") + 1]) if "--keys" in argv and argv.index("--keys") + 1 < len(argv) else None
    R = Report()

    # K1 manifest
    try:
        M = json.loads((snap / "manifest.json").read_text(encoding="utf-8"))
    except Exception as e:
        R.add("K1", "FAIL", f"manifest.json unreadable: {e}")
        print(R.text())
        return 1
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
    if g.get("profile") not in PROFILES:
        missing.append(f"grading.profile={g.get('profile')!r} not in {sorted(PROFILES)}")
    pre_bad = []  # pre-witness (SPEC 14): what the stage forbids, said as such
    if pre:
        if M.get("format") != "claims-snapshot/0.6":
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
        loc_ = M.get("evidence_locator")
        if not isinstance(loc_, dict):
            tr_bad.append("evidence_locator missing")
        else:
            for k_ in ("held_by", "where", "expires_at", "note"):
                if k_ not in loc_:
                    tr_bad.append(f"evidence_locator.{k_}")
            if "held_by" in loc_ and loc_["held_by"] not in HELD_BY:
                tr_bad.append(f"evidence_locator.held_by={loc_['held_by']!r} not in {sorted(HELD_BY)}")
            if loc_.get("expires_at") is not None and parse_time(loc_.get("expires_at")) is None:
                tr_bad.append(f"evidence_locator.expires_at={loc_.get('expires_at')!r} is not null or a time")
            if loc_.get("held_by") in HELD_BY and loc_.get("held_by") != "folder" and not (isinstance(loc_.get("where"), str) and loc_["where"].strip()):
                # trilix, adoption of section 13 (WB): the writer refuses a holder without `where`; the checker holds the same rule
                tr_bad.append(f"evidence_locator.held_by is {loc_['held_by']} but where is {loc_.get('where')!r}: a holder other than the folder is named by its url or path")
            if loc_.get("held_by") == "folder":
                for s_ in (M.get("sources") or []):
                    if isinstance(s_, dict) and s_.get("role") == "artefact" and not (s_.get("file") and (snap / s_["file"]).exists()):
                        tr_bad.append(f"evidence_locator.held_by is folder but artefact {s_.get('name') or s_.get('path')!r} has no copy in the folder (file {s_.get('file')!r})")
    for i, gate in enumerate(g.get("gates", []) or []):
        for k in ("run", "size", "sealed_sha256", "sealed_at", "first_gate", "final"):
            if k not in gate:
                missing.append(f"grading.gates[{i}].{k}")
    k1_text = "manifest fields" + (": missing " + ", ".join(missing) if missing else (" present" if tr_bad or pre_bad else f" present, format {M.get('format')}, profile {g.get('profile')}, {len(g.get('gates', []) or [])} holdout gate(s) recorded"))
    if tr_bad:
        k1_text += "; test-run subject or locator: " + ", ".join(tr_bad)
    if pre_bad:
        k1_text += "; pre-witness folder " + ", ".join(pre_bad)
    elif pre and not missing:
        k1_text += "; pre-witness: the auditor's part alone, no primary witness named yet"
    R.add("K1", "FAIL" if missing or tr_bad or pre_bad else "PASS", k1_text)
    if missing or tr_bad or pre_bad:
        print(R.text())
        return 1

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
    pages_norm = norm(" ".join(page_text.values()))
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
        frags = [norm(f) for f in c.get("text", "").split("[...]")]
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
            texts[file] = norm(page_text[file])
        else:
            src = by_file.get(file)
            if src is None:
                m = re.search(r"(\d{3})(?:\.pdf-text)?\.txt$", file or "")
                src = by_n.get(int(m.group(1))) if m else None
            raw = copy_text(snap, copies, src) if src else None
            texts[file] = norm(raw) if raw is not None else None
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
        if norm(p.get("quote", "")) and norm(p["quote"]) in t:
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
        if "artefact" in p and profile == "test-run":
            # 0.5, test-run (SPEC 13): an artefact of the run by name and hash, verified from the folder's copy
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

    k5_fail, k5_warn, k6_fail, k6_warn, k7_fail, page_only, bad_quotes, existence, published_misses = [], [], [], [], [], [], [], [], []
    pre_tally = {"verified": 0, "untestable": 0, "failed": 0}  # pre-witness: every pointer or candidate quote of the auditor's rows, tested without a verdict
    for c in claims:
        v = c.get("verdict")
        if pre:
            if agent_shape(c):
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
                    if t is not None and (p.get("quote") is None or (norm(p.get("quote", "")) and norm(p["quote"]) in t)):
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
        fmt06 = M.get("format") == "claims-snapshot/0.6"
        w_hdr, w_kind, w_kind_file, w_und = {}, {}, {}, {}  # 0.6: header, effective kind, kind by file, UNDECIDED count, per witness
        kind_bad = []   # a `kind` outside human | agent | model, said on K1 (FAIL in 0.6, WARN before)
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
                if isinstance(kv, str) and kv in WITNESS_KINDS:
                    if src_ == "header" or "kind" not in header:
                        ek = kv
                else:
                    kind_bad.append(f"witness {name!r}: {src_} kind {kv!r} is not human, agent or model")
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
            elif ek == "model" and (profile in ("agent-work", "test-run") or any(isinstance(a_.get("evidence"), list) for a_ in audit)):
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
            elif "carried" in header and ek == "model" and (profile in ("agent-work", "test-run") or any(isinstance(a_.get("evidence"), list) for a_ in audit)):
                k11_warn.append(f"witness {name!r}: a model witness records `carried` but no `bound`: which manifest its pointers resolved through is not on record (0.1.8 of the witness service writes it)")
            if "manifest_sha256" in header and not (isinstance(header["manifest_sha256"], str) and HEX64.match(header["manifest_sha256"])):
                bad.append(f"witness {name!r}: header manifest_sha256 {header['manifest_sha256']!r} is not 64 hex characters")
            w_hdr[name], w_kind[name], w_kind_file[wf] = header, ek, ek
            if header.get("method") == "classify" and ek != "model":
                bad.append(f"witness {name!r}: method 'classify' is for a witness of kind 'model' only (this one is {ek!r})")
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
                if v == "MISSING CLAIM" and profile == "agent-work":
                    # 0.5: the agent's reply is not in the folder (the kit keeps the block), so a claim the block left
                    # out cannot be found on a page: it needs its text and the witness's note saying where it was made
                    if not (r.get("text") or "").strip() or not (r.get("note") or "").strip():
                        bad.append(f"witness {name!r} {rid}: MISSING CLAIM needs the claim's text and a note saying where the agent made it")
                    if rid in audit_ids:
                        bad.append(f"witness {name!r} {rid}: MISSING CLAIM with an id the auditor listed")
                    continue
                if v == "MISSING CLAIM":
                    frags = [norm(f) for f in (r.get("text") or "").split("[...]") if norm(f)]
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
        R.add("K12", "FAIL" if bad else ("WARN" if k12_warn else "PASS"), (("pre-witness: no merge yet; per-witness scores and missing-claim counts recomputed" if pre else "claims.jsonl equals the merge; per-witness scores and missing-claim counts recomputed") if not bad else f"{len(bad)} difference(s)"), bad + k12_warn + info)

        # K13 signatures over the prescribed line, verified with ssh-keygen when it is on PATH
        parts = {"audit.jsonl": "auditor"} | {w.get("file"): "witness" for w in witnesses if w.get("file")} | {"manifest.json": "manifest"}  # manifest: 0.6, optional
        sig_p = snap / "signatures.json"
        bad, warn, ok, covered, bind_ok = [], [], [], set(), []
        if not sig_p.exists():
            warn.append("no signatures.json: the parts are unsigned")
        else:
            try:
                sigs = json.loads(sig_p.read_text(encoding="utf-8"))
            except Exception as e:
                sigs, bad = [], [f"signatures.json unreadable: {e}"]
            tool = shutil.which("ssh-keygen")
            allowed = snap / "allowed_signers"
            for i, e in enumerate(sigs if isinstance(sigs, list) else []):
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
                    h = bound_digest(M)
                    if e.get("sha256") != h:
                        bad.append(f"manifest.json: the sources signature is over bound sections sha256 {str(e.get('sha256'))[:12]}… and this record's are {h[:12]}…: subject, sources, pages, profile or sessions changed under the auditor")
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
                if not e.get("signature") or not sf.exists():
                    bad.append(f"signatures[{i}]: signature file {e.get('signature')!r} missing")
                    continue
                name = (e.get("signer") or {}).get("name")
                covered.add(f)
                if role == "sources":
                    # R4: the sources role is the auditor's. The signer's key (by type and base64 from allowed_signers, a trailing comment
                    # ignored, as the auditor-key rule below reads keys) is one of the keys of the `auditor` entries; no auditor entry, no match.
                    a_names = [(e_.get("signer") or {}).get("name") for e_ in sigs if e_.get("role") == "auditor"]
                    if not a_names:
                        bad.append("manifest.json: a sources signature with no auditor signature to match")
                        continue
                    if allowed.exists():
                        keys_ = allowed_keys(allowed)
                        if not (keys_.get(name, set()) & set().union(*[keys_.get(n_, set()) for n_ in a_names])):
                            bad.append(f"manifest.json: the sources signature by {name!r} is not the auditor's key: the sources list is bound to the auditor alone")
                            continue
                if tool and allowed.exists() and name:
                    r = subprocess.run([tool, "-Y", "verify", "-f", str(allowed), "-I", name, "-n", SIGN_NAMESPACE, "-s", str(sf)],
                                       input=line.encode(), capture_output=True)
                    if r.returncode == 0:
                        ok.append(f"{f}: sources bound by {name}, verified" if role == "sources" else f"{f}: signed by {name}, verified")
                    else:
                        bad.append(f"{f}: signature by {name!r} does NOT verify: {r.stderr.decode(errors='replace').strip()[:120]}")
                else:
                    warn.append(f"{f}: signature by {name!r} present, not verified here (" + ("ssh-keygen not on PATH" if not tool else "no allowed_signers in the snapshot" if not allowed.exists() else "no signer name") + ")")
            for f in parts:
                if f not in covered:
                    if f == "manifest.json":
                        continue  # 0.6: the manifest signature is optional (K11 asks for it when primary_named_by is set)
                    if profile == "test-run" and f == "audit.jsonl":
                        continue  # judged below: FAIL for this profile
                    warn.append(f"{f}: unsigned")
            # R5 (the sources cut): a model witness over an evidence-shaped auditor part (SPEC 12 and 13, or any audit row with an `evidence`
            # list) and no `sources` signature: the sources list rests on the published copy and the service's key alone. Nothing is printed
            # otherwise, so every 0.2 to 0.5 folder and every pre-witness folder without a model witness stays byte-identical.
            if (any(k_ == "model" for k_ in w_kind.values()) and (profile in ("agent-work", "test-run") or any(isinstance(a_.get("evidence"), list) for a_ in audit))
                    and not any(e.get("role") == "sources" for e in (sigs if isinstance(sigs, list) else []))):
                warn.append("manifest.json: no sources signature: the sources list rests on the published copy and the witness service's key alone (sign.py --role sources, the auditor's key)")
            # 0.5, agent-work: the witness is never the auditor (OneDroid Indie VR-I11). The agent signs with the key its
            # machine enrolled; a witness signed by the same key, under any name, is the agent judging itself.
            # 0.6: the same rule for a witness of kind agent or model in every profile (a human self-audit keeps one signer).
            # 0.6 erratum 1 (12 Nov 2026): in the page profiles a self-audit by an AGENT keeps one signer too, when the manifest
            # declares it: the witness is the primary, grading.kind is "self-audit" and grading.gates records the holdout
            # (section 1); K13 reports it instead of failing. A model witness never shares the auditor's key (a model is nobody's
            # self), a non-primary agent witness never does, and in agent-work and test-run no witness does (VR-I11).
            ma_files = {f_ for f_, k_ in w_kind_file.items() if k_ in ("model", "agent")}
            prim_file = next((w.get("file") for w in witnesses if w.get("primary")), None)
            gates_ = g.get("gates")
            declared_self_audit = g.get("kind") == "self-audit" and isinstance(gates_, list) and len(gates_) > 0
            if (profile in ("agent-work", "test-run") or ma_files) and allowed.exists() and isinstance(sigs, list):
                keys = allowed_keys(allowed)  # the key by type and base64; a trailing comment is not part of it (ssh-keygen ignores it, so must this comparison)
                a_keys = set().union(*[keys.get((e.get("signer") or {}).get("name"), set()) for e in sigs if e.get("role") == "auditor"] or [set()])
                for e in sigs:
                    if e.get("role") == "witness" and keys.get((e.get("signer") or {}).get("name"), set()) & a_keys:
                        if profile in ("agent-work", "test-run"):
                            bad.append(f"{e.get('file')}: signed with the auditor's key: the witness is never the auditor ({profile}, VR-I11)")
                        elif e.get("file") in ma_files:
                            k_ = w_kind_file[e.get("file")]
                            if k_ == "agent" and e.get("file") == prim_file and declared_self_audit:
                                ok.append(f"{e.get('file')}: self-audit by an agent: one signer for the auditor part and the primary witness, grading.kind self-audit, {len(gates_)} holdout gate(s) recorded (0.6 erratum 1)")
                            else:
                                bad.append(f"{e.get('file')}: signed with the auditor's key: the witness is never the auditor (kind {k_}, {profile})"
                                           + ("; an agent keeps one signer only as the primary of a declared self-audit (grading.kind self-audit, grading.gates recorded)" if k_ == "agent" else ""))
        if profile == "test-run" and "audit.jsonl" not in covered:
            bad.append("audit.jsonl: unsigned: the run record is a claim nobody stands behind (test-run needs the auditor's signature)")
        # 0.6: a witness of kind model: its file is named for its manifest entry, and its principal is in the key list,
        # bound to the header's model for the witness's started_at. --keys FILE is the published list (a broken binding fails);
        # the snapshot's own keys/model-keys.jsonl is a copy of it (a broken binding there warns); neither at hand warns.
        model_ws = [w for w in witnesses if w_kind.get(w.get("name")) == "model" and w.get("file") in w_kind_file]
        agent_ws = [w for w in witnesses if w_kind.get(w.get("name")) == "agent" and w.get("file") in w_kind_file]
        for w in model_ws + agent_ws:
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
            sig_list = sigs if (sig_p.exists() and isinstance(sigs, list)) else []
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
        bad, warn, info = [], [], []
        if not anc_p.exists():
            warn.append("no anchors.json: nothing fixes the signatures in time" + ("; no anchor exists yet (test-run: an anchor over the signatures file is optional until armarium ships)" if profile == "test-run" else ""))
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
        if profile == "test-run" and anc_p.exists() and not (info or warn or bad):
            warn.append("no anchor exists yet: anchors.json lists none (test-run: an anchor over the signatures file is optional until armarium ships)")
        R.add("K14", "FAIL" if bad else ("WARN" if warn else "PASS"), f"{len(info)} anchor binding(s) hold, {len(warn)} note(s), {len(bad)} broken", bad + warn + info)

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

    print(R.text())
    if want_json:
        flags = [a for a in argv[2:] if a.startswith("--") and a != "--json"]
        (snap / "CHECK.json").write_text(json.dumps(R.as_json(snap, M.get("format"), flags), ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
        print(f"CHECK.json written ({R.result()})")
    return 1 if R.failed() else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
