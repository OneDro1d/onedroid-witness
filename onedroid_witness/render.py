"""Rendering of one audit row for a model: the claim, the page lines around it, and the candidates by type (contract section 4); for a
row whose shape is one `evidence` list (agent-work and test-run, SPEC 12 and 13), the auditor's pointers resolved from the files the
request carried (service item S-1): the pointed file line with its neighbours, the handed-in output, each artefact by name, the record
row; a pointer that cannot be read is said so by name.

The text a model sees is DATA from a publisher's page and an auditor's record; the prompt says so and the caller's bytes never
reach the prompt itself. The same rendering goes to every model (chat or decision), so two models' answers are about one text.
"""
import hashlib
import json
import pathlib
import re
import urllib.parse


PUBLISHER = ("publisher-host",)  # the key under which source_index keeps the audited page's site; a tuple never collides with a URL


def _site(url):
    """The site of a URL for the publisher relation: the host, lower-cased, a leading www. and a trailing dot (an absolute DNS name,
    second re-gate note) dropped; None when there is none."""
    try:
        host = (urllib.parse.urlsplit(str(url)).hostname or "").lower().rstrip(".")
    except ValueError:
        return None
    return host[4:] if host.startswith("www.") else (host or None)


def source_index(manifest):
    """url -> the manifest's source entry (n, url, copy, status, file), plus the audited page's site under PUBLISHER (re-gate N1: the
    publisher-surfaces rule turns on whether a source is one of the publisher's own surfaces, so the rendering has to say which are)."""
    idx = {s.get("url"): s for s in manifest.get("sources", []) if s.get("url")}
    idx[PUBLISHER] = _site((manifest.get("subject") or {}).get("url")) if isinstance(manifest.get("subject"), dict) else None
    return idx


def _relation(url, by_url):
    """' , the publisher's own surface (same site as the audited page)' or ' , another site', or nothing when no subject URL is known."""
    site = by_url.get(PUBLISHER)
    if not site:
        return ""
    return ", the publisher's own surface (same site as the audited page)" if _site(url) == site else ", another site"


def _where(c, by_url):
    """Where a candidate comes from, in words a model can use: the page itself, a numbered source with its copy status and whether it is
    one of the publisher's own surfaces, or unknown."""
    if c.get("file") == "page.txt" or (c.get("url") is None and c.get("file") in (None, "page.txt")):
        return "the audited page itself (page.txt)"
    src = by_url.get(c.get("url"))
    if src is None:
        if c.get("file"):
            return f"saved file {c['file']} (not in the manifest's source list)"
        return f"source {c.get('url')} (not in the manifest)"
    copy = src.get("copy")
    copy_text = "fetched and not saved: copy: none" if copy in (None, "none") else f"copy: {copy}"
    return f"source [{src.get('n')}] {src.get('url')} ({copy_text}, http {src.get('status')}{_relation(src.get('url'), by_url)})"


FENCE_CHARS = set("=-_~*#")


# every separator str.splitlines() honours (re-gate N2): \r\n, \n, \r, \v, \f, the C1 and Unicode line and paragraph separators
LINE_SEPARATORS = re.compile("\r\n|[\n\r\x0b\x0c\x1c\x1d\x1e\x85  ]")


# 0.1.6 (fifth re-gate H2): a run of 8 or more fence-like characters INSIDE a line (72 '=' around a planted instruction in a carried
# README line) read as a fence to one chat model; every maximal run gets a visible mark after every 4th character, so no run of 8 survives
FENCE_RUN = re.compile(r"[=\-_~*#]{8,}")
FENCE_MARK = "·"  # U+00B7


def _break_run(m):
    s = m.group(0)
    return FENCE_MARK.join(s[i:i + 4] for i in range(0, len(s), 4))


def one_line(s, width=None):
    """Caller text as ONE line: a line separator inside a quote, a note or a claim text would otherwise end the item's line and could
    close the data fence the prompt names (gate D4). Every separator str.splitlines() knows becomes a visible mark, nothing is removed.
    Then every maximal run of 8 or more fence-like characters is broken by a visible mark after every 4th character (H2); every
    character stays, runs of 7 or fewer are untouched. The width cap applies after the marks are inserted."""
    t = LINE_SEPARATORS.sub(" ⏎ ", str(s))
    t = FENCE_RUN.sub(_break_run, t)
    return t[:width] if width else t


def neutralise_fence_lines(text, fence):
    """No line of caller data may equal the fence, nor consist of fence-like characters alone (a run of = or -): such a line gets a
    visible prefix. The data is kept, only its line shape changes. Lines are what str.splitlines() sees (re-gate N2), joined with \\n."""
    out = []
    for l in text.splitlines():
        s = l.strip()
        if l == fence or (len(s) >= 8 and set(s) <= FENCE_CHARS):
            out.append("| " + l)
        else:
            out.append(l)
    return "\n".join(out)


def copy_none_indices(row, by_url):
    """The candidate indices, per side, whose source the auditor fetched and did not save (copy: none): a verdict resting only on those
    is UNDECIDED, never EVIDENCED or CONTRADICTED (section 14, gate D3)."""
    out = {"proofs": set(), "counter": set()}
    for side in ("proofs", "counter"):
        for i, c in enumerate(row.get(side) or []):
            if c.get("file") == "page.txt" or c.get("url") is None:
                continue
            src = by_url.get(c.get("url"))
            if src is not None and src.get("copy") in (None, "none"):
                out[side].add(i)
    return out


def _candidate_line(i, c, by_url):
    where = _where(c, by_url)
    if c.get("quote") is not None:
        body = f'quote "{one_line(c["quote"])}"'
    elif c.get("expect_status") is not None:
        body = f"status proof: the URL answered {one_line(str(c.get('expect_status')), 40)}, no quote"
    elif c.get("file") and c.get("url") is None:
        body = "existence proof: the named file exists at the pinned commit, no quote"
    else:
        body = "existence or status proof, no quote"
    note = f"; note: {one_line(c['note'])}" if c.get("note") else ""
    return f"[{i}] from {one_line(where)}: {body}{note}"


def page_context(row, page_lines, around=1, width=600):
    out = []
    for loc in row.get("location") or []:
        n = loc.get("line")
        if isinstance(n, int) and 1 <= n <= len(page_lines):
            for i in range(max(1, n - around), min(len(page_lines), n + around) + 1):
                out.append(f"page.txt line {i}: {one_line(page_lines[i - 1], width)}")  # 0.1.6: a page line passes one_line too (H2)
    return out


# ---- the evidence list (S-1): the four pointer shapes resolved as vendor/check.py resolves them (lines 529-620 at f2edc3f4) ----
HEX64 = re.compile(r"^[0-9a-f]{64}$")
RECORD_PTR = re.compile(r"^([^#\s]{1,128})#([0-9]{1,18})$")  # check.py's RECORD_PTR
EVIDENCE_PROFILES = ("agent-work", "test-run")
LINE_WIDTH = 600  # a pointed file line and each of its neighbours
OUTPUT_HEAD, OUTPUT_TAIL, LOG_TAIL, OUTPUT_CHARS = 40, 20, 40, 4000  # a handed-in output or an artefact: head and tail, a .log its tail
RECORD_CHARS = 600  # a session record row


def safe_relative(name):
    """A normalised relative path inside the folder: no leading /, no empty, `.` or `..` component, no backslash, no NUL."""
    if not isinstance(name, str) or not name or name.startswith("/") or "\\" in name or "\x00" in name:
        return False
    return all(p not in ("", ".", "..") for p in name.split("/"))


def is_evidence_row(row):
    """The agent-work shape (SPEC 12): one `evidence` list and neither proofs nor counter; check.py's agent_shape."""
    return isinstance(row.get("evidence"), list) and not row.get("proofs") and not row.get("counter")


def _read(root, rel):
    """The bytes of a manifest-named file under root, or None when it is not there or its path could leave the folder."""
    if root is None or not safe_relative(rel):
        return None
    p = pathlib.Path(root) / rel
    return p.read_bytes() if p.is_file() else None


def evidence_index(manifest, root):
    """What resolve_pointer needs, from the manifest and the files carried under root: the sources, the carried bytes by manifest path,
    by_path (sources with `path`), by_sha (sources with `sha256` whose copy is carried), by_name (sources by `name` or `path`), the
    sessions' record rows by (session id, sequence) when the session file is carried and hashes to its record_sha256, the subject and
    the profile. A manifest-named file that is not under root is simply not carried: the pointer is said to be unreadable."""
    manifest = manifest if isinstance(manifest, dict) else {}
    sources = [s for s in (manifest.get("sources") or []) if isinstance(s, dict)]
    g = manifest.get("grading") if isinstance(manifest.get("grading"), dict) else {}
    carried = {}
    for s in sources:
        f = s.get("file")
        if isinstance(f, str) and f not in carried:
            b = _read(root, f)
            if b is not None:
                carried[f] = b
    by_path = {s["path"]: s for s in sources if s.get("path")}
    by_sha = {s["sha256"]: s for s in sources if s.get("sha256") and s.get("file") in carried}
    by_name = {}
    for s in sources:
        for k in (s.get("name"), s.get("path")):
            if k:
                by_name.setdefault(k, s)
    records = {}
    for s_ in (g.get("sessions") or []):
        if not isinstance(s_, dict) or not isinstance(s_.get("file"), str):
            continue
        b = _read(root, s_["file"])
        if b is None or hashlib.sha256(b).hexdigest() != s_.get("record_sha256"):
            continue
        rows = {}
        for l in b.decode("utf-8", "replace").split("\n"):  # JSON lines: "\n" only, as check.py's load_jsonl
            try:
                e = json.loads(l.rstrip("\r"))
            except Exception:
                continue
            if isinstance(e, dict) and isinstance(e.get("sequence"), int) and not isinstance(e.get("sequence"), bool):
                rows[(str(e.get("session_id", "")), e["sequence"])] = e
        records[str(s_.get("session_id", ""))] = rows
    subject = manifest.get("subject") if isinstance(manifest.get("subject"), dict) else {}
    profile = g.get("profile") or manifest.get("profile") or subject.get("profile") or "cited-sources"
    return {"sources": sources, "carried": carried, "by_path": by_path, "by_sha": by_sha, "by_name": by_name, "records": records,
            "subject": subject, "profile": profile}


def _short(h):
    return f"{one_line(h[:12])}..." if isinstance(h, str) and h else "?"  # 0.1.6: a caller's hash value passes one_line too (H2)


def _text_lines(b):
    return b.decode("utf-8", "replace").splitlines()


def _output_text(lines, tail_only=False):
    """A handed-in output or an artefact as the model sees it: the first 40 and last 20 lines with the omission said (a .log: its last 40
    lines), every line one line, the whole capped at 4,000 characters."""
    n = len(lines)
    if n > OUTPUT_HEAD + OUTPUT_TAIL:
        if tail_only:
            kept = [f"... ({n - LOG_TAIL} lines omitted) ..."] + lines[-LOG_TAIL:]
        else:
            kept = lines[:OUTPUT_HEAD] + [f"... ({n - OUTPUT_HEAD - OUTPUT_TAIL} lines omitted) ..."] + lines[-OUTPUT_TAIL:]
    else:
        kept = lines
    out = "\n".join(one_line(l) for l in kept)
    return out if len(out) <= OUTPUT_CHARS else out[:OUTPUT_CHARS] + f"\n... (cut at {OUTPUT_CHARS} characters)"


def _not_carried(src):
    """Why a listed source cannot be read here: no copy was ever listed (hash-only), or its copy was listed and this request did not carry it."""
    if not src.get("file"):
        return "held by hash only (the manifest lists no copy)"
    return f"not sent (the manifest lists its copy at {one_line(str(src['file']), 200)}, which this request did not carry)"


def resolve_pointer(p, idx, root=None):
    """One evidence pointer -> {kind, status, label, text}. status: readable (the bytes are here and the text is in `text`), unreadable
    (listed but not carried: hash-only, file null, or the file not sent), unlisted (no source lists it), malformed (not one of the four
    shapes, a bad line number, a name or hash that does not match, SPEC 13). The label carries the status sentence in its parentheses.
    The resolution mirrors check.py's test_pointer: by_path for a file pointer, by_sha for test and command outputs, name AND hash for an
    artefact, the carried session record for a record pointer. `root` is kept for the signature; the bytes are in idx."""
    def out(kind, status, label, text=""):
        return {"kind": kind, "status": status, "label": label, "text": text}
    if not isinstance(p, dict):
        return out("malformed", "malformed", f"pointer {one_line(json.dumps(p, ensure_ascii=False), 200)} (malformed: not one of the four pointer shapes)")
    if "file" in p and "line" in p:
        path, n = p.get("file"), p.get("line")
        head = f"file {one_line(str(path), 200)} line {one_line(str(n), 40)}"
        src = idx["by_path"].get(path) if isinstance(path, str) else None
        if src is None:
            return out("file", "unlisted", f"{head} (not listed: no source of the manifest lists that path)")
        where = f"source {src.get('n')}"
        b = idx["carried"].get(src.get("file")) if src.get("file") else None
        if b is None:
            return out("file", "unreadable", f"{head} ({where}, {_not_carried(src)})")
        lines = _text_lines(b)
        if not isinstance(n, int) or isinstance(n, bool) or not 1 <= n <= len(lines):
            return out("file", "malformed", f"{head} ({where}, copy at hand, malformed: the copy has {len(lines)} line(s), no line {one_line(str(n), 40)})")
        text = "\n".join(f"line {i}: {one_line(lines[i - 1], LINE_WIDTH)}" for i in range(max(1, n - 1), min(len(lines), n + 1) + 1))
        return out("file", "readable", f"{head} ({where}, copy at hand)", text)
    if "output_sha256" in p and ("test" in p or "command" in p):
        kind = "test" if "test" in p else "command"
        h = p.get("output_sha256")
        head = f'{kind} "{one_line(str(p.get(kind)), 200)}" output sha256 {_short(h)}'
        src = idx["by_sha"].get(h) if isinstance(h, str) else None
        if src is not None:
            return out(kind, "readable", f"{head} (source {src.get('n')}, copy at hand)", _output_text(_text_lines(idx["carried"][src["file"]])))
        listed = [s for s in idx["sources"] if s.get("sha256") == h]
        if listed:
            return out(kind, "unreadable", f"{head} (source {listed[0].get('n')}, {_not_carried(listed[0])})")
        return out(kind, "unlisted", f"{head} (not listed: no source of the manifest lists that sha256, so it is not in the record's inventory)")
    if "artefact" in p and idx.get("profile") == "test-run":
        h, nm = p.get("sha256"), p.get("artefact")
        head = f"artefact {one_line(str(nm), 200)} sha256 {_short(h)}"
        if not (isinstance(h, str) and HEX64.match(h)) or not nm:
            return out("artefact", "malformed", f"{head} (malformed: an artefact pointer needs a name and a 64-hex sha256)")
        held = [s for s in idx["sources"] if s.get("sha256") == h and s.get("file") in idx["carried"]]
        listed = [s for s in idx["sources"] if s.get("sha256") == h]
        if not held:
            if not listed:
                return out("artefact", "unlisted", f"{head} (not listed: no source of the manifest lists that sha256, so it is not in the record's inventory)")
            s = listed[0]
            return out("artefact", "unreadable", f"{head} (role {one_line(str(s.get('artefact_role')), 60)}, {_not_carried(s)})")
        named = [s for s in held if nm in (s.get("name"), s.get("path"))]
        if not named:
            other = held[0].get("name") or held[0].get("path")
            return out("artefact", "malformed", f"{head} (malformed: names sha256 {_short(h)}, which the folder holds under another name: {one_line(repr(other), 200)})")
        s = named[0]
        tail_only = str(nm).endswith(".log")
        return out("artefact", "readable", f"{head} (role {one_line(str(s.get('artefact_role')), 60)}, copy at hand)",
                   _output_text(_text_lines(idx["carried"][s["file"]]), tail_only))
    if "record" in p:
        ptr = str(p["record"])
        head = f"record {one_line(ptr, 200)}"
        m = RECORD_PTR.match(ptr)
        if not m:
            return out("record", "malformed", f"{head} (malformed: not <session>#<sequence>)")
        for sid, rows in idx["records"].items():
            if sid.startswith(m.group(1)):
                e = rows.get((sid, int(m.group(2))))
                if e is None:
                    return out("record", "malformed", f"{head} (malformed: the carried record of {one_line(sid, 128)} has no row #{m.group(2)})")
                return out("record", "readable", f"{head} (session record at hand)", one_line(json.dumps(e, ensure_ascii=False), RECORD_CHARS))
        return out("record", "unreadable", f"{head} (the session record is held by hash only)")
    return out("malformed", "malformed", f"pointer {one_line(json.dumps(p, ensure_ascii=False), 200)} (malformed: not one of the four pointer shapes)")


WITNESS_VOCABULARY = re.compile(r"\b(EVIDENCED|CONTRADICTED|UNDECIDED|NO EVIDENCE PUBLISHED)\b")  # case-sensitive, whole words


def witness_vocabulary_hits(row, idx, by_url):
    """0.1.8 (seventh re-gate H2, V1): the places where the evidence text a model would read holds a witness verdict token, one string per
    hit in index order: for an evidence row each readable pointer whose resolved `text` matches ("[i] <label> holds <token>"), for a
    candidate row each candidate (proofs then counter, indexed as _candidate_line indexes them) whose quote matches ("candidate [i] from
    <url or file> holds <token>"). Only the four tokens, upper case, whole words: a test-run result.json's "verdict": "PASS" is no hit,
    nor is the English word "evidenced". NOT scanned: the claim text, the page lines, consulted, searched, the run subject. A text that
    names a verdict is not evidence of a claim: answer.run passes such a row through as UNDECIDED for every model with no call."""
    out = []
    if is_evidence_row(row):
        for i, p in enumerate(row["evidence"]):
            r = resolve_pointer(p, idx)
            if r["status"] != "readable":
                continue
            m = WITNESS_VOCABULARY.search(r["text"])
            if m:
                out.append(f"[{i}] {r['label']} holds {m.group(1)}")
        return out
    for i, c in enumerate((row.get("proofs") or []) + (row.get("counter") or [])):
        if not isinstance(c, dict) or c.get("quote") is None:
            continue
        m = WITNESS_VOCABULARY.search(str(c.get("quote")))
        if m:
            out.append(f"candidate [{i}] from {c.get('url') or c.get('file')} holds {m.group(1)}")
    return out


def unreadable_indices(row, idx, root=None):
    """The evidence indices whose pointer is not readable (unreadable, unlisted or malformed): a verdict resting only on those is
    UNDECIDED, never EVIDENCED or CONTRADICTED."""
    if not is_evidence_row(row):
        return set()
    return {i for i, p in enumerate(row["evidence"]) if resolve_pointer(p, idx, root)["status"] != "readable"}


def all_unreadable(row, idx, root=None):
    """True when the row has pointers and none is readable (an empty list has its own rule: the auditor named no pointer)."""
    if not is_evidence_row(row) or not row["evidence"]:
        return False
    return len(unreadable_indices(row, idx, root)) == len(row["evidence"])


def _run_subject(idx):
    s = idx.get("subject") or {}
    sc = s.get("scenario") if isinstance(s.get("scenario"), dict) else {}
    sut = s.get("system_under_test") if isinstance(s.get("system_under_test"), dict) else {}
    env = s.get("environment") if isinstance(s.get("environment"), dict) else {}
    return ["", "run subject:",
            f"- scenario {one_line(sc.get('id'), 200)} sha256 {_short(sc.get('sha256'))}",
            f"- system under test {one_line(sut.get('repository'), 200)} commit {one_line(sut.get('commit'), 80)}, image digest {one_line(sut.get('image_digest'), 120)}",
            f"- environment {one_line(env.get('name'), 120)} sha256 {_short(env.get('sha256'))}",
            f"- started_at {one_line(s.get('started_at'), 40)}, finished_at {one_line(s.get('finished_at'), 40)}"]


def _evidence_section(row, idx):
    # 0.1.6 (H2): every run-subject line and every pointer label passes one_line whole, so the manifest values a label carries without
    # their own one_line (a source's `n`, a hash shortened by _short) cannot hold a fence run either; one_line is idempotent on its output
    out = [one_line(l) for l in _run_subject(idx)] if idx.get("profile") == "test-run" else []
    ev = row.get("evidence") or []
    if not ev:
        return out + ["", "evidence (0): (none; the auditor named no pointer)"]
    out += ["", f"evidence ({len(ev)}), the auditor's pointers, indexed from 0:"]
    for i, p in enumerate(ev):
        r = resolve_pointer(p, idx)
        out.append(f"[{i}] {one_line(r['label'])}")
        if r["text"]:
            out += ["  " + l for l in r["text"].splitlines()]
    return out


def render(row, page, by_url, evidence=None):
    """The rendered claim: id, kind, text, page context, then the candidates FOR and AGAINST, or, for a row with one `evidence` list,
    the auditor's pointers resolved from the carried files (`evidence` = evidence_index(manifest, root); None renders every pointer as
    not carried), consulted, searched."""
    lines = page.splitlines()
    out = [f"claim id: {one_line(row['id'])}", f"kind: {one_line(row.get('kind'))}", f"claim text: {one_line(row['text'])}", "",
           "page context (the lines around the claim):"]
    out += page_context(row, lines) or ["(no location)"]
    if is_evidence_row(row):
        out += _evidence_section(row, evidence if evidence is not None else evidence_index({}, None))
    else:
        for name, items in (("FOR", row.get("proofs") or []), ("AGAINST", row.get("counter") or [])):
            out += ["", f"candidates {name} ({len(items)}):"]
            out += [_candidate_line(i, c, by_url) for i, c in enumerate(items)] or ["(none)"]
    if row.get("consulted"):
        out += ["", "what the auditor consulted and found where it looked:"]
        out += [f"- {one_line(c.get('url') or c.get('file'))}: {one_line(str(c.get('quote')), 400)}" for c in row["consulted"]]
    if row.get("searched"):
        out += ["", f"what the auditor searched for and did not find: {one_line(row['searched'])}"]
    from .prompts import DATA_FENCE
    return neutralise_fence_lines("\n".join(out), DATA_FENCE)


def all_copy_none(row, by_url):
    """True when every candidate of the row is a source the auditor fetched and did not save (section 14: never EVIDENCED)."""
    cands = (row.get("proofs") or []) + (row.get("counter") or [])
    if not cands:
        return False
    for c in cands:
        if c.get("file") == "page.txt" or c.get("url") is None:
            return False
        src = by_url.get(c.get("url"))
        if src is None or src.get("copy") not in (None, "none"):
            return False
    return True
