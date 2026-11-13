#!/usr/bin/env python3
"""add_witness.py: insert the answer of a witness service into a published snapshot, the one change a published folder allows
(SPEC.md section 14). Standard library plus ssh-keygen on PATH.

usage: python3 -I add_witness.py SNAPSHOT_DIR ANSWER_DIR --key PRIVATE_KEY --identity NAME [--keys FILE]
       python3 -I add_witness.py SNAPSHOT_DIR answer.tar --sha256 HEX --key PRIVATE_KEY --identity NAME [--keys FILE]
  answer.tar with --sha256 (3c.9, 12 Nov 2026): the tar as the service served it and the sha256 the service announced in the job status;
    the hash is checked over the bytes before anything is unpacked, and a mismatch refuses the whole answer
  ANSWER_DIR holds what the service returned:
    witness/<name>.jsonl and witness/<name>.jsonl.sig   one pair per model witness
    allowed_signers                                     the fragment: one line per principal, `<principal> namespaces="claims-snapshot" <type> <base64>`
    manifest-entry.json                                 the witness entry for grading.witnesses[] (one object, or a list of them)
    signatures-entry.json                               the signatures.json entry (one object, or a list of them), role witness
    service.json, service.json.sig, service-signature.json, split.jsonl   optional; copied to the folder root and listed in the manifest's `files`
  --key/--identity   the adder's private key and principal: the manifest is re-signed with them (sign.py --role manifest), last
  --keys FILE        passed to check.py (the published key list)
What it does, in this order, after checking everything first and refusing before it writes anything: copies the witness files in,
appends the allowed_signers lines (never a duplicate), inserts the manifest entries (never a duplicate name, never `primary`),
appends the signatures entries, lists service.json and split.jsonl with their sha256 in the manifest's `files` (list or object, as the
writer shaped it) and drops signatures.json, allowed_signers, anchors.json and CHECK.* from it (structural files are never named by
hash: NEXT-REVISION 22), recomputes the sha256 of every file it added, re-signs the manifest, and runs check.py on the folder: prints
its SUMMARY line and exits with check.py's exit code. A pre-witness folder (no claims.jsonl) is taken as it is (13 Nov 2026).
It never touches audit.jsonl, claims.jsonl, an existing witness file, the pages, the sources or the primary witness's score
(it hashes them before and after, and says so). A witness header's `carried` (13 Nov 2026, NEXT-REVISION 25c) must name only pages, sources and
session records this snapshot's manifest lists, each with the manifest's sha256, else the whole answer is refused before anything is written.
A witness header's `bound` (the bound cut, 13 Nov 2026), when present, must name exactly the five bound manifest sections with the sha256 of each
section of THIS snapshot's manifest in canonical JSON (check.bound_sections), else the whole answer is refused before anything is written; when
the snapshot carries the auditor's verified `sources` signature (sign.py --role sources, the sources cut of 13 Nov 2026) the refusal says so.
A `sources` entry is a non-manifest entry: kept in order, its manifest.sources.sig untouched (nothing here writes it).
One principal, one key (the auditor-key cut, 13 Nov 2026, NEXT-REVISION 31): an answer whose `allowed_signers` fragment would leave any
principal with two distinct keys, against the snapshot's existing lines or inside the fragment itself, is refused before anything is written."""
import hashlib, json, pathlib, shutil, subprocess, sys, tarfile, tempfile

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import check  # noqa: E402

UNTOUCHED = ("audit.jsonl", "claims.jsonl")


def arg(argv, flag, default=None):
    return argv[argv.index(flag) + 1] if flag in argv and argv.index(flag) + 1 < len(argv) else default


def as_list(path):
    v = json.loads(path.read_text(encoding="utf-8"))
    return v if isinstance(v, list) else [v]


# the structural files a manifest never names by hash: signatures.json and allowed_signers grow with every signature, anchors.json
# with every anchor, CHECK.* is the checker's report, and the manifest's own signature lands in signatures.json AFTER the manifest is
# hashed, so a manifest that names them can never be versioned (the evidence store refused exactly that at the gate of 1e, 13 Nov 2026;
# NEXT-REVISION 22). Entries for other files are left exactly as found: this tool repairs no hash it did not make.
STRUCTURAL = ("manifest.json", "signatures.json", "allowed_signers", "anchors.json", "CHECK.json", "CHECK.txt")


def list_files(M, snap, extra):
    """Add the extra files to the manifest's `files` with their hashes, in the shape the writer used (a list of {file, sha256} or an
    object file -> sha256), and drop the structural entries. Returns the names dropped."""
    files = M.get("files")
    if isinstance(files, dict):
        entries = [{"file": k, "sha256": v} for k, v in files.items()]
    elif isinstance(files, list):
        entries = [dict(e) for e in files if isinstance(e, dict) and e.get("file")]
    else:
        entries = []
    dropped = [e["file"] for e in entries if e["file"] in STRUCTURAL]
    entries = [e for e in entries if e["file"] not in STRUCTURAL]
    for name in extra:
        entries = [e for e in entries if e["file"] != name] + [{"file": name, "sha256": check.sha256(snap / name)}]
    if isinstance(files, dict):
        M["files"] = {e["file"]: e.get("sha256") for e in entries}
    elif entries or files is not None:
        M["files"] = entries
    return dropped


def sources_signed(snap, M):
    """True when signatures.json holds a `sources` entry over THIS snapshot's bound digest whose signature verifies against allowed_signers
    (the sources cut, 13 Nov 2026): a `bound` mismatch is then a mismatch with what the AUDITOR signed, and the refusal says so. K13 judges
    the signature itself (the auditor's key, the line); this is a yes or no for one sentence."""
    tool = shutil.which("ssh-keygen")
    allowed = snap / "allowed_signers"
    try:
        sigs = json.loads((snap / "signatures.json").read_text(encoding="utf-8"))
    except Exception:
        return False
    digest = check.bound_digest(M)
    line = check.signed_line("sources", "manifest.json", digest)
    for e in sigs if isinstance(sigs, list) else []:
        if not (isinstance(e, dict) and e.get("role") == "sources" and e.get("file") == "manifest.json" and e.get("sha256") == digest and e.get("line") == line):
            continue
        name, sf = (e.get("signer") or {}).get("name"), snap / (e.get("signature") or "")
        if tool and allowed.exists() and name and e.get("signature") and sf.is_file():
            r = subprocess.run([tool, "-Y", "verify", "-f", str(allowed), "-I", name, "-n", check.SIGN_NAMESPACE, "-s", str(sf)], input=line.encode(), capture_output=True)
            if r.returncode == 0:
                return True
    return False


def main(argv):
    if len(argv) < 3 or any(f not in argv for f in ("--key", "--identity")):
        print(__doc__)
        return 2
    snap, ans = pathlib.Path(argv[1]), pathlib.Path(argv[2])
    key, ident, keys_file = arg(argv, "--key"), arg(argv, "--identity"), arg(argv, "--keys")
    problems = []
    tmp_unpack = None
    if ans.is_file():
        # 3c.9 (12 Nov 2026): the answer as the tar the service served, with the sha256 the service announced; the hash is checked over
        # the bytes BEFORE anything is unpacked, and a mismatch refuses the whole answer (nothing written, nothing inserted)
        want = arg(argv, "--sha256")
        if not want:
            print("refused: an answer given as a tar needs --sha256 <the hash the service announced in the job status>", file=sys.stderr)
            return 1
        got = hashlib.sha256(ans.read_bytes()).hexdigest()
        if got != want.lower():
            print(f"refused, nothing written: the tar's sha256 {got[:16]}... is not the announced {want[:16]}...", file=sys.stderr)
            return 1
        tmp_unpack = tempfile.mkdtemp(prefix="add-witness-")
        with tarfile.open(ans) as tar:
            for m in tar.getmembers():
                if m.name.startswith(("/", "..")) or "/../" in m.name or not (m.isfile() or m.isdir()):
                    print(f"refused, nothing written: the tar holds an entry outside the answer folder or not a plain file: {m.name!r}", file=sys.stderr)
                    shutil.rmtree(tmp_unpack, ignore_errors=True)
                    return 1
            tar.extractall(tmp_unpack, filter="data")
        ans = pathlib.Path(tmp_unpack)
    try:
        M = json.loads((snap / "manifest.json").read_text(encoding="utf-8"))
    except Exception as e:
        print(f"refused: {snap}/manifest.json unreadable: {e}", file=sys.stderr)
        return 1
    g = M.get("grading")
    if not isinstance(g, dict) or not isinstance(g.get("witnesses"), list) or not (snap / "audit.jsonl").exists():
        print("refused: not a 0.4 or later snapshot (no grading.witnesses or no audit.jsonl)", file=sys.stderr)
        return 1
    try:
        entries = as_list(ans / "manifest-entry.json")
        sig_entries = as_list(ans / "signatures-entry.json")
        frag = [l.strip() for l in (ans / "allowed_signers").read_text(encoding="utf-8").splitlines() if l.strip() and not l.lstrip().startswith("#")]
    except Exception as e:
        print(f"refused: the answer folder is incomplete or unreadable: {e}", file=sys.stderr)
        return 1
    if not entries or not all(isinstance(e, dict) for e in entries) or not all(isinstance(e, dict) for e in sig_entries):
        print("refused: manifest-entry.json and signatures-entry.json must hold witness entries (objects)", file=sys.stderr)
        return 1

    names = {w.get("name") for w in g["witnesses"]}
    files_have = {w.get("file") for w in g["witnesses"]}
    auditor_signed = sources_signed(snap, M)  # the sources cut: a bound mismatch against sections the auditor signed says so
    adds = []  # (source path, target path relative to the snapshot)
    new_names = set()
    for e in entries:
        n, f = e.get("name"), e.get("file")
        if not n or n in names or n in new_names:
            problems.append(f"witness name {n!r} is empty or already in grading.witnesses")
        new_names.add(n)
        if f != f"witness/{n}.jsonl":
            problems.append(f"entry {n!r}: file {f!r} is not witness/{n}.jsonl")
        if e.get("primary"):
            problems.append(f"entry {n!r}: marked primary: an added witness is never the primary (the primary's score does not change)")
        if f in files_have or (snap / str(f)).exists():
            problems.append(f"entry {n!r}: {f} already exists in the snapshot: existing witness files are never touched")
        for part in (f, str(f) + ".sig"):
            if not (ans / str(part)).is_file():
                problems.append(f"{part}: not in the answer folder")
            else:
                adds.append((ans / part, part))
        # the answer must describe its own file: a manifest entry whose sha256 is not the file's is refused, never corrected
        # (the format owner's withheld case W17 of 12 Nov 2026: the first cut overwrote it silently)
        if (ans / str(f)).is_file() and e.get("sha256") is not None and e.get("sha256") != check.sha256(ans / str(f)):
            problems.append(f"entry {n!r}: sha256 {str(e.get('sha256'))[:12]}… is not the witness file's {check.sha256(ans / str(f))[:12]}…: the answer does not describe its own file")
        # the carried cut (13 Nov 2026, NEXT-REVISION 25c): the header's `carried` must name only pages, sources and session records THIS
        # snapshot's manifest lists, each with the manifest's hash; a witness that read other bytes is refused before anything is written
        # (a header without `carried` is accepted here; K11 warns later where it applies). The inventory is check.carried_inventory, K11's.
        if (ans / str(f)).is_file():
            try:
                hdr, _ = check.load_witness(ans / str(f))
            except (ValueError, UnicodeDecodeError) as ex:
                hdr = None
                problems.append(f"entry {n!r}: {f} unreadable: {ex}")
            else:
                if hdr is None:
                    problems.append(f"entry {n!r}: {f} has no header line")
            if hdr is not None and "carried" in hdr:
                if not isinstance(hdr["carried"], dict):
                    problems.append(f"entry {n!r}: carried is not an object of path to sha256")
                else:
                    inv = check.carried_inventory(M)
                    for cpath in sorted(hdr["carried"]):
                        ch = hdr["carried"][cpath]
                        if cpath not in inv:
                            problems.append(f"entry {n!r}: carried {cpath!r} is not a page, source or session record this snapshot's manifest lists")
                        elif ch != inv[cpath]:
                            problems.append(f"entry {n!r}: carried {cpath!r} sha256 {str(ch)[:12]}… differs from the manifest's {inv[cpath][:12]}…: the witness read other bytes than this snapshot holds")
            # the bound cut (13 Nov 2026, the seventh re-gate's U1): the header's `bound` must hold the sha256 of each of the five bound sections of
            # THIS snapshot's manifest in canonical JSON (check.bound_sections, K11's: the sections insertion never touches), else the witness read a
            # manifest that is not this snapshot's and the whole answer is refused before anything is written. A header without `bound` is accepted
            # (K11 warns later where it applies). The decision-on-a-carried-file rule stays K11's, after insertion: add_witness is a header check.
            if hdr is not None and "bound" in hdr:
                if not isinstance(hdr["bound"], dict):
                    problems.append(f"entry {n!r}: bound is not an object of section to sha256")
                else:
                    if set(hdr["bound"]) != set(check.BOUND_SECTIONS):
                        problems.append(f"entry {n!r}: bound names {sorted(hdr['bound'])!r}, not the five bound sections {list(check.BOUND_SECTIONS)!r}")
                    want = check.bound_sections(M)
                    for section in check.BOUND_SECTIONS:
                        if section not in hdr["bound"]:
                            continue
                        bv = hdr["bound"][section]
                        if not (isinstance(bv, str) and check.HEX64.match(bv)):
                            problems.append(f"entry {n!r}: bound {section!r}: sha256 {bv!r} is not 64 hex characters")
                        elif bv != want[section]:
                            problems.append(f"entry {n!r}: bound {section!r} sha256 {bv[:12]}… differs from this snapshot's {want[section][:12]}…: the witness read a manifest whose {section} is not this snapshot's"
                                            + ("; the auditor signed these sections" if auditor_signed else ""))
        if e.get("kind") not in (None, "human", "agent", "model"):
            problems.append(f"entry {n!r}: kind {e.get('kind')!r}")
    files_new = {e.get("file") for e in entries}
    for se in sig_entries:
        if se.get("role") != "witness" or se.get("file") not in files_new:
            problems.append(f"signatures entry {se.get('role')!r} over {se.get('file')!r} is not a witness entry for one of the added files")
        if se.get("signature") not in {str(f) + ".sig" for f in files_new}:
            problems.append(f"signatures entry over {se.get('file')!r}: signature {se.get('signature')!r} is not the added .sig file")
        if se.get("file") in files_new and (ans / str(se.get("file"))).is_file() and se.get("sha256") != check.sha256(ans / str(se.get("file"))):
            problems.append(f"signatures entry over {se.get('file')!r}: sha256 {str(se.get('sha256'))[:12]}… is not the file's: the service signed another file")
    for f in files_new:
        if not any(se.get("file") == f for se in sig_entries):
            problems.append(f"{f}: no signatures entry in the answer")
    extra = []
    for name in ("service.json", "service.json.sig", "service-signature.json", "split.jsonl"):  # the service's own signature travels with its record (12 Nov 2026)
        if (ans / name).is_file():
            if (snap / name).exists():
                problems.append(f"{name} already exists in the snapshot: refused to overwrite")
            extra.append(name)
    # the auditor-key cut (13 Nov 2026, NEXT-REVISION 31; the ninth re-gate's S13): one principal, one key. The fragment's lines against the
    # snapshot's allowed_signers and against each other: a principal that would end up holding two distinct keys refuses the whole answer
    # (ssh-keygen -Y verify -I <name> accepts any key listed under the name, so a second line under the auditor's name is a forger's door)
    allowed_p = snap / "allowed_signers"
    would = {k: set(v) for k, v in (check.allowed_keys(allowed_p) if allowed_p.exists() else {}).items()}
    for l in frag:
        f_ = l.split()
        if len(f_) >= 3 and check.key_of(f_[1:]):
            for p_ in f_[0].split(","):
                would.setdefault(p_, set()).add(check.key_of(f_[1:]))
    for p_, ks_ in would.items():
        if len(ks_) > 1:
            problems.append(f"principal '{p_}' would hold two keys in allowed_signers: one principal, one key")
    if problems:
        print("refused, nothing written:\n  " + "\n  ".join(problems), file=sys.stderr)
        return 1

    before = {f: check.sha256(snap / f) for f in UNTOUCHED if (snap / f).exists()}  # a pre-witness folder has no claims.jsonl (gate of 1e, 13 Nov 2026)
    for w in g["witnesses"]:
        before[w["file"]] = check.sha256(snap / w["file"]) if w.get("file") and (snap / w["file"]).exists() else None
    for src, rel in adds:
        (snap / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, snap / rel)
    allowed = snap / "allowed_signers"
    have = allowed.read_text(encoding="utf-8").splitlines() if allowed.exists() else []
    new_lines = [l for l in dict.fromkeys(frag) if l not in {h.strip() for h in have}]
    if new_lines:
        allowed.write_text("".join(l + "\n" for l in have) + "".join(l + "\n" for l in new_lines), encoding="utf-8")
    for e in entries:
        e = dict(e)
        e["primary"] = False
        e["sha256"] = check.sha256(snap / e["file"])
        g["witnesses"].append(e)
    sigs_p = snap / "signatures.json"
    sigs = json.loads(sigs_p.read_text(encoding="utf-8")) if sigs_p.exists() else []
    for se in sig_entries:
        sigs.append(dict(se))  # as the service signed it: a hash that does not match the file fails K13, which is the point
    sigs_p.write_text(json.dumps(sigs, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    for name in extra:
        shutil.copyfile(ans / name, snap / name)
    dropped = list_files(M, snap, extra)
    (snap / "manifest.json").write_text(json.dumps(M, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")

    after = {f: (check.sha256(snap / f) if (snap / f).exists() else None) for f in before}
    if before != after:
        print("ABORT: a file that must not change did change: " + ", ".join(k for k in before if before[k] != after[k]), file=sys.stderr)
        return 1
    untouched = [f for f in UNTOUCHED if f in before]
    print(f"added {len(entries)} witness(es): {', '.join(sorted(new_names))}; {len(new_lines)} allowed_signers line(s), {len(extra)} extra file(s); "
          f"{', '.join(untouched)} and the {len(before) - len(untouched)} existing witness file(s) unchanged (sha256 equal before and after)"
          + (f"; dropped from the manifest's files: {', '.join(dropped)} (structural files are never named by hash)" if dropped else ""))
    r = subprocess.run([sys.executable, "-I", str(HERE / "sign.py"), str(snap), "--role", "manifest", "--key", key, "--identity", ident],
                       capture_output=True, text=True)
    print((r.stdout + r.stderr).strip())
    if r.returncode != 0:
        print("manifest not signed: stopping", file=sys.stderr)
        return 1
    cmd = [sys.executable, "-I", str(HERE / "check.py"), str(snap)] + (["--keys", keys_file] if keys_file else []) + (["--json"] if (snap / "CHECK.json").exists() else [])
    r = subprocess.run(cmd, capture_output=True, text=True)
    print(next((l for l in r.stdout.splitlines() if l.startswith("SUMMARY:")), "check.py printed no SUMMARY line"))
    if r.returncode not in (0, 1):
        print(r.stderr[-400:], file=sys.stderr)
    if tmp_unpack:
        shutil.rmtree(tmp_unpack, ignore_errors=True)
    return r.returncode


if __name__ == "__main__":
    sys.exit(main(sys.argv))
