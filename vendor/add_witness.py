#!/usr/bin/env python3
"""add_witness.py: insert the answer of a witness service into a published snapshot, the one change a published folder allows
(SPEC.md section 14). Standard library plus ssh-keygen on PATH.

usage: python3 -I add_witness.py SNAPSHOT_DIR ANSWER_DIR --key PRIVATE_KEY --identity NAME [--keys FILE]
  ANSWER_DIR holds what the service returned:
    witness/<name>.jsonl and witness/<name>.jsonl.sig   one pair per model witness
    allowed_signers                                     the fragment: one line per principal, `<principal> namespaces="claims-snapshot" <type> <base64>`
    manifest-entry.json                                 the witness entry for grading.witnesses[] (one object, or a list of them)
    signatures-entry.json                               the signatures.json entry (one object, or a list of them), role witness
    service.json, split.jsonl                           optional; copied to the folder root and listed in the manifest's `files`
  --key/--identity   the adder's private key and principal: the manifest is re-signed with them (sign.py --role manifest), last
  --keys FILE        passed to check.py (the published key list)
What it does, in this order, after checking everything first and refusing before it writes anything: copies the witness files in,
appends the allowed_signers lines (never a duplicate), inserts the manifest entries (never a duplicate name, never `primary`),
appends the signatures entries, lists service.json and split.jsonl with their sha256, recomputes the sha256 of every file it
added, re-signs the manifest, and runs check.py on the folder: prints its SUMMARY line and exits with check.py's exit code.
It never touches audit.jsonl, claims.jsonl, an existing witness file, the pages, the sources or the primary witness's score
(it hashes them before and after, and says so)."""
import json, pathlib, shutil, subprocess, sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import check  # noqa: E402

UNTOUCHED = ("audit.jsonl", "claims.jsonl")


def arg(argv, flag, default=None):
    return argv[argv.index(flag) + 1] if flag in argv and argv.index(flag) + 1 < len(argv) else default


def as_list(path):
    v = json.loads(path.read_text(encoding="utf-8"))
    return v if isinstance(v, list) else [v]


def main(argv):
    if len(argv) < 3 or any(f not in argv for f in ("--key", "--identity")):
        print(__doc__)
        return 2
    snap, ans = pathlib.Path(argv[1]), pathlib.Path(argv[2])
    key, ident, keys_file = arg(argv, "--key"), arg(argv, "--identity"), arg(argv, "--keys")
    problems = []
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
    for name in ("service.json", "split.jsonl"):
        if (ans / name).is_file():
            if (snap / name).exists():
                problems.append(f"{name} already exists in the snapshot: refused to overwrite")
            extra.append(name)
    if problems:
        print("refused, nothing written:\n  " + "\n  ".join(problems), file=sys.stderr)
        return 1

    before = {f: check.sha256(snap / f) for f in UNTOUCHED}
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
    if extra:
        files = M.setdefault("files", [])
        for name in extra:
            shutil.copyfile(ans / name, snap / name)
            files.append({"file": name, "sha256": check.sha256(snap / name)})
    (snap / "manifest.json").write_text(json.dumps(M, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")

    after = {f: (check.sha256(snap / f) if (snap / f).exists() else None) for f in before}
    if before != after:
        print("ABORT: a file that must not change did change: " + ", ".join(k for k in before if before[k] != after[k]), file=sys.stderr)
        return 1
    print(f"added {len(entries)} witness(es): {', '.join(sorted(new_names))}; {len(new_lines)} allowed_signers line(s), {len(extra)} extra file(s); "
          f"audit.jsonl, claims.jsonl and the {len(before) - len(UNTOUCHED)} existing witness file(s) unchanged (sha256 equal before and after)")
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
    return r.returncode


if __name__ == "__main__":
    sys.exit(main(sys.argv))
