"""R4c: helpers for the claims-snapshot 0.9 "document" fixtures (SPEC 17), shared by test_r4c_document.py.

The two fixtures under fixtures/ are the format's own examples at OneDro1d/onedroid-claims a5ce040 (PR #35 head), exported with
`git archive` and passed through strip_witnesses() below: the folder as the auditor published it, before any witness was added (the
pre-witness stage, SPEC 14). Every helper that changes a fixture works on a copy in a temp dir and re-signs with a throwaway key made by
ssh-keygen there, never committed.
"""
import hashlib
import json
import pathlib
import shutil
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
FIXTURES = ROOT / "fixtures"
DOC_IN = FIXTURES / "document-in-document-proof-2026-11-22"
DOC_EXT = FIXTURES / "document-external-proof-2026-11-22"
DOC_REC = FIXTURES / "recordings-document"
CHECK_PY = ROOT / "vendor" / "check.py"
SIGN_PY = ROOT / "vendor" / "sign.py"
ADD_WITNESS = ROOT / "vendor" / "add_witness.py"
FIXED = ("manifest.json", "audit.jsonl", "audit.jsonl.sig", "allowed_signers", "signatures.json")
CHAT, DECISION = "openai/gpt-4.1-mini", "typesafe/jev-1.14"
DOC_MODELS = [{"id": CHAT, "kind": "chat", "max_tokens": 400}, {"id": DECISION, "kind": "decision"}]
DOC_PRICES = {CHAT: {"prompt": 4e-7, "completion": 1.6e-6}, DECISION: {"prompt": 4.2e-8, "completion": 0}}


def load(p):
    return json.loads(pathlib.Path(p).read_text(encoding="utf-8"))


def dump(p, obj):
    pathlib.Path(p).write_text(json.dumps(obj, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")


def sha(p):
    return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()


def strip_witnesses(src, dst):
    """The example folder as the auditor published it: witness/ removed, and with it the witness entries of grading.witnesses, the
    witness signature entries of signatures.json, the witness principals' allowed_signers lines and the witness files' `files` entries.
    The example's README.md (it describes the witnesses) is not copied. audit.jsonl, its signature, the pages, the sources, the key list
    copy and the auditor's sources signature stay byte for byte: the sources signature is over the five bound sections, which a witness
    never changes."""
    src, dst = pathlib.Path(src), pathlib.Path(dst)
    shutil.copytree(src, dst, ignore=shutil.ignore_patterns("witness", "README.md", "CHECK.json"))
    M = load(dst / "manifest.json")
    wfiles = {w.get("file") for w in M["grading"]["witnesses"]}
    M["grading"]["witnesses"] = []
    if isinstance(M.get("files"), dict):
        M["files"] = {k: v for k, v in M["files"].items() if k not in wfiles}
    dump(dst / "manifest.json", M)
    sigs = load(dst / "signatures.json")
    principals = {(e.get("signer") or {}).get("name") for e in sigs if e.get("role") == "witness"}
    dump(dst / "signatures.json", [e for e in sigs if e.get("role") != "witness"])
    lines = (dst / "allowed_signers").read_text(encoding="utf-8").splitlines()
    (dst / "allowed_signers").write_text("".join(l + "\n" for l in lines if l.split()[:1] and l.split()[0] not in principals), encoding="utf-8")
    return dst


def make_key(directory, name):
    path = pathlib.Path(directory) / name
    if not path.exists():
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", name, "-f", str(path)], check=True)
    return path


def fingerprint(pub):
    return subprocess.run(["ssh-keygen", "-lf", str(pub)], capture_output=True, text=True, check=True).stdout.split()[1]


def copy_fixture(src, tmp, name=None):
    dst = pathlib.Path(tmp) / (name or pathlib.Path(src).name)
    shutil.copytree(src, dst)
    return dst


def edit_audit(snap, keydir, mutate, identity="r4c-fixture-auditor"):
    """Change audit.jsonl (`mutate(rows)` edits the row list in place) and re-sign the folder the way a careful auditor would: a new
    throwaway auditor key and principal, the old auditor and sources entries and the old auditor's allowed_signers line removed,
    `sign.py --role auditor`, grading.auditor's sha256, signer, score and counts and the `files` entry refreshed from the new rows (the
    checker's own evidence_score over the claimed verdicts), `counts` recomputed, then `sign.py --role sources`."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("check_for_fixtures", str(CHECK_PY))
    check = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(check)
    snap = pathlib.Path(snap)
    rows = [json.loads(l) for l in (snap / "audit.jsonl").read_text(encoding="utf-8").split("\n") if l.strip()]
    mutate(rows)
    (snap / "audit.jsonl").write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows), encoding="utf-8")
    M = load(snap / "manifest.json")
    old = M["grading"]["auditor"]["signer"].split()[0]
    sigs = load(snap / "signatures.json")
    dump(snap / "signatures.json", [e for e in sigs if e.get("role") not in ("auditor", "sources")])
    lines = (snap / "allowed_signers").read_text(encoding="utf-8").splitlines()
    (snap / "allowed_signers").write_text("".join(l + "\n" for l in lines if l.split()[:1] != [old]), encoding="utf-8")
    for f in ("audit.jsonl.sig", "manifest.sources.sig"):
        (snap / f).unlink(missing_ok=True)
    key = make_key(keydir, identity)
    au = M["grading"]["auditor"]
    au["sha256"] = sha(snap / "audit.jsonl")
    au["signer"] = f"{identity} <{fingerprint(str(key) + '.pub')}>"
    cl = [{"verdict": r["claimed"]["verdict"], "confidence": r["claimed"].get("confidence"), "checkable": True, "kind": r.get("kind")}
          for r in rows if bool(r.get("checkable", True)) and r.get("kind") != "promise" and isinstance(r.get("claimed"), dict)]
    s = check.evidence_score(cl)
    au["score"] = {k: s.get(k) for k in ("coverage_pct", "contradiction_pct", "band")}
    au["counts"] = {k: s.get(k, 0) for k in ("evidenced", "no_evidence", "contradicted", "contradicted_high")}
    M["counts"] = {"claims": len(rows), "checkable": sum(1 for r in rows if bool(r.get("checkable", True)) and r.get("kind") != "promise")}
    if isinstance(M.get("files"), dict):
        M["files"]["audit.jsonl"] = au["sha256"]
    dump(snap / "manifest.json", M)
    for args in (["--role", "auditor", "--file", "audit.jsonl"], ["--role", "sources"]):
        r = subprocess.run([sys.executable, "-I", str(SIGN_PY), str(snap), *args, "--key", str(key), "--identity", identity], capture_output=True, text=True)
        if r.returncode != 0:
            raise RuntimeError(f"sign.py {args[1]}: {r.stdout}{r.stderr}")
    return snap


def model_keys_file(keystore, path):
    """The service's keys in the published key-list shape of SPEC 14 (keys/model-keys.jsonl: principal, model, key, valid_from, valid_to,
    note), from KeyStore.keys_list(), the list GET /keys serves; what `check.py --keys FILE` reads."""
    out = []
    for k in keystore.keys_list()["keys"]:
        out.append({"principal": k["principal"], "model": k["model"], "key": f"{k['key_type']} {k['key']}", "valid_from": k["valid_from"],
                    "valid_to": k["valid_to"], "note": k.get("note", "")})
    pathlib.Path(path).write_text("".join(json.dumps(e, ensure_ascii=False) + "\n" for e in out), encoding="utf-8")
    return pathlib.Path(path)


def parts_of(snap):
    """The request parts of a document folder: the fixed parts, every page the manifest lists, every source copy it lists."""
    snap = pathlib.Path(snap)
    M = load(snap / "manifest.json")
    out = {n: (snap / n).read_bytes() for n in FIXED if (snap / n).exists()}
    for p in M.get("pages") or []:
        out[p["file"]] = (snap / p["file"]).read_bytes()
    for s in M.get("sources") or []:
        if s.get("file") and (snap / s["file"]).is_file():
            out[s["file"]] = (snap / s["file"]).read_bytes()
    return out


def run_check(snap, keys=None):
    cmd = [sys.executable, "-I", str(CHECK_PY), str(snap)] + (["--keys", str(keys)] if keys else [])
    return subprocess.run(cmd, capture_output=True, text=True)


def add_witness(snap, ans, adder_key, keys=None, identity="r4c-adder"):
    cmd = [sys.executable, "-I", str(ADD_WITNESS), str(snap), str(ans), "--key", str(adder_key), "--identity", identity] + (["--keys", str(keys)] if keys else [])
    return subprocess.run(cmd, capture_output=True, text=True)
