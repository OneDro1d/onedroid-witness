#!/usr/bin/env python3
"""sign.py: sign one part of a 0.4 snapshot with an SSH key (SPEC.md 3a). Standard library plus ssh-keygen on PATH.

usage: python3 -I sign.py SNAPSHOT_DIR --role auditor|witness|manifest --file PART --key PRIVATE_KEY --identity NAME [--commit SHA]
  PART      audit.jsonl, or witness/<name>.jsonl; for --role manifest it is manifest.json (and --file may be left out)
  NAME      the signer's identity as it stands in allowed_signers (`ssh-keygen -Y verify -I NAME`): an email address or a
            hyphenated name, no spaces (the principal field of allowed_signers ends at the first space)
Writes PART.sig (ssh-keygen -Y sign, namespace claims-snapshot) over the one prescribed line, appends the entry to
signatures.json, and adds the public key to allowed_signers in the snapshot if it is not there yet.
--role manifest (0.6) signs the manifest itself, `claims-snapshot/0.4 manifest manifest.json sha256:<hex>`: do it last, after every
other change to the folder, because any later change to manifest.json breaks it (it does not rewrite the manifest).
The private key never enters the snapshot; keep it out of the folder."""
import datetime, json, pathlib, subprocess, sys, tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import check  # noqa: E402


def arg(argv, flag, default=None):
    return argv[argv.index(flag) + 1] if flag in argv else default


def main(argv):
    need = ("--role", "--key", "--identity") if arg(argv, "--role") == "manifest" else ("--role", "--file", "--key", "--identity")
    if len(argv) < 2 or any(f not in argv for f in need):
        print(__doc__)
        return 2
    snap = pathlib.Path(argv[1])
    role, part, key, ident = arg(argv, "--role"), arg(argv, "--file"), pathlib.Path(arg(argv, "--key")), arg(argv, "--identity")
    if role not in ("auditor", "witness", "manifest"):
        print("role must be auditor, witness or manifest", file=sys.stderr)
        return 1
    if role == "manifest":
        if part not in (None, "manifest.json"):
            print("--role manifest signs manifest.json only", file=sys.stderr)
            return 1
        part = "manifest.json"
    if any(ch.isspace() for ch in ident) or "," in ident:
        print("the identity is the principal in allowed_signers: no spaces or commas (an email address, or a hyphenated name)", file=sys.stderr)
        return 1
    if snap.resolve() in key.resolve().parents:
        print("the private key is inside the snapshot folder: refused", file=sys.stderr)
        return 1
    fp = snap / part
    h = check.sha256(fp)
    audit_h = check.sha256(snap / "audit.jsonl")
    line = check.signed_line(role, part, h, audit_h)
    pub = pathlib.Path(str(key) + ".pub").read_text(encoding="utf-8").strip()
    key_type, key_b64 = pub.split()[0], pub.split()[1]
    fingerprint = subprocess.run(["ssh-keygen", "-lf", str(key) + ".pub"], capture_output=True, text=True, check=True).stdout.split()[1]
    with tempfile.TemporaryDirectory() as td:
        msg = pathlib.Path(td) / "line"
        msg.write_text(line, encoding="utf-8")
        subprocess.run(["ssh-keygen", "-Y", "sign", "-f", str(key), "-n", check.SIGN_NAMESPACE, str(msg)], check=True, capture_output=True)
        sig = (pathlib.Path(td) / "line.sig").read_bytes()
    sig_rel = part + ".sig"
    (snap / sig_rel).write_bytes(sig)
    allowed = snap / "allowed_signers"
    entry_line = f'{ident} namespaces="{check.SIGN_NAMESPACE}" {key_type} {key_b64}\n'
    existing = allowed.read_text(encoding="utf-8") if allowed.exists() else ""
    if entry_line not in existing:
        allowed.write_text(existing + entry_line, encoding="utf-8")
    sigs_p = snap / "signatures.json"
    sigs = json.loads(sigs_p.read_text(encoding="utf-8")) if sigs_p.exists() else []
    sigs = [s for s in sigs if not (s.get("file") == part and s.get("role") == role)]
    sigs.append({"role": role, "file": part, "sha256": h, "line": line,
                 "signer": {"name": ident, "key_id": fingerprint, "kind": key_type},
                 "signed_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                 "signature": sig_rel, "commit": arg(argv, "--commit")})
    sigs_p.write_text(json.dumps(sigs, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    # the manifest's signer field for this part (never for the manifest itself: the signature is over its bytes)
    M = json.loads((snap / "manifest.json").read_text(encoding="utf-8"))
    g = M.get("grading", {})
    if role == "auditor" and g.get("auditor"):
        g["auditor"]["signer"] = f"{ident} <{fingerprint}>"
    for w in g.get("witnesses") or []:
        if w.get("file") == part:
            w["signer"] = f"{ident} <{fingerprint}>"
    if role != "manifest":
        (snap / "manifest.json").write_text(json.dumps(M, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    r = subprocess.run(["ssh-keygen", "-Y", "verify", "-f", str(allowed), "-I", ident, "-n", check.SIGN_NAMESPACE, "-s", str(snap / sig_rel)],
                       input=line.encode(), capture_output=True)
    print(f"{part}: signed as {ident} ({fingerprint}); self-verify exit {r.returncode}: {(r.stdout + r.stderr).decode(errors='replace').strip()}")
    return 0 if r.returncode == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
