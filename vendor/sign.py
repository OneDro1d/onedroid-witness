#!/usr/bin/env python3
"""sign.py: sign one part of a 0.4 snapshot with an SSH key (SPEC.md 3a). Standard library plus ssh-keygen on PATH.

usage: python3 -I sign.py SNAPSHOT_DIR --role auditor|witness|manifest|sources --file PART --key PRIVATE_KEY --identity NAME [--commit SHA]
  PART      audit.jsonl, or witness/<name>.jsonl; for --role manifest and --role sources it is manifest.json (and --file may be left out)
  NAME      the signer's identity as it stands in allowed_signers (`ssh-keygen -Y verify -I NAME`): an email address or a
            hyphenated name, no spaces (the principal field of allowed_signers ends at the first space)
Writes PART.sig (ssh-keygen -Y sign, namespace claims-snapshot) over the one prescribed line, appends the entry to
signatures.json, and adds the public key to allowed_signers in the snapshot if it is not there yet.
--role manifest (0.6) signs the manifest itself, `claims-snapshot/0.4 manifest manifest.json sha256:<hex>`: do it last, after every
other change to the folder, because any later change to manifest.json breaks it (it does not rewrite the manifest).
--role sources (the sources cut, 13 Nov 2026, NEXT-REVISION 25b) is the AUDITOR's signature over the five bound manifest sections (subject,
sources, pages, grading.profile, grading.sessions): the line `claims-snapshot/0.4 sources manifest.json sha256:<bound digest>`
(check.bound_digest), the file manifest.sources.sig, the entry's sha256 the bound digest itself, so it holds through every witness insertion
where a manifest signature cannot. It needs the key that signed audit.jsonl (an `auditor` entry in signatures.json and the key EMBEDDED in
audit.jsonl.sig, read with check.sshsig_public_key, never a name in allowed_signers: the auditor-key cut, 13 Nov 2026, NEXT-REVISION 31;
audit.jsonl.sig alone, never another auditor entry's file: the one-auditor cut of the same day, NEXT-REVISION 32, so an auditor entry
whose signature file is another name is refused), else it refuses and writes nothing; like --role manifest it does not rewrite the manifest.
Every role (the auditor-key cut): when allowed_signers already lists --identity with a DIFFERENT key it refuses before writing (one principal,
one key; a new key is a new principal).
The private key never enters the snapshot; keep it out of the folder."""
import datetime, json, pathlib, subprocess, sys, tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import check  # noqa: E402


def arg(argv, flag, default=None):
    return argv[argv.index(flag) + 1] if flag in argv else default


def main(argv):
    need = ("--role", "--key", "--identity") if arg(argv, "--role") in ("manifest", "sources") else ("--role", "--file", "--key", "--identity")
    if len(argv) < 2 or any(f not in argv for f in need):
        print(__doc__)
        return 2
    snap = pathlib.Path(argv[1])
    role, part, key, ident = arg(argv, "--role"), arg(argv, "--file"), pathlib.Path(arg(argv, "--key")), arg(argv, "--identity")
    if role not in ("auditor", "witness", "manifest", "sources"):
        print("role must be auditor, witness, manifest or sources", file=sys.stderr)
        return 1
    if role in ("manifest", "sources"):
        if part not in (None, "manifest.json"):
            print(f"--role {role} signs manifest.json only", file=sys.stderr)
            return 1
        part = "manifest.json"
    if any(ch.isspace() for ch in ident) or "," in ident:
        print("the identity is the principal in allowed_signers: no spaces or commas (an email address, or a hyphenated name)", file=sys.stderr)
        return 1
    if snap.resolve() in key.resolve().parents:
        print("the private key is inside the snapshot folder: refused", file=sys.stderr)
        return 1
    fp = snap / part
    pub = pathlib.Path(str(key) + ".pub").read_text(encoding="utf-8").strip()
    key_type, key_b64 = pub.split()[0], pub.split()[1]
    sigs_p = snap / "signatures.json"
    # V2d (the fourteenth re-gate's T02, 13 Nov 2026): a file this tool cannot read at all is refused by name, never a traceback.
    try:
        sigs = json.loads(sigs_p.read_text(encoding="utf-8")) if sigs_p.exists() else []
    except Exception as ex_:
        print(f"signatures.json is unreadable: {ex_}: fix signatures.json before signing, nothing written", file=sys.stderr)
        return 1
    # V2c (the twelfth cut, 13 Nov 2026; the thirteenth re-gate's residual 2): a signatures.json this tool cannot read by shape is refused by
    # name before anything is written, never a traceback, by the rule check.py judges the folder by (check.entry_shape_fault).
    if not isinstance(sigs, list):
        print(f"signatures.json: a JSON {check.json_kind(sigs)} is not a list of signature entries: fix signatures.json before signing, nothing written", file=sys.stderr)
        return 1
    for i_, s_ in enumerate(sigs):
        if not isinstance(s_, dict):
            print(check.entry_not_object_line(i_, s_) + ": fix signatures.json before signing, nothing written", file=sys.stderr)
            return 1
        fault_ = check.entry_shape_fault(s_)
        if fault_:
            print(check.shape_fault_line(i_, fault_) + ": fix signatures.json before signing, nothing written", file=sys.stderr)
            return 1
    try:
        M = json.loads((snap / "manifest.json").read_text(encoding="utf-8"))
    except Exception as ex_:
        print(f"manifest.json is unreadable: {ex_}: fix manifest.json before signing, nothing written", file=sys.stderr)
        return 1
    # V2e (the fifteenth re-gate's T03, 13 Nov 2026): every part of the manifest this tool reads after writing is checked by shape BEFORE the
    # first write; a manifest of another shape used to crash after signatures.json and the .sig were already written.
    shape_ = None
    if not isinstance(M, dict):
        shape_ = f"a JSON {check.json_kind(M)} is not an object"
    elif "grading" in M and not isinstance(M["grading"], dict):
        shape_ = f"grading is a JSON {check.json_kind(M['grading'])}, not an object"
    elif isinstance(M.get("grading"), dict):
        g_ = M["grading"]
        if g_.get("auditor") and not isinstance(g_["auditor"], dict):
            shape_ = f"grading.auditor is a JSON {check.json_kind(g_['auditor'])}, not an object"
        elif g_.get("witnesses") and not isinstance(g_["witnesses"], list):
            shape_ = f"grading.witnesses is a JSON {check.json_kind(g_['witnesses'])}, not a list"
        else:
            bad_w_ = next((i_ for i_, w_ in enumerate(g_.get("witnesses") or []) if not isinstance(w_, dict)), None)
            if bad_w_ is not None:
                shape_ = f"grading.witnesses[{bad_w_}] is a JSON {check.json_kind(g_['witnesses'][bad_w_])}, not an object"
    if shape_:
        print(f"manifest.json: {shape_}: fix manifest.json before signing, nothing written", file=sys.stderr)
        return 1
    allowed = snap / "allowed_signers"
    given = f"{key_type} {key_b64}"
    keys = check.allowed_keys(allowed) if allowed.exists() else {}
    if role == "sources":
        # the sources role is the auditor's: an `auditor` entry must exist, and this key must be the one EMBEDDED in that entry's signature
        # file (check.sshsig_public_key; the auditor-key cut, 13 Nov 2026, NEXT-REVISION 31: a name in allowed_signers is not a key, the
        # ninth re-gate's S13 put a forger's key under the auditor's name); refused before anything is written
        a_entries = [s for s in sigs if s.get("role") == "auditor"]
        if not a_entries:
            print("the sources role is the auditor's: sign audit.jsonl first", file=sys.stderr)
            return 1
        # the one-auditor cut (13 Nov 2026, NEXT-REVISION 32; the tenth re-gate's K16): audit.jsonl has one signature file, audit.jsonl.sig,
        # and the key is read from that one and no other (a second auditor entry under its own file was the forger's door)
        odd = next((s for s in a_entries if s.get("signature") != "audit.jsonl.sig"), None)
        if odd is not None:
            print(f"the auditor's signature file is audit.jsonl.sig, not '{odd.get('signature')}'", file=sys.stderr)
            return 1
        a_key = check.sshsig_public_key(snap / "audit.jsonl.sig")
        if not a_key:
            print("the sources role is the auditor's: audit.jsonl.sig is missing or not an SSH signature", file=sys.stderr)
            return 1
        if given != a_key:
            print("the sources role is the auditor's: use the key that signed audit.jsonl", file=sys.stderr)
            return 1
        h = check.bound_digest(M)
        sig_rel = "manifest.sources.sig"
    else:
        h = check.sha256(fp)
        sig_rel = part + ".sig"
    if role == "auditor":
        # the one-auditor cut (13 Nov 2026, NEXT-REVISION 32; the tenth re-gate's K16): one auditor entry in a record. The same identity
        # re-signing replaces its entry (below); another identity is refused before anything is written, so a second auditor entry is never
        # made by this tool (K13 O1 fails one in a record anyway).
        other = next((s for s in sigs if s.get("role") == "auditor" and (s.get("signer") or {}).get("name") != ident), None)
        if other is not None:
            print(f"one auditor: audit.jsonl is already signed by '{(other.get('signer') or {}).get('name')}'; remove that entry first to re-sign under another name", file=sys.stderr)
            return 1
    # the auditor-key cut: one principal, one key. A second key under a listed name would make K13 fail the record (A1) and would let
    # `ssh-keygen -Y verify -I <name>` accept either key; refused before anything is written
    if keys.get(ident, set()) - {given}:
        print(f"principal '{ident}' already holds another key in allowed_signers: one principal, one key (a new key is a new principal)", file=sys.stderr)
        return 1
    audit_h = check.sha256(snap / "audit.jsonl")
    line = check.signed_line(role, part, h, audit_h)
    fingerprint = subprocess.run(["ssh-keygen", "-lf", str(key) + ".pub"], capture_output=True, text=True, check=True).stdout.split()[1]
    with tempfile.TemporaryDirectory() as td:
        msg = pathlib.Path(td) / "line"
        msg.write_text(line, encoding="utf-8")
        subprocess.run(["ssh-keygen", "-Y", "sign", "-f", str(key), "-n", check.SIGN_NAMESPACE, str(msg)], check=True, capture_output=True)
        sig = (pathlib.Path(td) / "line.sig").read_bytes()
    (snap / sig_rel).write_bytes(sig)
    entry_line = f'{ident} namespaces="{check.SIGN_NAMESPACE}" {key_type} {key_b64}\n'
    existing = allowed.read_text(encoding="utf-8") if allowed.exists() else ""
    if entry_line not in existing:
        allowed.write_text(existing + entry_line, encoding="utf-8")
    sigs = [s for s in sigs if not (s.get("file") == part and s.get("role") == role)]
    sigs.append({"role": role, "file": part, "sha256": h, "line": line,
                 "signer": {"name": ident, "key_id": fingerprint, "kind": key_type},
                 "signed_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                 "signature": sig_rel, "commit": arg(argv, "--commit")})
    sigs_p.write_text(json.dumps(sigs, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    # the manifest's signer field for this part (never for the manifest itself: the manifest signature is over its bytes, the sources
    # signature over its bound sections, and neither rewrites it)
    g = M.get("grading", {})
    if role == "auditor" and g.get("auditor"):
        g["auditor"]["signer"] = f"{ident} <{fingerprint}>"
    for w in g.get("witnesses") or []:
        if w.get("file") == part:
            w["signer"] = f"{ident} <{fingerprint}>"
    if role not in ("manifest", "sources"):
        (snap / "manifest.json").write_text(json.dumps(M, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    r = subprocess.run(["ssh-keygen", "-Y", "verify", "-f", str(allowed), "-I", ident, "-n", check.SIGN_NAMESPACE, "-s", str(snap / sig_rel)],
                       input=line.encode(), capture_output=True)
    print(f"{part}: signed as {ident} ({fingerprint}); self-verify exit {r.returncode}: {(r.stdout + r.stderr).decode(errors='replace').strip()}")
    return 0 if r.returncode == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
