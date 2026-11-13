"""Keys and signatures (contract 3.4, 3b.5, section 10): one ed25519 key per model identity, held by the service as files in one
directory (a Kubernetes Secret mount in the cluster, a folder on a machine in private mode); SSH signatures with ssh-keygen under the
namespace claims-snapshot, as sign.py and check.py use; a key list that records every key ever used with its validity window and never
deletes one. The signature proves "the service says model X answered", never that a model signed.
"""
import datetime
import json
import os
import pathlib
import re
import subprocess

NAMESPACE = "claims-snapshot"


def principal_of(model_id):
    """A hyphenated principal from a model id: onedroid-witness-<slug> (SPEC.md:88: no slash, no space)."""
    slug = re.sub(r"[^a-z0-9]+", "-", model_id.lower()).strip("-")
    return f"onedroid-witness-{slug}"


def now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class KeyStore:
    """Keys as files: <dir>/<principal> (the seed, mode 0600) and <dir>/<principal>.pub; <dir>/keys.json the list."""

    def __init__(self, directory, service_name="onedroid-witness"):
        self.dir = pathlib.Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.list_path = self.dir / "keys.json"
        self.service_name = service_name

    def _list(self):
        try:
            return json.loads(self.list_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {"keys": []}

    def _save_list(self, d):
        tmp = self.list_path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(d, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
        os.replace(tmp, self.list_path)

    def fingerprint(self, pub_path):
        out = subprocess.run(["ssh-keygen", "-lf", str(pub_path)], capture_output=True, text=True, check=True).stdout.split()
        return out[1]

    def key_for(self, model_id):
        """The current key of a model identity, minted on first use: (principal, private path, allowed_signers line, fingerprint, type)."""
        principal = principal_of(model_id)
        priv = self.dir / principal
        d = self._list()
        if priv.exists():
            # a volume mounted with fsGroup is re-permissioned by Kubernetes on every pod start (g+rw on files): a private key then
            # reads 0660 and ssh-keygen refuses it ("UNPROTECTED PRIVATE KEY FILE", exit 255; seen on dev 12 Nov 2026 after the
            # 0.1.1 rollout). The mode is repaired before every use; k8s/dev.yaml also sets fsGroupChangePolicy OnRootMismatch.
            os.chmod(priv, 0o600)
            if priv.with_suffix(".pub").exists():
                os.chmod(priv.with_suffix(".pub"), 0o644)
        if not priv.exists():
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", principal, "-f", str(priv)], check=True)
            os.chmod(priv, 0o600)
            pub = priv.with_suffix(".pub").read_text(encoding="utf-8").split()
            d["keys"].append({"principal": principal, "model": model_id, "key_type": pub[0], "key": pub[1],
                              "key_id": self.fingerprint(priv.with_suffix(".pub")), "valid_from": now(), "valid_to": None,
                              "note": f"minted by {self.service_name}; the signature proves the service says this model answered, never that a model signed"})
            self._save_list(d)
        pub = priv.with_suffix(".pub").read_text(encoding="utf-8").split()
        line = f'{principal} namespaces="{NAMESPACE}" {pub[0]} {pub[1]}'
        return principal, priv, line, self.fingerprint(priv.with_suffix(".pub")), pub[0]

    def sign(self, priv, text, sig_path):
        r = subprocess.run(["ssh-keygen", "-Y", "sign", "-f", str(priv), "-n", NAMESPACE], input=text.encode(), capture_output=True, check=True)
        pathlib.Path(sig_path).write_bytes(r.stdout)

    def keys_list(self):
        """GET /keys: every key ever used, with valid_from and valid_to; never deleted (3b.5)."""
        return self._list()

    def retire(self, model_id):
        """A rotation: the current key's valid_to is set, the file is renamed with its key id, the next use mints a new key and a new line."""
        principal = principal_of(model_id)
        d = self._list()
        for k in d["keys"]:
            if k["principal"] == principal and k["valid_to"] is None:
                k["valid_to"] = now()
                priv = self.dir / principal
                if priv.exists():
                    tag = k["key_id"].replace("SHA256:", "").replace("/", "_").replace("+", "-")[:16]
                    priv.rename(self.dir / f"{principal}.retired.{tag}")
                    priv.with_suffix(".pub").rename(self.dir / f"{principal}.retired.{tag}.pub")
        self._save_list(d)


def verify(allowed_signers_path, identity, text, sig_path):
    """ssh-keygen -Y verify over the one-line text: (ok, output). Used to refuse an unsigned or broken auditor part before any model call."""
    r = subprocess.run(["ssh-keygen", "-Y", "verify", "-f", str(allowed_signers_path), "-I", identity, "-n", NAMESPACE, "-s", str(sig_path)],
                       input=text, capture_output=True, text=True)
    return r.returncode == 0, (r.stdout + r.stderr).strip()
