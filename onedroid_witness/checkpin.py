"""The public checker, pinned. The service calls check.py (its functions and its command line), never a copy of its rules: the score a
witness entry carries is computed by the same code a stranger runs. The file is found by path and its sha256 must equal the pin, or
the service refuses to start; the pin moves only with a format revision.
"""
import hashlib
import importlib.util
import pathlib
import subprocess
import sys

CHECK_PY_SHA256 = "7a20c25a526f97339bcc06f7b5f6ae33c0456486c5bb13313085d5b826e25969"  # claims-snapshot 0.6, the auditor-key cut of 13 Nov 2026 (one principal one key in allowed_signers; the sources signature's key is the key inside the audit signature; every signature's key is its principal's listed key); the sources cut was 5ec50d48…, the bound cut af216591…, the carried cut 559e54a9… (K11 reads a witness header carried against the manifest pages, sources and session records, add_witness refuses a mismatch, K3 on a non-object on_request), the K2 cut was f2edc3f4…, erratum 1 0495931b…


def sha256(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()


def load_check(path, expected=CHECK_PY_SHA256):
    path = pathlib.Path(path)
    actual = sha256(path)
    if actual != expected:
        raise RuntimeError(f"check.py at {path} has sha256 {actual}, the service pins {expected}; refusing to start")
    spec = importlib.util.spec_from_file_location("check", str(path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def run_check(check_py, snapshot_dir, keys_file=None):
    """The command line, as a stranger runs it; returns (exit code, the SUMMARY line)."""
    cmd = [sys.executable, "-I", str(check_py), str(snapshot_dir)]
    if keys_file:
        cmd += ["--keys", str(keys_file)]
    r = subprocess.run(cmd, capture_output=True, text=True)
    summary = next((l for l in (r.stdout + r.stderr).splitlines() if l.startswith("SUMMARY")), "")
    return r.returncode, summary
