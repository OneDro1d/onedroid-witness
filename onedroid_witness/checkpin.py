"""The public checker, pinned. The service calls check.py (its functions and its command line), never a copy of its rules: the score a
witness entry carries is computed by the same code a stranger runs. The file is found by path and its sha256 must equal the pin, or
the service refuses to start; the pin moves only with a format revision.
"""
import hashlib
import importlib.util
import pathlib
import subprocess
import sys

CHECK_PY_SHA256 = "0495931bc60509143bf84a7c95216838382c1e9f81ba52b37e7bff1c495013bf"  # claims-snapshot 0.6, erratum 1 (12 Nov 2026)


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
