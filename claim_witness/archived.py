"""The archive of every methods tarball the witness could have signed with (README_CLAIM decision 161).

A record names the tarball it was signed with in `method.code_sha256`, and witness-verify refuses any other. The bundle builder
reads that tarball from claim_witness/methods_archive/<sha256>.tar.gz (index.json lists them with the library version and the
git commit each is rebuilt from, by tools/archive_methods_tarball.py). The package directory is copied whole into the image
(Dockerfile.claim), so the deployed server carries it. Nothing here is signed or hashed into a record: it is a lookup of bytes
whose sha256 is checked on every read, and a file that is not the sha256 it is named by is treated as absent."""
import functools
import hashlib
import json
import pathlib
import re

ARCHIVE_DIR = pathlib.Path(__file__).resolve().parent / "methods_archive"
_SHA = re.compile(r"[0-9a-f]{64}")


@functools.lru_cache(maxsize=1)
def _index():
    try:
        entries = json.loads((ARCHIVE_DIR / "index.json").read_text())["entries"]
    except (OSError, ValueError, KeyError, TypeError):
        return {}
    return {e["sha256"]: e["library_version"] for e in entries
            if isinstance(e, dict) and isinstance(e.get("sha256"), str) and isinstance(e.get("library_version"), str)}


def get(code_sha256):
    """(library_version, tarball bytes) for an archived methods tarball, or None: unknown sha256, a file missing, or a file
    whose sha256 is not the one it is named by (never a wrong tarball)."""
    if not isinstance(code_sha256, str) or not _SHA.fullmatch(code_sha256):
        return None
    version = _index().get(code_sha256)
    if version is None:
        return None
    try:
        data = (ARCHIVE_DIR / f"{code_sha256}.tar.gz").read_bytes()
    except OSError:
        return None
    return (version, data) if hashlib.sha256(data).hexdigest() == code_sha256 else None


def tarball_name(library_version):
    return f"witness-methods-{library_version}.tar.gz"
