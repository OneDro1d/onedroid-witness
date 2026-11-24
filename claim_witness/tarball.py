"""The reproducible methods tarball (SPEC §9.4): witness-methods-<version>.tar.gz holding claim_witness/methods/*.py as
witness_methods/*.py, files sorted, mtime 0, uid/gid 0, no user or group names, mode 0644, gzip header mtime 0 and no file
name. Its sha256 is every pure-Python method's `code_sha256`, and GET /v1/methods reports it."""
import functools
import gzip
import hashlib
import io
import pathlib
import tarfile

METHODS_DIR = pathlib.Path(__file__).resolve().parent / "methods"
ARC_ROOT = "witness_methods"


def library_version():
    from .methods import LIBRARY_VERSION
    return LIBRARY_VERSION


def tarball_name():
    return f"witness-methods-{library_version()}.tar.gz"


def _info(name, size=0, is_dir=False):
    ti = tarfile.TarInfo(name)
    ti.size = size
    ti.mtime = 0
    ti.uid = ti.gid = 0
    ti.uname = ti.gname = ""
    ti.mode = 0o755 if is_dir else 0o644
    ti.type = tarfile.DIRTYPE if is_dir else tarfile.REGTYPE
    return ti


SHIPPED = (".py", ".txt")  # the code and the fixed model prompts (methods/prompts/<method>-<version>.txt, B6)


def build_methods_tarball(src=METHODS_DIR):
    src = pathlib.Path(src)
    files = sorted((p for p in src.rglob("*") if p.is_file() and p.suffix in SHIPPED and "__pycache__" not in p.parts),
                   key=lambda p: p.relative_to(src).as_posix())
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as tf:
        for p in files:
            data = p.read_bytes()
            name = f"{ARC_ROOT}/{p.relative_to(src).as_posix()}"
            tf.addfile(_info(name, len(data)), io.BytesIO(data))
    out = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=out, mtime=0, compresslevel=9) as gz:
        gz.write(raw.getvalue())
    return out.getvalue()


@functools.lru_cache(maxsize=1)
def methods_code_sha256():
    return hashlib.sha256(build_methods_tarball()).hexdigest()
