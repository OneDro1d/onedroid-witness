#!/usr/bin/env python3
"""The server-side archive of every methods tarball the witness has signed with (README_CLAIM decision 161).

A record names the tarball it was signed with (`method.code_sha256`); witness-verify refuses any other. The bundle builder
therefore reads the record's tarball from claim_witness/methods_archive/<sha256>.tar.gz, not today's build. Each file is
rebuilt from the git commit named in index.json by that commit's own builder (claim_witness/tarball.py at that commit,
run over that commit's claim_witness/methods):

    python3 tools/archive_methods_tarball.py rebuild COMMIT [--out FILE]   # rebuild one tarball, print its sha256 and version
    python3 tools/archive_methods_tarball.py add [COMMIT]                  # archive COMMIT's tarball (default HEAD)
    python3 tools/archive_methods_tarball.py check                         # every entry: file, sha256, rebuild from its commit

Run `add` for every methods change, in the commit after the one that changes claim_witness/methods (the commit is then the
one the tarball is rebuilt from); tests_claim/test_methods_archive.py fails until the current build is archived."""
import argparse
import hashlib
import io
import json
import pathlib
import subprocess
import sys
import tarfile
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
ARCHIVE = ROOT / "claim_witness" / "methods_archive"
INDEX = ARCHIVE / "index.json"

# runs inside the extracted commit, python -I: that commit's own builder
_BUILD = ("import sys; sys.path.insert(0, sys.argv[1]); from claim_witness import tarball; "
          "sys.stdout.buffer.write(tarball.library_version().encode() + b'\\n' + tarball.build_methods_tarball())")


def git(*args):
    return subprocess.run(["git", "-C", str(ROOT), *args], check=True, capture_output=True).stdout


def rebuild(commit):
    """(full commit sha, library version, tarball bytes) built from COMMIT by the builder that COMMIT carries."""
    full = git("rev-parse", "--verify", f"{commit}^{{commit}}").decode().strip()
    with tempfile.TemporaryDirectory(prefix="methods-rebuild-") as d:
        with tarfile.open(fileobj=io.BytesIO(git("archive", full, "claim_witness"))) as tf:
            tf.extractall(d, filter="data")
        out = subprocess.run([sys.executable, "-I", "-c", _BUILD, d], capture_output=True, check=True).stdout
    version, _, data = out.partition(b"\n")
    return full, version.decode(), data


def load_index():
    return json.loads(INDEX.read_text()) if INDEX.is_file() else {"entries": []}


def write_index(index):
    index["entries"].sort(key=lambda e: (e["first_commit_date"], e["sha256"]))
    INDEX.write_text(json.dumps(index, indent=1) + "\n")


def add(commit):
    full, version, data = rebuild(commit)
    sha = hashlib.sha256(data).hexdigest()
    index = load_index()
    if any(e["sha256"] == sha for e in index["entries"]):
        print(f"{sha}  already archived (library {version})")
        return 0
    ARCHIVE.mkdir(exist_ok=True)
    (ARCHIVE / f"{sha}.tar.gz").write_bytes(data)
    date = git("show", "-s", "--format=%cI", full).decode().strip()
    index["entries"].append({"sha256": sha, "library_version": version, "commit": full, "first_commit_date": date})
    write_index(index)
    print(f"{sha}  library {version}  from {full}")
    return 0


def check():
    bad = 0
    for e in load_index()["entries"]:
        have = (ARCHIVE / f"{e['sha256']}.tar.gz").read_bytes()
        _, version, data = rebuild(e["commit"])
        ok = hashlib.sha256(have).hexdigest() == e["sha256"] and have == data and version == e["library_version"]
        bad += not ok
        print(("OK   " if ok else "FAIL ") + f"{e['sha256']}  {e['library_version']}  {e['commit'][:7]}")
    return 1 if bad else 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("rebuild")
    r.add_argument("commit")
    r.add_argument("--out")
    sub.add_parser("add").add_argument("commit", nargs="?", default="HEAD")
    sub.add_parser("check")
    a = ap.parse_args(argv)
    if a.cmd == "rebuild":
        full, version, data = rebuild(a.commit)
        if a.out:
            pathlib.Path(a.out).write_bytes(data)
        print(f"{hashlib.sha256(data).hexdigest()}  library {version}  from {full}")
        return 0
    return add(a.commit) if a.cmd == "add" else check()


if __name__ == "__main__":
    sys.exit(main())
