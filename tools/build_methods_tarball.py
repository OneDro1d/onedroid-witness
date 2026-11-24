#!/usr/bin/env python3
"""Build the reproducible methods tarball (SPEC §9.4) and print its sha256, the `code_sha256` every pure-Python method's
record carries and GET /v1/methods reports.

    python3 tools/build_methods_tarball.py --out dist/
"""
import argparse
import hashlib
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from claim_witness import tarball  # noqa: E402


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--out", default=".", help="directory to write witness-methods-<version>.tar.gz into")
    a = ap.parse_args(argv)
    out = pathlib.Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    data = tarball.build_methods_tarball()
    path = out / tarball.tarball_name()
    path.write_bytes(data)
    print(f"{hashlib.sha256(data).hexdigest()}  {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
