"""python3 -m claim_witness.vectors --check [--file vectors.json] | --write"""
import argparse
import json
import pathlib
import sys

from . import VECTORS, check, generate


def main(argv=None):
    ap = argparse.ArgumentParser(prog="claim_witness.vectors")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--check", action="store_true", help="reproduce every vector in the witness and in witness-verify")
    g.add_argument("--write", action="store_true", help="regenerate vectors.json from the current code")
    ap.add_argument("--file", default=str(VECTORS))
    a = ap.parse_args(argv)
    path = pathlib.Path(a.file)
    if a.write:
        path.write_text(json.dumps(generate(), ensure_ascii=False, indent=1, sort_keys=True) + "\n", encoding="utf-8")
        print(f"wrote {path}")
        return 0
    doc = json.loads(path.read_text(encoding="utf-8"))
    return 1 if check(doc, sys.stdout) else 0


if __name__ == "__main__":
    sys.exit(main())
