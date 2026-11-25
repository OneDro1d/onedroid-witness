#!/usr/bin/env python3
"""Exploratory: how do Tesseract settings change match.screenshot's similarity on the calibration set? Run INSIDE the
claim-witness image like measure.py:

    PYTHONPATH=/app python3 ocrvar.py <set dir> <out json> [variant ...]

A variant is a name from VARIANTS (extra tesseract arguments after the witness's own `stdin stdout -l eng --psm 3`). Writes
{variant: {case name: similarity_bp}} and prints min/max per kind and per image kind (full-size or resampled)."""
import importlib.util
import json
import pathlib
import subprocess
import sys

from claim_witness import methods

VARIANTS = {
    "asis": [],
    "dpi300": ["--dpi", "300"],
    "dpi200": ["--dpi", "200"],
    "dpi150": ["--dpi", "150"],
    "dpi96": ["--dpi", "96"],
    "psm6": ["--psm", "6"],
}


def tess(img, extra):
    cmd = ["/usr/bin/tesseract", "stdin", "stdout", "-l", "eng", "--psm", "3"] + extra
    done = subprocess.run(cmd, input=img, capture_output=True, timeout=60, check=False,
                          env={"PATH": "/usr/bin:/bin", "LC_ALL": "C.UTF-8", "OMP_THREAD_LIMIT": "1"})
    return done.stdout.decode("utf-8", "replace") if done.returncode == 0 else None


def main(src, out, names):
    src = pathlib.Path(src)
    spec = importlib.util.spec_from_file_location("m", src / "measure.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    doc = json.loads((src / "cases.json").read_text(encoding="utf-8"))
    res = {}
    for v in names:
        res[v] = {}
        for c in doc["cases"]:
            img, dom = (src / c["image"]).read_bytes(), (src / c["page"]).read_bytes()
            text = tess(img, VARIANTS[v])
            r = methods.run("match.screenshot", {}, m.evidence(c, img, text, dom))
            res[v][c["name"]] = (r.detail or {}).get("similarity_bp")
        print("VARIANT", v, flush=True)
        for kind in ("honest", "forgery", "unrelated"):
            for sub, pred in (("all", lambda c: True), ("fullsize", lambda c: "-s" not in c["view"]), ("resampled", lambda c: "-s" in c["view"])):
                vals = [res[v][c["name"]] for c in doc["cases"] if c["kind"] == kind and pred(c) and res[v][c["name"]] is not None]
                if vals:
                    print(f"  {kind:<9} {sub:<9} n={len(vals):<3} min={min(vals)} max={max(vals)}", flush=True)
    pathlib.Path(out).write_text(json.dumps(res, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2], sys.argv[3:] or list(VARIANTS))
