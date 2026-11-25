#!/usr/bin/env python3
"""Measure candidate readability values (BD19 addendum) for every image of the screenshot calibration set and the regression
fixture, INSIDE the claim-witness image, next to the similarity match.screenshot gives it:

    PYTHONPATH=/app python3 measure_gate.py <set dir> <out dir>      # writes <out dir>/measured_gate.json

Readability comes from Tesseract itself: the same command as claim_witness/ocr.py with the `tsv` config appended, which prints
one row per recognised word with its confidence. Candidate values per image (they depend on the image only, never on the page):
  words        words Tesseract returned (non-empty text, conf >= 0)
  mean_conf    mean word confidence, x100 (integer)
  share60_bp   share of words with conf >= 60, in basis points
  words_per_mpx words per megapixel x1 (integer)
  px           page width x height from the TSV's level-1 row
The plain-text OCR is run too (the existing command) and its sha256 is compared with the one in measured.json, so the text the
similarity is computed from is unchanged. Standard library and claim_witness only.
"""
import datetime
import hashlib
import importlib.util
import json
import os
import pathlib
import platform
import subprocess
import sys

from claim_witness import methods, ocr, tarball
from claim_witness.methods import match_screenshot

ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C.UTF-8", "OMP_THREAD_LIMIT": "1"}


def sha(b):
    return hashlib.sha256(b).hexdigest()


def tsv(binary, img):
    done = subprocess.run([binary, "stdin", "stdout", "-l", "eng", "--psm", "3", "tsv"], input=img, capture_output=True,
                          timeout=60, check=False, env=ENV)
    return done.stdout.decode("utf-8", "replace") if done.returncode == 0 else None


def stats(raw):
    words, w, h = [], 0, 0
    for line in raw.splitlines()[1:]:
        f = line.split("\t")
        if len(f) < 12:
            continue
        if f[0] == "1":
            w, h = int(f[8]), int(f[9])
        if f[0] == "5" and f[11].strip() and float(f[10]) >= 0:
            words.append(float(f[10]))
    n = len(words)
    px = w * h
    return {"words": n, "mean_conf_x100": int(round(100 * sum(words) / n)) if n else 0,
            "share60_bp": int(round(10000 * sum(1 for c in words if c >= 60) / n)) if n else 0,
            "words_per_mpx": int(round(n * 1e6 / px)) if px else 0, "px": [w, h]}


def main(src, out):
    src, out = pathlib.Path(src), pathlib.Path(out)
    spec = importlib.util.spec_from_file_location("m", src / "measure.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    doc = json.loads((src / "cases.json").read_text(encoding="utf-8"))
    old = {r["name"]: r for r in json.loads((src / "measured.json").read_text(encoding="utf-8"))["cases"]}
    old["regression-honest-1000x420"] = {"ocr_text_sha256": sha((src / "regression" / "ocr_as_is.txt").read_bytes())}
    binary = os.environ.get("WITNESS_TESSERACT_BIN", "/usr/bin/tesseract")
    o = ocr.Ocr(binary)
    head = {"image": os.environ.get("CAL_IMAGE"), "pod": platform.node(), "tesseract_version": o.version(),
            "ocr_module": ocr.__file__, "methods_code_sha256_of_package": tarball.methods_code_sha256(),
            "library_version_of_package": tarball.library_version(),
            "tesseract_command_text": [binary, "stdin", "stdout", "-l", "eng", "--psm", "3"],
            "tesseract_command_tsv": [binary, "stdin", "stdout", "-l", "eng", "--psm", "3", "tsv"],
            "thresholds_in_image": {"T_bp": match_screenshot.T_BP, "F_bp": match_screenshot.F_BP},
            "cases_json_sha256": sha((src / "cases.json").read_bytes()),
            "started_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
    print("HEAD " + json.dumps(head, sort_keys=True), flush=True)
    items = [dict(c, image_path=src / c["image"], page_path=src / c["page"]) for c in doc["cases"]]
    reg = src / "regression"
    items.append({"name": "regression-honest-1000x420", "kind": "honest", "view": "regression", "width": 1000, "dpr": 1,
                  "format": "png", "article": "fx", "image": "regression/honest-1000x420.png", "image_path": reg / "honest-1000x420.png",
                  "page_path": reg / "page.html"})
    rows = []
    for c in items:
        img, dom = c["image_path"].read_bytes(), c["page_path"].read_bytes()
        text = o.text(img)
        raw = tsv(binary, img)
        prod = o.readability(img) if hasattr(o, "readability") else None   # the witness's own value, once the code has it
        extra = {"ocr_readability": prod} if hasattr(o, "readability") else {}
        r = methods.run("match.screenshot", {}, m.evidence(c, img, text, dom, **extra))
        d = r.detail or {}
        row = {k: c.get(k) for k in ("name", "kind", "view", "width", "dpr", "format", "image")}
        row.update(similarity_bp=d.get("similarity_bp"), ocr_tokens=d.get("ocr_tokens"), image_sha256=sha(img),
                   ocr_text_sha256=sha(text.encode("utf-8")) if text is not None else None,
                   ocr_text_same_as_measured_json=(old[c["name"]]["ocr_text_sha256"] == sha(text.encode("utf-8")))
                   if c["name"] in old and text is not None else None,
                   readability_x100_production=prod, finding_in_image=r.finding, reason_in_image=r.reason,
                   readability=stats(raw) if raw is not None else None)
        rows.append(row)
        s = row["readability"]
        print(f"CASE {row['name']:<36} {row['kind']:<9} {row['view']:<9} w={row['width']:<4} bp={row['similarity_bp']} words={s['words']} "
              f"mean={s['mean_conf_x100']} share60={s['share60_bp']} wpm={s['words_per_mpx']} px={s['px']} "
              f"prod={prod} {r.finding or r.reason} sameText={row['ocr_text_same_as_measured_json']}", flush=True)
    head["finished_at"] = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    result = {"measured_by": "tests_claim/fixtures/calibration/screenshots2/measure_gate.py", "head": head, "cases": rows}
    out.mkdir(parents=True, exist_ok=True)
    data = (json.dumps(result, ensure_ascii=False, indent=1, sort_keys=True) + "\n").encode("utf-8")
    (out / "measured_gate.json").write_bytes(data)
    print(f"DONE {len(rows)} cases, measured_gate.json sha256 {sha(data)}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2]))
