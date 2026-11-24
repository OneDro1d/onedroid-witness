#!/usr/bin/env python3
"""Measure the screenshot calibration set with the witness's own OCR and match.screenshot code. Run it INSIDE the
claim-witness image, so the OCR is the image's Tesseract, language data and command line (claim_witness/ocr.py):

    PYTHONPATH=/app python3 measure.py <set dir> <out dir>      # writes <out dir>/measured.json, prints a line per case

For every case: the image bytes go through ocr.Ocr(WITNESS_TESSERACT_BIN).text (as service.py does for match.screenshot),
the page's DOM becomes an observation through observation.from_capture (as the witness builds one from a fetcher capture,
so the page side is its text.canonical.txt), and methods.run("match.screenshot") compares them. The similarity, the token
counts and the OCR text are recorded; the finding under the thresholds the image carries is recorded too, for reference.
Standard library and claim_witness only. Every file's sha256 is checked against cases.json first.
"""
import datetime
import hashlib
import json
import os
import pathlib
import platform
import sys
import time

from claim_witness import methods, observation, ocr, tarball
from claim_witness.methods import match_screenshot


def sha(b):
    return hashlib.sha256(b).hexdigest()


def evidence(case, img, ocr_text, dom):
    manifest = {"requested_url": f"https://calibration.example/{case['article']}", "final_url": None, "redirects": [],
                "fetched_at": "2026-11-24T00:00:00Z", "fetch_ms": 0, "status": 200, "resolved_ips": [], "tls": None,
                "robots": None, "fetcher": {}, "files": [{"name": "response.body", "media_type": "text/html"},
                                                         {"name": "rendered.html", "media_type": "text/html"}]}
    pred, files = observation.from_capture(manifest, {"response.body": dom, "rendered.html": dom}, "public")
    mt = "image/png" if case["format"] == "png" else "image/jpeg"
    return {"submitted": {"slot": "submitted", "kind": "object", "sha256": sha(img), "media_type": mt, "name": case["name"],
                          "data": img, "ocr_text": ocr_text},
            "page": {"slot": "page", "kind": "observation", "id": "0" * 64, "manifest": pred, "files": files}}


def main(src, out):
    src, out = pathlib.Path(src), pathlib.Path(out)
    doc = json.loads((src / "cases.json").read_text(encoding="utf-8"))
    binary = os.environ.get("WITNESS_TESSERACT_BIN", "/usr/bin/tesseract")
    o = ocr.Ocr(binary)
    if not o.available():
        print(f"FAIL tesseract not available at {binary}")
        return 2
    traineddata = sorted(pathlib.Path("/usr/share/tesseract-ocr").rglob("eng.traineddata"))
    head = {"image": os.environ.get("CAL_IMAGE"), "pod": platform.node(), "python": platform.python_version(),
            "tesseract_bin": binary, "tesseract_version": o.version(),
            "tesseract_command": [binary, "stdin", "stdout", "-l", "eng", "--psm", "3"],
            "eng_traineddata": [{"path": str(p), "sha256": sha(p.read_bytes())} for p in traineddata],
            "methods_code_sha256_in_image": tarball.methods_code_sha256(), "library_version_in_image": tarball.library_version(),
            "thresholds_in_image": {"T_bp": match_screenshot.T_BP, "F_bp": match_screenshot.F_BP},
            "set": doc["meta"], "cases_json_sha256": sha((src / "cases.json").read_bytes()),
            "started_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
    print("HEAD " + json.dumps(head, sort_keys=True), flush=True)
    rows = []
    for case in doc["cases"]:
        img, dom = (src / case["image"]).read_bytes(), (src / case["page"]).read_bytes()
        if sha(img) != case["image_sha256"] or sha(dom) != case["page_sha256"]:
            print(f"FAIL sha256 mismatch for {case['name']}")
            return 3
        t0 = time.monotonic()
        text = o.text(img)
        ms = int((time.monotonic() - t0) * 1000)
        r = methods.run("match.screenshot", {}, evidence(case, img, text, dom))
        d = r.detail or {}
        row = {k: case[k] for k in ("name", "kind", "article", "width", "dpr", "font", "view", "format", "image", "image_sha256",
                                    "page", "page_sha256")}
        row.update(similarity_bp=d.get("similarity_bp"), ocr_tokens=d.get("ocr_tokens"), page_tokens=d.get("page_tokens"),
                   window_tokens=d.get("window_tokens"), finding_in_image=r.finding, reason_in_image=r.reason, ocr_ms=ms,
                   ocr_text=text, ocr_text_sha256=sha(text.encode("utf-8")) if text is not None else None)
        rows.append(row)
        print(f"CASE {row['name']:<36} {row['kind']:<9} w={row['width']:<4} {row['format']:<3} {row['view']:<4} "
              f"bp={row['similarity_bp']} ocr_tokens={row['ocr_tokens']} window={row['window_tokens']} "
              f"page={row['page_tokens']} {r.finding or r.reason} {ms}ms", flush=True)
    head["finished_at"] = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    result = {"measured_by": "tests_claim/fixtures/calibration/screenshots/measure.py", "head": head, "cases": rows}
    out.mkdir(parents=True, exist_ok=True)
    data = (json.dumps(result, ensure_ascii=False, indent=1, sort_keys=True) + "\n").encode("utf-8")
    (out / "measured.json").write_bytes(data)
    print(f"DONE {len(rows)} cases, measured.json sha256 {sha(data)}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2]))
