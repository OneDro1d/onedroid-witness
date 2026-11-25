#!/usr/bin/env python3
"""End-to-end proof, no cluster and no network: the real witness API on memory storage against a fake fetcher makes a page.live
record and a match.text record, each kept and sealed; GET /v1/records/{id}/bundle is unpacked as the server builds it, and
`python3 -m claim_witness.verify --bundle DIR` is run on it (a real process): PASS method-rerun. Then ONE byte of the
observation's text.canonical.txt is changed (and, separately, of rendered.html) and witness-verify must fail by name.

    PYTHONPATH=<repo> python3 tools/e2e_verify_obs.py [--out DIR]
"""
import argparse
import io
import pathlib
import subprocess
import sys
import tarfile
import tempfile
import urllib.request

from tests_claim import helpers as h
from tests_claim.fake_seal import FakeNotary
from tests_claim.fakefetch import page, stack, url_item
from tests_claim.helpers import claim, obj_item, request

OWNER = "dev-key-a-0123456789abcdef"
U = "https://e2e.example/release"
HTML = b"<html><body><h1>Release notes</h1><p>Version 2 ships today with faster search and a new export button.</p></body></html>"
RENDERED = b"<html><body><nav data-witness-hidden='1'>Menu</nav><h1>Release notes</h1><p>Version 2 ships today with faster search and a new export button.</p></body></html>"


def unpack(data, dest):
    with tarfile.open(fileobj=io.BytesIO(data)) as tf:
        for m in tf.getmembers():
            if m.isfile():
                p = dest / m.name
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_bytes(tf.extractfile(m).read())


def witness_verify(bundle):
    p = subprocess.run([sys.executable, "-m", "claim_witness.verify", "--bundle", str(bundle)], capture_output=True, text=True)
    return p.returncode, p.stdout


def show(title, code, out):
    print(f"--- {title}  (exit {code})")
    for line in out.splitlines():
        if line.startswith(("PASS", "FAIL", "SKIP", "RESULT", "observation id")) and "seal-chain" not in line:
            print("   ", line[:230])


def flip(path):
    data = bytearray(path.read_bytes())
    data[len(data) // 2] ^= 1
    path.write_bytes(bytes(data))
    return len(data) // 2


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out")
    a = ap.parse_args()
    root = pathlib.Path(a.out or tempfile.mkdtemp(prefix="e2e-verify-obs-"))
    root.mkdir(parents=True, exist_ok=True)
    clock = h.Clock()
    s, ff, _ = stack(clock=clock, notary=FakeNotary(clock), batch_interval_s=3600)
    try:
        ff.set(U, page(HTML, rendered=RENDERED))
        cases = {
            "page.live": (request(claim("page.live", {"url": U}), [url_item(U)], "public"), []),
            "match.text": (request(claim("match.text", {}), [obj_item("submitted", HTML, "text/html", "copy.html"), url_item(U)],
                                   "public"), [HTML]),
        }
        for name, (body, evidence) in cases.items():
            code, out, _ = s.witness_call(body)
            assert code == 200, out
            keep = {"envelope": out["envelope"]}
            if evidence:
                keep.update(keep_evidence_days=30, evidence=[{"sha256": h.sha(d), "content_b64": h.b64(d)} for d in evidence])
            code, k, _ = s.call("POST", f"/v1/records/{out['record_id']}/keep", keep, key=OWNER)
            assert code == 200, k
            clock.advance(3601)
            s.witness.sealer.tick()
            with urllib.request.urlopen(s.url(f"/v1/records/{out['record_id']}/bundle"), timeout=30) as r:
                data = r.read()
            good = root / name / "good"
            unpack(data, good)
            print(f"\n=== {name}: record {out['record_id']}, finding {h.payload_of(out['envelope'])['predicate']['finding']}")
            print("bundle files:", ", ".join(sorted(str(p.relative_to(good)) for p in good.rglob("*") if p.is_file())))
            show(f"{name}: the bundle as the server built it", *witness_verify(good))
            (obs,) = [p for p in (good / "observations").iterdir()]
            for fname in ("text.canonical.txt", "rendered.html"):
                bad = root / name / f"bad-{fname}"
                unpack(data, bad)
                at = flip(bad / "observations" / obs.name / "files" / fname)
                show(f"{name}: byte {at} of observations/<id>/files/{fname} changed", *witness_verify(bad))
    finally:
        s.close()
        ff.close()
    print("\nbundles kept in", root)


if __name__ == "__main__":
    main()
