#!/usr/bin/env python3
"""A local end-to-end run of slice B3, through the real HTTP API, with no network and no real armarium:

  1. a public quote.in-source check (POST /v1/witness), with an agent signature;
  2. keep it with its evidence (POST /v1/records/{id}/keep);
  3. a batch close by the sealer, with the real notary client (claim_witness.notary.HttpNotary) against a local HTTPS fake of
     POST /notary/v1/seals (final:false on base-sepolia until it finalizes), and the real armarium client (ndim.HttpArmarium)
     against a local HTTPS fake of the object service (one claimant chain per owner, created in the background);
  4. GET /v1/records/{id}/seal: anchored;
  5. witness-verify on the record's bundle: PASS seal;
  6. the same with one path hash changed: FAIL seal.

    .venv/bin/python tools/e2e_keep_seal.py [--postgres]
"""
import argparse
import io
import json
import pathlib
import sys
import tarfile
import tempfile
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from claim_witness import ndim, notary, verify  # noqa: E402
from tests_claim import helpers as h  # noqa: E402
from tests_claim.fake_armarium_real import CASE, RealNotary, RealObjects  # noqa: E402
from tests_claim.fake_seal import make_tls  # noqa: E402


def say(text):
    print(text, flush=True)


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("--postgres", action="store_true", help="run on a throwaway Postgres 16 (pgserver or initdb on PATH)")
    a = ap.parse_args(argv)
    tls = make_tls()
    nsrv, asrv = RealNotary(tls), RealObjects(tls)
    pg, storage = None, None
    if a.postgres:
        from tests_claim.test_storage import ThrowawayPostgres, pg_bin_dir
        from claim_witness import pg as pg_mod
        pg = ThrowawayPostgres(pg_bin_dir())
        storage = pg_mod.PostgresStorage(pg.dsn)
        storage.migrate()
    clock = h.Clock()
    n = notary.from_env({"WITNESS_NOTARY_URL": nsrv.url, "WITNESS_NOTARY_TOKEN_FILE": nsrv.token_file,
                         "WITNESS_NOTARY_CA_FILE": nsrv.ca_file})
    arm, case = ndim.from_env({"ARMARIUM_URL": asrv.url, "ARMARIUM_TOKEN_FILE": asrv.token_file, "ARMARIUM_CA_FILE": asrv.ca_file,
                               "ARMARIUM_CASE": CASE})
    s = h.Stack(storage=storage, clock=clock, config_overrides={"notary": n, "armarium": arm, "ndim_case": case,
                                                                "batch_interval_s": 3600})
    try:
        say(f"storage: {'postgres 16' if a.postgres else 'memory'}; notary {nsrv.url} (HttpNotary); armarium {asrv.url} "
            "(HttpArmarium)")
        seed = h.seed(70)
        code, reg, _ = s.call("POST", "/v1/agent-keys", {"public_key": h.b64(h.public_of(seed))})
        src = b"The witness is not a judge of truth. It signs one answer."
        c = h.claim("quote.in-source", {"quote": "not a judge of truth"})
        ev = [h.obj_item("source", src, name="source.txt")]
        body = h.request(c, ev, "public")
        body["agent"] = h.agent_block(seed, reg["agent_key_id"], "witness:test", c, ev, "nonce-e2e-0001", h.iso(clock()))
        code, out, _ = s.witness_call(body)
        say(f"1. check: {code} record {out['record_id']} outcome {h.payload_of(out['envelope'])['predicate']['outcome']} "
            f"seal {out['seal']}")
        code, k, _ = s.call("POST", f"/v1/records/{out['record_id']}/keep",
                            {"envelope": out["envelope"], "keep_evidence_days": 30,
                             "evidence": [{"sha256": h.sha(src), "content_b64": h.b64(src)}]})
        say(f"2. keep: {code} link {k['link']} evidence_key returned: {'evidence_key' in k}; ndim {k['ndim']['state']}")
        clock.advance(3601)
        closed = s.witness.sealer.tick()
        say("   first tick: base-sepolia answered final:false, so the seal is pending; the chain finalizes, the next tick asks again")
        nsrv.finalize()
        s.witness.sealer.tick()
        say(f"3. batch close (sealer tick after 3601 s): {closed}; notary requests: "
            f"{[r['path'] for r in nsrv.requests]}; armarium requests: {[(r['method'], r['path']) for r in asrv.requests]}")
        code, seal, _ = s.call("GET", f"/v1/records/{out['record_id']}/seal", key=None)
        say(f"4. seal: {code} state {seal['state']} leaf {seal['leaf_index']} of {seal['batch_header']['size']}, "
            f"path {len(seal['path'])} hash(es), notary {seal['notary']['status']} over {seal['notary']['over'][:23]}... on "
            f"{seal['notary']['anchors'][0]['chain']}")
        code, rec, _ = s.call("GET", f"/v1/records/{out['record_id']}", key=None)
        say(f"   record view: ndim {rec['ndim']['state']} object {rec['ndim'].get('object_id')}")
        with urllib.request.urlopen(s.url(f"/v1/records/{out['record_id']}/bundle"), timeout=30) as r:
            data = r.read()
        d = pathlib.Path(tempfile.mkdtemp(prefix="cw-e2e-"))
        with tarfile.open(fileobj=io.BytesIO(data)) as tf:
            names = tf.getnames()
            tf.extractall(d, filter="data")
        say(f"5. witness-verify --bundle ({', '.join(names)}):")
        buf = io.StringIO()
        code5 = verify.main(["--bundle", str(d)], out=buf)
        for line in buf.getvalue().splitlines():
            say("   " + line)
        say(f"   exit {code5}")
        bad = json.loads((d / "seal.json").read_text())
        i = 0
        old = bad["path"][i]
        bad["path"][i] = ("f" if old[0] != "f" else "e") + old[1:]
        (d / "seal.json").write_text(json.dumps(bad))
        say(f"6. one path hash changed (path[{i}] {old[:12]}... -> {bad['path'][i][:12]}...):")
        buf = io.StringIO()
        code6 = verify.main(["--bundle", str(d)], out=buf)
        for line in buf.getvalue().splitlines():
            if "seal" in line or line.startswith(("FAIL", "RESULT")):
                say("   " + line)
        say(f"   exit {code6}")
        ok = code5 == 0 and code6 == 1 and seal["state"] == "anchored"
        say("E2E: " + ("PASS" if ok else "FAIL"))
        return 0 if ok else 1
    finally:
        s.close()
        nsrv.close()
        asrv.close()
        if pg is not None:
            pg.stop()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
