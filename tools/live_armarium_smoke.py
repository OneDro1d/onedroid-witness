#!/usr/bin/env python3
"""A bounded live smoke of the claim witness's two armarium clients, to be run FROM A POD in witness-dev (the tokens are mounted
there and nowhere else). It runs the witness's own code paths, not curl:

  n-dim object service (claim_witness.ndim.HttpArmarium)   1 claimant create (a throwaway owner), then 5 object calls:
      POST object, PUT a new version, GET it, DELETE it (expect dek "deleted"), GET it again (expect 410)
  notary (claim_witness.notary.HttpNotary)                  1 seal of a random `over` (at most 2 seal requests, retries
      included), then 1 verify (POST /notary/v1/verify, no token) of the first anchor

Settings are the service's own (the same env names): ARMARIUM_URL, ARMARIUM_TOKEN_FILE, ARMARIUM_CA_FILE, ARMARIUM_CASE,
WITNESS_NOTARY_URL, WITNESS_NOTARY_TOKEN_FILE, WITNESS_NOTARY_CA_FILE. A token is read from its file for each call and sent only as
the bearer header; this script never prints a token, a Secret value or the environment. The throwaway owner's claimant chain stays
(removing a whole claimant chain needs a person-approved token); its objects are deleted as above.

    python3 tools/live_armarium_smoke.py          # prints each step and a JSON summary; exit 0 when every check held
"""
import hashlib
import json
import os
import pathlib
import sys
import urllib.error
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from claim_witness import ndim, notary  # noqa: E402

MAX_SEAL_REQUESTS = 2


class BoundedNotary(notary.HttpNotary):
    """HttpNotary that sends at most MAX_SEAL_REQUESTS requests in all, retries included."""

    def __init__(self, cfg):
        super().__init__(cfg)
        self.posts = 0

    def _post(self, body, headers, ctx, timeout):
        if self.posts >= MAX_SEAL_REQUESTS:
            raise notary._Stop("bound: the smoke's seal requests are used up")
        self.posts += 1
        return super()._post(body, headers, ctx, timeout)


def _verify(cfg, over, anchor):
    """POST /notary/v1/verify {over, chain, tx_hash}, no token -> {status, answer}"""
    body = json.dumps({"over": over, "chain": anchor["chain"], "tx_hash": anchor["tx_hash"]}, separators=(",", ":")).encode()
    req = urllib.request.Request(cfg["url"] + "/notary/v1/verify", data=body, method="POST",
                                 headers={"Content-Type": "application/json", "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30, context=notary.tls_context(cfg["ca_file"])) as r:
            status, raw = r.status, r.read(1 << 20)
    except urllib.error.HTTPError as e:
        try:
            status, raw = e.code, e.read(1 << 20)
        finally:
            e.close()
    try:
        answer = json.loads(raw)
    except ValueError:
        answer = {}
    keep = {k: v for k, v in (answer.items() if isinstance(answer, dict) else []) if isinstance(v, (str, int, bool)) and len(str(v)) < 200}
    return {"status": status, "answer": keep}


def run(env, out=sys.stdout):
    def say(text):
        print(text, file=out, flush=True)

    res = {"ok": False, "calls": {"claimant": 0, "object": 0, "seal": 0, "verify": 0}}
    try:
        client, case = ndim.from_env(env)
        cfg = notary.settings(env)
    except ValueError as e:
        res["error"] = f"settings: {e}"
        say(res["error"])
        return res
    if client is None or cfg is None:
        res["error"] = "settings: the object service and the notary must both be configured (their token files mounted)"
        say(res["error"])
        return res
    checks = {}
    try:
        key = os.urandom(32)
        account = "smoke-" + os.urandom(8).hex()
        params = ndim.owner_params(key, account)
        say(f"== object service {env.get('ARMARIUM_URL')} case {case}")
        res["calls"]["claimant"] += 1
        res["claimant_id"] = cid = client.create_claimant(case, params["body"])["id"]
        say(f"POST /chain/{case}/claimant -> 201 claimant {cid}")
        res["calls"]["object"] += 1
        v1 = client.create_object(cid, {"kind": "claim-witness/smoke/1", "v": 1, "n": os.urandom(8).hex()})
        say(f"POST /chain/{cid}/object -> correlation_id {v1['id']} block {v1['block']}")
        res["calls"]["object"] += 1
        v2 = client.put_version(cid, v1["id"], v1["block"], {"kind": "claim-witness/smoke/1", "v": 2})
        say(f"PUT  /chain/{cid}/object/{v1['id']}?block={v1['block']} -> new_correlation_id {v2['id']} new_block {v2['block']} "
            f"original_id {v2['original_id']}")
        res["calls"]["object"] += 1
        doc = client.get_object(cid, v2["id"])
        say(f"GET  /chain/{cid}/object/{v2['id']} -> 200 v={doc.get('v')}")
        res["calls"]["object"] += 1
        d = client.delete_object(cid, v2["id"], v2["block"])
        say(f"DELETE /chain/{cid}/object/{v2['id']}?block={v2['block']} -> 200 dek {d['dek']} residual {d['residual']}")
        res["calls"]["object"] += 1
        try:
            client.get_object(cid, v2["id"])
            res["after_delete_status"] = 200
        except ndim.Gone:
            res["after_delete_status"] = 410
        say(f"GET  /chain/{cid}/object/{v2['id']} after the delete -> {res['after_delete_status']}")
        res.update(v1=v1, v2=v2, delete=d)
        checks.update(put_is_a_new_version=v2["id"] != v1["id"] and v2["original_id"] == v1["id"], read_v2=doc.get("v") == 2,
                      dek_deleted=d["dek"] == "deleted", gone_410=res["after_delete_status"] == 410)

        say(f"== notary {cfg['url']}")
        over_hex = hashlib.sha256(b"claim-witness smoke " + os.urandom(16)).hexdigest()
        bn = BoundedNotary(cfg)
        seal = bn.seal(over_hex)
        res["calls"]["seal"] = bn.posts
        res["seal"] = seal
        say(f"POST /notary/v1/seals over sha256:{over_hex} -> status {seal['status']} reason {seal['reason']}")
        for a in seal["anchors"]:
            say(f"  chain {a['chain']} state {a['state']} block {a['block']} tx {a['tx_hash']} final {a['final']}")
        checks["seal_landed"] = seal["status"] == "landed"
        if seal["anchors"] and seal["anchors"][0]["tx_hash"]:
            res["calls"]["verify"] = 1
            res["verify"] = v = _verify(cfg, "sha256:" + over_hex, seal["anchors"][0])
            say(f"POST /notary/v1/verify {seal['anchors'][0]['chain']} -> {v['status']} {v['answer']}")
            checks["verify_200"] = v["status"] == 200
        else:
            checks["verify_200"] = False
    except ndim.ArmariumError as e:
        res["error"] = f"{type(e).__name__}: {e}"
        say(res["error"])
    res["checks"] = checks
    res["ok"] = bool(checks) and all(checks.values()) and "error" not in res
    say("SMOKE: " + ("PASS" if res["ok"] else "FAIL") + " " + json.dumps(checks))
    return res


def main():
    res = run(dict(os.environ))
    print("SUMMARY " + json.dumps({k: v for k, v in res.items()}, sort_keys=True, default=str))
    return 0 if res["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
