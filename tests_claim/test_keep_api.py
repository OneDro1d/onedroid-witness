"""B3 (a)-(c), (e), (f) through the real HTTP API, on memory storage and again on real Postgres (KeepOnPostgres):

- keep (SPEC §3, BD1): POST /v1/records/{id}/keep {envelope, disclosure? (private), keep_evidence_days?, evidence?}; both
  commitments checked for a private record; no visibility field; kept evidence encrypted, evidence_key returned once; keeping
  twice is idempotent; TS-13 (kept after its batch closed: already sealed);
- reads: GET /v1/records/{id} (public: anyone; private: the envelope to anyone, the disclosure to the owner and to share-token
  holders); share tokens (create, list, revoke, 30 days by default, scoped to one record); owner search over the owner's own
  private records (GET /v1/records?q=);
- owner delete (BD1): the data key, the bytes, the index rows, the share tokens and the job answers deleted; a DELETE of every
  version of the n-dim object (B3W: no tombstone version); deleted_at; the envelope and the seal still served and verifiable. DELETE /evidence, takedown;
- n-dim through the ArmariumClient interface (fake): the sealer writes each kept record's envelope (commitments only when
  private); NDIM_STORE_EVIDENCE puts the kept evidence ciphertext there too; unset armarium says "not-configured";
- the bundle (tar) verifies with witness-verify --bundle, seal included; a private bundle carries no agent key;
- the wording rule: no answer says private data is "gone", "erased" or "permanently removed"."""
import base64
import io
import json
import pathlib
import tarfile
import tempfile
import unittest
import urllib.error
import urllib.request

from claim_witness import verify
from tests_claim import helpers as h
from tests_claim.fake_seal import FakeArmarium, FakeNotary
from tests_claim.helpers import claim, obj_item, request

CANARY = "Zbigniewcanary7Q"
SOURCE = b"The witness is not a judge of truth. It signs one answer."
PRIVATE_SOURCE = f"Private notes: {CANARY} moved to Gdansk in 2019.".encode()
FORBIDDEN = ("gone", "erased", "permanently removed")
OWNER, OTHER = "dev-key-a-0123456789abcdef", "dev-key-b-0123456789abcdef"


class Base:
    """self.make_storage() gives a fresh storage; self.s is a Stack with a fake notary and (unless ndim=False) fake armarium."""

    ndim = True
    store_evidence = False

    def make_storage(self):
        return None

    def setUp(self):
        self.clock = h.Clock()
        self.notary = FakeNotary(self.clock)
        self.arm = FakeArmarium() if self.ndim else None
        cfg = {"notary": self.notary, "armarium": self.arm, "ndim_case": "1e59334fee73fc758f793ce01c3cdd00" if self.ndim else None,
               "batch_interval_s": 3600, "ndim_store_evidence": self.store_evidence, "operator_accounts": ["acct_op"],
               "link_base": "https://evidence.example"}
        self.s = h.Stack(storage=self.make_storage(), clock=self.clock, config_overrides=cfg)
        self.s.auth.dev_keys.mapping["dev-key-op-0123456789abcdef"] = "acct_op"

    def tearDown(self):
        self.s.close()

    # ---------------------------------------------------------------------------------------------------- helpers

    def check(self, visibility="public", source=SOURCE, quote="not a judge of truth", agent=False):
        c = claim("quote.in-source", {"quote": quote})
        ev = [obj_item("source", source, name="source.txt")]
        body = request(c, ev, visibility)
        if agent:
            seed = h.seed(40)
            code, reg, _ = self.s.call("POST", "/v1/agent-keys", {"public_key": h.b64(h.public_of(seed))})
            body["agent"] = h.agent_block(seed, reg["agent_key_id"], "witness:test", c, ev, f"nonce-keep-{visibility}-1",
                                          h.iso(self.clock()))
            self.agent_key = {"agent_key_id": reg["agent_key_id"], "agent": reg["agent"], "public_key": h.b64(h.public_of(seed))}
        code, out, _ = self.s.witness_call(body)
        self.assertEqual(code, 200, out)
        return out

    def private_check(self, label=None):
        c = claim("quote.in-source", {"quote": f"{CANARY} moved"})
        body = request(c, [obj_item("source", PRIVATE_SOURCE, name=f"{CANARY}.txt")], "private")
        body["label"] = label or f"label {CANARY}"
        code, out, _ = self.s.witness_call(body)
        self.assertEqual(code, 200, out)
        return out

    def keep(self, out, key=OWNER, **extra):
        body = {"envelope": out["envelope"]}
        if "disclosure" in out:
            body["disclosure"] = out["disclosure"]
        body.update(extra)
        return self.s.call("POST", f"/v1/records/{out['record_id']}/keep", body, key=key)

    def get(self, rid, key=None, token=None, suffix=""):
        path = f"/v1/records/{rid}{suffix}" + (f"?token={token}" if token else "")
        return self.s.call("GET", path, key=key)

    def raw_get(self, path, key=None):
        hd = {"Authorization": f"Bearer {key}"} if key else {}
        req = urllib.request.Request(self.s.url(path), headers=hd)
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()

    def seal_all(self):
        self.clock.advance(3601)
        return self.s.witness.sealer.tick()

    def evidence(self, data=SOURCE):
        return [{"sha256": h.sha(data), "content_b64": h.b64(data)}]

    def assert_wording(self, obj):
        text = json.dumps(obj).lower()
        for w in FORBIDDEN:
            self.assertNotIn(w, text)


class KeepCases(Base):
    def test_keep_public_record(self):
        out = self.check()
        code, k, _ = self.keep(out)
        self.assertEqual(code, 200, k)
        self.assertEqual(k["record_id"], out["record_id"])
        self.assertEqual(k["visibility"], "public")
        self.assertEqual(k["link"], f"https://evidence.example/r/{out['record_id']}")
        self.assertNotIn("evidence_key", k)
        code, rec, _ = self.get(out["record_id"])
        self.assertEqual(code, 200, rec)
        self.assertEqual(rec["envelope"], out["envelope"])
        self.assertIsNone(rec["deleted_at"])
        self.assertIsNone(rec["taken_down_at"])

    def test_keep_twice_is_idempotent(self):
        out = self.check()
        code, k1, _ = self.keep(out, keep_evidence_days=30, evidence=self.evidence())
        self.assertIn("evidence_key", k1)
        code, k2, _ = self.keep(out, keep_evidence_days=30, evidence=self.evidence())
        self.assertEqual(code, 200, k2)
        self.assertTrue(k2["already_kept"])
        self.assertEqual(k2["kept_at"], k1["kept_at"])
        self.assertNotIn("evidence_key", k2)  # returned once

    def test_keep_refusals(self):
        out = self.check()
        rid = out["record_id"]
        cases = [
            ({"envelope": out["envelope"], "visibility": "private"}, OWNER, 422),
            ({"envelope": out["envelope"], "disclosure": {"salt": "AAAA", "body": {}}}, OWNER, 422),
            ({}, OWNER, 422),
            ({"envelope": out["envelope"]}, OTHER, 403),
            ({"envelope": out["envelope"], "keep_evidence_days": 5}, OWNER, 422),  # days without evidence
            ({"envelope": out["envelope"], "evidence": self.evidence()}, OWNER, 422),  # evidence without days
            ({"envelope": out["envelope"], "keep_evidence_days": 5, "evidence": self.evidence(b"other bytes")}, OWNER, 422),
            ({"envelope": out["envelope"], "keep_evidence_days": 5,
              "evidence": [{"sha256": h.sha(SOURCE), "content_b64": h.b64(b"not the bytes")}]}, OWNER, 400),
        ]
        for body, key, status in cases:
            code, got, _ = self.s.call("POST", f"/v1/records/{rid}/keep", body, key=key)
            self.assertEqual(code, status, (body.keys(), got))
        code, got, _ = self.s.call("POST", f"/v1/records/{'0' * 64}/keep", {"envelope": out["envelope"]}, key=OWNER)
        self.assertEqual(code, 422, got)  # the id is not the envelope's
        code, got, _ = self.s.call("POST", f"/v1/records/{rid}/keep", {"envelope": out["envelope"]}, key=None)
        self.assertEqual(code, 401)
        code, _, _ = self.get(rid)
        self.assertEqual(code, 404)  # nothing was kept

    def test_an_envelope_this_witness_did_not_sign_is_refused(self):
        from claim_witness import dsse, jcs, ids
        out = self.check()
        st = h.payload_of(out["envelope"])
        st["predicate"]["finding"] = "quote-absent"
        raw = jcs.canonical(st)
        forged = dsse.sign(raw, [("witness:test:2026a", h.seed(9))])
        code, got, _ = self.s.call("POST", f"/v1/records/{ids.record_id(raw)}/keep", {"envelope": forged}, key=OWNER)
        self.assertEqual(code, 422, got)

    def test_keep_private_checks_both_commitments(self):
        out = self.private_check()
        bad = json.loads(json.dumps(out["disclosure"]))
        bad["body"]["label"] = "changed"
        code, got, _ = self.s.call("POST", f"/v1/records/{out['record_id']}/keep", {"envelope": out["envelope"], "disclosure": bad})
        self.assertEqual(code, 422, got)
        code, got, _ = self.s.call("POST", f"/v1/records/{out['record_id']}/keep", {"envelope": out["envelope"]})
        self.assertEqual(code, 422, got)  # a private record needs its disclosure
        code, k, _ = self.keep(out)
        self.assertEqual(code, 200, k)
        self.assertEqual(k["visibility"], "private")
        code, k, _ = self.keep(out, key=OTHER)
        self.assertEqual(code, 403, k)

    def test_ts13_kept_an_hour_later_is_already_sealed(self):
        out = self.check()
        self.seal_all()
        code, k, _ = self.keep(out)
        self.assertEqual(code, 200, k)
        self.assertEqual(k["record_id"], out["record_id"])
        self.assertEqual(k["seal"]["state"], "anchored")
        code, rec, _ = self.get(out["record_id"])
        self.assertEqual(rec["seal"]["state"], "anchored")

    def test_inline_keep_option_still_points_to_the_route(self):
        code, got, _ = self.s.witness_call(h.exact_request(keep=True))
        self.assertEqual(code, 422)
        self.assertIn("/keep", got["detail"])


class PrivateReads(Base):
    def test_owner_reads_the_body_others_see_fingerprints_only(self):
        out = self.private_check()
        self.keep(out)
        code, anon, _ = self.get(out["record_id"])
        self.assertEqual(code, 200, anon)
        self.assertEqual(anon["visibility"], "private")
        self.assertNotIn("disclosure", anon)
        self.assertNotIn(CANARY, json.dumps(anon))
        code, other, _ = self.get(out["record_id"], key=OTHER)
        self.assertNotIn("disclosure", other)
        code, mine, _ = self.get(out["record_id"], key=OWNER)
        self.assertEqual(mine["disclosure"], out["disclosure"])

    def test_share_tokens(self):
        out = self.private_check()
        self.keep(out)
        rid = out["record_id"]
        code, sh, _ = self.s.call("POST", f"/v1/records/{rid}/shares", {})
        self.assertEqual(code, 200, sh)
        self.assertTrue(sh["token"])
        self.assertEqual(sh["link"], f"https://evidence.example/r/{rid}?token={sh['token']}")
        self.assertEqual(sh["expires_at"], h.iso(self.clock() + 30 * 86400))
        code, rec, _ = self.get(rid, token=sh["token"])
        self.assertEqual(code, 200, rec)
        self.assertEqual(rec["disclosure"], out["disclosure"])
        code, lst, _ = self.s.call("GET", f"/v1/records/{rid}/shares")
        self.assertEqual([x["token_id"] for x in lst["shares"]], [sh["token_id"]])
        self.assertNotIn(sh["token"], json.dumps(lst))
        code, lst, _ = self.s.call("GET", f"/v1/records/{rid}/shares", key=OTHER)
        self.assertEqual(code, 403)
        # scoped to one record
        out2 = self.private_check(label="a second record")
        self.keep(out2)
        code, rec2, _ = self.get(out2["record_id"], token=sh["token"])
        self.assertEqual(code, 403, rec2)
        # revoke
        code, rv, _ = self.s.call("DELETE", f"/v1/records/{rid}/shares/{sh['token_id']}")
        self.assertEqual(code, 200, rv)
        code, rec, _ = self.get(rid, token=sh["token"])
        self.assertEqual(code, 403, rec)

    def test_share_token_expires(self):
        out = self.private_check()
        self.keep(out)
        code, sh, _ = self.s.call("POST", f"/v1/records/{out['record_id']}/shares", {"days": 1})
        self.assertEqual(code, 200, sh)
        self.clock.advance(86400 + 1)
        code, rec, _ = self.get(out["record_id"], token=sh["token"])
        self.assertEqual(code, 403, rec)

    def test_share_refusals(self):
        pub = self.check()
        self.keep(pub)
        code, got, _ = self.s.call("POST", f"/v1/records/{pub['record_id']}/shares", {})
        self.assertEqual(code, 422, got)  # a public record needs no token
        out = self.private_check()
        self.keep(out)
        for body in ({"days": 0}, {"days": 400}, {"days": "3"}, {"other": 1}):
            code, got, _ = self.s.call("POST", f"/v1/records/{out['record_id']}/shares", body)
            self.assertEqual(code, 422, (body, got))

    def test_owner_search_is_scoped_to_the_owner(self):
        out = self.private_check()
        self.keep(out)
        pub = self.check()
        self.keep(pub)
        code, res, _ = self.s.call("GET", f"/v1/records?q={CANARY.lower()}")
        self.assertEqual(code, 200, res)
        self.assertEqual([r["record_id"] for r in res["records"]], [out["record_id"]])
        self.assertIn(CANARY, res["records"][0]["statement"])
        code, res, _ = self.s.call("GET", f"/v1/records?q={CANARY.upper()}%20MOVED")
        self.assertEqual([r["record_id"] for r in res["records"]], [out["record_id"]])
        code, res, _ = self.s.call("GET", "/v1/records?q=gdansk%20moved%20nowhere")
        self.assertEqual(res["records"], [])
        code, res, _ = self.s.call("GET", f"/v1/records?q={CANARY}", key=OTHER)
        self.assertEqual((code, res["records"]), (200, []))
        code, res, _ = self.s.call("GET", f"/v1/records?q={CANARY}", key=None)
        self.assertEqual(code, 401)
        code, res, _ = self.s.call("GET", "/v1/records?outcome=SUPPORTED")
        self.assertEqual([r["record_id"] for r in res["records"]], [out["record_id"]])

    def test_private_kept_evidence_for_owner_and_evidence_tokens(self):
        out = self.private_check()
        code, k, _ = self.keep(out, keep_evidence_days=7, evidence=self.evidence(PRIVATE_SOURCE))
        self.assertEqual(code, 200, k)
        self.assertTrue(k["evidence_key"])
        code, rec, _ = self.get(out["record_id"], key=OWNER)
        self.assertEqual(rec["evidence"]["files"], [h.sha(PRIVATE_SOURCE)])
        self.assertEqual(rec["evidence"]["expires_at"], h.iso(self.clock() + 7 * 86400))
        code, blob = self.raw_get(f"/v1/records/{out['record_id']}/evidence/{h.sha(PRIVATE_SOURCE)}", key=OWNER)
        self.assertEqual((code, blob), (200, PRIVATE_SOURCE))
        code, blob = self.raw_get(f"/v1/records/{out['record_id']}/evidence/{h.sha(PRIVATE_SOURCE)}")
        self.assertEqual(code, 404)
        code, sh, _ = self.s.call("POST", f"/v1/records/{out['record_id']}/shares", {"evidence": True})
        code, blob = self.raw_get(f"/v1/records/{out['record_id']}/evidence/{h.sha(PRIVATE_SOURCE)}?token={sh['token']}")
        self.assertEqual((code, blob), (200, PRIVATE_SOURCE))
        code, sh2, _ = self.s.call("POST", f"/v1/records/{out['record_id']}/shares", {})
        code, blob = self.raw_get(f"/v1/records/{out['record_id']}/evidence/{h.sha(PRIVATE_SOURCE)}?token={sh2['token']}")
        self.assertEqual(code, 404)
        # kept evidence expires
        self.clock.advance(7 * 86400 + 1)
        self.s.witness.purge()
        code, blob = self.raw_get(f"/v1/records/{out['record_id']}/evidence/{h.sha(PRIVATE_SOURCE)}", key=OWNER)
        self.assertEqual(code, 404)


class DeleteAndTakedown(Base):
    def test_owner_delete(self):
        out = self.private_check()
        code, k, _ = self.keep(out, keep_evidence_days=7, evidence=self.evidence(PRIVATE_SOURCE))
        code, sh, _ = self.s.call("POST", f"/v1/records/{out['record_id']}/shares", {})
        self.seal_all()
        rid = out["record_id"]
        code, d, _ = self.s.call("DELETE", f"/v1/records/{rid}")
        self.assertEqual(code, 200, d)
        self.assertEqual(d["deleted_at"], h.iso(self.clock()))
        self.assertTrue(d["deleted"])
        self.assertTrue(d["kept"])
        self.assert_wording(d)
        # the envelope and the seal stay, nothing readable does
        code, rec, _ = self.get(rid, key=OWNER)
        self.assertEqual(code, 200, rec)
        self.assertEqual(rec["deleted_at"], d["deleted_at"])
        self.assertEqual(rec["envelope"], out["envelope"])
        self.assertNotIn("disclosure", rec)
        self.assertEqual(rec["seal"]["state"], "anchored")
        self.assert_wording(rec)
        code, rec, _ = self.get(rid, token=sh["token"])
        self.assertEqual(code, 403)
        code, res, _ = self.s.call("GET", f"/v1/records?q={CANARY}")
        self.assertEqual(res["records"], [])
        code, blob = self.raw_get(f"/v1/records/{rid}/evidence/{h.sha(PRIVATE_SOURCE)}", key=OWNER)
        self.assertEqual(code, 404)
        row = self.s.storage.get_kept(rid)
        self.assertIsNone(row["wrapped_key"])
        self.assertIsNone(row["body_box"])
        self.assertEqual(self.s.storage.get_kept_evidence(rid), [])
        self.assertEqual(self.s.storage.shares_of(rid), [])
        self.assertFalse([j for j in self.s.storage.all_jobs() if j.get("record_id") == rid])
        # still verifiable from the envelope and the seal
        d2 = pathlib.Path(tempfile.mkdtemp(prefix="cw-del-"))
        code, wk, _ = self.s.call("GET", "/.well-known/witness.json", key=None)
        (d2 / "keys.json").write_text(json.dumps(wk["key_list"]))
        (d2 / "a.json").write_text(json.dumps({"envelope": rec["envelope"] if "envelope" in rec else out["envelope"],
                                               "seal": self.get(rid)[1]["seal"]}))
        buf = io.StringIO()
        self.assertEqual(verify.main(["--envelope", str(d2 / "a.json"), "--keys", str(d2 / "keys.json")], out=buf), 0, buf.getvalue())
        self.assertIn("PASS seal", buf.getvalue())
        # deleting again answers the same, keeping again is refused
        code, d3, _ = self.s.call("DELETE", f"/v1/records/{rid}")
        self.assertEqual((code, d3["deleted_at"]), (200, d["deleted_at"]))
        code, got, _ = self.keep(out)
        self.assertEqual(code, 410, got)

    def test_delete_refusals(self):
        pub = self.check()
        self.keep(pub)
        code, got, _ = self.s.call("DELETE", f"/v1/records/{pub['record_id']}")
        self.assertEqual(code, 422, got)  # a public record is taken down, not deleted
        out = self.private_check()
        self.keep(out)
        code, got, _ = self.s.call("DELETE", f"/v1/records/{out['record_id']}", key=OTHER)
        self.assertEqual(code, 403, got)
        code, got, _ = self.s.call("DELETE", f"/v1/records/{'1' * 64}")
        self.assertEqual(code, 404, got)

    def test_delete_evidence_keeps_the_record(self):
        out = self.check()
        self.keep(out, keep_evidence_days=30, evidence=self.evidence())
        code, d, _ = self.s.call("DELETE", f"/v1/records/{out['record_id']}/evidence")
        self.assertEqual(code, 200, d)
        self.assertTrue(d["evidence_deleted_at"])
        self.assert_wording(d)
        code, rec, _ = self.get(out["record_id"])
        self.assertEqual(code, 200)
        self.assertEqual(rec["evidence"]["files"], [])
        self.assertEqual(rec["envelope"], out["envelope"])
        code, blob = self.raw_get(f"/v1/records/{out['record_id']}/evidence/{h.sha(SOURCE)}")
        self.assertEqual(code, 404)
        code, d, _ = self.s.call("DELETE", f"/v1/records/{out['record_id']}/evidence", key=OTHER)
        self.assertEqual(code, 403)

    def test_takedown_hides_the_record_and_bundle_not_the_seal(self):
        out = self.check()
        self.keep(out)
        self.seal_all()
        rid = out["record_id"]
        code, got, _ = self.s.call("POST", f"/v1/records/{rid}/takedown", {"reason": "subject request"}, key=OTHER)
        self.assertEqual(code, 403, got)
        code, td, _ = self.s.call("POST", f"/v1/records/{rid}/takedown", {"reason": "subject request"},
                                  key="dev-key-op-0123456789abcdef")
        self.assertEqual(code, 200, td)
        self.assertTrue(td["taken_down_at"])
        code, got, _ = self.get(rid)
        self.assertEqual(code, 410, got)
        code, blob = self.raw_get(f"/v1/records/{rid}/bundle")
        self.assertEqual(code, 410)
        code, seal, _ = self.get(rid, suffix="/seal")
        self.assertEqual((code, seal["state"]), (200, "anchored"))
        code, mine, _ = self.get(rid, key=OWNER)
        self.assertEqual(code, 200)
        self.assertEqual(mine["taken_down_at"], td["taken_down_at"])

    def test_owner_takedown(self):
        out = self.private_check()
        self.keep(out)
        code, td, _ = self.s.call("POST", f"/v1/records/{out['record_id']}/takedown", {})
        self.assertEqual(code, 200, td)
        code, got, _ = self.get(out["record_id"])
        self.assertEqual(code, 410)


class Bundles(Base):
    def unpack(self, data):
        d = pathlib.Path(tempfile.mkdtemp(prefix="cw-bundle-"))
        with tarfile.open(fileobj=io.BytesIO(data)) as tf:
            names = tf.getnames()
            for m in tf.getmembers():
                self.assertFalse(m.name.startswith("/") or ".." in m.name)
                if m.isfile():
                    p = d / m.name
                    p.parent.mkdir(parents=True, exist_ok=True)
                    p.write_bytes(tf.extractfile(m).read())
        return d, names

    def test_ts12_public_bundle_verifies_with_its_seal_and_reruns_the_method(self):
        out = self.check(agent=True)
        self.keep(out, keep_evidence_days=30, evidence=self.evidence())
        self.seal_all()
        code, data = self.raw_get(f"/v1/records/{out['record_id']}/bundle")
        self.assertEqual(code, 200, data[:200])
        d, names = self.unpack(data)
        for n in ("envelope.json", "seal.json", "keys.json", "keys-seal.json", "agent_key.json", f"evidence/{h.sha(SOURCE)}"):
            self.assertIn(n, names)
        self.assertTrue(any(n.startswith("witness-methods-") for n in names))
        buf = io.StringIO()
        code = verify.main(["--bundle", str(d)], out=buf)
        self.assertEqual(code, 0, buf.getvalue())
        for name in ("seal", "method-rerun", "agent-signature", "key-validity"):
            self.assertIn(f"PASS {name}", buf.getvalue())

    def test_private_bundle_has_no_agent_key(self):
        out = self.private_check()
        self.keep(out)
        self.seal_all()
        code, data = self.raw_get(f"/v1/records/{out['record_id']}/bundle", key=OWNER)
        self.assertEqual(code, 200)
        d, names = self.unpack(data)
        self.assertNotIn("agent_key.json", names)
        self.assertNotIn("disclosure.json", names)  # BD17: was assertIn; the owner's bundle no longer carries the disclosure
        buf = io.StringIO()
        self.assertEqual(verify.main(["--bundle", str(d)], out=buf), 0, buf.getvalue())
        self.assertNotIn("FAIL", buf.getvalue())  # BD17: was PASS body-commitment, which needed disclosure.json (now a SKIP without --disclosure)
        code, data = self.raw_get(f"/v1/records/{out['record_id']}/bundle")
        d, names = self.unpack(data)
        self.assertNotIn("disclosure.json", names)
        self.assertNotIn(CANARY.encode(), data)

    # BD17: a bundle is the portable proof file; the private body travels only through a deliberate share link.

    def _kept_private(self):
        out = self.private_check()
        code, k, _ = self.keep(out)  # no kept evidence: the private source is not in the bundle by another door
        self.assertEqual(code, 200, k)
        self.seal_all()
        return out

    def test_bd17_no_reader_gets_the_disclosure_in_the_bundle(self):
        out = self._kept_private()
        rid = out["record_id"]
        code, sh, _ = self.s.call("POST", f"/v1/records/{rid}/shares", {})
        self.assertEqual(code, 200, sh)
        for who, path, key in (("owner", f"/v1/records/{rid}/bundle", OWNER),
                               ("token holder", f"/v1/records/{rid}/bundle?token={sh['token']}", None),
                               ("anonymous", f"/v1/records/{rid}/bundle", None),
                               ("other account", f"/v1/records/{rid}/bundle", OTHER)):
            code, data = self.raw_get(path, key=key)
            self.assertEqual(code, 200, who)
            d, names = self.unpack(data)
            self.assertNotIn("disclosure.json", names, who)
            self.assertNotIn("disclosure.json", [n.rsplit("/", 1)[-1] for n in names], who)
            self.assertNotIn(CANARY.encode(), data, who)  # the tar as bytes
            with tarfile.open(fileobj=io.BytesIO(data)) as tf:
                for m in tf.getmembers():
                    if m.isfile():
                        self.assertNotIn(CANARY.encode(), tf.extractfile(m).read(), f"{who}: {m.name}")

    def test_bd17_owner_verifies_a_private_bundle_with_the_disclosure_flag(self):
        out = self._kept_private()
        rid = out["record_id"]
        code, data = self.raw_get(f"/v1/records/{rid}/bundle", key=OWNER)
        self.assertEqual(code, 200)
        d, names = self.unpack(data)
        self.assertNotIn("disclosure.json", names)
        # the disclosure comes from GET /v1/records/{id} as the owner, and is handed to witness-verify on purpose
        code, rec, _ = self.get(rid, key=OWNER)
        self.assertEqual(code, 200, rec)
        self.assertIn(CANARY, json.dumps(rec["disclosure"]))
        dfile = pathlib.Path(tempfile.mkdtemp(prefix="cw-disc-")) / "disclosure.json"
        dfile.write_text(json.dumps(rec["disclosure"]))
        buf = io.StringIO()
        self.assertEqual(verify.main(["--bundle", str(d), "--disclosure", str(dfile)], out=buf), 0, buf.getvalue())
        for name in ("claim-commitment", "body-commitment", "seal", "key-validity"):
            self.assertIn(f"PASS {name}", buf.getvalue())
        self.assertNotIn("FAIL", buf.getvalue())
        # the same bundle without the disclosure verifies what it can, and nothing fails
        buf = io.StringIO()
        self.assertEqual(verify.main(["--bundle", str(d)], out=buf), 0, buf.getvalue())
        self.assertNotIn("FAIL", buf.getvalue())
        self.assertNotIn("PASS body-commitment", buf.getvalue())
        self.assertIn("PASS seal", buf.getvalue())
        # a wrong disclosure still fails by name
        bad = json.loads(dfile.read_text())
        bad["body"]["tampered"] = True
        bfile = dfile.with_name("bad.json")
        bfile.write_text(json.dumps(bad))
        buf = io.StringIO()
        self.assertNotEqual(verify.main(["--bundle", str(d), "--disclosure", str(bfile)], out=buf), 0, buf.getvalue())


class NdimWrites(Base):
    def test_the_sealer_writes_each_kept_envelope(self):
        pub = self.check()
        self.keep(pub)
        out = self.private_check()
        self.keep(out)
        code, rec, _ = self.get(out["record_id"])
        self.assertEqual(rec["ndim"]["state"], "pending")
        self.seal_all()
        code, rec, _ = self.get(out["record_id"])
        self.assertEqual(rec["ndim"]["state"], "written", rec["ndim"])
        (claimant,) = {c for c in self.arm.claimants}  # one claimant chain for the one owner (B3W)
        self.assertEqual(rec["ndim"]["chain"], claimant)
        obj = self.arm.get_object(claimant, rec["ndim"]["object_id"])
        self.assertEqual(obj["record_id"], out["record_id"])
        self.assertEqual(obj["envelope"], out["envelope"])
        self.assertEqual(obj["seal"]["state"], "anchored")
        self.assertNotIn(CANARY, self.arm.all_text())  # a private envelope holds commitments only
        code, prec, _ = self.get(pub["record_id"])
        self.assertEqual(prec["ndim"]["state"], "written")
        # owner delete DELETEs the version (B3W: armarium's DELETE, not a tombstone version we write)
        code, d, _ = self.s.call("DELETE", f"/v1/records/{out['record_id']}")
        self.assertEqual(code, 200, d)
        code, rec, _ = self.get(out["record_id"])
        self.assertEqual(rec["ndim"]["state"], "deleted", rec["ndim"])
        self.assertTrue(self.arm.objects[(claimant, rec["ndim"]["object_id"])]["deleted"])
        self.assertNotIn("put", {c[0] for c in self.arm.calls})
        self.assert_wording(rec)

    def test_armarium_failure_is_retried_by_a_later_tick(self):
        out = self.check()
        self.keep(out)
        self.arm.fail = True
        self.seal_all()
        code, rec, _ = self.get(out["record_id"])
        self.assertEqual(rec["ndim"]["state"], "pending")
        self.arm.fail = False
        self.clock.advance(3601)  # B3W: a failed attempt backs off before the next one
        self.s.witness.sealer.tick()
        code, rec, _ = self.get(out["record_id"])
        self.assertEqual(rec["ndim"]["state"], "written")


class NdimEvidence(Base):
    store_evidence = True

    def test_kept_evidence_goes_to_ndim_and_delete_deletes_its_key(self):
        out = self.private_check()
        code, k, _ = self.keep(out, keep_evidence_days=7, evidence=self.evidence(PRIVATE_SOURCE))
        self.seal_all()
        code, rec, _ = self.get(out["record_id"], key=OWNER)
        ev = rec["ndim"]["evidence"]
        self.assertEqual(ev["state"], "written", rec["ndim"])
        self.assertNotIn(CANARY, self.arm.all_text())
        self.assertNotIn(base64.b64encode(PRIVATE_SOURCE).decode(), self.arm.all_text())
        code, d, _ = self.s.call("DELETE", f"/v1/records/{out['record_id']}/evidence")
        self.assertEqual(code, 200, d)
        code, rec, _ = self.get(out["record_id"], key=OWNER)
        self.assertEqual(rec["ndim"]["evidence"]["state"], "deleted")
        self.assertEqual(rec["ndim"]["evidence"]["dek"], "deleted")
        self.assertIn("the key is deleted; the encrypted bytes stay on the chain", json.dumps(rec["ndim"]))
        self.assertTrue(self.arm.objects[(rec["ndim"]["chain"], ev["object_id"])]["deleted"])
        self.assert_wording(rec)
        self.assert_wording(d)


class NdimNotConfigured(Base):
    ndim = False

    def test_nothing_is_written_and_the_record_says_so(self):
        out = self.check()
        self.keep(out)
        self.seal_all()
        code, rec, _ = self.get(out["record_id"])
        self.assertEqual(rec["ndim"]["state"], "not-configured")
        self.assertNotIn("object_id", rec["ndim"])


class Retention(Base):
    def test_ts19_unkept_answers_leave_only_the_log_row_leaf_and_attempt(self):
        out = self.check()
        self.seal_all()
        self.clock.advance(86400 + 60)
        self.s.witness.purge()
        self.assertEqual(self.s.storage.all_jobs(), [])
        self.assertIsNone(self.s.storage.get_kept(out["record_id"]))
        row = [r for r in self.s.storage.signing_log() if r["payload_id"] == out["record_id"]][0]
        self.assertTrue(row["leaf"])
        code, seal, _ = self.get(out["record_id"], suffix="/seal")
        self.assertEqual((code, seal["state"]), (200, "anchored"))
        code, rec, _ = self.get(out["record_id"])
        self.assertEqual(code, 404)


class Privacy(Base):
    """TS-10 on memory storage: a private claim kept and sealed leaves no plaintext in the payload, the seal, the store, the
    logs or the chain data (fake armarium); the owner and a token holder read it."""

    def test_ts10_no_plaintext_anywhere(self):
        import contextlib
        log = io.StringIO()
        with contextlib.redirect_stdout(log), contextlib.redirect_stderr(log):
            out = self.private_check()
            self.keep(out, keep_evidence_days=7, evidence=self.evidence(PRIVATE_SOURCE))
            code, sh, _ = self.s.call("POST", f"/v1/records/{out['record_id']}/shares", {})
            self.seal_all()
            code, rec, _ = self.get(out["record_id"], token=sh["token"])
            code, anon, _ = self.get(out["record_id"])
        self.assertIn(CANARY, json.dumps(rec["disclosure"]))
        self.assertNotIn(CANARY, json.dumps(anon))
        self.assertNotIn(CANARY.encode(), h.payload_bytes(out["envelope"]))
        self.assertNotIn(CANARY, json.dumps(anon["seal"]))
        self.assertNotIn(CANARY, log.getvalue())
        self.assertNotIn(sh["token"], log.getvalue())
        self.assertNotIn(CANARY, self.arm.all_text())
        st = self.s.storage
        dump = repr({k: v for k, v in vars(st).items() if k != "lock"})
        self.assertNotIn(CANARY, dump)
        self.assertNotIn(CANARY.lower(), dump.lower())
        self.assertNotIn(PRIVATE_SOURCE.hex(), dump)


for cls in (KeepCases, PrivateReads, DeleteAndTakedown, Bundles, NdimWrites, NdimEvidence, NdimNotConfigured, Retention, Privacy):
    globals()["Memory" + cls.__name__] = type("Memory" + cls.__name__, (cls, unittest.TestCase), {})


if __name__ == "__main__":
    unittest.main()
