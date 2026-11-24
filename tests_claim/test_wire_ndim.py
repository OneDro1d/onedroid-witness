"""B3W: n-dim wired to armarium's REAL object service (claimant chain per owner, real field names, DELETE per version), tested
through the real HttpArmarium client against tests_claim/fake_armarium_real.py. RED first: every test here fails on the B3 code.

Client: ARMARIUM_CASE; claimant create (201, a digit-first id); POST vs PUT answer names; DELETE ?block= per version, no block in
its answer, 410 after; 401/403 are configuration errors; 409 incomplete is a plain retryable error; the token never shows.
Owner parameters: deterministic, derived under a key, never carrying the account.
Records: keep never calls armarium; the background step creates one chain per owner (stored durably), writes the pending objects,
retries with backoff, fails with a reason on a configuration error; owner delete = one DELETE per version, no tombstone write."""
import json
import re
import threading
import time
import unittest

from tests_claim import helpers as h
from tests_claim import test_keep_api as k
from tests_claim.fake_armarium_real import CASE, RealObjects
from tests_claim.fake_seal import FakeNotary, make_tls

TLS = None
KEY_DELETED = "the key is deleted; the encrypted bytes stay on the chain"


def setUpModule():
    global TLS
    TLS = make_tls()


def env_for(srv, case=CASE):
    return {"ARMARIUM_URL": srv.url, "ARMARIUM_TOKEN_FILE": srv.token_file, "ARMARIUM_CA_FILE": srv.ca_file,
            "ARMARIUM_CASE": case}


class ClientCases(unittest.TestCase):
    def setUp(self):
        from claim_witness import ndim
        self.ndim = ndim
        self.srv = RealObjects(TLS)
        self.client, self.case = ndim.from_env(env_for(self.srv))

    def tearDown(self):
        self.srv.close()

    def claimant(self):
        body = self.ndim.owner_params(b"k" * 32, "acct_x")["body"]
        return self.client.create_claimant(self.case, body)["id"]

    def test_the_case_is_required_and_returned(self):
        self.assertEqual(self.case, CASE)
        for bad in ("", "zz", "1e59334f", CASE.upper()):
            with self.assertRaises(ValueError):
                self.ndim.from_env(dict(env_for(self.srv), ARMARIUM_CASE=bad))
        self.assertEqual(self.ndim.from_env({}), (None, None))

    def test_create_claimant_201_with_a_digit_first_id(self):
        cid = self.claimant()
        self.assertRegex(cid, r"^[0-9a-f]{32}$")
        self.assertTrue(cid[0].isdigit())
        req = self.srv.calls("POST", "claimant")[0]
        self.assertEqual(req["path"], f"/chain/{CASE}/claimant")
        self.assertEqual(req["auth"], "Bearer " + self.srv.TOKEN)
        self.assertEqual(set(json.loads(req["body"])), {"from", "to", "ruleSet"})

    def test_object_round_trip_with_the_real_field_names(self):
        cid = self.claimant()
        v1 = self.client.create_object(cid, {"kind": "x", "v": 1})
        self.assertEqual(set(v1), {"id", "block"})
        v2 = self.client.put_version(cid, v1["id"], v1["block"], {"kind": "x", "v": 2})
        self.assertNotEqual(v2["id"], v1["id"])  # PUT answers new_correlation_id
        self.assertGreater(v2["block"], v1["block"])  # and new_block
        self.assertEqual(v2["original_id"], v1["id"])
        self.assertEqual(self.srv.calls("PUT")[0]["query"], f"block={v1['block']}")
        self.assertEqual(self.client.get_object(cid, v1["id"]), {"kind": "x", "v": 1})
        self.assertEqual(self.client.get_object(cid, v2["id"]), {"kind": "x", "v": 2})

    def test_delete_each_version_with_its_own_block_then_410(self):
        cid = self.claimant()
        v1 = self.client.create_object(cid, {"v": 1})
        v2 = self.client.put_version(cid, v1["id"], v1["block"], {"v": 2})
        d2 = self.client.delete_object(cid, v2["id"], v2["block"])
        self.assertEqual(d2["dek"], "deleted")
        self.assertEqual(d2["residual"], ["ciphertext-on-chain"])
        self.assertEqual(self.srv.calls("DELETE")[0]["query"], f"block={v2['block']}")
        with self.assertRaises(self.ndim.Gone):
            self.client.get_object(cid, v2["id"])
        self.assertEqual(self.client.get_object(cid, v1["id"]), {"v": 1})  # an earlier version still reads
        d1 = self.client.delete_object(cid, v1["id"], v1["block"])
        self.assertEqual(d1["dek"], "deleted")
        with self.assertRaises(self.ndim.Gone):
            self.client.get_object(cid, v1["id"])

    def test_401_and_403_are_configuration_errors(self):
        import pathlib
        import tempfile
        cid = self.claimant()
        bad = pathlib.Path(tempfile.mkdtemp()) / "t"
        bad.write_text("wrong-token-value-123456\n")
        client, _ = self.ndim.from_env(dict(env_for(self.srv), ARMARIUM_TOKEN_FILE=str(bad)))
        with self.assertRaises(self.ndim.ArmariumConfigError) as cm:
            client.create_object(cid, {"a": 1})
        self.assertIn("401", str(cm.exception))
        self.assertNotIn("wrong-token-value", str(cm.exception))
        with self.assertRaises(self.ndim.ArmariumConfigError) as cm:
            self.client.create_object("1" * 32, {"a": 1})  # a chain outside the token's bind
        self.assertIn("403", str(cm.exception))
        self.assertTrue(issubclass(self.ndim.ArmariumConfigError, self.ndim.ArmariumError))

    def test_409_incomplete_is_a_retryable_plain_error(self):
        cid = self.claimant()
        v = self.client.create_object(cid, {"v": 1})
        self.srv.incomplete_once = True
        with self.assertRaises(self.ndim.ArmariumError) as cm:
            self.client.delete_object(cid, v["id"], v["block"])
        self.assertNotIsInstance(cm.exception, self.ndim.ArmariumConfigError)
        self.assertIn("incomplete", str(cm.exception))
        self.assertEqual(self.client.delete_object(cid, v["id"], v["block"])["dek"], "deleted")  # the same DELETE again

    def test_the_first_create_may_take_minutes(self):
        self.assertGreaterEqual(self.ndim.CLAIMANT_TIMEOUT_S, 360)
        self.srv.claimant_delay_s = 0.4
        t0 = time.time()
        self.claimant()
        self.assertGreaterEqual(time.time() - t0, 0.4)


class OwnerParams(unittest.TestCase):
    def test_deterministic_formatted_and_free_of_the_account(self):
        from claim_witness import ndim
        a = ndim.owner_params(b"k" * 32, "acct_secret_owner")
        self.assertEqual(a, ndim.owner_params(b"k" * 32, "acct_secret_owner"))
        self.assertNotEqual(a["tag"], ndim.owner_params(b"k" * 32, "acct_other")["tag"])
        self.assertNotEqual(a["tag"], ndim.owner_params(b"j" * 32, "acct_secret_owner")["tag"])
        self.assertRegex(a["tag"], r"^[0-9a-f]{64}$")
        b = a["body"]
        self.assertRegex(b["ruleSet"], r"^[0-9a-f]{32}$")
        for side in ("from", "to"):
            self.assertRegex(b[side]["id"], r"^[0-9a-f]{32}$")
            self.assertRegex(b[side]["address"], r"^0x[0-9a-f]{40}$")
        self.assertNotEqual(b["from"], b["to"])
        self.assertNotIn("secret_owner", json.dumps(a))


class WireBase(k.Base):
    """k.Base with the real-shaped object service behind the real client."""

    ndim = True
    store_evidence = False

    def setUp(self):
        from claim_witness import ndim
        self.clock = h.Clock()
        self.notary = FakeNotary(self.clock)
        self.srv = RealObjects(TLS)
        self.arm, case = ndim.from_env(env_for(self.srv))
        cfg = {"notary": self.notary, "armarium": self.arm, "ndim_case": case, "batch_interval_s": 3600,
               "ndim_store_evidence": self.store_evidence, "operator_accounts": ["acct_op"], "link_base": "https://evidence.example"}
        self.s = h.Stack(storage=None, clock=self.clock, config_overrides=cfg)

    def tearDown(self):
        self.s.close()
        self.srv.close()

    @property
    def records(self):
        return self.s.witness.records

    def account_of(self, rid):
        return self.s.storage.get_kept(rid)["account"]

    def chain_row(self, rid):
        from claim_witness import ndim
        tag = ndim.owner_params(self.records.ndim_key, self.account_of(rid))["tag"]
        return self.s.storage.get_ndim_chain(tag)

    def kept(self, key=k.OWNER, **extra):
        out = self.check(source=k.SOURCE + str(time.time()).encode(), quote="not a judge of truth")
        code, kk, _ = self.keep(out, key=key, **extra)
        self.assertEqual(code, 200, kk)
        return out

    def ndim_of(self, rid, key=k.OWNER):
        return self.get(rid, key=key)[1]["ndim"]


class Background(WireBase):
    def test_keep_never_calls_armarium(self):
        out = self.kept()
        self.assertEqual(self.srv.requests, [])
        nd = self.ndim_of(out["record_id"])
        self.assertEqual(nd["state"], "pending")
        self.assertIsNone(nd["chain"])

    def test_the_background_step_creates_the_owners_chain_then_writes(self):
        out = self.kept()
        rid = out["record_id"]
        self.seal_all()
        nd = self.ndim_of(rid)
        self.assertEqual(nd["state"], "written", nd)
        row = self.chain_row(rid)
        self.assertEqual((row["state"], row["case_id"]), ("ready", CASE))
        self.assertTrue(row["claimant_id"][0].isdigit())
        self.assertEqual(nd["chain"], row["claimant_id"])
        post = self.srv.calls("POST", "object")[0]
        self.assertEqual(post["path"], f"/chain/{row['claimant_id']}/object")
        doc = self.arm.get_object(row["claimant_id"], nd["object_id"])
        self.assertEqual(doc["record_id"], rid)
        self.assertEqual(doc["envelope"], out["envelope"])
        self.assertEqual(len(self.srv.calls("POST", "claimant")), 1)

    def test_one_chain_per_owner_and_the_account_never_leaves(self):
        a1, a2, b1 = self.kept(), self.kept(), self.kept(key=k.OTHER)
        self.seal_all()
        self.assertEqual(len(self.srv.calls("POST", "claimant")), 2)
        ca1, ca2, cb1 = (self.chain_row(o["record_id"])["claimant_id"] for o in (a1, a2, b1))
        self.assertEqual(ca1, ca2)
        self.assertNotEqual(ca1, cb1)
        sent = "\n".join(r["path"] + r["query"] + r["body"].decode("utf-8", "replace") for r in self.srv.requests)
        for rid in (a1["record_id"], b1["record_id"]):
            self.assertNotIn(self.account_of(rid), sent)
        bodies = [r["body"] for r in self.srv.calls("POST", "claimant")]
        self.assertNotEqual(bodies[0], bodies[1])

    def test_the_chain_is_stored_durably_so_a_later_tick_does_not_create_again(self):
        out = self.kept()
        self.seal_all()
        self.kept()
        self.s.witness.sealer.tick()
        self.assertEqual(len(self.srv.calls("POST", "claimant")), 1)
        self.assertEqual(len(self.srv.calls("POST", "object")), 2)
        self.assertTrue(self.chain_row(out["record_id"])["claimant_id"])

    def test_a_slow_first_create_blocks_neither_keep_nor_reads(self):
        first = self.kept()
        self.srv.claimant_delay_s = 1.5
        self.clock.advance(3601)
        t = threading.Thread(target=self.s.witness.sealer.tick)
        t.start()
        time.sleep(0.4)
        t0 = time.time()
        second = self.check(source=k.SOURCE + b"2", quote="not a judge of truth")
        code, kk, _ = self.keep(second)
        view = self.ndim_of(first["record_id"])
        self.assertLess(time.time() - t0, 1.0)
        self.assertEqual(view["state"], "pending")
        t.join(timeout=30)
        self.assertEqual(self.ndim_of(first["record_id"])["state"], "written")

    def test_the_sealer_loop_has_its_own_ndim_thread(self):
        out = self.kept()
        self.clock.advance(3601)
        sealer = self.s.witness.sealer
        sealer.start(poll_s=0.05)
        try:
            names = {t.name for t in threading.enumerate()}
            self.assertIn("sealer", names)
            self.assertIn("ndim", names)
            deadline = time.time() + 15
            while time.time() < deadline and self.ndim_of(out["record_id"])["state"] != "written":
                time.sleep(0.1)
            self.assertEqual(self.ndim_of(out["record_id"])["state"], "written")
        finally:
            sealer.stop()


class RetryAndFail(WireBase):
    def test_a_transient_failure_backs_off_and_then_succeeds(self):
        out = self.kept()
        rid = out["record_id"]
        self.srv.claimant_status = 500
        self.seal_all()
        row = self.chain_row(rid)
        self.assertEqual((row["state"], row["attempts"]), ("pending", 1))
        self.assertTrue(row["last_error"])
        nd = self.ndim_of(rid)
        self.assertEqual(nd["state"], "pending")
        self.assertTrue(nd["last_error"])
        self.s.witness.sealer.tick()  # same instant: inside the backoff, no new call
        self.assertEqual(len(self.srv.calls("POST", "claimant")), 1)
        self.srv.claimant_status = None
        self.clock.advance(3601)
        self.s.witness.sealer.tick()
        self.assertEqual(self.ndim_of(rid)["state"], "written")
        self.assertEqual(len(self.srv.calls("POST", "claimant")), 2)

    def test_too_many_transient_failures_end_in_failed_with_a_reason(self):
        from claim_witness import ndim
        out = self.kept()
        rid = out["record_id"]
        self.srv.claimant_status = 500
        self.seal_all()
        for _ in range(ndim.MAX_ATTEMPTS + 2):
            self.clock.advance(3601)
            self.s.witness.sealer.tick()
        nd = self.ndim_of(rid)
        self.assertEqual(nd["state"], "failed", nd)
        self.assertTrue(nd["last_error"])
        n = len(self.srv.calls("POST", "claimant"))
        self.assertEqual(n, ndim.MAX_ATTEMPTS)
        self.clock.advance(3601)
        self.s.witness.sealer.tick()
        self.assertEqual(len(self.srv.calls("POST", "claimant")), n)  # never retried forever

    def test_a_configuration_error_fails_at_once_and_is_not_retried(self):
        out = self.kept()
        rid = out["record_id"]
        self.srv.claimant_status = 401
        self.seal_all()
        nd = self.ndim_of(rid)
        self.assertEqual(nd["state"], "failed", nd)
        self.assertIn("configuration", nd["last_error"])
        self.assertIn("401", nd["last_error"])
        for _ in range(3):
            self.clock.advance(7200)
            self.s.witness.sealer.tick()
        self.assertEqual(len(self.srv.calls("POST", "claimant")), 1)
        self.assertEqual(self.chain_row(rid)["state"], "failed")

    def test_a_failed_chain_is_rearmed_when_the_sealer_starts(self):
        out = self.kept()
        rid = out["record_id"]
        self.srv.claimant_status = 403
        self.seal_all()
        self.assertEqual(self.ndim_of(rid)["state"], "failed")
        self.srv.claimant_status = None
        sealer = self.s.witness.sealer
        sealer.start(poll_s=0.05)  # the operator fixed the token and restarted the pod
        try:
            deadline = time.time() + 15
            while time.time() < deadline and self.ndim_of(rid)["state"] != "written":
                time.sleep(0.1)
            self.assertEqual(self.ndim_of(rid)["state"], "written")
        finally:
            sealer.stop()

    def test_an_object_write_refused_with_403_fails_with_a_reason(self):
        out = self.kept()
        rid = out["record_id"]
        self.srv.object_status = 403
        self.seal_all()
        nd = self.ndim_of(rid)
        self.assertEqual(nd["state"], "failed", nd)
        self.assertIn("configuration", nd["last_error"])
        before = len(self.srv.calls("POST", "object"))
        self.clock.advance(7200)
        self.s.witness.sealer.tick()
        self.assertEqual(len(self.srv.calls("POST", "object")), before)


class OwnerDelete(WireBase):
    def versions_of(self, rid):
        cid = self.chain_row(rid)["claimant_id"]
        return cid, self.srv.versions[cid]

    def add_version(self, rid, doc):
        """A second version of the record's object, as a later feature would write it, tracked in the record's n-dim state."""
        st = self.s.storage
        row = st.get_kept(rid)
        n = json.loads(json.dumps(row["ndim"]))
        rec = n["record"]
        tail = rec["versions"][-1]
        r = self.arm.put_version(n["chain"], tail["id"], tail["block"], doc)
        rec["versions"].append({"id": r["id"], "block": r["block"]})
        st.update_kept(rid, ndim=n)

    def test_delete_is_one_delete_per_version_and_no_tombstone_write(self):
        out = self.kept()
        rid = out["record_id"]
        self.seal_all()
        self.add_version(rid, {"kind": "claim-witness/record/1", "v": 2})
        cid, vs = self.versions_of(rid)
        self.assertEqual(len(vs), 2)
        writes_before = len(self.srv.calls("POST")) + len(self.srv.calls("PUT"))
        code, d, _ = self.s.call("DELETE", f"/v1/records/{rid}", key=k.OWNER)
        self.assertEqual(code, 200, d)
        deletes = self.srv.calls("DELETE")
        self.assertEqual(len(deletes), 2)
        self.assertEqual({r["path"] for r in deletes}, {f"/chain/{cid}/object/{vid}" for vid in vs})
        for r in deletes:
            vid = r["path"].rsplit("/", 1)[1]
            self.assertEqual(r["query"], f"block={vs[vid]['block']}")  # each its own tail
        self.assertEqual(len(self.srv.calls("POST")) + len(self.srv.calls("PUT")), writes_before)  # no tombstone version
        self.assertTrue(all(v["deleted"] for v in vs.values()))
        nd = self.ndim_of(rid)
        self.assertEqual(nd["state"], "deleted", nd)
        self.assertEqual(nd["dek"], "deleted")
        self.assertIn(KEY_DELETED, json.dumps(nd))
        self.assertIn(KEY_DELETED, json.dumps(d["ndim"]))
        text = json.dumps([nd, d]).lower()
        for w in k.FORBIDDEN:
            self.assertNotIn(w, text)

    def test_a_409_leaves_progress_and_a_later_tick_finishes(self):
        out = self.kept()
        rid = out["record_id"]
        self.seal_all()
        self.add_version(rid, {"v": 2})
        self.srv.incomplete_once = True
        code, d, _ = self.s.call("DELETE", f"/v1/records/{rid}", key=k.OWNER)
        self.assertEqual(code, 200, d)
        nd = self.ndim_of(rid)
        self.assertEqual(nd["state"], "written")  # not yet deleted, and not claimed to be
        self.assertNotIn(KEY_DELETED, json.dumps(nd))
        for _ in range(4):
            self.clock.advance(3601)
            self.s.witness.sealer.tick()
        cid, vs = self.versions_of(rid)
        self.assertTrue(all(v["deleted"] for v in vs.values()))
        nd = self.ndim_of(rid)
        self.assertEqual((nd["state"], nd["dek"]), ("deleted", "deleted"))

    def test_deleting_a_record_never_written_writes_nothing(self):
        out = self.kept()
        rid = out["record_id"]
        code, d, _ = self.s.call("DELETE", f"/v1/records/{rid}", key=k.OWNER)
        self.assertEqual(code, 200, d)
        self.seal_all()
        self.assertEqual(self.srv.requests, [])
        self.assertEqual(self.ndim_of(rid)["state"], "not-written")


class EvidenceObject(WireBase):
    store_evidence = True

    def test_evidence_goes_to_the_owners_chain_and_its_delete_deletes_the_key(self):
        out = self.private_check()
        code, kk, _ = self.keep(out, keep_evidence_days=7, evidence=self.evidence(k.PRIVATE_SOURCE))
        self.assertEqual(code, 200, kk)
        rid = out["record_id"]
        self.seal_all()
        nd = self.ndim_of(rid)
        self.assertEqual(nd["evidence"]["state"], "written", nd)
        cid = self.chain_row(rid)["claimant_id"]
        self.assertEqual(len(self.srv.calls("POST", "object")), 2)
        self.assertNotIn(k.CANARY, json.dumps([v["doc"] for v in self.srv.versions[cid].values()]))
        code, d, _ = self.s.call("DELETE", f"/v1/records/{rid}/evidence", key=k.OWNER)
        self.assertEqual(code, 200, d)
        ev = self.ndim_of(rid)["evidence"]
        self.assertEqual((ev["state"], ev["dek"]), ("deleted", "deleted"))
        self.assertIn(KEY_DELETED, json.dumps(ev))
        self.assertEqual(len(self.srv.calls("DELETE")), 1)  # the evidence version only; the record object stays readable
        oid = self.ndim_of(rid)["object_id"]
        self.assertEqual(self.arm.get_object(cid, oid)["record_id"], rid)


if __name__ == "__main__":
    unittest.main()
