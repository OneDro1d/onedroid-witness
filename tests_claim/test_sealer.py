"""B3 (d): the sealer. Every signing-log row carries its leaf H(0x00 || payload); a batch closes when its oldest leaf is
batch_interval_s old or it holds batch_max_leaves leaves; the signer signs the batch header (batch-header/v1); the notary seals
over = "sha256:" + H(canonical signed header) behind the NotaryClient interface; proofs are stored and GET
/v1/records/{id}/seal serves them for any payload id in the signing log, kept or not. witness-verify step 4 checks the leaf,
the path, the header signature and the notary's `over`, and judges key validity at the anchor time (VR-15, VR-16, TS-20)."""
import base64
import copy
import hashlib
import io
import json
import pathlib
import tempfile
import threading
import time
import unittest

from claim_witness import ids, jcs, verify
from tests_claim import helpers as h
from tests_claim.fake_seal import FakeNotary
from tests_claim.helpers import claim, obj_item, request

BATCH_KEYS = {"witness", "batch_id", "root", "size", "opened_at", "closed_at", "interval_s", "key_id", "sig"}


def stack(notary=True, **over):
    clock = h.Clock()
    cfg = {"notary": FakeNotary(clock) if notary else None, "batch_interval_s": 3600}
    cfg.update(over)
    return h.Stack(clock=clock, config_overrides=cfg)


def check(s, quote="not a judge", visibility="public"):
    src = b"The witness is not a judge of truth."
    code, out, _ = s.witness_call(request(claim("quote.in-source", {"quote": quote}), [obj_item("source", src, name="s.txt")],
                                          visibility))
    assert code == 200, out
    return out


def run_verify(*args):
    buf = io.StringIO()
    code = verify.main([str(a) for a in args], out=buf)
    return code, buf.getvalue()


class SigningLogLeaves(unittest.TestCase):
    def test_every_row_has_its_leaf(self):
        s = stack()
        try:
            out = check(s)
            raw = h.payload_bytes(out["envelope"])
            rows = s.storage.signing_log()
            row = [r for r in rows if r["payload_id"] == out["record_id"]][0]
            self.assertEqual(row["leaf"], ids.leaf_hash(raw))
            kl = s.storage.get_key_list(1)
            self.assertEqual(rows[0]["leaf"], ids.leaf_hash(base64.b64decode(kl["payload"])))
        finally:
            s.close()


class Batches(unittest.TestCase):
    def setUp(self):
        self.s = stack()

    def tearDown(self):
        self.s.close()

    def seal(self, rid, key=None):
        return self.s.call("GET", f"/v1/records/{rid}/seal", key=key)

    def test_no_batch_before_the_interval(self):
        out = check(self.s)
        self.s.clock.advance(3599 - 0)
        self.assertEqual(self.s.witness.sealer.tick(), [])
        code, seal, _ = self.seal(out["record_id"])
        self.assertEqual((code, seal), (200, {"state": "pending"}))

    def test_a_batch_closes_after_the_interval_and_the_seal_is_anchored(self):
        out = check(self.s)
        self.s.clock.advance(3601)
        closed = self.s.witness.sealer.tick()
        self.assertEqual(len(closed), 1)
        code, seal, _ = self.seal(out["record_id"])
        self.assertEqual(code, 200, seal)
        self.assertEqual(seal["state"], "anchored")
        hdr = seal["batch_header"]
        self.assertEqual(set(hdr), BATCH_KEYS)
        self.assertEqual(hdr["batch_id"], closed[0])
        self.assertEqual(hdr["size"], 2)  # key list 1 and the record
        self.assertEqual(hdr["interval_s"], 3600)
        self.assertEqual(hdr["witness"], "witness:test")
        leaf = ids.leaf_hash(h.payload_bytes(out["envelope"]))
        self.assertEqual(verify.merkle_root_from_path(leaf, seal["leaf_index"], hdr["size"], seal["path"]), hdr["root"])
        over = hashlib.sha256(jcs.canonical(hdr)).hexdigest()
        self.assertEqual(seal["notary"]["over"], "sha256:" + over)
        self.assertEqual(seal["notary"]["status"], "landed")
        self.assertEqual(self.s.witness.cfg.notary.calls, [over])
        # the header is signed by the witness key as PAE(batch-header payload type, canonical header without sig)
        unsigned = {k: v for k, v in hdr.items() if k != "sig"}
        msg = verify.pae("application/vnd.onedroid.witness.batch-header+json", jcs.canonical(unsigned))
        self.assertTrue(verify.ed25519_verify(h.public_of(self.s.seed), base64.b64decode(hdr["sig"]), msg))
        # the key list's own seal is served the same way (any payload id in the signing log)
        kl_id = ids.record_id(base64.b64decode(self.s.storage.get_key_list(1)["payload"]))
        code, kseal, _ = self.seal(kl_id)
        self.assertEqual((code, kseal["state"], kseal["batch_header"]["batch_id"]), (200, "anchored", closed[0]))

    def test_the_header_is_itself_a_leaf_of_the_next_batch(self):
        check(self.s)
        self.s.clock.advance(3601)
        first = self.s.witness.sealer.tick()[0]
        rows = self.s.storage.signing_log()
        hdr_rows = [r for r in rows if r["predicate_type"] == "https://onedroid.ai/witness/batch-header/v1"]
        self.assertEqual(len(hdr_rows), 1)
        self.s.clock.advance(3601)
        second = self.s.witness.sealer.tick()
        self.assertEqual(len(second), 1)
        self.assertNotEqual(second[0], first)
        code, seal, _ = self.seal(hdr_rows[0]["payload_id"])
        self.assertEqual(seal["batch_header"]["batch_id"], second[0])

    def test_max_leaves_closes_a_full_batch_early(self):
        s = stack(batch_max_leaves=2)
        try:
            check(s)
            check(s, quote="judge of truth")
            closed = s.witness.sealer.tick()
            self.assertEqual(len(closed), 1)
            self.assertEqual(s.witness.storage.get_batch(closed[0])["size"], 2)
            self.assertEqual(len(s.witness.storage.pending_leaves(10)), 2)  # the third leaf and the header wait
        finally:
            s.close()

    def test_notary_failure_leaves_a_pending_seal_that_a_later_tick_anchors(self):
        out = check(self.s)
        self.s.witness.cfg.notary.fail = True
        self.s.clock.advance(3601)
        bid = self.s.witness.sealer.tick()[0]
        code, seal, _ = self.seal(out["record_id"])
        self.assertEqual(seal["state"], "pending")
        self.assertEqual(seal["batch_header"]["batch_id"], bid)
        self.assertEqual(seal["notary"]["status"], "failed")
        self.assertIn("path", seal)
        self.s.witness.cfg.notary.fail = False
        self.s.witness.sealer.tick()
        code, seal, _ = self.seal(out["record_id"])
        self.assertEqual((seal["state"], seal["batch_header"]["batch_id"]), ("anchored", bid))

    def test_unknown_id_is_404(self):
        code, out, _ = self.seal("0" * 64)
        self.assertEqual(code, 404)
        code, out, _ = self.seal("not-hex")
        self.assertEqual(code, 404)

    def test_well_known_names_the_seal(self):
        code, wk, _ = self.s.call("GET", "/.well-known/witness.json", key=None)
        self.assertEqual(wk["batch_interval_s"], 3600)
        self.assertEqual(wk["seal"]["profile"], "hash/1")
        self.assertTrue(wk["seal"]["notary"])


class NoNotary(unittest.TestCase):
    def test_batches_close_but_never_anchor_without_a_notary(self):
        s = stack(notary=False)
        try:
            out = check(s)
            s.clock.advance(3601)
            self.assertEqual(len(s.witness.sealer.tick()), 1)
            code, seal, _ = s.call("GET", f"/v1/records/{out['record_id']}/seal", key=None)
            self.assertEqual(seal["state"], "pending")
            self.assertEqual(seal["notary"]["status"], "off")
            code, wk, _ = s.call("GET", "/.well-known/witness.json", key=None)
            self.assertFalse(wk["seal"]["notary"])
        finally:
            s.close()


class BackgroundLoop(unittest.TestCase):
    def test_the_loop_closes_batches_on_its_own(self):
        s = stack()
        try:
            out = check(s)
            s.clock.advance(3601)
            s.witness.sealer.start(poll_s=0.05)
            deadline = time.monotonic() + 10
            state = None
            while time.monotonic() < deadline:
                code, seal, _ = s.call("GET", f"/v1/records/{out['record_id']}/seal", key=None)
                state = seal.get("state")
                if state == "anchored":
                    break
                time.sleep(0.05)
            self.assertEqual(state, "anchored")
        finally:
            s.witness.sealer.stop()
            s.close()


class VerifySeal(unittest.TestCase):
    """witness-verify step 4 (SPEC §6) on a sealed record: PASS seal, and FAIL seal by name when a path hash, the header's
    signature, the root or the notary's `over` changes; a pending seal is SKIP."""

    @classmethod
    def setUpClass(cls):
        cls.s = stack()
        cls.out = check(cls.s)
        cls.s.clock.advance(3601)
        cls.s.witness.sealer.tick()
        code, cls.seal, _ = cls.s.call("GET", f"/v1/records/{cls.out['record_id']}/seal", key=None)
        code, wk, _ = cls.s.call("GET", "/.well-known/witness.json", key=None)
        cls.dir = pathlib.Path(tempfile.mkdtemp(prefix="cw-seal-"))
        (cls.dir / "keys.json").write_text(json.dumps(wk["key_list"]))

    @classmethod
    def tearDownClass(cls):
        cls.s.close()

    def run_with(self, seal):
        p = self.dir / "answer.json"
        p.write_text(json.dumps({"envelope": self.out["envelope"], "seal": seal}))
        return run_verify("--envelope", p, "--keys", self.dir / "keys.json")

    def test_sealed_record_passes_the_seal_step(self):
        code, text = self.run_with(self.seal)
        self.assertEqual(code, 0, text)
        self.assertIn("PASS seal", text)
        self.assertIn("PASS key-validity", text)
        self.assertNotIn("SKIP seal:", text)

    def test_seal_given_as_its_own_file(self):
        (self.dir / "seal.json").write_text(json.dumps(self.seal))
        (self.dir / "env.json").write_text(json.dumps(self.out["envelope"]))
        code, text = run_verify("--envelope", self.dir / "env.json", "--keys", self.dir / "keys.json", "--seal",
                                self.dir / "seal.json")
        self.assertEqual(code, 0, text)
        self.assertIn("PASS seal", text)

    def test_one_changed_path_hash_fails_the_seal_by_name(self):
        bad = copy.deepcopy(self.seal)
        self.assertTrue(bad["path"])
        bad["path"][0] = ("f" if bad["path"][0][0] != "f" else "e") + bad["path"][0][1:]
        code, text = self.run_with(bad)
        self.assertEqual(code, 1, text)
        self.assertIn("FAIL seal", text)

    def test_changed_header_or_root_or_over_fails(self):
        for mutate in (lambda s: s["batch_header"].update(sig=base64.b64encode(b"\x00" * 64).decode()),
                       lambda s: s["batch_header"].update(root="0" * 64),
                       lambda s: s["notary"].update(over="sha256:" + "0" * 64),
                       lambda s: s.update(leaf_index=s["leaf_index"] + 1)):
            bad = copy.deepcopy(self.seal)
            mutate(bad)
            code, text = self.run_with(bad)
            self.assertEqual(code, 1, text)
            self.assertIn("FAIL seal", text)

    def test_pending_seal_is_skipped(self):
        code, text = self.run_with({"state": "pending"})
        self.assertEqual(code, 0, text)
        self.assertIn("SKIP seal", text)


class KeyValidityAtAnchorTime(unittest.TestCase):
    """TS-20 / VR-16: a record signed with a key revoked before its batch was anchored fails; a plain rotation does not."""

    def _sealed_after_rotation(self, revoke):
        from claim_witness import signer
        s = stack()
        try:
            out = check(s)
            s.clock.advance(10)
            new_seed = h.seed(2)
            signer.keylist_rotate(s.storage, s.seed, s.key_id, new_seed, "witness:test:2026b", "witness:test", clock=s.clock,
                                  revoke_reason="compromised" if revoke else None)
            core = signer.SignerCore(new_seed, "witness:test:2026b", "witness:test", s.storage, clock=s.clock)
            s.witness.signer = signer.LocalSignerClient(core)
            s.clock.advance(3601)
            s.witness.sealer.tick()
            code, seal, _ = s.call("GET", f"/v1/records/{out['record_id']}/seal", key=None)
            self.assertEqual(seal["state"], "anchored")
            self.assertEqual(seal["batch_header"]["key_id"], "witness:test:2026b")
            d = pathlib.Path(tempfile.mkdtemp(prefix="cw-ts20-"))
            (d / "keys.json").write_text(json.dumps(s.storage.get_key_list(2)))
            (d / "a.json").write_text(json.dumps({"envelope": out["envelope"], "seal": seal}))
            return run_verify("--envelope", d / "a.json", "--keys", d / "keys.json")
        finally:
            s.close()

    def test_revoked_before_anchor_fails(self):
        code, text = self._sealed_after_rotation(revoke=True)
        self.assertEqual(code, 1, text)
        self.assertIn("FAIL key-validity", text)
        self.assertIn("PASS seal", text)

    def test_rotated_without_revocation_passes(self):
        code, text = self._sealed_after_rotation(revoke=False)
        self.assertEqual(code, 0, text)
        self.assertIn("PASS key-validity", text)


if __name__ == "__main__":
    unittest.main()
