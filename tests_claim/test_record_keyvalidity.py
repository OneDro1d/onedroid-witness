"""record.valid and witness-verify NAME key validity at the anchor time (SPEC §4 record.valid, §6 step 5, VR-16, TS-20).

Live defect on witness-dev: a sealed, anchored record whose key list revokes the witness's key before the anchor time gave
NOT_SUPPORTED `record-invalid` (right) with detail `failed: ["seal"]` only. The same key signed the batch header and the record
(the normal case), so the header key's revocation was folded into "seal" and the record key's own check was skipped because
"seal" had failed. Wanted: a key revoked at or before the anchor time, or outside its validity, is `key-validity` (the record's
key and the header's key alike); `seal` stays for path, header signature, header witness, over, not-landed and block-time; when
the seal fails for a structural reason the record key's validity is still judged if an anchor time can be read. Outcomes and
findings do not change: only which checks are named, and the verifier's lines.
"""
import base64
import calendar
import io
import json
import time
import unittest

from claim_witness import crypto, signer, storage, verify
from tests_claim import helpers as h
from tests_claim.test_record_methods import Base, predicate


def _secs(t):
    return calendar.timegm(time.strptime(t, "%Y-%m-%dT%H:%M:%SZ"))


class KeyValidityNamed(Base, unittest.TestCase):
    def listed(self, offset, revoke):
        """A key list of the same witness and the same signing key that ends it `offset` seconds after the key list's first key
        starts (revoked at that time when `revoke`), signed by both keys as a rotation is. The record is witnessed before it."""
        first = json.loads(base64.b64decode(self.s.storage.get_key_list(1)["payload"]))["predicate"]["keys"][0]["valid_from"]
        t0 = _secs(first)
        st = storage.MemoryStorage()
        signer.keylist_init(st, self.s.seed, self.s.key_id, "witness:test", clock=lambda: t0)
        return signer.keylist_rotate(st, self.s.seed, self.s.key_id, h.seed(7), "witness:test:2026z", "witness:test",
                                     clock=lambda: t0 + offset, revoke_reason="compromised" if revoke else None)

    def sealed_before(self, revoke):
        """A sealed record, and a key list that ends its key after the record was witnessed and before the anchor time."""
        rec = self.sealed_public()
        witnessed = _secs(h.payload_of(rec["envelope"])["predicate"]["witnessed_at"])
        first = json.loads(base64.b64decode(self.s.storage.get_key_list(1)["payload"]))["predicate"]["keys"][0]["valid_from"]
        offset = witnessed - _secs(first) + 1
        kl = self.listed(offset, revoke)
        self.assertLess(witnessed + 1, _secs(self.anchor_time(rec["record_id"])))
        return rec, kl

    def failed(self, out):
        return predicate(out)["detail"]["failed"].split(",")

    def test_the_same_key_revoked_before_the_anchor_is_named_key_validity_not_seal(self):
        rec, kl = self.sealed_before(revoke=True)
        code, out = self.run_valid(rec["record_id"], key_list=self.key_list_item(env=kl))
        self.assertEqual(code, 200, out)
        p = predicate(out)
        self.assertEqual((p["finding"], p["outcome"]), ("record-invalid", "NOT_SUPPORTED"))
        self.assertEqual(p["detail"]["failed"], "key-validity")

    def test_a_key_that_ended_before_the_batch_closed_is_named_key_validity_not_seal(self):
        rec, kl = self.sealed_before(revoke=False)
        code, out = self.run_valid(rec["record_id"], key_list=self.key_list_item(env=kl))
        p = predicate(out)
        self.assertEqual((p["finding"], p["outcome"]), ("record-invalid", "NOT_SUPPORTED"))
        self.assertEqual(p["detail"]["failed"], "key-validity")

    def test_a_structural_seal_failure_still_judges_the_keys_validity(self):
        rec, kl = self.sealed_before(revoke=True)
        batch_id = self.s.storage.get_seal(rec["record_id"])["batch_id"]
        b = self.s.storage.get_batch(batch_id)
        self.s.storage.update_batch(batch_id, notary=dict(b["notary"], over="sha256:" + "0" * 64))
        code, out = self.run_valid(rec["record_id"], key_list=self.key_list_item(env=kl))
        self.assertEqual(predicate(out)["detail"]["failed"], "seal,key-validity")

    def test_a_structural_seal_failure_alone_stays_seal(self):
        rec = self.sealed_public()
        batch_id = self.s.storage.get_seal(rec["record_id"])["batch_id"]
        b = self.s.storage.get_batch(batch_id)
        self.s.storage.update_batch(batch_id, notary=dict(b["notary"], over="sha256:" + "0" * 64))
        code, out = self.run_valid(rec["record_id"])
        self.assertEqual(predicate(out)["detail"]["failed"], "seal")

    def test_a_valid_record_stays_valid(self):
        rec = self.sealed_public()
        code, out = self.run_valid(rec["record_id"])
        self.assertEqual(predicate(out)["finding"], "record-valid")

    def verify_lines(self, rid, kl):
        code, seal, _ = self.s.call("GET", f"/v1/records/{rid}/seal", key=None)
        code, view, _ = self.s.call("GET", f"/v1/records/{rid}", key=None)
        buf = io.StringIO()
        verify.run_checks(verify.Report(buf), view["envelope"], kl, False, None, None, [], None, rid, seal)
        return buf.getvalue().splitlines()

    def test_witness_verify_names_key_validity_for_the_same_case(self):
        rec, kl = self.sealed_before(revoke=True)
        lines = self.verify_lines(rec["record_id"], kl)
        text = "\n".join(lines)
        self.assertTrue(any(x.startswith("FAIL key-validity") for x in lines), text)
        self.assertFalse(any(x.startswith("FAIL seal") for x in lines), text)
        self.assertTrue(any(x.startswith("PASS seal") for x in lines), text)
        self.assertIn("was revoked at", text)

    def test_witness_verify_judges_key_validity_beside_a_structural_seal_failure(self):
        rec, kl = self.sealed_before(revoke=True)
        batch_id = self.s.storage.get_seal(rec["record_id"])["batch_id"]
        b = self.s.storage.get_batch(batch_id)
        self.s.storage.update_batch(batch_id, notary=dict(b["notary"], over="sha256:" + "0" * 64))
        lines = self.verify_lines(rec["record_id"], kl)
        text = "\n".join(lines)
        self.assertTrue(any(x.startswith("FAIL seal") for x in lines), text)
        self.assertTrue(any(x.startswith("FAIL key-validity") for x in lines), text)

    def test_witness_verify_leaves_a_valid_record_passing(self):
        rec = self.sealed_public()
        lines = self.verify_lines(rec["record_id"], self.s.storage.get_key_list(1))
        self.assertFalse(any(x.startswith("FAIL") for x in lines), "\n".join(lines))


class VectorsNameIt(unittest.TestCase):
    def test_the_revoked_before_the_anchor_vector_says_key_validity(self):
        from claim_witness import vectors
        doc = json.loads(vectors.VECTORS.read_text(encoding="utf-8"))
        by = {c["name"]: c for c in doc["record_methods"]}
        c = by["public, key revoked before the anchor"]
        self.assertEqual((c["finding"], c["detail"]), ("record-invalid", {"failed": "key-validity"}))
        c = by["public, bad seal and key revoked before the anchor"]
        self.assertEqual((c["finding"], c["detail"]), ("record-invalid", {"failed": "seal,key-validity"}))
        c = by["public, bad seal alone"]
        self.assertEqual((c["finding"], c["detail"]), ("record-invalid", {"failed": "seal"}))


if __name__ == "__main__":
    unittest.main()
