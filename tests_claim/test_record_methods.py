"""B5b: `record.valid` and `record.disclose` (SPEC §4, §2.2 the `record` evidence kind; VR-6, VR-9, TS-11, TS-20), through the
real HTTP API on memory storage (the Postgres run is test_record_methods_pg.py).

record.valid: slots `record` (a kept record, by id) and `key_list` (object: a signed key list). + record-valid when the
signature verifies under the given key list, the key was valid at the anchor time and the seal verifies; - record-invalid for a
bad signature, a key not in the list, a key revoked at or before the anchor time, or a bad seal. A record whose seal is not
anchored yet cannot be called "sealed": no finding, reason `undecided` (VR-6: NOT_SUPPORTED only from a real negative finding).
It reads the envelope and the seal only, never a private record's plaintext, and the Evidence-trust rule does not apply to it.

record.disclose: slots `record` (one of the caller's own kept private records) and `disclosure` (object: {salt, body}). + disclosed
when both commitments match; a mismatch or a false assertion is 422; the new record is PUBLIC, carries the body in the clear
(in the disclosure evidence item), names the record, makes no new judgment, and goes through the public-claim screening. The
original stays private. An original that is not anchored yet is 422 `record-not-anchored` (nothing is signed or published)."""
import base64
import copy
import io
import json
import pathlib
import tarfile
import tempfile
import unittest

from claim_witness import methods, signer, tarball, verify
from tests_claim import helpers as h
from tests_claim import test_keep_api as k
from tests_claim.helpers import claim, obj_item, request

VALID_T = "Record {id} is validly signed under key list {key_list_sha} and sealed."
VALID_F = "Record {id} is not validly signed under key list {key_list_sha} and sealed."
VALID_LIMITS = "Checks signature, key validity and seal under the given key list only, not the record's content."
DISCLOSE_T = "Record {id}, sealed at {anchor_time}, had the content shown here."
DISCLOSE_LIMITS = "Publishes an earlier private record unchanged. No new check was made."
OWNER, OTHER = k.OWNER, k.OTHER
EMAIL_LABEL = "contact jane.roe@example.org about this"


def record_item(rid, slot="record"):
    return {"slot": slot, "kind": "record", "id": rid}


def predicate(out):
    return h.payload_of(out["envelope"])["predicate"]


class Base(k.Base):
    def key_list_item(self, seq=1, env=None):
        env = env if env is not None else self.s.storage.get_key_list(seq)
        return obj_item("key_list", json.dumps(env).encode(), "application/json", "keys.json")

    def valid_request(self, rid, key_list=None, assertion=True, visibility="public"):
        return request(claim("record.valid", {}, assertion), [record_item(rid), key_list or self.key_list_item()], visibility)

    def run_valid(self, rid, key=OWNER, **kw):
        code, out, _ = self.s.witness_call(self.valid_request(rid, **kw), key=key)
        return code, out

    def sealed_public(self, **kw):
        out = self.check(**kw)
        self.keep(out)
        self.seal_all()
        return out

    def sealed_private(self, label=None):
        out = self.private_check(label=label)
        self.keep(out)
        self.seal_all()
        return out

    def anchor_time(self, rid):
        code, seal, _ = self.s.call("GET", f"/v1/records/{rid}/seal", key=None)
        self.assertEqual(seal["state"], "anchored", seal)
        return min(a["block_time"] for a in seal["notary"]["anchors"])

    def disclose_request(self, rid, disclosure, assertion=True, visibility="public", slot_bytes=None):
        data = slot_bytes if slot_bytes is not None else json.dumps(disclosure).encode()
        return request(claim("record.disclose", {}, assertion),
                       [record_item(rid), obj_item("disclosure", data, "application/json", "disclosure.json")], visibility)

    def run_disclose(self, rid, disclosure, key=OWNER, **kw):
        code, out, _ = self.s.witness_call(self.disclose_request(rid, disclosure, **kw), key=key)
        return code, out


class Registered(Base, unittest.TestCase):
    def test_both_methods_are_in_the_registry_with_the_spec_text(self):
        v, d = methods.get("record.valid"), methods.get("record.disclose")
        self.assertEqual((v.id, v.major, v.version), ("record.valid", 1, "1.0.0"))
        self.assertEqual(v.slots, {"record": ("record",), "key_list": ("object",)})
        self.assertEqual(v.templates, {True: VALID_T, False: VALID_F})
        self.assertEqual(v.findings, {"record-valid": "positive", "record-invalid": "negative"})
        self.assertEqual(v.limits, VALID_LIMITS)
        self.assertTrue(v.mechanical)
        self.assertTrue(v.pure)
        self.assertEqual((d.id, d.major, d.version), ("record.disclose", 1, "1.0.0"))
        self.assertEqual(d.slots, {"record": ("record",), "disclosure": ("object",)})
        self.assertEqual(d.templates, {True: DISCLOSE_T, False: None})
        self.assertEqual(d.findings, {"disclosed": "positive"})
        self.assertEqual(d.limits, DISCLOSE_LIMITS)
        self.assertTrue(d.pure)
        self.assertEqual(methods.LIBRARY_VERSION, "1.6.0")

    def test_get_methods_lists_them_with_the_tarball_hash(self):
        code, reg, _ = self.s.call("GET", "/v1/methods", key=None)
        self.assertEqual(code, 200)
        self.assertEqual(reg["library"]["version"], "1.6.0")
        self.assertEqual(reg["library"]["tarball"], "witness-methods-1.6.0.tar.gz")
        by = {m["id"]: m for m in reg["methods"]}
        for mid in ("record.valid", "record.disclose"):
            self.assertEqual(by[mid]["code_sha256"], reg["library"]["code_sha256"])
            self.assertTrue(by[mid]["pure"])
            self.assertEqual(by[mid]["version"], "1.0.0")
        self.assertEqual(by["record.valid"]["templates"], {"true": VALID_T, "false": VALID_F})
        self.assertEqual(by["record.disclose"]["templates"], {"true": DISCLOSE_T, "false": None})
        self.assertEqual(by["record.valid"]["slots"], {"record": ["record"], "key_list": ["object"]})
        self.assertEqual(by["record.disclose"]["limits"], DISCLOSE_LIMITS)

    def test_the_tarball_holds_both_modules_and_loads_them(self):
        data = tarball.build_methods_tarball()
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
            names = tf.getnames()
        for n in ("witness_methods/record_valid.py", "witness_methods/record_disclose.py"):
            self.assertIn(n, names)
        lib = verify._load_methods(data)
        self.assertEqual(lib.get("record.valid").version, "1.0.0")
        self.assertEqual(lib.get("record.disclose").templates[True], DISCLOSE_T)
        self.assertEqual(lib.LIBRARY_VERSION, "1.6.0")


class RecordValid(Base, unittest.TestCase):
    def test_a_valid_sealed_public_record(self):
        rec = self.sealed_public()
        code, out = self.run_valid(rec["record_id"])
        self.assertEqual(code, 200, out)
        p = predicate(out)
        kl = json.dumps(self.s.storage.get_key_list(1)).encode()
        self.assertEqual((p["finding"], p["reason"], p["outcome"]), ("record-valid", "record-valid", "SUPPORTED"))
        self.assertEqual(p["statement"], VALID_T.format(id=rec["record_id"], key_list_sha=h.sha(kl)))
        self.assertEqual(p["method"]["id"], "record.valid")
        self.assertEqual(p["method"]["code_sha256"], tarball.methods_code_sha256())
        self.assertEqual(p["limits"], VALID_LIMITS)
        self.assertEqual(p["detail"], {"seal": "anchored", "anchor_time": self.anchor_time(rec["record_id"])})
        self.assertEqual(p["evidence"][0], {"slot": "record", "kind": "record", "id": rec["record_id"]})
        self.assertEqual(p["evidence"][1], {"slot": "key_list", "kind": "object", "sha256": h.sha(kl),
                                            "media_type": "application/json", "name": "keys.json"})
        self.assertIsNone(p["judgment"])

    def test_assertion_false_on_a_valid_record_is_not_supported(self):
        rec = self.sealed_public()
        code, out = self.run_valid(rec["record_id"], assertion=False)
        p = predicate(out)
        self.assertEqual((p["finding"], p["outcome"]), ("record-valid", "NOT_SUPPORTED"))
        self.assertEqual(p["statement"], VALID_F.format(id=rec["record_id"], key_list_sha=h.sha(
            json.dumps(self.s.storage.get_key_list(1)).encode())))

    def test_a_valid_private_record_checked_by_its_owner_and_privately(self):
        rec = self.sealed_private()
        code, out = self.run_valid(rec["record_id"], visibility="private")
        self.assertEqual(code, 200, out)
        self.assertEqual(out["envelope"]["payloadType"], "application/vnd.in-toto+json")
        self.assertEqual(out["disclosure"]["body"]["finding"], "record-valid")
        self.assertNotIn(k.CANARY, json.dumps(out))

    def test_one_flipped_payload_byte_is_record_invalid_ts11(self):
        rec = self.sealed_public()
        rid = rec["record_id"]
        env = copy.deepcopy(self.s.storage.get_kept(rid)["envelope"])
        raw = bytearray(base64.b64decode(env["payload"]))
        i = bytes(raw).index(b"SUPPORTED")
        raw[i] ^= 0x01  # SUPPORTED -> RUPPORTED: still canonical JSON, so only the signature can notice
        env["payload"] = base64.b64encode(bytes(raw)).decode()
        self.s.storage.update_kept(rid, envelope=env)
        code, out = self.run_valid(rid)
        self.assertEqual(code, 200, out)
        p = predicate(out)
        self.assertEqual((p["finding"], p["outcome"]), ("record-invalid", "NOT_SUPPORTED"))
        self.assertIn("signature", p["detail"]["failed"].split(","))

    def test_a_flipped_signature_byte_is_record_invalid(self):
        rec = self.sealed_public()
        rid = rec["record_id"]
        env = copy.deepcopy(self.s.storage.get_kept(rid)["envelope"])
        sig = bytearray(base64.b64decode(env["signatures"][0]["sig"]))
        sig[3] ^= 0x01
        env["signatures"][0]["sig"] = base64.b64encode(bytes(sig)).decode()
        self.s.storage.update_kept(rid, envelope=env)
        code, out = self.run_valid(rid)
        p = predicate(out)
        self.assertEqual((p["finding"], p["outcome"], p["detail"]["failed"]), ("record-invalid", "NOT_SUPPORTED", "signature"))

    def test_a_key_list_the_signer_is_not_in_is_record_invalid(self):
        rec = self.sealed_public()
        from claim_witness import storage
        other = storage.MemoryStorage()
        env = signer.keylist_init(other, h.seed(9), "witness:test:other", "witness:test", clock=self.clock)
        code, out = self.run_valid(rec["record_id"], key_list=self.key_list_item(env=env))
        self.assertEqual(code, 200, out)
        p = predicate(out)
        self.assertEqual((p["finding"], p["outcome"]), ("record-invalid", "NOT_SUPPORTED"))
        self.assertIn("signature", p["detail"]["failed"].split(","))

    def test_a_key_list_of_another_witness_is_record_invalid(self):
        rec = self.sealed_public()
        from claim_witness import storage
        env = signer.keylist_init(storage.MemoryStorage(), h.seed(1), "witness:test:2026a", "witness:elsewhere", clock=self.clock)
        code, out = self.run_valid(rec["record_id"], key_list=self.key_list_item(env=env))
        p = predicate(out)
        self.assertEqual(p["finding"], "record-invalid")
        self.assertIn("key-list-witness", p["detail"]["failed"].split(","))

    def _rotated(self, revoke):
        """Keep a record, rotate the signer key (revoking the old one, or not) before the batch closes, seal."""
        out = self.check()
        self.keep(out)
        self.clock.advance(10)
        new_seed = h.seed(2)
        signer.keylist_rotate(self.s.storage, self.s.seed, self.s.key_id, new_seed, "witness:test:2026b", "witness:test",
                              clock=self.clock, revoke_reason="compromised" if revoke else None)
        core = signer.SignerCore(new_seed, "witness:test:2026b", "witness:test", self.s.storage, clock=self.clock)
        self.s.witness.signer = signer.LocalSignerClient(core)
        self.clock.advance(3601)
        self.s.witness.sealer.tick()
        return out

    def test_a_key_revoked_before_the_anchor_time_is_record_invalid_ts20(self):
        rec = self._rotated(revoke=True)
        code, out = self.run_valid(rec["record_id"], key_list=self.key_list_item(seq=2))
        self.assertEqual(code, 200, out)
        p = predicate(out)
        self.assertEqual((p["finding"], p["outcome"]), ("record-invalid", "NOT_SUPPORTED"))
        self.assertEqual(p["detail"]["failed"], "key-validity")

    def test_a_plain_rotation_leaves_the_record_valid(self):
        rec = self._rotated(revoke=False)
        code, out = self.run_valid(rec["record_id"], key_list=self.key_list_item(seq=2))
        p = predicate(out)
        self.assertEqual((p["finding"], p["outcome"]), ("record-valid", "SUPPORTED"))

    def test_an_unanchored_record_is_no_finding_not_a_negative(self):
        out = self.check()
        self.keep(out)
        code, got = self.run_valid(out["record_id"])
        self.assertEqual(code, 200, got)
        p = predicate(got)
        self.assertEqual((p["finding"], p["reason"], p["outcome"]), (None, "undecided", "CANNOT_WITNESS"))
        self.assertEqual(p["detail"], {"seal": "pending"})
        code, got = self.run_valid(out["record_id"], assertion=False)
        self.assertEqual(predicate(got)["outcome"], "CANNOT_WITNESS")  # VR-6: never NOT_SUPPORTED from no finding

    def test_a_bad_seal_is_record_invalid(self):
        rec = self.sealed_public()
        rid = rec["record_id"]
        batch_id = self.s.storage.get_seal(rid)["batch_id"]
        b = self.s.storage.get_batch(batch_id)
        # a notary result whose `over` is not H(the signed header)
        self.s.storage.update_batch(batch_id, notary=dict(b["notary"], over="sha256:" + "0" * 64))
        code, out = self.run_valid(rid)
        p = predicate(out)
        self.assertEqual((p["finding"], p["outcome"]), ("record-invalid", "NOT_SUPPORTED"))
        self.assertIn("seal", p["detail"]["failed"].split(","))

    def test_an_unreadable_key_list_is_no_finding(self):
        rec = self.sealed_public()
        item = obj_item("key_list", b"this is not a key list", "text/plain", "keys.txt")
        code, out = self.run_valid(rec["record_id"], key_list=item)
        self.assertEqual(code, 200, out)
        p = predicate(out)
        self.assertEqual((p["finding"], p["reason"], p["outcome"]), (None, "unreadable", "CANNOT_WITNESS"))

    def test_an_unknown_id_is_422_and_signs_nothing(self):
        before = self.s.log_count()
        code, out = self.run_valid("ab" * 32)
        self.assertEqual((code, out["error"]), (422, "record-not-found"), out)
        self.assertEqual(self.s.log_count(), before)

    def test_a_record_that_was_not_kept_is_not_found(self):
        out = self.check()
        code, got = self.run_valid(out["record_id"])
        self.assertEqual((code, got["error"]), (422, "record-not-found"), got)

    def test_another_accounts_private_record_is_checked_on_its_envelope_alone(self):
        rec = self.sealed_private()
        code, out = self.run_valid(rec["record_id"], key=OTHER)
        self.assertEqual(code, 200, out)
        self.assertEqual(predicate(out)["finding"], "record-valid")
        everything = [out]
        everything.append(self.s.call("GET", f"/v1/records/{rec['record_id']}", key=OTHER)[1])
        code, view, _ = self.s.call("POST", f"/v1/records/{out['record_id']}/keep", {"envelope": out["envelope"]}, key=OTHER)
        everything.append(view)
        code, blob = self.raw_get(f"/v1/records/{out['record_id']}/bundle", key=OTHER)
        everything.append(blob.decode("latin-1"))
        for x in everything:
            self.assertNotIn(k.CANARY, json.dumps(x))
        self.assertNotIn(k.CANARY, json.dumps(self.s.storage.signing_log()))

    def test_a_taken_down_record_is_not_found_to_others_but_valid_to_its_owner(self):
        rec = self.sealed_public()
        code, got, _ = self.s.call("POST", f"/v1/records/{rec['record_id']}/takedown", {}, key=OWNER)
        self.assertEqual(code, 200, got)
        code, out = self.run_valid(rec["record_id"], key=OTHER)
        self.assertEqual((code, out["error"]), (422, "record-not-found"), out)
        code, out = self.run_valid(rec["record_id"], key=OWNER)
        self.assertEqual(code, 200, out)

    def test_a_deleted_private_record_still_checks_on_its_envelope(self):
        rec = self.sealed_private()
        code, got, _ = self.s.call("DELETE", f"/v1/records/{rec['record_id']}", key=OWNER)
        self.assertEqual(code, 200, got)
        code, out = self.run_valid(rec["record_id"])
        self.assertEqual(predicate(out)["finding"], "record-valid")

    def test_wrong_slots_and_kinds_are_422(self):
        rec = self.sealed_public()
        rid = rec["record_id"]
        bad = [
            [record_item(rid)],
            [record_item(rid), obj_item("key_list", b"{}"), obj_item("extra", b"x")],
            [record_item(rid), {"slot": "key_list", "kind": "observation", "id": "a" * 64}],
            [{"slot": "record", "kind": "object", "sha256": "a" * 64, "media_type": "text/plain", "name": "x"}, self.key_list_item()],
            [dict(record_item(rid), extra=1), self.key_list_item()],
            [record_item("not-hex"), self.key_list_item()],
        ]
        for ev in bad:
            code, out, _ = self.s.witness_call(request(claim("record.valid", {}), ev, "public"))
            self.assertEqual(code, 422, (ev, out))

    def test_other_methods_refuse_the_record_kind(self):
        rec = self.sealed_public()
        code, out, _ = self.s.witness_call(request(claim("match.exact", {}), [
            record_item(rec["record_id"], "submitted"), obj_item("target", b"x")], "public"))
        self.assertEqual((code, out["error"]), (422, "wrong-evidence-slots"), out)

    def test_params_must_be_empty(self):
        rec = self.sealed_public()
        code, out, _ = self.s.witness_call(request(claim("record.valid", {"x": 1}), [record_item(rec["record_id"]),
                                                                                    self.key_list_item()], "public"))
        self.assertEqual((code, out["error"]), (422, "invalid-params"), out)

    def test_the_price_is_one_check_and_no_observation_fields(self):
        rec = self.sealed_public()
        code, out = self.run_valid(rec["record_id"])
        self.assertEqual(out["price"]["credits"], 1)
        self.assertNotIn("fresh_observations", out["price"])

    def test_each_run_is_a_new_record_with_the_attempt_history(self):
        rec = self.sealed_public()
        code, a = self.run_valid(rec["record_id"])
        code, b = self.run_valid(rec["record_id"])
        self.assertNotEqual(a["record_id"], b["record_id"])
        self.assertEqual(predicate(b)["attempt"]["n"], 2)


class RerunInWitnessVerify(Base, unittest.TestCase):
    """record.valid's re-run is pure over its inputs: the record, its seal, the key list."""

    def files(self, rec, out, d):
        d = pathlib.Path(d)
        (d / "answer.json").write_text(json.dumps(out))
        (d / "keys.json").write_text(json.dumps(self.s.storage.get_key_list(1)))
        code, view, _ = self.s.call("GET", f"/v1/records/{rec['record_id']}", key=None)
        (d / "record.json").write_text(json.dumps(view))
        (d / "methods.tar.gz").write_bytes(tarball.build_methods_tarball())
        (d / "keylist.json").write_text(json.dumps(self.s.storage.get_key_list(1)))
        return d

    def run_verify(self, d, *extra):
        buf = io.StringIO()
        code = verify.main(["--envelope", str(d / "answer.json"), "--keys", str(d / "keys.json"), "--methods", str(d / "methods.tar.gz"),
                            "--evidence", str(d / "keylist.json"), "--record", str(d / "record.json"), *extra], out=buf)
        return code, buf.getvalue()

    def test_the_rerun_passes_and_notices_a_changed_seal(self):
        rec = self.sealed_public()
        code, out = self.run_valid(rec["record_id"])
        d = self.files(rec, out, tempfile.mkdtemp(prefix="cw-b5b-"))
        code, text = self.run_verify(d)
        self.assertEqual(code, 0, text)
        self.assertIn("PASS method-rerun", text)
        # the record's seal as the checker saw it was anchored: a pending one gives another answer
        view = json.loads((d / "record.json").read_text())
        view["seal"] = {"state": "pending"}
        (d / "record.json").write_text(json.dumps(view))
        code, text = self.run_verify(d)
        self.assertEqual(code, 1, text)
        self.assertIn("FAIL method-rerun", text)

    def test_the_rerun_of_an_invalid_verdict_reproduces_it(self):
        rec = self.sealed_public()
        env = copy.deepcopy(self.s.storage.get_kept(rec["record_id"])["envelope"])
        sig = bytearray(base64.b64decode(env["signatures"][0]["sig"]))
        sig[0] ^= 1
        env["signatures"][0]["sig"] = base64.b64encode(bytes(sig)).decode()
        self.s.storage.update_kept(rec["record_id"], envelope=env)
        code, out = self.run_valid(rec["record_id"])
        self.assertEqual(predicate(out)["finding"], "record-invalid")
        d = self.files(rec, out, tempfile.mkdtemp(prefix="cw-b5b-"))
        code, text = self.run_verify(d)
        self.assertIn("PASS method-rerun", text)

    def test_without_the_record_the_rerun_is_skipped_not_failed(self):
        rec = self.sealed_public()
        code, out = self.run_valid(rec["record_id"])
        d = self.files(rec, out, tempfile.mkdtemp(prefix="cw-b5b-"))
        buf = io.StringIO()
        code = verify.main(["--envelope", str(d / "answer.json"), "--keys", str(d / "keys.json"), "--methods", str(d / "methods.tar.gz"),
                            "--evidence", str(d / "keylist.json")], out=buf)
        self.assertEqual(code, 0, buf.getvalue())
        self.assertIn("SKIP method-rerun", buf.getvalue())

    def test_the_bundle_carries_the_checked_record_and_reruns(self):
        rec = self.sealed_public()
        code, out = self.run_valid(rec["record_id"])
        self.s.call("POST", f"/v1/records/{out['record_id']}/keep", {"envelope": out["envelope"], "keep_evidence_days": 30,
                                                                     "evidence": [{"sha256": h.sha(json.dumps(
                                                                         self.s.storage.get_key_list(1)).encode()),
                                                                         "content_b64": h.b64(json.dumps(
                                                                             self.s.storage.get_key_list(1)).encode())}]})
        self.seal_all()
        code, data = self.raw_get(f"/v1/records/{out['record_id']}/bundle")
        self.assertEqual(code, 200)
        d = pathlib.Path(tempfile.mkdtemp(prefix="cw-b5b-bundle-"))
        with tarfile.open(fileobj=io.BytesIO(data)) as tf:
            names = tf.getnames()
            for m in tf.getmembers():
                if m.isfile():
                    p = d / m.name
                    p.parent.mkdir(parents=True, exist_ok=True)
                    p.write_bytes(tf.extractfile(m).read())
        self.assertIn(f"records/{rec['record_id']}/envelope.json", names)
        self.assertIn(f"records/{rec['record_id']}/seal.json", names)
        buf = io.StringIO()
        self.assertEqual(verify.main(["--bundle", str(d)], out=buf), 0, buf.getvalue())
        self.assertIn("PASS method-rerun", buf.getvalue())

    def test_the_rerun_runs_on_the_pure_python_ed25519_too(self):
        import os
        rec = self.sealed_public()
        code, out = self.run_valid(rec["record_id"])
        d = self.files(rec, out, tempfile.mkdtemp(prefix="cw-b5b-"))
        os.environ["WITNESS_VERIFY_PURE"] = "1"
        try:
            code, text = self.run_verify(d)
        finally:
            del os.environ["WITNESS_VERIFY_PURE"]
        self.assertEqual(code, 0, text)
        self.assertIn("ed25519: pure-python", text)
        self.assertIn("PASS method-rerun", text)


class RecordDisclose(Base, unittest.TestCase):
    def test_disclosing_my_private_record_makes_a_public_one_with_the_body(self):
        rec = self.sealed_private(label="my own label")
        rid = rec["record_id"]
        code, out = self.run_disclose(rid, rec["disclosure"])
        self.assertEqual(code, 200, out)
        p = predicate(out)
        self.assertEqual(p["visibility"], "public")
        self.assertEqual((p["finding"], p["reason"], p["outcome"]), ("disclosed", "disclosed", "SUPPORTED"))
        at = self.anchor_time(rid)
        self.assertEqual(p["statement"], DISCLOSE_T.format(id=rid, anchor_time=at))
        self.assertEqual(p["detail"], {"anchor_time": at})
        self.assertEqual(p["limits"], DISCLOSE_LIMITS)
        self.assertEqual(p["claim"], claim("record.disclose", {}, True))
        self.assertIsNone(p["judgment"])
        self.assertEqual(p["relied_on"], [])
        self.assertEqual(p["evidence"][0], {"slot": "record", "kind": "record", "id": rid})
        item = p["evidence"][1]
        self.assertEqual((item["slot"], item["kind"], item["media_type"], item["name"]),
                         ("disclosure", "object", "application/json", "disclosure.json"))
        self.assertEqual(item["sha256"], h.sha(json.dumps(rec["disclosure"]).encode()))
        self.assertEqual(item["content"], rec["disclosure"])  # the body is in the clear in the signed record
        self.assertEqual(item["content"]["body"]["label"], "my own label")
        self.assertNotIn("disclosure", out)

    def test_the_original_stays_private_and_unchanged(self):
        rec = self.sealed_private()
        rid = rec["record_id"]
        before = self.s.storage.get_kept(rid)
        code, out = self.run_disclose(rid, rec["disclosure"])
        self.assertEqual(code, 200, out)
        after = self.s.storage.get_kept(rid)
        self.assertEqual(after["visibility"], "private")
        self.assertEqual(after["envelope"], before["envelope"])
        self.assertEqual(after["body_box"], before["body_box"])
        code, view, _ = self.get(rid, key=OTHER)
        self.assertNotIn("disclosure", view)
        self.assertNotIn(k.CANARY, json.dumps(view))
        code, view, _ = self.get(rid, key=None)
        self.assertNotIn("disclosure", view)
        self.assertEqual(view["visibility"], "private")
        code, mine, _ = self.get(rid, key=OWNER)
        self.assertEqual(mine["disclosure"], rec["disclosure"])

    def test_the_new_record_verifies_and_reruns(self):
        rec = self.sealed_private()
        code, out = self.run_disclose(rec["record_id"], rec["disclosure"])
        d = pathlib.Path(tempfile.mkdtemp(prefix="cw-b5b-disc-"))
        (d / "answer.json").write_text(json.dumps(out))
        (d / "keys.json").write_text(json.dumps(self.s.storage.get_key_list(1)))
        (d / "methods.tar.gz").write_bytes(tarball.build_methods_tarball())
        (d / "disclosure.json").write_text(json.dumps(rec["disclosure"]))
        code, view, _ = self.get(rec["record_id"], key=None)
        (d / "record.json").write_text(json.dumps(view))
        buf = io.StringIO()
        code = verify.main(["--envelope", str(d / "answer.json"), "--keys", str(d / "keys.json"), "--methods", str(d / "methods.tar.gz"),
                            "--evidence", str(d / "disclosure.json"), "--record", str(d / "record.json")], out=buf)
        self.assertEqual(code, 0, buf.getvalue())
        self.assertIn("PASS method-rerun", buf.getvalue())

    def test_a_changed_body_or_salt_is_422_and_signs_nothing(self):
        rec = self.sealed_private()
        before = self.s.log_count()
        bad_body = copy.deepcopy(rec["disclosure"])
        bad_body["body"]["statement"] = bad_body["body"]["statement"] + " (edited)"
        bad_salt = dict(rec["disclosure"], salt=base64.urlsafe_b64encode(bytes(16)).decode().rstrip("="))
        for d in (bad_body, bad_salt, {"salt": rec["disclosure"]["salt"]}, {"body": rec["disclosure"]["body"]}, []):
            code, out = self.run_disclose(rec["record_id"], d)
            self.assertEqual((code, out["error"]), (422, "disclosure-mismatch"), out)
        code, out = self.run_disclose(rec["record_id"], None, slot_bytes=b"not json at all")
        self.assertEqual((code, out["error"]), (422, "disclosure-mismatch"), out)
        self.assertEqual(self.s.log_count(), before)

    def test_a_record_that_is_not_mine_is_403(self):
        rec = self.sealed_private()
        before = self.s.log_count()
        code, out = self.run_disclose(rec["record_id"], rec["disclosure"], key=OTHER)
        self.assertEqual((code, out["error"]), (403, "not-owner"), out)
        self.assertEqual(self.s.log_count(), before)
        self.assertNotIn(k.CANARY, json.dumps(out))

    def test_a_false_assertion_is_422(self):
        rec = self.sealed_private()
        before = self.s.log_count()
        code, out = self.run_disclose(rec["record_id"], rec["disclosure"], assertion=False)
        self.assertEqual((code, out["error"]), (422, "assertion-not-allowed"), out)
        self.assertEqual(self.s.log_count(), before)

    def test_personal_data_in_the_body_is_422_personal_data(self):
        rec = self.sealed_private(label=EMAIL_LABEL)
        before = self.s.log_count()
        code, out = self.run_disclose(rec["record_id"], rec["disclosure"])
        self.assertEqual((code, out["error"]), (422, "personal-data"), out)
        self.assertNotIn("jane.roe", json.dumps(out))
        self.assertEqual(self.s.log_count(), before)

    def test_a_public_record_in_the_slot_is_422(self):
        rec = self.sealed_public()
        code, out = self.run_disclose(rec["record_id"], {"salt": "AAAAAAAAAAAAAAAAAAAAAA", "body": {}})
        self.assertEqual((code, out["error"]), (422, "public-record"), out)

    def test_an_unanchored_original_is_422_and_nothing_is_published(self):
        out = self.private_check()
        self.keep(out)
        before = self.s.log_count()
        code, got = self.run_disclose(out["record_id"], out["disclosure"])
        self.assertEqual((code, got["error"]), (422, "record-not-anchored"), got)
        self.assertEqual(self.s.log_count(), before)

    def test_unknown_and_unkept_ids_are_not_found(self):
        code, out = self.run_disclose("cd" * 32, {"salt": "x", "body": {}})
        self.assertEqual((code, out["error"]), (422, "record-not-found"), out)
        out = self.private_check()
        code, got = self.run_disclose(out["record_id"], out["disclosure"])
        self.assertEqual((code, got["error"]), (422, "record-not-found"), got)

    def test_the_new_record_must_be_public_by_an_explicit_request(self):
        rec = self.sealed_private()
        code, out = self.run_disclose(rec["record_id"], rec["disclosure"], visibility="private")
        self.assertEqual((code, out["error"]), (422, "invalid-options"), out)
        body = self.disclose_request(rec["record_id"], rec["disclosure"])
        del body["options"]["visibility"]
        code, out, _ = self.s.witness_call(body)
        self.assertEqual((code, out["error"]), (422, "invalid-options"), out)

    def test_a_deleted_original_cannot_be_disclosed(self):
        rec = self.sealed_private()
        self.s.call("DELETE", f"/v1/records/{rec['record_id']}", key=OWNER)
        code, out = self.run_disclose(rec["record_id"], rec["disclosure"])
        self.assertEqual((code, out["error"]), (410, "deleted"), out)

    def test_a_taken_down_original_cannot_be_disclosed(self):
        rec = self.sealed_private()
        self.s.call("POST", f"/v1/records/{rec['record_id']}/takedown", {}, key=OWNER)
        code, out = self.run_disclose(rec["record_id"], rec["disclosure"])
        self.assertEqual((code, out["error"]), (410, "taken-down"), out)

    def test_the_record_slot_takes_a_record_only(self):
        rec = self.sealed_private()
        code, out, _ = self.s.witness_call(request(claim("record.disclose", {}), [
            obj_item("record", b"x"), obj_item("disclosure", json.dumps(rec["disclosure"]).encode())], "public"))
        self.assertEqual((code, out["error"]), (422, "wrong-evidence-slots"), out)

    def test_the_agent_signature_covers_the_record_id(self):
        rec = self.sealed_private()
        seed = h.seed(41)
        code, reg, _ = self.s.call("POST", "/v1/agent-keys", {"public_key": h.b64(h.public_of(seed))}, key=OWNER)
        body = self.disclose_request(rec["record_id"], rec["disclosure"])
        msg = verify.agent_message("witness:test", body["claim"], body["evidence"], "nonce-b5b-0001", h.iso(self.clock()))
        from claim_witness import crypto
        body["agent"] = {"agent_key_id": reg["agent_key_id"], "agent_sig": h.b64(crypto.ed25519_sign(seed, msg)),
                         "nonce": "nonce-b5b-0001", "agent_time": h.iso(self.clock())}
        code, out, _ = self.s.witness_call(body, key=OWNER)
        self.assertEqual(code, 200, out)
        # the same signature over a different record id would not verify: the id is among the signed references
        refs = json.loads(verify.agent_message("witness:test", body["claim"], body["evidence"], "n", "t"))["evidence"]
        self.assertIn(rec["record_id"], refs)


class Vectors(unittest.TestCase):
    def test_vectors_hold_record_method_cases_and_reproduce(self):
        from claim_witness import vectors
        doc = json.loads(vectors.VECTORS.read_text(encoding="utf-8"))
        cases = doc["record_methods"]
        self.assertGreaterEqual(len([c for c in cases if c["method"] == "record.valid"]), 5)
        self.assertGreaterEqual(len([c for c in cases if c["method"] == "record.disclose"]), 2)
        findings = {c["finding"] for c in cases}
        self.assertTrue({"record-valid", "record-invalid", "disclosed", None} <= findings)
        buf = io.StringIO()
        self.assertEqual(vectors.check(doc, buf), 0, buf.getvalue())


if __name__ == "__main__":
    unittest.main()
