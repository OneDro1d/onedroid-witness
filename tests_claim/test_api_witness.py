"""POST /v1/witness end to end over HTTP (in-process server, memory storage): TS-1', TS-7, TS-16, VR-1, VR-2, VR-4, VR-14,
VR-17, VR-19, the outcome table, Idempotency-Key and the object-only idempotency rule, sync and 202 answers, GET /v1/jobs."""
import base64
import json
import time
import unittest
import uuid

from claim_witness import ids, jcs
from tests_claim import helpers as h
from tests_claim.helpers import GO_TEST_FAIL, GO_TEST_PASS, claim, obj_item, payload_bytes, payload_of, request, sha


class Base(unittest.TestCase):
    def setUp(self):
        self.s = h.Stack()

    def tearDown(self):
        self.s.close()

    def ok(self, body, **kw):
        code, out, _ = self.s.witness_call(body, **kw)
        self.assertEqual(code, 200, out)
        return out

    def refused(self, body, code, error=None, **kw):
        before = self.s.log_count()
        got, out, _ = self.s.witness_call(body, **kw)
        self.assertEqual(got, code, out)
        if error is not None:
            self.assertEqual(out["error"], error, out)
        self.assertEqual(self.s.log_count(), before, "a refused claim must make no record")
        return out


class MatchExactTS1(Base):
    def test_supported_with_limits_attempt_and_template(self):
        a = b"identical bytes\n"
        out = self.ok(h.exact_request(a, a))
        env = out["envelope"]
        self.assertEqual(env["payloadType"], "application/vnd.in-toto+json")
        st = payload_of(env)
        self.assertEqual(st["_type"], "https://in-toto.io/Statement/v1")
        self.assertEqual(st["predicateType"], "https://onedroid.ai/witness/claim/v1")
        p = st["predicate"]
        self.assertEqual((p["outcome"], p["finding"], p["reason"]), ("SUPPORTED", "match", "match"))
        self.assertEqual(p["limits"], "Bytes only.")
        self.assertEqual(p["statement"], f"The submitted file {sha(a)} is byte-identical to {sha(a)}.")
        self.assertEqual(p["attempt"], {"n": 1, "prior": {"SUPPORTED": 0, "NOT_SUPPORTED": 0, "CANNOT_WITNESS": 0},
                                        "window_days": 30, "scope": "account"})
        self.assertEqual(p["method"]["id"], "match.exact")
        self.assertRegex(p["method"]["version"], r"^\d+\.\d+\.\d+$")
        self.assertRegex(p["method"]["code_sha256"], r"^[0-9a-f]{64}$")
        self.assertTrue(p["method"]["runtime"].startswith("python3."))
        self.assertEqual(p["visibility"], "public")
        self.assertIsNone(p["judgment"])
        self.assertEqual(p["relied_on"], [])
        self.assertEqual(p["submitter"], {"account": "acct_a"})
        self.assertEqual(p["witness"], {"id": "witness:test", "key_id": "witness:test:2026a", "key_list_seq": 1})
        self.assertRegex(p["witnessed_at"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
        self.assertEqual(out["seal"], {"state": "pending"})
        self.assertNotIn("disclosure", out)
        # ids
        self.assertEqual(st["subject"], [{"name": "claim", "digest": {"sha256": ids.claim_id(p["claim"])}}])
        self.assertEqual(out["record_id"], ids.record_id(payload_bytes(env)))
        self.assertTrue(jcs.is_canonical(payload_bytes(env)))
        self.assertEqual(p["evidence"], [
            {"slot": "submitted", "kind": "object", "sha256": sha(a), "media_type": "text/plain", "name": "submitted.txt"},
            {"slot": "target", "kind": "object", "sha256": sha(a), "media_type": "text/plain", "name": "target.txt"}])
        self.assertEqual(p["claim"], {"method": "match.exact", "method_major": 1, "params": {}, "assertion": True, "statement": None})

    def test_assertion_false_gives_not_supported_with_f_template(self):
        a = b"identical bytes\n"
        p = payload_of(self.ok(h.exact_request(a, a, assertion=False))["envelope"])["predicate"]
        self.assertEqual((p["outcome"], p["finding"]), ("NOT_SUPPORTED", "match"))
        self.assertEqual(p["statement"], f"The submitted file {sha(a)} is not byte-identical to {sha(a)}.")

    def test_negative_finding_table(self):
        p = payload_of(self.ok(h.exact_request(b"a", b"b"))["envelope"])["predicate"]
        self.assertEqual((p["outcome"], p["finding"]), ("NOT_SUPPORTED", "differs"))
        p = payload_of(self.ok(h.exact_request(b"a", b"b", assertion=False))["envelope"])["predicate"]
        self.assertEqual((p["outcome"], p["finding"]), ("SUPPORTED", "differs"))

    def test_envelope_signature_verifies_with_listed_key(self):
        from claim_witness import dsse
        out = self.ok(h.exact_request())
        env = out["envelope"]
        self.assertEqual(env["signatures"][0]["keyid"], "witness:test:2026a")
        self.assertTrue(dsse.verify(env, {"witness:test:2026a": h.public_of(self.s.seed)}))

    def test_every_answer_is_one_signing_log_row(self):
        before = self.s.log_count()
        out = self.ok(h.exact_request(b"x", b"y"))
        log = self.s.storage.signing_log()
        self.assertEqual(len(log), before + 1)
        self.assertEqual(log[-1]["payload_id"], out["record_id"])
        self.assertEqual(log[-1]["predicate_type"], "https://onedroid.ai/witness/claim/v1")

    def test_multipart_upload(self):
        a = b"multipart bytes"
        body = h.exact_request(a, a)
        for e in body["evidence"]:
            del e["content_b64"]
        boundary = "b" + uuid.uuid4().hex
        parts = [("request", json.dumps(body).encode(), "application/json"), (sha(a), a, "application/octet-stream")]
        raw = b""
        for name, data, ct in parts:
            raw += (f"--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\nContent-Type: {ct}\r\n\r\n").encode()
            raw += data + b"\r\n"
        raw += f"--{boundary}--\r\n".encode()
        code, out, _ = self.s.call("POST", "/v1/witness", raw=raw, content_type=f"multipart/form-data; boundary={boundary}")
        self.assertEqual(code, 200, out)
        self.assertEqual(payload_of(out["envelope"])["predicate"]["outcome"], "SUPPORTED")


class TestsPassTS7(Base):
    def tp(self, data, params=None, assertion=True, media_type="application/json"):
        return request(claim("tests.pass", params or {}, assertion), [obj_item("log", data, media_type, "log.json")])

    def test_go_json_pass_supported(self):
        out = self.ok(self.tp(GO_TEST_PASS))
        p = payload_of(out["envelope"])["predicate"]
        self.assertEqual((p["outcome"], p["finding"]), ("SUPPORTED", "tests-passed"))
        self.assertEqual(p["limits"], "The log's origin was not verified.")

    def test_one_failure_not_supported_with_failing_tests_beside_envelope(self):
        out = self.ok(self.tp(GO_TEST_FAIL))
        p = payload_of(out["envelope"])["predicate"]
        self.assertEqual((p["outcome"], p["finding"]), ("NOT_SUPPORTED", "tests-failed"))
        self.assertEqual(out["failing_tests"], ["example.com/x.TestBroken"])
        self.assertNotIn("TestBroken", payload_bytes(out["envelope"]).decode())

    def test_prose_cannot_witness_unreadable(self):
        p = payload_of(self.ok(self.tp(b"everything is green", media_type="text/plain"))["envelope"])["predicate"]
        self.assertEqual((p["outcome"], p["finding"], p["reason"]), ("CANNOT_WITNESS", None, "unreadable"))
        p = payload_of(self.ok(self.tp(b"everything is green", assertion=False, media_type="text/plain"))["envelope"])["predicate"]
        self.assertEqual(p["outcome"], "CANNOT_WITNESS")

    def test_commit_mismatch_and_absent(self):
        log = GO_TEST_PASS + b'{"Action":"output","Package":"example.com/x","Output":"commit: 1111111aaaaaaa\\n"}\n'
        p = payload_of(self.ok(self.tp(log, {"expect_commit": "2222222bbbbbbb"}))["envelope"])["predicate"]
        self.assertEqual((p["outcome"], p["finding"], p["reason"]), ("CANNOT_WITNESS", "commit-mismatch", "commit-mismatch"))
        p = payload_of(self.ok(self.tp(GO_TEST_PASS, {"expect_commit": "2222222bbbbbbb"}))["envelope"])["predicate"]
        self.assertEqual((p["outcome"], p["finding"]), ("CANNOT_WITNESS", "commit-absent"))
        p = payload_of(self.ok(self.tp(log, {"expect_commit": "1111111aaaaaaa"}))["envelope"])["predicate"]
        self.assertEqual(p["outcome"], "SUPPORTED")
        self.assertTrue(p["statement"].endswith("no failures for commit 1111111aaaaaaa."))


class RefusalsTS16(Base):
    QUOTE_SRC = b"The quick brown fox jumps over the lazy dog."

    def quote_req(self, quote="brown fox", assertion=True, statement=None, evidence=None):
        return request(claim("quote.in-source", {"quote": quote}, assertion, statement),
                       evidence if evidence is not None else [obj_item("source", self.QUOTE_SRC)])

    def test_statement_on_mechanical_method_422(self):
        self.refused(self.quote_req(statement="I say so"), 422, "statement-not-allowed")

    def test_wrong_slot_422(self):
        self.refused(self.quote_req(evidence=[obj_item("page", self.QUOTE_SRC)]), 422, "wrong-evidence-slots")
        self.refused(self.quote_req(evidence=[obj_item("source", self.QUOTE_SRC), obj_item("source", b"two")]), 422,
                     "wrong-evidence-slots")
        self.refused(self.quote_req(evidence=[]), 422, "wrong-evidence-slots")
        self.refused(request(claim("match.exact"), [obj_item("submitted", b"a")]), 422, "wrong-evidence-slots")

    def test_hash_mismatch_400(self):
        item = obj_item("source", self.QUOTE_SRC)
        item["content_b64"] = base64.b64encode(b"other bytes").decode()
        self.refused(self.quote_req(evidence=[item]), 400, "hash-mismatch")

    def test_missing_bytes_400(self):
        item = obj_item("source", self.QUOTE_SRC, inline=False)
        self.refused(self.quote_req(evidence=[item]), 400)

    def test_valid_quote_record_has_exact_templates(self):
        s = sha(self.QUOTE_SRC)
        p = payload_of(self.ok(self.quote_req())["envelope"])["predicate"]
        self.assertEqual((p["outcome"], p["finding"]), ("SUPPORTED", "quote-found"))
        self.assertEqual(p["statement"], f"{s} contains the passage: \u201cbrown fox\u201d.")
        self.assertEqual(set(p["detail"]), {"start", "end", "source_chars"})
        p = payload_of(self.ok(self.quote_req(assertion=False))["envelope"])["predicate"]
        self.assertEqual(p["outcome"], "NOT_SUPPORTED")
        self.assertEqual(p["statement"], f"{s} does not contain the passage: \u201cbrown fox\u201d.")
        p = payload_of(self.ok(self.quote_req(quote="purple fox", assertion=False))["envelope"])["predicate"]
        self.assertEqual((p["outcome"], p["finding"]), ("SUPPORTED", "quote-absent"))

    def test_vr1_malformed_claims(self):
        c = claim("match.exact")
        ev = [obj_item("submitted", b"a"), obj_item("target", b"a")]
        for key in ("method", "params", "assertion"):
            bad = dict(c)
            del bad[key]
            self.refused(request(bad, ev), 422)
        self.refused(request(dict(c, method="no.such.method"), ev), 422, "unknown-method")
        self.refused(request(dict(c, method_major=2), ev), 422, "unknown-method")
        self.refused(request(dict(c, params={"x": 1}), ev), 422, "invalid-params")
        self.refused(request(dict(c, assertion="yes"), ev), 422)
        self.refused(request(dict(c, extra=1), ev), 422)
        self.refused(request(claim("quote.in-source", {}), [obj_item("source", b"a")]), 422, "invalid-params")
        self.refused(request(claim("quote.in-source", {"quote": ""}), [obj_item("source", b"a")]), 422, "invalid-params")
        self.refused(request(claim("tests.pass", {"expect_commit": "not hex"}), [obj_item("log", b"a")]), 422, "invalid-params")
        self.refused(request(claim("quote.in-source", {"quote": "e\u0301"}), [obj_item("source", b"a")]), 422, "invalid-params")

    def test_vr1_not_json_400(self):
        before = self.s.log_count()
        code, out, _ = self.s.call("POST", "/v1/witness", raw=b"{not json", content_type="application/json")
        self.assertEqual(code, 400)
        code, out, _ = self.s.call("POST", "/v1/witness", raw=b"[1,2]", content_type="application/json")
        self.assertEqual(code, 400)
        self.assertEqual(self.s.log_count(), before)

    def test_bad_options_422(self):
        body = h.exact_request()
        body["options"]["visibility"] = "secret"
        self.refused(body, 422, "invalid-options")
        body = h.exact_request()
        body["options"]["wait"] = -1
        self.refused(body, 422, "invalid-options")

    def test_label_too_long_422(self):
        body = h.exact_request()
        body["label"] = "x" * 201
        self.refused(body, 422)

    def test_observation_and_url_evidence_not_served_in_b1(self):
        body = request(claim("match.exact"), [obj_item("submitted", b"a"), {"slot": "target", "kind": "observation", "id": "0" * 64}])
        self.refused(body, 422)
        body = request(claim("match.exact"), [obj_item("submitted", b"a"), {"slot": "target", "kind": "url", "url": "https://x.example/"}])
        self.refused(body, 422, "wrong-evidence-slots")

    def test_object_too_large_413(self):
        self.s.close()
        self.s = h.Stack(config_overrides={"max_object_bytes": 10})
        self.refused(h.exact_request(b"0123456789abc", b"0123456789abc"), 413)


class PrivateRecords(Base):
    def test_private_by_default_with_disclosure(self):
        a = b"private bytes"
        body = h.exact_request(a, a)
        del body["options"]["visibility"]
        body["label"] = "my own words"
        out = self.ok(body)
        st = payload_of(out["envelope"])
        p = st["predicate"]
        self.assertEqual(p["visibility"], "private")
        self.assertEqual(set(p), {"visibility", "body_commitment", "finding", "outcome", "reason", "method", "limits", "detail",
                                  "attempt", "options_used", "witnessed_at", "witness"})
        d = out["disclosure"]
        salt = ids.b64url_decode(d["salt"])
        self.assertEqual(len(salt), 16)
        body_obj = d["body"]
        self.assertEqual(body_obj["label"], "my own words")
        self.assertEqual(body_obj["visibility"], "private")
        self.assertEqual(body_obj["outcome"], "SUPPORTED")
        self.assertEqual(body_obj["statement"], f"The submitted file {sha(a)} is byte-identical to {sha(a)}.")
        self.assertEqual(st["subject"], [{"name": "claim", "digest": {"sha256": ids.claim_commitment(salt, body_obj["claim"])}}])
        self.assertEqual(p["body_commitment"], ids.body_commitment(salt, body_obj))
        self.assertNotIn(sha(a), payload_bytes(out["envelope"]).decode())
        self.assertNotIn("acct_a", payload_bytes(out["envelope"]).decode())

    def test_fresh_salt_each_record(self):
        b1 = h.exact_request(b"p1", b"p1", visibility="private")
        b2 = h.exact_request(b"p2", b"p2", visibility="private")
        self.assertNotEqual(self.ok(b1)["disclosure"]["salt"], self.ok(b2)["disclosure"]["salt"])

    def test_keep_not_served_in_b1(self):
        self.refused(h.exact_request(keep=True), 422)


class AttemptsVR19(Base):
    def test_attempts_count_across_visibility_and_window(self):
        a = b"attempt bytes"
        p1 = payload_of(self.ok(h.exact_request(a, a, visibility="private"))["envelope"])["predicate"]
        self.assertEqual(p1["attempt"]["n"], 1)
        p2 = payload_of(self.ok(h.exact_request(a, a, visibility="public"))["envelope"])["predicate"]
        self.assertEqual(p2["attempt"]["n"], 2)
        self.assertEqual(p2["attempt"]["prior"], {"SUPPORTED": 1, "NOT_SUPPORTED": 0, "CANNOT_WITNESS": 0})
        # past the 24 h idempotency window the same claim runs again and counts
        self.s.clock.advance(25 * 3600)
        p3 = payload_of(self.ok(h.exact_request(a, a, visibility="public"))["envelope"])["predicate"]
        self.assertEqual(p3["attempt"]["n"], 3)
        # outside the 30-day window nothing earlier is counted
        self.s.clock.advance(31 * 86400)
        p4 = payload_of(self.ok(h.exact_request(a, a, visibility="public"))["envelope"])["predicate"]
        self.assertEqual(p4["attempt"]["n"], 1)

    def test_other_accounts_attempts_not_counted(self):
        a = b"scoped bytes"
        self.ok(h.exact_request(a, a))
        p = payload_of(self.ok(h.exact_request(a, a), key="dev-key-b-0123456789abcdef")["envelope"])["predicate"]
        self.assertEqual(p["attempt"]["n"], 1)
        self.assertEqual(p["submitter"], {"account": "acct_b"})

    def test_attempt_tag_is_hmac_of_plaintext(self):
        from claim_witness import attempts
        c = claim("match.exact")
        t1 = attempts.attempt_tag(b"K" * 32, c, ["b", "a"], [], "match.exact", "acct_a")
        t2 = attempts.attempt_tag(b"K" * 32, c, ["a", "b"], [], "match.exact", "acct_a")
        self.assertEqual(t1, t2)
        self.assertNotEqual(t1, attempts.attempt_tag(b"L" * 32, c, ["a", "b"], [], "match.exact", "acct_a"))
        self.assertNotEqual(t1, attempts.attempt_tag(b"K" * 32, c, ["a", "b"], [], "match.exact", "acct_b"))
        import hashlib
        import hmac
        want = hmac.new(b"K" * 32, jcs.canonical({"claim": c, "objects": ["a", "b"], "urls": [], "method": "match.exact",
                                                  "account": "acct_a"}), hashlib.sha256).hexdigest()
        self.assertEqual(t1, want)


class Idempotency(Base):
    def test_object_only_mechanical_same_claim_returns_existing_record(self):
        first = self.ok(h.exact_request(b"same", b"same"))
        n = self.s.log_count()
        again = self.ok(h.exact_request(b"same", b"same"))
        self.assertEqual(again["record_id"], first["record_id"])
        self.assertEqual(again["envelope"], first["envelope"])
        self.assertEqual(self.s.log_count(), n)

    def test_idempotency_key_returns_first_answer_without_second_run(self):
        hk = {"Idempotency-Key": "retry-123"}
        first = self.ok(h.exact_request(b"k1", b"k1"), headers=hk)
        n = self.s.log_count()
        again = self.ok(h.exact_request(b"k1", b"k1"), headers=hk)
        self.assertEqual(again, first)
        self.assertEqual(self.s.log_count(), n)
        code, out, _ = self.s.witness_call(h.exact_request(b"k2", b"k2"), headers=hk)
        self.assertEqual(code, 409, out)
        # another account's identical key is its own
        code, out, _ = self.s.witness_call(h.exact_request(b"k1", b"k1"), headers=hk, key="dev-key-b-0123456789abcdef")
        self.assertEqual(code, 200)
        self.assertEqual(payload_of(out["envelope"])["predicate"]["submitter"]["account"], "acct_b")

    def test_private_idempotent_answer_keeps_its_disclosure(self):
        first = self.ok(h.exact_request(b"pv", b"pv", visibility="private"))
        again = self.ok(h.exact_request(b"pv", b"pv", visibility="private"))
        self.assertEqual(again["disclosure"], first["disclosure"])

    # The replay marker (Aleksander, #argus-onedroid 26 Nov): an answer from the object-only rule says it is a replay and
    # reports price 0, because the BFF charges a record once; the record itself is unchanged.
    def test_content_replay_says_replayed_and_price_zero(self):
        first = self.ok(h.exact_request(b"rp", b"rp"))
        self.assertNotIn("replayed", first)
        self.assertEqual(first["price"]["credits"], 1)
        again = self.ok(h.exact_request(b"rp", b"rp"))
        self.assertIs(again["replayed"], True)
        self.assertEqual(again["price"], {"credits": 0, "lines": []})
        self.assertEqual(again["record_id"], first["record_id"])
        self.assertEqual(again["envelope"], first["envelope"])

    def test_content_replay_under_a_new_idempotency_key_is_marked_and_repeats_marked(self):
        first = self.ok(h.exact_request(b"rk", b"rk"), headers={"Idempotency-Key": "rk-1"})
        self.assertNotIn("replayed", first)
        again = self.ok(h.exact_request(b"rk", b"rk"), headers={"Idempotency-Key": "rk-2"})
        self.assertIs(again["replayed"], True)
        self.assertEqual(again["price"], {"credits": 0, "lines": []})
        self.assertEqual(again["record_id"], first["record_id"])
        # the same key again answers that (marked) answer; the first key still answers the first, unmarked one
        self.assertEqual(self.ok(h.exact_request(b"rk", b"rk"), headers={"Idempotency-Key": "rk-2"}), again)
        self.assertEqual(self.ok(h.exact_request(b"rk", b"rk"), headers={"Idempotency-Key": "rk-1"}), first)

    def test_content_replay_of_private_record_keeps_disclosure_and_is_marked(self):
        first = self.ok(h.exact_request(b"rv", b"rv", visibility="private"))
        again = self.ok(h.exact_request(b"rv", b"rv", visibility="private"))
        self.assertEqual(again["disclosure"], first["disclosure"])
        self.assertIs(again["replayed"], True)

    def test_new_label_is_a_new_record_not_a_replay(self):
        first = self.ok(h.exact_request(b"rl", b"rl"))
        req = h.exact_request(b"rl", b"rl")
        req["label"] = "another run"
        other = self.ok(req)
        self.assertNotEqual(other["record_id"], first["record_id"])
        self.assertNotIn("replayed", other)
        self.assertEqual(other["price"]["credits"], 1)


class Jobs(Base):
    def test_wait_zero_gives_202_then_job_done(self):
        code, out, _ = self.s.witness_call(h.exact_request(b"job", b"job", wait=0))
        self.assertEqual(code, 202, out)
        jid = out["job_id"]
        deadline = time.time() + 10
        while True:
            code, st, _ = self.s.call("GET", f"/v1/jobs/{jid}")
            self.assertEqual(code, 200, st)
            if st["state"] == "done" or time.time() > deadline:
                break
            time.sleep(0.05)
        self.assertEqual(st["state"], "done")
        self.assertEqual(payload_of(st["answer"]["envelope"])["predicate"]["outcome"], "SUPPORTED")
        code, _, _ = self.s.call("GET", f"/v1/jobs/{jid}", key="dev-key-b-0123456789abcdef")
        self.assertEqual(code, 404)
        code, _, _ = self.s.call("GET", "/v1/jobs/no-such-job")
        self.assertEqual(code, 404)

    def test_job_answer_is_stored_encrypted(self):
        out = self.ok(h.exact_request(b"enc", b"enc", visibility="private"))
        for job in self.s.storage.all_jobs():
            blob = job.get("answer") or b""
            self.assertNotIn(out["disclosure"]["salt"].encode(), blob)
            self.assertNotIn(b"SUPPORTED", blob)

    def test_jobs_expire_after_24h(self):
        code, out, _ = self.s.witness_call(h.exact_request(b"exp", b"exp", wait=0))
        jid = out["job_id"]
        time.sleep(0.3)
        self.s.clock.advance(24 * 3600 + 60)
        self.s.witness.purge()
        code, _, _ = self.s.call("GET", f"/v1/jobs/{jid}")
        self.assertEqual(code, 404)


if __name__ == "__main__":
    unittest.main()
