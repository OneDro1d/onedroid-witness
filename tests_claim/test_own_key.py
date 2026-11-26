"""Own model key (DESIGN M-20261126-CLAIMS-DOCS-BYOK, C1 witness part and C2): a check the BFF forwards with
`options.billing: "own-key"` and the account's OpenRouter key in `X-Witness-Model-Key`.

C1: billing is a known option whose only value is "own-key"; billing own-key without the header is 422 model-key-missing; the
header without billing is ignored. An own-key judged run calls the configured models with the header key (never the
witness's own key); the key is never logged, stored or echoed. A key the router refuses on every run (401, 402, 403) is 422
model-key-rejected with nothing signed. The price is {credits: 0, billing: own-key, lines}, model-run lines paid_by own-key.
Fresh observations past the free allowance are 402 own-key-observation-limit. Answers carry top-level `anchoring`.

C2: every signing-log row signed while serving an own-key request has tier own; the sealer never mixes tiers in a batch; the
header carries `anchoring`; own batches go only to the own notary profile (never hash/1), unanchored without one, and an
own seal naming any chain but lab-qbft is a failed seal. witness-verify prints the INFO line for an own header, never FAILs
it for the missing public anchor, and FAILs an own header whose seal carries a base-sepolia anchor.

Every model call goes to the local fake (tests_claim/fake_models.py), every notary call to the fakes in fake_seal.py.
"""
import base64
import contextlib
import copy
import io
import json
import pathlib
import tempfile
import unittest

from claim_witness import crypto, dsse, jcs, judge, notary, signer as signer_mod, verify
from claim_witness.schemas import BATCH_TYPE, CLAIM_TYPE
from tests_claim import fake_models as fm
from tests_claim import helpers as h
from tests_claim.fake_seal import FakeNotary, HttpsNotary, make_tls
from tests_claim.fakefetch import page, stack as fetch_stack, url_item
from tests_claim.helpers import claim, exact_request, obj_item, payload_of, request

OWN_KEY = "sk-or-v1-test-own-0123456789abcdefOWNKEY"
OTHER_KEY = "sk-or-v1-test-other-0123456789abcdefXYZ"
HDR = {"X-Witness-Model-Key": OWN_KEY}
INFO = "INFO anchoring: own chain only (a check paid with the user's own model key is not anchored on a public chain)"
PAGE = ("<html><body><h1>Acme Widgets</h1><p>The Model X widget ships with a two-year warranty.</p>"
        "<p>Prices start at 40 EUR.</p></body></html>").encode()
PAGE_TEXT = fm.visible_of(PAGE, "text/html")
STATEMENT = "The Model X widget has a two-year warranty."
MODELS = [{"id": "acme/judge-1", "vendor": "acme", "price_factor": 1, "timeout": 3},
          {"id": "beta/judge-2", "vendor": "beta", "price_factor": 2, "timeout": 3}]
U = "https://own.example/p"


def supports():
    return fm.answer("judged-supports", [fm.quote(0, PAGE_TEXT, "two-year warranty")])


def judge_request(visibility="public", billing="own-key", **options):
    body = request(claim("judge.supports", {}, True, STATEMENT), [obj_item("evidence", PAGE, "text/html", "page.html")],
                   visibility, **options)
    if billing is not None:
        body["options"]["billing"] = billing
    return body


def own(body):
    body = copy.deepcopy(body)
    body.setdefault("options", {})["billing"] = "own-key"
    return body


class JudgeBase(unittest.TestCase):
    def setUp(self):
        self.fake = fm.FakeModels()
        self.fake.accepted_keys.add(OWN_KEY)
        self.dir = pathlib.Path(tempfile.mkdtemp(prefix="cw-own-"))
        (self.dir / "key").write_text(self.fake.api_key)
        (self.dir / "models.json").write_text(json.dumps(MODELS))
        env = {"WITNESS_JUDGE_BASE_URL": self.fake.base_url, "WITNESS_JUDGE_API_KEY_FILE": str(self.dir / "key"),
               "WITNESS_JUDGE_MODELS_FILE": str(self.dir / "models.json")}
        self.s = h.Stack(config_overrides={"judge": judge.from_env(env)})
        for spec in MODELS:
            self.fake.script(spec["id"], supports())

    def tearDown(self):
        self.s.close()
        self.fake.close()

    def refused(self, body, code, error, headers=None):
        before = self.s.log_count()
        got, out, _ = self.s.witness_call(body, headers=headers)
        self.assertEqual((got, out.get("error")), (code, error), out)
        self.assertEqual(self.s.log_count(), before, "a refused check signs nothing")
        return out

    def everything_stored(self):
        """Every byte the witness keeps: jobs (answers opened), judge outputs, the signing log, observations."""
        st = self.s.storage
        parts = [json.dumps(st.signing_log()), json.dumps([dict(r) for r in st.judge_outputs()], default=str)]
        for j in st.all_jobs():
            row = {k: (v.hex() if isinstance(v, (bytes, bytearray)) else v) for k, v in j.items()}
            parts.append(json.dumps(row, default=str))
            if j.get("answer"):
                parts.append(json.dumps(self.s.witness._answer_of(j)))
        return "\n".join(parts)


class Options(JudgeBase):
    def test_billing_other_than_own_key_is_invalid_options(self):
        for value in ("credits", "OWN-KEY", "", 1, None, True):
            body = judge_request(billing=None)
            body["options"]["billing"] = value
            out = self.refused(body, 422, "invalid-options", HDR)
            self.assertIn("billing", out["detail"])

    def test_billing_own_key_without_the_header_is_model_key_missing(self):
        self.refused(judge_request(), 422, "model-key-missing")
        self.assertEqual(self.fake.chat_requests(), [])

    def test_an_empty_or_malformed_header_is_model_key_missing_and_never_echoed(self):
        for value in ("", "   ", "sk-or v1 with spaces"):
            out = self.refused(judge_request(), 422, "model-key-missing", {"X-Witness-Model-Key": value})
            if value.strip():
                self.assertNotIn(value, json.dumps(out))

    def test_the_header_without_billing_is_ignored(self):
        code, out, _ = self.s.witness_call(judge_request(billing=None), headers=HDR)
        self.assertEqual(code, 200, out)
        auths = {r["authorization"] for r in self.fake.chat_requests()}
        self.assertEqual(auths, {f"Bearer {self.fake.api_key}"})
        self.assertNotIn("billing", out["price"])
        self.assertEqual(out["price"]["credits"], 11)
        self.assertEqual(out["anchoring"], "public")
        row = [r for r in self.s.storage.signing_log() if r["payload_id"] == out["record_id"]][0]
        self.assertEqual(row["tier"], "public")


class OwnKeyJudged(JudgeBase):
    def test_the_header_key_is_used_for_every_model_call(self):
        code, out, _ = self.s.witness_call(judge_request(models={"count": 2, "require": 2}), headers=HDR)
        self.assertEqual(code, 200, out)
        auths = [r["authorization"] for r in self.fake.chat_requests()]
        self.assertEqual(auths, [f"Bearer {OWN_KEY}"] * 2)
        p = payload_of(out["envelope"])["predicate"]
        self.assertEqual(p["outcome"], "SUPPORTED")
        self.assertEqual([m["id"] for m in p["judgment"]["models"]], ["acme/judge-1", "beta/judge-2"])

    def test_the_own_key_price_shape(self):
        code, out, _ = self.s.witness_call(judge_request(models={"count": 2, "require": 2}), headers=HDR)
        self.assertEqual(code, 200, out)
        self.assertEqual(out["price"], {"credits": 0, "billing": "own-key", "lines": [
            {"item": "check", "credits": 0},
            {"item": "model-run", "model": "acme/judge-1", "credits": 0, "paid_by": "own-key"},
            {"item": "model-run", "model": "beta/judge-2", "credits": 0, "paid_by": "own-key"}]})

    def test_answer_job_and_record_view_say_anchoring_own(self):
        code, out, _ = self.s.witness_call(judge_request(wait=0), headers=HDR)
        self.assertEqual(code, 202, out)
        from tests_claim.fakefetch import wait_job
        job = wait_job(self.s, out["job_id"])
        self.assertEqual(job["state"], "done", job)
        ans = job["answer"]
        self.assertEqual(ans["anchoring"], "own")
        rid = ans["record_id"]
        code, kept, _ = self.s.call("POST", f"/v1/records/{rid}/keep", {"envelope": ans["envelope"]})
        self.assertEqual(code, 200, kept)
        code, view, _ = self.s.call("GET", f"/v1/records/{rid}", key=None)
        self.assertEqual((code, view["anchoring"]), (200, "own"), view)

    def test_a_paid_record_view_says_anchoring_public(self):
        code, out, _ = self.s.witness_call(judge_request(billing=None))
        self.assertEqual((code, out["anchoring"]), (200, "public"), out)
        self.s.call("POST", f"/v1/records/{out['record_id']}/keep", {"envelope": out["envelope"]})
        code, view, _ = self.s.call("GET", f"/v1/records/{out['record_id']}", key=None)
        self.assertEqual((code, view["anchoring"]), (200, "public"), view)

    def test_the_record_row_has_tier_own(self):
        code, out, _ = self.s.witness_call(judge_request(), headers=HDR)
        self.assertEqual(code, 200, out)
        row = [r for r in self.s.storage.signing_log() if r["payload_id"] == out["record_id"]][0]
        self.assertEqual(row["tier"], "own")
        self.assertEqual(self.s.witness.storage.log_tier(out["record_id"]), "own")

    def test_the_key_is_never_stored_logged_or_echoed(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            code, out, _ = self.s.witness_call(judge_request(), headers=HDR)
            self.assertEqual(code, 200, out)
            code, job, _ = self.s.call("GET", "/v1/jobs/" + self.s.storage.all_jobs()[0]["id"])
        self.assertNotIn(OWN_KEY, json.dumps(out))
        self.assertNotIn(OWN_KEY, json.dumps(job))
        self.assertNotIn(OWN_KEY, buf.getvalue())
        self.assertNotIn(OWN_KEY, self.everything_stored())
        self.assertNotIn(OWN_KEY, repr(self.s.witness.cfg.judge))

    def test_a_provider_answer_echoing_the_key_is_scrubbed_everywhere(self):
        echo = json.dumps({"finding": "judged-supports", "quotes": [fm.quote(0, PAGE_TEXT, "two-year warranty")],
                           "note": "called with " + OWN_KEY})
        self.fake.script("acme/judge-1", fm.completion({
            "id": "x", "object": "chat.completion", "model": "acme/judge-1-" + OWN_KEY, "provider": "Echo " + OWN_KEY,
            "choices": [{"index": 0, "message": {"role": "assistant", "content": echo}, "finish_reason": "stop"}]}))
        code, out, _ = self.s.witness_call(judge_request(), headers=HDR)
        self.assertEqual(code, 200, out)
        self.assertNotIn(OWN_KEY, json.dumps(out))
        self.assertNotIn(OWN_KEY, base64.b64decode(out["envelope"]["payload"]).decode("utf-8"))
        self.assertNotIn(OWN_KEY, self.everything_stored())

    def test_a_provider_error_body_echoing_the_key_leaves_no_trace(self):
        self.fake.script("acme/judge-1", fm.status(500, json.dumps({"error": "bad key " + OWN_KEY}).encode()))
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            code, out, _ = self.s.witness_call(judge_request(), headers=HDR)
        self.assertEqual(code, 200, out)  # a 500 is a failed run (model-unavailable), not a refused key
        self.assertNotIn(OWN_KEY, json.dumps(out) + buf.getvalue() + self.everything_stored())


class OwnKeyRejected(JudgeBase):
    def test_401_on_every_run_is_model_key_rejected_with_nothing_signed(self):
        self.fake.key_answers[OWN_KEY] = (401, json.dumps({"error": {"message": "No auth credentials " + OWN_KEY}}).encode())
        out = self.refused(judge_request(models={"count": 2, "require": 1}), 422, "model-key-rejected", HDR)
        self.assertEqual(out["detail"], "OpenRouter answered 401: the key is not valid")
        self.assertNotIn(OWN_KEY, json.dumps(out) + self.everything_stored())
        self.assertEqual(len(self.fake.chat_requests()), 2)

    def test_402_names_credit(self):
        self.fake.key_answers[OWN_KEY] = (402, b'{"error": {"message": "Insufficient credits"}}')
        out = self.refused(judge_request(), 422, "model-key-rejected", HDR)
        self.assertEqual(out["detail"], "OpenRouter answered 402: the key's OpenRouter account is out of credit")

    def test_403_names_a_disabled_key(self):
        self.fake.key_answers[OWN_KEY] = (403, b'{"error": {"message": "Key disabled"}}')
        out = self.refused(judge_request(), 422, "model-key-rejected", HDR)
        self.assertTrue(out["detail"].startswith("OpenRouter answered 403: "), out)
        self.assertIn("disabled", out["detail"])

    def test_a_job_refused_this_way_fails_with_422_and_no_answer(self):
        self.fake.key_answers[OWN_KEY] = (401, b"{}")
        code, out, _ = self.s.witness_call(judge_request(wait=0), headers=HDR)
        self.assertEqual(code, 202, out)
        from tests_claim.fakefetch import wait_job
        job = wait_job(self.s, out["job_id"])
        self.assertEqual((job["state"], job["http_status"], job["error"]["error"]), ("failed", 422, "model-key-rejected"))
        self.assertEqual([r for r in self.s.storage.signing_log() if r["predicate_type"] == CLAIM_TYPE], [])

    def test_the_witness_own_key_being_refused_is_not_model_key_rejected(self):
        self.fake.key_answers[self.fake.api_key] = (401, b"{}")
        code, out, _ = self.s.witness_call(judge_request(billing=None))
        self.assertEqual(code, 200, out)  # today's behaviour: failed runs, a record


class OwnKeyMechanical(unittest.TestCase):
    def setUp(self):
        self.s = h.Stack()

    def tearDown(self):
        self.s.close()

    def test_a_mechanical_own_key_check_is_free_and_own(self):
        code, out, _ = self.s.witness_call(own(exact_request()), headers=HDR)
        self.assertEqual(code, 200, out)
        self.assertEqual(out["price"], {"credits": 0, "billing": "own-key", "lines": [{"item": "check", "credits": 0}]})
        self.assertEqual(out["anchoring"], "own")
        self.assertEqual(self.s.storage.log_tier(out["record_id"]), "own")

    def test_a_paid_answer_is_never_served_for_an_own_key_request_or_back(self):
        code, paid, _ = self.s.witness_call(exact_request())
        self.assertEqual((code, paid["anchoring"]), (200, "public"))
        code, mine, _ = self.s.witness_call(own(exact_request()), headers=HDR)
        self.assertEqual((code, mine["anchoring"]), (200, "own"))
        self.assertNotEqual(mine["record_id"], paid["record_id"])
        code, again, _ = self.s.witness_call(exact_request())
        self.assertEqual(again["record_id"], paid["record_id"])

    def test_an_own_key_replay_is_marked_and_keeps_its_billing(self):
        # the replay marker (README_CLAIM.md item 5) on an own-key record: price 0 with billing own-key, anchoring own
        code, mine, _ = self.s.witness_call(own(exact_request(b"own replay\n")), headers=HDR)
        self.assertEqual(code, 200, mine)
        code, again, _ = self.s.witness_call(own(exact_request(b"own replay\n")), headers=HDR)
        self.assertEqual(code, 200, again)
        self.assertEqual(again["record_id"], mine["record_id"])
        self.assertIs(again["replayed"], True)
        self.assertEqual(again["price"], {"credits": 0, "lines": [], "billing": "own-key"})
        self.assertEqual(again["anchoring"], "own")

    def test_signer_answers_name_the_tier(self):
        out = self.s.signer.sign(BATCH_TYPE, {"witness": "witness:test", "batch_id": "a" * 64, "root": "b" * 64, "size": 1,
                                              "opened_at": "2026-11-24T00:00:00Z", "closed_at": "2026-11-24T01:00:00Z",
                                              "interval_s": 3600, "key_id": self.s.key_id, "anchoring": "own"}, tier="own")
        self.assertEqual(out["tier"], "own")
        self.assertEqual(self.s.storage.signing_log()[-1]["tier"], "own")

    def test_the_signer_refuses_an_unknown_tier_and_a_header_whose_anchoring_is_not_its_tier(self):
        hdr = {"witness": "witness:test", "batch_id": "a" * 64, "root": "b" * 64, "size": 1, "opened_at": "2026-11-24T00:00:00Z",
               "closed_at": "2026-11-24T01:00:00Z", "interval_s": 3600, "key_id": self.s.key_id, "anchoring": "own"}
        n = self.s.log_count()
        with self.assertRaises(signer_mod.Refused):
            self.s.signer.sign(BATCH_TYPE, hdr, tier="gold")
        with self.assertRaises(signer_mod.Refused):
            self.s.signer.sign(BATCH_TYPE, hdr, tier="public")
        with self.assertRaises(signer_mod.Refused):
            self.s.signer.sign(BATCH_TYPE, dict(hdr, anchoring="gold"), tier="public")
        self.assertEqual(self.s.log_count(), n)

    def test_storage_keeps_the_tier_and_old_rows_are_public(self):
        st = self.s.storage
        st.append_signing_log("p" * 64, CLAIM_TYPE, h.T0, leaf="1" * 64)
        st.append_signing_log("o" * 64, CLAIM_TYPE, h.T0, leaf="2" * 64, tier="own")
        self.assertEqual(st.log_tier("p" * 64), "public")
        self.assertEqual(st.log_tier("o" * 64), "own")
        self.assertIsNone(st.log_tier("z" * 64))
        self.assertEqual([r["payload_id"] for r in st.pending_leaves(10, tier="own")], ["o" * 64])
        self.assertNotIn("o" * 64, [r["payload_id"] for r in st.pending_leaves(10, tier="public")])


class OwnKeyObservations(unittest.TestCase):
    def setUp(self):
        self.s, self.ff, self.sleeper = fetch_stack(free_observations_per_day=2)
        self.ff.set(U, page())

    def tearDown(self):
        self.s.close()
        self.ff.close()

    def observe(self, billing="own-key", headers=HDR, **extra):
        body = {"url": U, "capture": "page", "visibility": "public"}
        if billing is not None:
            body["options"] = {"billing": billing}
        body.update(extra)
        return self.s.call("POST", "/v1/observe", body, headers=headers)

    def test_an_own_key_observation_is_free_own_and_says_so(self):
        code, out, _ = self.observe()
        self.assertEqual(code, 200, out)
        self.assertEqual(out["anchoring"], "own")
        self.assertEqual(out["price"]["credits"], 0)
        self.assertEqual(out["price"]["billing"], "own-key")
        self.assertEqual(self.s.storage.log_tier(out["observation_id"]), "own")

    def test_observe_billing_rules(self):
        code, out, _ = self.observe(headers=None)
        self.assertEqual((code, out["error"]), (422, "model-key-missing"), out)
        code, out, _ = self.observe(billing="credits")
        self.assertEqual((code, out["error"]), (422, "invalid-options"), out)
        code, out, _ = self.s.call("POST", "/v1/observe", {"url": U, "options": {"billing": "own-key", "keep": True}}, headers=HDR)
        self.assertEqual((code, out["error"]), (422, "invalid-options"), out)
        code, out, _ = self.observe(billing=None)  # the header alone is ignored: a paid observation
        self.assertEqual((code, out["anchoring"]), (200, "public"), out)
        self.assertNotIn("billing", out["price"])

    def test_past_the_free_allowance_own_key_observations_are_refused_before_any_fetch(self):
        for _ in range(2):
            code, out, _ = self.observe()
            self.assertEqual(code, 200, out)
        n, calls = self.s.log_count(), len(self.ff.calls)
        code, out, _ = self.observe()
        self.assertEqual((code, out["error"]), (402, "own-key-observation-limit"), out)
        self.assertEqual(out["detail"], "own-key checks include 2 fresh page observations a day")
        self.assertEqual((self.s.log_count(), len(self.ff.calls)), (n, calls))
        code, out, _ = self.observe(billing=None)  # a paid observation past the allowance is still served, and priced
        self.assertEqual(code, 200, out)
        self.assertGreater(out["price"]["credits"], 0)

    def test_an_own_key_check_with_url_evidence_signs_its_observation_own(self):
        body = own(request(claim("page.live", {"url": U}), [url_item(U)], "public"))
        code, out, _ = self.s.witness_call(body, headers=HDR)
        self.assertEqual(code, 200, out)
        p = payload_of(out["envelope"])["predicate"]
        oid = p["evidence"][0]["observations"][0]
        self.assertEqual(self.s.storage.log_tier(oid), "own")
        self.assertEqual(self.s.storage.log_tier(out["record_id"]), "own")
        self.assertEqual(out["price"]["billing"], "own-key")
        self.assertEqual(out["price"]["credits"], 0)

    def test_an_own_key_check_past_the_allowance_is_refused_up_front(self):
        for _ in range(2):
            self.assertEqual(self.observe()[0], 200)
        n = self.s.log_count()
        body = own(request(claim("page.live", {"url": U}), [url_item(U)], "public"))
        code, out, _ = self.s.witness_call(body, headers=HDR)
        self.assertEqual((code, out["error"]), (402, "own-key-observation-limit"), out)
        self.assertEqual(self.s.log_count(), n)

    def test_a_paid_check_never_reuses_an_own_observation(self):
        code, mine, _ = self.observe()
        self.assertEqual(code, 200, mine)
        self.s.clock.advance(5)  # a fresh capture in the same second would be the very same signed payload
        code, paid, _ = self.observe(billing=None, max_age=3600)
        self.assertEqual(code, 200, paid)
        self.assertFalse(paid["reused"])
        self.assertNotEqual(paid["observation_id"], mine["observation_id"])


# ------------------------------------------------------------------------------------------------------------------- C2


def sealer_stack(public=True, own_notary="lab", **over):
    clock = h.Clock()
    cfg = {"notary": FakeNotary(clock) if public else None, "batch_interval_s": 3600}
    if own_notary == "lab":
        cfg["notary_own"] = FakeNotary(clock, chain="lab-qbft", profile="hash/1-own")
    elif own_notary is not None:
        cfg["notary_own"] = own_notary
    cfg.update(over)
    return h.Stack(clock=clock, config_overrides=cfg)


def own_check(s, data=b"own bytes\n"):
    code, out, _ = s.witness_call(own(exact_request(data)), headers=HDR)
    assert code == 200, out
    return out


def paid_check(s, data=b"paid bytes\n"):
    code, out, _ = s.witness_call(exact_request(data))
    assert code == 200, out
    return out


def seal_of(s, rid):
    code, seal, _ = s.call("GET", f"/v1/records/{rid}/seal", key=None)
    assert code == 200, seal
    return seal


class SealerTiers(unittest.TestCase):
    def test_tiers_never_share_a_batch_and_headers_say_their_anchoring(self):
        s = sealer_stack()
        try:
            mine, paid = own_check(s), paid_check(s)
            s.clock.advance(3601)
            closed = s.witness.sealer.tick()
            self.assertEqual(len(closed), 2)
            a, b = seal_of(s, mine["record_id"]), seal_of(s, paid["record_id"])
            self.assertNotEqual(a["batch_header"]["batch_id"], b["batch_header"]["batch_id"])
            self.assertEqual(a["batch_header"]["anchoring"], "own")
            self.assertEqual(b["batch_header"]["anchoring"], "public")
            self.assertEqual(a["batch_header"]["size"], 1)
            log = {r["payload_id"]: r for r in s.storage.signing_log()}
            for bid in closed:
                batch = s.storage.get_batch(bid)
                tiers = {r["tier"] for r in s.storage.signing_log() if r["batch_id"] == bid}
                self.assertEqual(tiers, {batch["header"]["anchoring"]})
            hdr_rows = [r for r in log.values() if r["predicate_type"] == BATCH_TYPE]
            self.assertEqual(sorted(r["tier"] for r in hdr_rows), ["own", "public"])
        finally:
            s.close()

    def test_own_batches_go_to_the_own_notary_and_public_ones_to_hash_1(self):
        s = sealer_stack()
        try:
            mine, paid = own_check(s), paid_check(s)
            s.clock.advance(3601)
            s.witness.sealer.tick()
            a, b = seal_of(s, mine["record_id"]), seal_of(s, paid["record_id"])
            own_over = a["notary"]["over"].split(":")[1]
            pub_over = b["notary"]["over"].split(":")[1]
            self.assertEqual(s.witness.cfg.notary_own.calls, [own_over])
            self.assertEqual(s.witness.cfg.notary.calls, [pub_over])
            self.assertEqual((a["state"], a["notary"]["profile"], [x["chain"] for x in a["notary"]["anchors"]]),
                             ("anchored", "hash/1-own", ["lab-qbft"]))
            self.assertEqual(b["notary"]["profile"], "hash/1")
        finally:
            s.close()

    def test_without_an_own_notary_own_batches_close_unanchored_and_never_reach_hash_1(self):
        s = sealer_stack(own_notary=None)
        try:
            mine = own_check(s)
            s.clock.advance(3601)
            s.witness.sealer.tick()
            s.clock.advance(3601)
            s.witness.sealer.tick()
            seal = seal_of(s, mine["record_id"])
            self.assertEqual(seal["state"], "pending")
            self.assertEqual(seal["notary"]["status"], "off")
            batch = s.storage.get_batch(seal["batch_header"]["batch_id"])
            self.assertEqual(batch["state"], "unanchored")
            self.assertNotIn(seal["batch_header"]["sig"], json.dumps(s.witness.cfg.notary.calls))
            over = verify.sha256_hex(verify.canonical(seal["batch_header"]))
            self.assertNotIn(over, s.witness.cfg.notary.calls)
        finally:
            s.close()

    def test_an_own_notary_with_the_public_profile_is_never_used(self):
        wrong = FakeNotary(h.Clock(), chain="lab-qbft", profile="hash/1")
        s = sealer_stack(own_notary=wrong)
        try:
            mine = own_check(s)
            s.clock.advance(3601)
            s.witness.sealer.tick()
            self.assertEqual(wrong.calls, [])
            self.assertEqual(seal_of(s, mine["record_id"])["notary"]["status"], "off")
        finally:
            s.close()

    def test_an_own_seal_naming_another_chain_is_a_failed_seal(self):
        for chains in (["base-sepolia"], ["lab-qbft", "base-sepolia"]):
            n = FakeNotary(h.Clock(), profile="hash/1-own", chains=chains)
            s = sealer_stack(own_notary=n)
            try:
                mine = own_check(s)
                s.clock.advance(3601)
                s.witness.sealer.tick()
                seal = seal_of(s, mine["record_id"])
                self.assertEqual(seal["state"], "pending", chains)
                self.assertEqual(seal["notary"]["status"], "failed")
                self.assertIn("base-sepolia", seal["notary"]["reason"])
                self.assertNotIn("base-sepolia", json.dumps(seal["notary"]["anchors"]))
                calls = len(n.calls)  # a tick notarizes what it closes and then repeats every pending batch
                s.clock.advance(60)
                s.witness.sealer.tick()  # retried with the own notary, still never anchored
                self.assertEqual(seal_of(s, mine["record_id"])["state"], "pending")
                self.assertGreater(len(n.calls), calls)
                self.assertFalse(set(n.calls) & set(s.witness.cfg.notary.calls))  # (the key list's public batch goes there)
            finally:
                s.close()

    def test_old_headers_without_the_field_are_public_and_well_known_is_unchanged(self):
        s = sealer_stack()
        try:
            code, wk, _ = s.call("GET", "/.well-known/witness.json", key=None)
            self.assertEqual(wk["seal"]["profile"], "hash/1")
        finally:
            s.close()


class OwnNotarySettings(unittest.TestCase):
    def setUp(self):
        self.tls = make_tls()
        self.srv = HttpsNotary(self.tls, chain="lab-qbft")
        self.addCleanup(self.srv.close)
        self.env = {"WITNESS_NOTARY_URL": self.srv.url, "WITNESS_NOTARY_TOKEN_FILE": self.srv.token_file,
                    "WITNESS_NOTARY_CA_FILE": self.srv.ca_file, "WITNESS_NOTARY_OWN_TOKEN_FILE": self.srv.token_file}

    def test_no_own_token_file_means_no_own_notary_never_the_public_token(self):
        # DESIGN C2: "No own profile or token configured -> own batches unanchored". The own-key judge found own_settings()
        # falling back to WITNESS_NOTARY_TOKEN_FILE, so an own batch went out with the PUBLIC token (26 Nov, PROBE-own-token-unset).
        env = dict(self.env)
        del env["WITNESS_NOTARY_OWN_TOKEN_FILE"]
        self.assertIsNone(notary.own_from_env(env))
        self.assertIsNone(notary.own_from_env(dict(env, WITNESS_NOTARY_OWN_TOKEN_FILE="")))
        missing = str(pathlib.Path(tempfile.mkdtemp(prefix="cw-owntok-")) / "absent")
        self.assertIsNone(notary.own_from_env(dict(env, WITNESS_NOTARY_OWN_TOKEN_FILE=missing)))
        self.assertEqual(self.srv.requests, [])

    def test_the_default_own_profile_is_hash_1_own_and_is_sent_as_the_profile(self):
        n = notary.own_from_env(self.env)
        self.assertEqual(n.profile, "hash/1-own")
        res = n.seal("ab" * 32)
        self.assertEqual(res["status"], "landed", res)
        self.assertEqual(res["profile"], "hash/1-own")
        self.assertEqual(json.loads(self.srv.requests[-1]["body"])["profile"], "hash/1-own")

    def test_a_named_profile_and_an_off_profile(self):
        self.assertEqual(notary.own_from_env(dict(self.env, WITNESS_NOTARY_OWN_PROFILE="hash/1-ndim")).profile, "hash/1-ndim")
        self.assertIsNone(notary.own_from_env(dict(self.env, WITNESS_NOTARY_OWN_PROFILE="")))
        self.assertIsNone(notary.own_from_env(dict(self.env, WITNESS_NOTARY_OWN_PROFILE="off")))

    def test_the_public_profile_is_refused_as_the_own_profile(self):
        with self.assertRaises(ValueError):
            notary.own_from_env(dict(self.env, WITNESS_NOTARY_OWN_PROFILE="hash/1"))

    def test_the_own_token_file_is_used_when_set(self):
        d = pathlib.Path(tempfile.mkdtemp(prefix="cw-owntok-"))
        (d / "wrong").write_text("not-the-token\n")
        env = dict(self.env, WITNESS_NOTARY_TOKEN_FILE=str(d / "wrong"), WITNESS_NOTARY_OWN_TOKEN_FILE=self.srv.token_file)
        res = notary.own_from_env(env).seal("cd" * 32)
        self.assertEqual(res["status"], "landed", res)
        res = notary.from_env(env).seal("cd" * 32)  # the public client keeps its own token
        self.assertNotEqual(res["status"], "landed")

    def test_no_notary_settings_means_no_own_notary(self):
        self.assertIsNone(notary.own_from_env({}))

    def test_a_200_for_another_profile_is_not_landed(self):
        n = notary.own_from_env(self.env)
        self.srv.handle_orig = self.srv.handle

        def wrong_profile(method, path, q, body):
            code, obj = self.srv.handle_orig(method, path, q, body)
            return code, dict(obj, profile="hash/1")
        self.srv.handle = wrong_profile
        self.assertEqual(n.seal("ef" * 32)["status"], "failed")


class OwnMigration(unittest.TestCase):
    def test_migration_008_adds_the_tier_column(self):
        files = sorted((h.ROOT / "claim_witness" / "migrations").glob("008_*.sql"))
        self.assertEqual([f.name for f in files], ["008_signing_log_tier.sql"])
        sql = files[0].read_text()
        self.assertIn("ALTER TABLE signing_log ADD COLUMN IF NOT EXISTS tier", sql)
        self.assertIn("DEFAULT 'public'", sql)
        self.assertIn("'own'", sql)


# ------------------------------------------------------------------------------------------------------------- verify


def run_verify(*args):
    buf = io.StringIO()
    code = verify.main([str(a) for a in args], out=buf)
    return code, buf.getvalue()


class VerifyOwnSeals(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.s = sealer_stack()
        cls.mine, cls.paid = own_check(cls.s), paid_check(cls.s)
        cls.s.clock.advance(3601)
        cls.s.witness.sealer.tick()
        cls.own_seal, cls.pub_seal = seal_of(cls.s, cls.mine["record_id"]), seal_of(cls.s, cls.paid["record_id"])
        code, wk, _ = cls.s.call("GET", "/.well-known/witness.json", key=None)
        cls.dir = pathlib.Path(tempfile.mkdtemp(prefix="cw-own-verify-"))
        (cls.dir / "keys.json").write_text(json.dumps(wk["key_list"]))

    @classmethod
    def tearDownClass(cls):
        cls.s.close()

    def run_with(self, out, seal, *extra):
        p = self.dir / "answer.json"
        p.write_text(json.dumps({"envelope": out["envelope"], "seal": seal}))
        return run_verify("--envelope", p, "--keys", self.dir / "keys.json", *extra)

    def test_an_own_seal_prints_the_info_line_and_passes(self):
        self.assertEqual(self.own_seal["state"], "anchored")
        code, text = self.run_with(self.mine, self.own_seal)
        self.assertEqual(code, 0, text)
        self.assertIn(INFO, text.splitlines())
        self.assertIn("PASS seal", text)
        self.assertNotIn("FAIL", text)

    def test_with_rpc_an_own_seal_is_not_failed_for_the_missing_public_anchor(self):
        from tests_claim.test_verify_chain import FakeRpc
        rpc = FakeRpc()
        try:
            code, text = self.run_with(self.mine, self.own_seal, "--rpc", rpc.url)
        finally:
            rpc.close()
        self.assertEqual(code, 0, text)
        self.assertIn(INFO, text)
        self.assertIn("SKIP seal-chain: lab-qbft", text)
        self.assertNotIn("FAIL", text)
        self.assertEqual(rpc.calls, [])

    def test_a_public_seal_has_no_info_line(self):
        code, text = self.run_with(self.paid, self.pub_seal)
        self.assertEqual(code, 0, text)
        self.assertNotIn("INFO anchoring", text)

    def test_an_own_header_whose_seal_carries_base_sepolia_fails_the_seal(self):
        bad = copy.deepcopy(self.own_seal)
        bad["notary"]["anchors"].append(dict(bad["notary"]["anchors"][0], chain="base-sepolia"))
        code, text = self.run_with(self.mine, bad)
        self.assertEqual(code, 1, text)
        line = [x for x in text.splitlines() if x.startswith("FAIL seal:")]
        self.assertTrue(line, text)
        self.assertIn("base-sepolia", line[0])
        bad["notary"]["anchors"] = [dict(a, chain="base-sepolia") for a in self.own_seal["notary"]["anchors"]]
        code, text = self.run_with(self.mine, bad)
        self.assertEqual(code, 1, text)
        self.assertIn("base-sepolia", [x for x in text.splitlines() if x.startswith("FAIL seal:")][0])

    def resign(self, seal, **changes):
        out = copy.deepcopy(seal)
        hdr = {k: v for k, v in out["batch_header"].items() if k != "sig"}
        hdr.update(changes)
        for k, v in changes.items():
            if v is None:
                del hdr[k]
        sig = crypto.ed25519_sign(self.s.seed, dsse.pae("application/vnd.onedroid.witness.batch-header+json", jcs.canonical(hdr)))
        out["batch_header"] = dict(hdr, sig=base64.b64encode(sig).decode())
        out["notary"]["over"] = "sha256:" + verify.sha256_hex(verify.canonical(out["batch_header"]))
        return out

    def test_an_unknown_anchoring_value_fails_the_seal(self):
        code, text = self.run_with(self.mine, self.resign(self.own_seal, anchoring="gold"))
        self.assertEqual(code, 1, text)
        self.assertIn("anchoring", [x for x in text.splitlines() if x.startswith("FAIL seal:")][0])

    def test_a_header_without_the_field_behaves_as_public_today(self):
        lab_only = self.resign(self.own_seal, anchoring=None)
        code, text = self.run_with(self.mine, lab_only)
        self.assertEqual(code, 0, text)
        self.assertNotIn("INFO anchoring", text)
        with_bs = copy.deepcopy(lab_only)
        with_bs["notary"]["anchors"].append(dict(with_bs["notary"]["anchors"][0], chain="base-sepolia"))
        code, text = self.run_with(self.mine, with_bs)
        self.assertNotIn("FAIL seal:", text)


if __name__ == "__main__":
    unittest.main()
