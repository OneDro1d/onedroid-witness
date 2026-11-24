"""Auth (§3, BD8): static dev keys, the BFF's onedroid-req/1 signature with X-Witness-Account, agent keys and the agent content
signature with nonce and time checks (VR-22, TS-25); the read routes (/v1/methods, /.well-known/witness.json,
/v1/key-lists/{seq}, /healthz)."""
import base64
import hashlib
import json
import unittest

from claim_witness import api, reqauth
from tests_claim import helpers as h
from tests_claim.helpers import claim, obj_item, payload_of, request

BFF_SEED = h.seed(50)


def bff_key_list():
    return json.dumps({"service": "onedroid-bus", "keys": [
        {"key_id": "bff-2026", "public_key": base64.b64encode(h.public_of(BFF_SEED)).decode()}]}).encode()


def bff_headers(body_bytes, path="/v1/witness", method="POST", account="acct_bff", t=None, seed_bytes=BFF_SEED, kid="bff-2026"):
    t = int(h.T0 if t is None else t)
    line = f"onedroid-req/1 claim-witness {method} {path} sha256:{hashlib.sha256(body_bytes).hexdigest()} {t}"
    armored = reqauth.sshsig_sign(seed_bytes, "onedroid-req", line.encode())
    out = {"X-Store-Key": kid, "X-Store-Time": str(t), "X-Store-Signature": base64.b64encode(armored).decode()}
    if account is not None:
        out["X-Witness-Account"] = account
    return out


class DevKeys(unittest.TestCase):
    def setUp(self):
        self.s = h.Stack()

    def tearDown(self):
        self.s.close()

    def test_no_key_401_bad_key_401(self):
        before = self.s.log_count()  # the bootstrap key list is the log's first row (SPEC §7.1)
        code, out, _ = self.s.witness_call(h.exact_request(), key=None)
        self.assertEqual(code, 401)
        code, out, _ = self.s.witness_call(h.exact_request(), key="dev-key-wrong-0000000000000")
        self.assertEqual(code, 401)
        self.assertEqual(self.s.log_count(), before)

    def test_dev_key_maps_to_account(self):
        code, out, _ = self.s.witness_call(h.exact_request(), key="dev-key-b-0123456789abcdef")
        self.assertEqual(code, 200)
        self.assertEqual(payload_of(out["envelope"])["predicate"]["submitter"], {"account": "acct_b"})

    def test_dev_keys_file_list_form(self):
        import pathlib
        p = pathlib.Path(self.s.tmp) / "list.json"
        p.write_text(json.dumps({"keys": [{"key": "k-list-0123456789", "account": "acct_l"}]}))
        dk = api.DevKeys.from_file(str(p))
        self.assertEqual(dk.account("k-list-0123456789"), "acct_l")
        self.assertIsNone(dk.account("nope"))


class BffSignature(unittest.TestCase):
    def setUp(self):
        self.clock = h.Clock()
        caller = reqauth.CallerKeys("http://bff.invalid/keys", fetch=bff_key_list, clock=self.clock)
        self.s = h.Stack(clock=self.clock, caller_keys=caller)

    def tearDown(self):
        self.s.close()

    def post(self, body, headers):
        raw = json.dumps(body).encode()
        return self.s.call("POST", "/v1/witness", raw=raw, key=None, content_type="application/json", headers=headers(raw))

    def test_signed_bff_request_with_account(self):
        code, out, _ = self.post(h.exact_request(), lambda raw: bff_headers(raw))
        self.assertEqual(code, 200, out)
        self.assertEqual(payload_of(out["envelope"])["predicate"]["submitter"], {"account": "acct_bff"})

    def test_missing_account_header_401(self):
        code, out, _ = self.post(h.exact_request(), lambda raw: bff_headers(raw, account=None))
        self.assertEqual(code, 401)

    def test_stale_signature_401(self):
        code, out, _ = self.post(h.exact_request(), lambda raw: bff_headers(raw, t=h.T0 - 301))
        self.assertEqual(code, 401)

    def test_body_changed_after_signing_401(self):
        code, out, _ = self.post(h.exact_request(), lambda raw: bff_headers(raw + b" "))
        self.assertEqual(code, 401)

    def test_unknown_signer_401(self):
        code, out, _ = self.post(h.exact_request(), lambda raw: bff_headers(raw, seed_bytes=h.seed(51)))
        self.assertEqual(code, 401)

    def test_x_witness_account_ignored_with_dev_key(self):
        code, out, _ = self.s.call("POST", "/v1/witness", h.exact_request(), headers={"X-Witness-Account": "acct_evil"})
        self.assertEqual(code, 200)
        self.assertEqual(payload_of(out["envelope"])["predicate"]["submitter"]["account"], "acct_a")

    def test_sshsig_round_trip_and_namespace(self):
        pub = h.public_of(BFF_SEED)
        armored = reqauth.sshsig_sign(BFF_SEED, "onedroid-req", b"line")
        self.assertTrue(armored.startswith(b"-----BEGIN SSH SIGNATURE-----"))
        self.assertTrue(reqauth.sshsig_verify(pub, armored, "onedroid-req", b"line"))
        self.assertFalse(reqauth.sshsig_verify(pub, armored, "other-ns", b"line"))
        self.assertFalse(reqauth.sshsig_verify(pub, armored, "onedroid-req", b"line2"))


class AgentKeysTS25(unittest.TestCase):
    AGENT_SEED = h.seed(7)

    def setUp(self):
        self.s = h.Stack()
        code, out, _ = self.s.call("POST", "/v1/agent-keys", {"public_key": h.b64(h.public_of(self.AGENT_SEED))})
        self.assertEqual(code, 200, out)
        self.agent_key_id = out["agent_key_id"]
        self.agent = out["agent"]

    def tearDown(self):
        self.s.close()

    def body(self, nonce="nonce-0001-abcdef", agent_time=None, data=b"agent bytes", seed_bytes=None, visibility="public"):
        c = claim("match.exact")
        ev = [obj_item("submitted", data), obj_item("target", data)]
        at = agent_time or h.iso(self.s.clock())
        b = request(c, ev, visibility)
        b["agent"] = h.agent_block(seed_bytes or self.AGENT_SEED, self.agent_key_id, "witness:test", c, ev, nonce, at)
        return b

    def test_register_returns_ids(self):
        self.assertTrue(self.agent_key_id)
        self.assertTrue(self.agent.startswith("agt_"))
        code, out, _ = self.s.call("POST", "/v1/agent-keys", {"public_key": "not base64 of 32 bytes"})
        self.assertEqual(code, 400)

    def test_signed_agent_request_records_submitter(self):
        b = self.body()
        code, out, _ = self.s.witness_call(b)
        self.assertEqual(code, 200, out)
        sub = payload_of(out["envelope"])["predicate"]["submitter"]
        self.assertEqual(sub, {"account": "acct_a", "agent": self.agent, "agent_key_id": self.agent_key_id,
                               "agent_sig": b["agent"]["agent_sig"], "nonce": b["agent"]["nonce"],
                               "agent_time": b["agent"]["agent_time"]})

    def test_replayed_nonce_401(self):
        code, out, _ = self.s.witness_call(self.body(nonce="nonce-replay-0001"))
        self.assertEqual(code, 200, out)
        n = self.s.log_count()
        code, out, _ = self.s.witness_call(self.body(nonce="nonce-replay-0001"))
        self.assertEqual(code, 401, out)
        self.assertEqual(self.s.log_count(), n)
        # a nonce is remembered for 24 h, then may be used again
        self.s.clock.advance(24 * 3600 + 10)
        code, out, _ = self.s.witness_call(self.body(nonce="nonce-replay-0001", data=b"later bytes"))
        self.assertEqual(code, 200, out)

    def test_stale_agent_time_401(self):
        before = self.s.log_count()  # the bootstrap key list is the log's first row (SPEC §7.1)
        code, out, _ = self.s.witness_call(self.body(agent_time=h.iso(self.s.clock() - 600)))
        self.assertEqual(code, 401, out)
        code, out, _ = self.s.witness_call(self.body(agent_time=h.iso(self.s.clock() + 301), nonce="nonce-future-01"))
        self.assertEqual(code, 401, out)
        self.assertEqual(self.s.log_count(), before)

    def test_bad_agent_signature_401(self):
        code, out, _ = self.s.witness_call(self.body(seed_bytes=h.seed(8)))
        self.assertEqual(code, 401, out)

    def test_other_accounts_agent_key_403(self):
        code, out, _ = self.s.witness_call(self.body(), key="dev-key-b-0123456789abcdef")
        self.assertEqual(code, 403, out)

    def test_unknown_agent_key_403(self):
        b = self.body()
        b["agent"]["agent_key_id"] = "ak_unknown"
        code, out, _ = self.s.witness_call(b)
        self.assertIn(code, (401, 403))

    def test_idempotency_key_retry_with_same_nonce_returns_first_answer(self):
        hk = {"Idempotency-Key": "agent-retry-1"}
        b = self.body(nonce="nonce-idem-0001")
        code, first, _ = self.s.witness_call(b, headers=hk)
        self.assertEqual(code, 200)
        code, again, _ = self.s.witness_call(b, headers=hk)
        self.assertEqual(code, 200, again)
        self.assertEqual(again["record_id"], first["record_id"])


class ReadRoutes(unittest.TestCase):
    def setUp(self):
        self.s = h.Stack()

    def tearDown(self):
        self.s.close()

    def test_methods_registry_with_tarball_digest(self):
        from claim_witness import tarball
        code, out, _ = self.s.call("GET", "/v1/methods", key=None)
        self.assertEqual(code, 200)
        self.assertEqual(out["library"]["code_sha256"], hashlib.sha256(tarball.build_methods_tarball()).hexdigest())
        by_id = {m["id"]: m for m in out["methods"]}
        self.assertEqual(set(by_id), {"match.exact", "quote.in-source", "tests.pass", "judge.supports", "page.live", "match.text",
                                      "match.screenshot", "post.by-author"})  # B6 adds judge.supports, B2b the three observation methods, B5a post.by-author
        m = by_id["quote.in-source"]
        self.assertEqual(m["code_sha256"], out["library"]["code_sha256"])
        self.assertEqual(m["templates"]["true"], "{source} contains the passage: “{quote}”.")
        self.assertEqual(m["findings"], {"quote-found": "positive", "quote-absent": "negative"})
        self.assertEqual(m["slots"], {"source": ["object"]})
        self.assertIn("limits", m)
        self.assertIn("params_schema", m)
        self.assertEqual(out["models"], [])

    def test_well_known_and_key_lists(self):
        code, wk, _ = self.s.call("GET", "/.well-known/witness.json", key=None)
        self.assertEqual(code, 200)
        self.assertEqual(wk["witness_id"], "witness:test")
        self.assertEqual(wk["key_list_seq"], 1)
        self.assertEqual(wk["batch_interval_s"], 3600)
        kl = payload_of(wk["key_list"])["predicate"]
        self.assertEqual(kl["seq"], 1)
        self.assertEqual(kl["keys"][0]["key_id"], "witness:test:2026a")
        self.assertEqual(kl["keys"][0]["public"], h.b64(h.public_of(self.s.seed)))
        code, one, _ = self.s.call("GET", "/v1/key-lists/1", key=None)
        self.assertEqual((code, one), (200, wk["key_list"]))
        code, _, _ = self.s.call("GET", "/v1/key-lists/2", key=None)
        self.assertEqual(code, 404)
        code, _, _ = self.s.call("GET", "/v1/key-lists/abc", key=None)
        self.assertEqual(code, 404)

    def test_healthz(self):
        code, out, _ = self.s.call("GET", "/healthz", key=None)
        self.assertEqual(code, 200)
        self.assertTrue(out["ok"])

    def test_unknown_route_404(self):
        code, _, _ = self.s.call("GET", "/v1/nothing", key=None)
        self.assertEqual(code, 404)


if __name__ == "__main__":
    unittest.main()
