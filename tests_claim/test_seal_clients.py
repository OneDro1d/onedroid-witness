"""B3 (d), (e): the real HTTP clients behind the two interfaces, against local HTTPS fakes of armarium's routes (no real
armarium is called): the notary's POST /notary/v1/seals (hash/1, key = the header hash hex, payload = base64 of
{"over":"sha256:<hex>"}) and n-dim's POST /chain/{name}/object, PUT/DELETE /chain/{name}/object/{id}?block=, GET .../{id}.
TLS is verified against the CA file; the token comes from a file and is never in an error or a result."""
import base64
import json
import pathlib
import tempfile
import unittest

from tests_claim.fake_seal import HttpsNotary, make_tls

TLS = None


def setUpModule():
    global TLS
    TLS = make_tls()


class NotaryClient(unittest.TestCase):
    def setUp(self):
        self.srv = HttpsNotary(TLS)
        self.env = {"WITNESS_NOTARY_URL": self.srv.url, "WITNESS_NOTARY_TOKEN_FILE": self.srv.token_file,
                    "WITNESS_NOTARY_CA_FILE": self.srv.ca_file, "WITNESS_NOTARY_TIMEOUT_S": "5"}

    def tearDown(self):
        self.srv.close()

    def test_off_without_a_token_file(self):
        from claim_witness import notary
        self.assertIsNone(notary.from_env({}))
        self.assertIsNone(notary.from_env({"WITNESS_NOTARY_URL": "https://x.example"}))

    def test_https_only(self):
        from claim_witness import notary
        with self.assertRaises(ValueError):
            notary.settings(dict(self.env, WITNESS_NOTARY_URL="http://127.0.0.1:1"))

    def test_seal_lands(self):
        from claim_witness import notary
        n = notary.from_env(self.env)
        hexv = "ab" * 32
        out = n.seal(hexv)
        self.assertEqual(out["status"], "landed", out)
        self.assertEqual(out["over"], "sha256:" + hexv)
        self.assertEqual(out["key"], hexv)
        self.assertEqual(out["profile"], "hash/1")
        self.assertEqual(out["anchors"][0]["chain"], "base-sepolia")
        self.assertEqual(out["anchors"][0]["block_time"], "2026-11-24T12:00:00Z")
        req = self.srv.requests[-1]
        self.assertEqual(req["path"], "/notary/v1/seals")
        body = json.loads(req["body"])
        self.assertEqual(body["profile"], "hash/1")
        self.assertEqual(body["key"], hexv)
        # B3W: the real notary's hash/1 takes {"label", "over"} (label optional there, always sent here)
        self.assertEqual(json.loads(base64.b64decode(body["payload"])), {"label": "claim-witness/batch/1", "over": "sha256:" + hexv})

    def test_conflict_and_bad_ca_fail_without_the_token(self):
        from claim_witness import notary
        self.srv.answer_status = 409
        out = notary.from_env(self.env).seal("cd" * 32)
        self.assertEqual(out["status"], "failed")
        self.assertIn("key_conflict", out["reason"])
        other_ca = make_tls()[0]
        out = notary.HttpNotary(notary.settings(dict(self.env, WITNESS_NOTARY_CA_FILE=other_ca))).seal("ef" * 32)
        self.assertEqual(out["status"], "failed")
        self.assertIn("tls", out["reason"])
        self.assertNotIn(self.srv.TOKEN, json.dumps(out))


class ArmariumClient(unittest.TestCase):
    """B3W: the object routes themselves (claimant, POST/PUT/DELETE/GET, 401/403/409) are tested against the real-shaped fake in
    test_wire_ndim.py, which replaced the B3 route fake that lived here (its PUT and DELETE answers were not armarium's)."""

    def test_not_configured_without_url(self):
        from claim_witness import ndim
        self.assertEqual(ndim.from_env({}), (None, None))

    def test_https_only_and_case_required(self):
        from claim_witness import ndim
        env = {"ARMARIUM_URL": "https://127.0.0.1:1", "ARMARIUM_TOKEN_FILE": __file__, "ARMARIUM_CASE": "1e59334fee73fc758f793ce01c3cdd00"}
        with self.assertRaises(ValueError):
            ndim.from_env(dict(env, ARMARIUM_URL="http://127.0.0.1:1"))
        with self.assertRaises(ValueError):
            ndim.from_env(dict(env, ARMARIUM_CASE=""))


if __name__ == "__main__":
    unittest.main()
