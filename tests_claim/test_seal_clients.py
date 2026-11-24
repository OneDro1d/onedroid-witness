"""B3 (d), (e): the real HTTP clients behind the two interfaces, against local HTTPS fakes of armarium's routes (no real
armarium is called): the notary's POST /notary/v1/seals (hash/1, key = the header hash hex, payload = base64 of
{"over":"sha256:<hex>"}) and n-dim's POST /chain/{name}/object, PUT/DELETE /chain/{name}/object/{id}?block=, GET .../{id}.
TLS is verified against the CA file; the token comes from a file and is never in an error or a result."""
import base64
import json
import pathlib
import tempfile
import unittest

from tests_claim.fake_seal import HttpsArmarium, HttpsNotary, make_tls

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
        self.assertEqual(base64.b64decode(body["payload"]), b'{"over":"sha256:' + hexv.encode() + b'"}')

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
    def setUp(self):
        self.srv = HttpsArmarium(TLS)
        self.env = {"ARMARIUM_URL": self.srv.url, "ARMARIUM_TOKEN_FILE": self.srv.token_file,
                    "ARMARIUM_CA_FILE": self.srv.ca_file, "ARMARIUM_CHAIN": "claim-witness-dev"}

    def tearDown(self):
        self.srv.close()

    def test_not_configured_without_url(self):
        from claim_witness import ndim
        self.assertEqual(ndim.from_env({}), (None, None))

    def test_https_only_and_chain_required(self):
        from claim_witness import ndim
        with self.assertRaises(ValueError):
            ndim.from_env(dict(self.env, ARMARIUM_URL="http://127.0.0.1:1"))
        with self.assertRaises(ValueError):
            ndim.from_env(dict(self.env, ARMARIUM_CHAIN=""))

    def test_create_put_get_delete(self):
        from claim_witness import ndim
        client, chain = ndim.from_env(self.env)
        self.assertEqual(chain, "claim-witness-dev")
        self.assertEqual(ndim.chain_for("acct_a", chain), "claim-witness-dev")
        c = client.create_object(chain, {"kind": "x", "n": 1})
        self.assertTrue(c["id"])
        self.assertIsInstance(c["block"], int)
        self.assertEqual(client.get_object(chain, c["id"]), {"kind": "x", "n": 1})
        p = client.put_version(chain, c["id"], c["block"], {"kind": "y"})
        self.assertGreater(p["block"], c["block"])
        self.assertEqual(self.srv.requests[-1]["query"], f"block={c['block']}")
        self.assertEqual(client.get_object(chain, c["id"]), {"kind": "y"})
        d = client.delete_object(chain, c["id"], p["block"])
        self.assertEqual(d["dek"], "deleted")
        self.assertEqual(d["residual"], ["ciphertext-on-chain"])
        with self.assertRaises(ndim.Gone):
            client.get_object(chain, c["id"])
        for r in self.srv.requests:
            self.assertEqual(r["auth"], "Bearer " + self.srv.TOKEN)

    def test_errors_never_carry_the_token(self):
        from claim_witness import ndim
        bad_tok = pathlib.Path(tempfile.mkdtemp()) / "t"
        bad_tok.write_text("wrong-token-value-123456\n")
        client, chain = ndim.from_env(dict(self.env, ARMARIUM_TOKEN_FILE=str(bad_tok)))
        with self.assertRaises(ndim.ArmariumError) as cm:
            client.create_object(chain, {"a": 1})
        self.assertNotIn("wrong-token-value", str(cm.exception))
        self.assertIn("401", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
