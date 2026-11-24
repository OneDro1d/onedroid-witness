"""B3W: the notary client against a fake that mimics the REAL notary (hash/1, label + over payload, `final` per chain, base-sepolia
final:false at write time). RED first. `final:false` means not yet anchored on that chain: the seal stays pending and the same
request (same key, same bytes) is repeated on a later tick until every chain is final."""
import base64
import json
import re
import unittest

from tests_claim import helpers as h
from tests_claim import test_keep_api as k
from tests_claim.fake_armarium_real import RealNotary
from tests_claim.fake_seal import make_tls

TLS = None


def setUpModule():
    global TLS
    TLS = make_tls()


class Client(unittest.TestCase):
    def setUp(self):
        self.srv = RealNotary(TLS)
        self.env = {"WITNESS_NOTARY_URL": self.srv.url, "WITNESS_NOTARY_TOKEN_FILE": self.srv.token_file,
                    "WITNESS_NOTARY_CA_FILE": self.srv.ca_file, "WITNESS_NOTARY_TIMEOUT_S": "5"}

    def tearDown(self):
        self.srv.close()

    def test_the_payload_is_the_base64_of_label_and_over(self):
        from claim_witness import notary
        hexv = "ab" * 32
        out = notary.from_env(self.env).seal(hexv)
        self.assertEqual(out["status"], "landed", out)
        req = json.loads(self.srv.requests[-1]["body"])
        self.assertEqual(set(req), {"profile", "key", "payload"})
        self.assertEqual((req["profile"], req["key"]), ("hash/1", hexv))
        payload = json.loads(base64.b64decode(req["payload"], validate=True))
        self.assertEqual(set(payload), {"label", "over"})
        self.assertEqual(payload["over"], "sha256:" + hexv)
        self.assertRegex(payload["label"], r"^[A-Za-z0-9][A-Za-z0-9.:/_-]{0,63}$")

    def test_final_false_is_landed_but_not_final(self):
        from claim_witness import notary
        out = notary.from_env(self.env).seal("cd" * 32)
        self.assertEqual(out["status"], "landed")
        self.assertEqual({a["chain"]: a["final"] for a in out["anchors"]}, {"lab-qbft": True, "base-sepolia": False})
        self.assertFalse(notary.all_final(out))
        for a in out["anchors"]:
            self.assertRegex(a["tx_hash"], r"^0x[0-9a-f]{64}$")
            self.assertIsInstance(a["block"], int)
        self.srv.finalize()
        again = notary.from_env(self.env).seal("cd" * 32)
        self.assertTrue(notary.all_final(again))
        bodies = [r["body"] for r in self.srv.requests]
        self.assertEqual(bodies[0], bodies[1])  # the repeat is the same request: same key, same bytes

    def test_all_final_is_false_without_a_landed_result(self):
        from claim_witness import notary
        self.assertFalse(notary.all_final(notary.off_result()))
        self.assertFalse(notary.all_final(None))

    def test_token_is_sent_and_never_returned(self):
        from claim_witness import notary
        out = notary.from_env(self.env).seal("ef" * 32)
        self.assertEqual(self.srv.requests[-1]["auth"], "Bearer " + self.srv.TOKEN)
        self.assertNotIn(self.srv.TOKEN, json.dumps(out))


class SealerWithFinality(k.Base, unittest.TestCase):
    ndim = False

    def setUp(self):
        from claim_witness import notary
        self.srv = RealNotary(TLS)
        env = {"WITNESS_NOTARY_URL": self.srv.url, "WITNESS_NOTARY_TOKEN_FILE": self.srv.token_file,
               "WITNESS_NOTARY_CA_FILE": self.srv.ca_file, "WITNESS_NOTARY_TIMEOUT_S": "5"}
        self.clock = h.Clock()
        cfg = {"notary": notary.from_env(env), "batch_interval_s": 3600, "operator_accounts": ["acct_op"],
               "link_base": "https://evidence.example"}
        self.s = h.Stack(storage=None, clock=self.clock, config_overrides=cfg)

    def tearDown(self):
        self.s.close()
        self.srv.close()

    def test_a_non_final_seal_stays_pending_and_is_repolled_until_final(self):
        out = self.check()
        rid = out["record_id"]
        self.seal_all()
        code, seal, _ = self.get(rid, suffix="/seal")
        self.assertEqual(code, 200, seal)
        self.assertEqual(seal["state"], "pending", seal)
        self.assertEqual({a["chain"]: a["final"] for a in seal["notary"]["anchors"]}, {"lab-qbft": True, "base-sepolia": False})
        n = len(self.srv.requests)
        self.s.witness.sealer.tick()  # still not final: the same request again
        self.assertEqual(len(self.srv.requests), n + 1)
        self.assertEqual(self.srv.requests[-1]["body"], self.srv.requests[0]["body"])
        self.srv.finalize()
        self.s.witness.sealer.tick()
        code, seal, _ = self.get(rid, suffix="/seal")
        self.assertEqual(seal["state"], "anchored", seal)
        self.assertTrue(all(a["final"] for a in seal["notary"]["anchors"]))
        n = len(self.srv.requests)
        self.s.witness.sealer.tick()
        self.assertEqual(len(self.srv.requests), n)  # anchored: never asked again
        self.assertTrue(re.fullmatch(r"[0-9a-f]{64}", json.loads(self.srv.requests[0]["body"])["key"]))


if __name__ == "__main__":
    unittest.main()
