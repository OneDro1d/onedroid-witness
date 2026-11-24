"""VR-10 (payload part), TS-18 and TS-24: a private payload holds only the §2.6 fields, no candidate plaintext hashes into it,
and no registered agent key verifies or appears in it."""
import base64
import hashlib
import unittest

from claim_witness import ids, jcs
from tests_claim import helpers as h
from tests_claim.helpers import claim, obj_item, payload_bytes, payload_of, request, sha

NAMES = ["Agnieszka", "Bartosz", "Celina", "Dariusz", "Elzbieta", "Filip", "Grazyna", "Henryk", "Irena", "Jakub"]
SURNAMES = ["Nowak", "Kowalski", "Wisniewski", "Wojcik", "Kowalczyk", "Kaminski", "Lewandowski", "Zielinski", "Szymanski",
            "Wozniak"]


def candidates(n=10000):
    out = []
    for i in range(n):
        first = NAMES[i % 10]
        last = SURNAMES[(i // 10) % 10]
        out.append(f"{first} {last}{'' if i < 100 else i // 100}")
    return out


def hashes_every_way(name, source, witness_id="witness:test"):
    quote = f"{name} is Polish"
    out = set()
    for s in (name, quote, name.lower(), quote.lower()):
        for b in (s.encode(), jcs.canonical(s)):
            out.add(hashlib.sha256(b).hexdigest())
            out.add(hashlib.sha256(b"\x00" + b).hexdigest())
    for assertion in (True, False):
        c = claim("quote.in-source", {"quote": quote}, assertion)
        out.add(ids.claim_id(c))
        out.add(ids.claim_id(c["params"]))
        out.add(hashlib.sha256(jcs.canonical(c["params"])).hexdigest())
    out.add(sha(source))
    return out


class PrivatePayloadTS18(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.s = h.Stack()
        cls.secret_name = "Celina Wisniewski42"
        cls.source = f"Notes. {cls.secret_name} is Polish. Nothing else.".encode()
        body = request(claim("quote.in-source", {"quote": f"{cls.secret_name} is Polish"}),
                       [obj_item("source", cls.source, name="notes.txt")], visibility="private")
        code, cls.out, _ = cls.s.witness_call(body)
        assert code == 200, cls.out
        cls.raw = payload_bytes(cls.out["envelope"])
        cls.text = cls.raw.decode()
        cls.everything = cls.text + base64.b64encode(cls.raw).decode() + str(cls.out["envelope"]["signatures"])

    @classmethod
    def tearDownClass(cls):
        cls.s.close()

    def test_allow_list_only(self):
        st = payload_of(self.out["envelope"])
        self.assertEqual(set(st), {"_type", "subject", "predicateType", "predicate"})
        self.assertEqual(len(st["subject"]), 1)
        self.assertEqual(st["subject"][0]["name"], "claim")
        self.assertEqual(set(st["predicate"]), {"visibility", "body_commitment", "finding", "outcome", "reason", "method",
                                                "limits", "detail", "attempt", "options_used", "witnessed_at", "witness"})
        self.assertEqual(st["predicate"]["outcome"], "SUPPORTED")

    def test_no_plaintext_and_no_candidate_hash_matches(self):
        self.assertNotIn("Polish", self.text)
        self.assertNotIn("notes.txt", self.text)
        self.assertNotIn("acct_a", self.text)
        cands = candidates()
        self.assertIn(self.secret_name, cands)
        for name in cands:
            self.assertNotIn(name, self.everything)
            for hx in hashes_every_way(name, self.source):
                self.assertNotIn(hx, self.everything, name)

    def test_disclosure_opens_the_commitments(self):
        d = self.out["disclosure"]
        salt = ids.b64url_decode(d["salt"])
        st = payload_of(self.out["envelope"])
        self.assertEqual(st["subject"][0]["digest"]["sha256"], ids.claim_commitment(salt, d["body"]["claim"]))
        self.assertEqual(st["predicate"]["body_commitment"], ids.body_commitment(salt, d["body"]))
        self.assertEqual(d["body"]["evidence"][0]["name"], "notes.txt")


class AgentKeysTS24(unittest.TestCase):
    def test_no_private_payload_verifies_or_matches_under_any_agent_key(self):
        from claim_witness import dsse
        s = h.Stack()
        try:
            seeds = [h.seed(100 + i) for i in range(5)]
            regs = []
            for sd in seeds:
                code, out, _ = s.call("POST", "/v1/agent-keys", {"public_key": h.b64(h.public_of(sd))})
                self.assertEqual(code, 200)
                regs.append((sd, out["agent_key_id"], out["agent"]))
            envelopes = []
            for i, (sd, kid, agent) in enumerate(regs):
                data = f"agent private {i}".encode()
                c = claim("match.exact")
                ev = [obj_item("submitted", data), obj_item("target", data)]
                b = request(c, ev, "private")
                b["agent"] = h.agent_block(sd, kid, "witness:test", c, ev, f"nonce-ts24-{i:04d}", h.iso(s.clock()))
                code, out, _ = s.witness_call(b)
                self.assertEqual(code, 200, out)
                envelopes.append((out["envelope"], b["agent"]["agent_sig"]))
            for env, agent_sig in envelopes:
                text = payload_bytes(env).decode()
                self.assertNotIn(agent_sig, text)
                for sd, kid, agent in regs:
                    pub = h.public_of(sd)
                    self.assertFalse(dsse.verify(env, {env["signatures"][0]["keyid"]: pub}))
                    for needle in (kid, agent, h.b64(pub), pub.hex(), sha(pub)):
                        self.assertNotIn(needle, text)
        finally:
            s.close()


if __name__ == "__main__":
    unittest.main()
