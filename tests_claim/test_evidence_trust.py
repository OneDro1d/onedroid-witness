"""B2b (c): `observation` evidence by id or by envelope, with the Evidence-trust rule (SPEC §4, TS-11 second half): a bad
signature, an unknown signer or a bad manifest digest gives no finding (evidence-untrusted) without fetching anything; a
valid observation from a signer outside the trust list is used only with options.accept_untrusted, which is recorded."""
import base64
import copy
import hashlib
import json
import unittest

from claim_witness import dsse, ids, jcs, observation, signer, storage
from tests_claim import helpers as h
from tests_claim.fakefetch import build_capture, iso, page, stack
from tests_claim.helpers import claim, obj_item, request

U = "https://trust.example/p"
HTML = b"<html><body><h1>Trust</h1><p>The text the page shows.</p></body></html>"


class Base(unittest.TestCase):
    def setUp(self):
        self.s, self.ff, _ = stack()
        self.ff.set(U, page(HTML))

    def tearDown(self):
        self.s.close()
        self.ff.close()

    def check(self, obs_item, visibility="public", key="dev-key-a-0123456789abcdef", **opts):
        body = request(claim("match.text"), [obj_item("submitted", HTML, "text/html", "copy.html"), obs_item], visibility, **opts)
        code, out, _ = self.s.witness_call(body, key=key)
        return code, out

    def predicate(self, out):
        return h.payload_of(out["envelope"])["predicate"]

    def own_observation(self, visibility="public"):
        code, out, _ = self.s.call("POST", "/v1/observe", {"url": U, "visibility": visibility})
        self.assertEqual(code, 200, out)
        return out

    def foreign(self, seed_n=9, witness="witness:other", tamper_digest=False):
        """An observation signed by another witness's key, with its key list and its files."""
        clock = self.s.clock
        st = storage.MemoryStorage()
        kl = signer.keylist_init(st, h.seed(seed_n), f"{witness}:k", witness, clock=clock)
        manifest, files = build_capture(U, page(HTML), iso(clock()))
        pred, files = observation.from_capture(manifest, files, "public")
        stmt, _ = observation.statement(pred)
        if tamper_digest:
            stmt["subject"][0]["digest"]["sha256"] = "0" * 64
        raw = jcs.canonical(stmt)
        env = dsse.sign(raw, [(f"{witness}:k", h.seed(seed_n))])
        return {"slot": "page", "kind": "observation", "id": ids.record_id(raw), "envelope": env, "key_list": kl,
                "files": {n: h.b64(b) for n, b in files.items()}}


class ById(Base):
    def test_own_public_observation_is_trusted(self):
        obs = self.own_observation()
        code, out = self.check({"slot": "page", "kind": "observation", "id": obs["observation_id"]})
        self.assertEqual(code, 200, out)
        p = self.predicate(out)
        self.assertEqual(p["finding"], "match")
        self.assertEqual(p["relied_on"], [{"id": obs["observation_id"], "kind": "observation", "signer": self.s.key_id, "trusted": True}])

    def test_unknown_id_is_422(self):
        code, out = self.check({"slot": "page", "kind": "observation", "id": "a" * 64})
        self.assertEqual((code, out["error"]), (422, "observation-not-found"))

    def test_another_accounts_private_observation_is_not_visible(self):
        obs = self.own_observation("private")
        code, out = self.check({"slot": "page", "kind": "observation", "id": obs["observation_id"]}, visibility="private",
                               key="dev-key-b-0123456789abcdef")
        self.assertEqual((code, out["error"]), (422, "observation-not-found"))
        code, out = self.check({"slot": "page", "kind": "observation", "id": obs["observation_id"]}, visibility="private")
        self.assertEqual(code, 200, out)
        self.assertEqual(out["disclosure"]["body"]["finding"], "match")

    def test_a_public_claim_cannot_rest_on_a_private_observation(self):
        obs = self.own_observation("private")
        code, out = self.check({"slot": "page", "kind": "observation", "id": obs["observation_id"]}, visibility="public")
        self.assertEqual((code, out["error"]), (422, "observation-not-found"))


class ByEnvelope(Base):
    def untrusted(self, item, **opts):
        n = len(self.ff.calls)
        code, out = self.check(item, **opts)
        self.assertEqual(code, 200, out)
        p = self.predicate(out)
        self.assertEqual((p["finding"], p["outcome"], p["reason"]), (None, "CANNOT_WITNESS", "evidence-untrusted"))
        self.assertEqual(len(self.ff.calls), n, "nothing is fetched for untrusted evidence")
        return p

    def test_own_envelope_verifies(self):
        obs = self.own_observation()
        code, out = self.check({"slot": "page", "kind": "observation", "id": obs["observation_id"], "envelope": obs["envelope"]})
        self.assertEqual(self.predicate(out)["finding"], "match")

    def test_bad_signature(self):
        obs = self.own_observation()
        env = copy.deepcopy(obs["envelope"])
        sig = bytearray(base64.b64decode(env["signatures"][0]["sig"]))
        sig[5] ^= 1
        env["signatures"][0]["sig"] = base64.b64encode(bytes(sig)).decode()
        p = self.untrusted({"slot": "page", "kind": "observation", "id": obs["observation_id"], "envelope": env})
        self.assertEqual(p["relied_on"][0]["trusted"], False)

    def test_id_that_is_not_the_payload_hash(self):
        obs = self.own_observation()
        self.untrusted({"slot": "page", "kind": "observation", "id": "b" * 64, "envelope": obs["envelope"]})

    def test_bad_manifest_digest_even_when_signed_by_this_witness(self):
        manifest, files = build_capture(U, page(HTML), iso(self.s.clock()))
        pred, files = observation.from_capture(manifest, files, "public")
        stmt, _ = observation.statement(pred)
        stmt["subject"][0]["digest"]["sha256"] = "0" * 64
        raw = jcs.canonical(stmt)
        env = dsse.sign(raw, [(self.s.key_id, self.s.seed)])
        self.untrusted({"slot": "page", "kind": "observation", "id": ids.record_id(raw), "envelope": env,
                        "files": {n: h.b64(b) for n, b in files.items()}})

    def test_unknown_signer_without_a_key_list(self):
        item = self.foreign()
        del item["key_list"]
        self.untrusted(item)
        self.untrusted(item, accept_untrusted=True)

    def test_valid_foreign_signer_needs_accept_untrusted(self):
        item = self.foreign()
        p = self.untrusted(item)
        self.assertEqual(p["options_used"]["accept_untrusted"], False)
        code, out = self.check(item, accept_untrusted=True)
        self.assertEqual(code, 200, out)
        p = self.predicate(out)
        self.assertEqual((p["finding"], p["outcome"]), ("match", "SUPPORTED"))
        self.assertEqual(p["options_used"]["accept_untrusted"], True)
        self.assertEqual(p["relied_on"], [{"id": item["id"], "kind": "observation", "signer": "witness:other:k", "trusted": False}])

    def test_a_key_list_claiming_this_witness_id_is_not_trusted(self):
        item = self.foreign(seed_n=11, witness="witness:test")
        self.untrusted(item)

    def test_files_that_do_not_match_the_manifest(self):
        item = self.foreign()
        item["files"]["text.canonical.txt"] = h.b64(b"something else")
        self.untrusted(item, accept_untrusted=True)

    def test_foreign_bad_manifest_digest(self):
        self.untrusted(self.foreign(tamper_digest=True), accept_untrusted=True)

    def test_foreign_observation_without_files_is_unreadable(self):
        item = self.foreign()
        del item["files"]
        code, out = self.check(item, accept_untrusted=True)
        self.assertEqual(self.predicate(out)["reason"], "unreadable")

    def test_malformed_items_are_422(self):
        for bad in ({"slot": "page", "kind": "observation"}, {"slot": "page", "kind": "observation", "id": "XYZ"},
                    {"slot": "page", "kind": "observation", "id": "a" * 64, "envelope": "nope"},
                    {"slot": "page", "kind": "observation", "id": "a" * 64, "extra": 1}):
            code, out = self.check(bad)
            self.assertEqual(code, 422, bad)


if __name__ == "__main__":
    unittest.main()
