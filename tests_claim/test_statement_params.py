"""Every signed statement fills the claim's params on every path (SPEC §2.4: the statement is the method version's template
filled from the params and the observation). The defect this pins (seen on the live dev witness): a post.by-author claim whose
observation evidence was untrusted signed "The post at <url> was published by the account ." with the handle missing, because
the early CANNOT_WITNESS paths of service.py rendered the template from the observation's variables alone.

Rules pinned here:
- the claim's params are always template variables (handle, quote, expect_commit, url of page.live), on a finding and on every
  no-finding path, whatever the evidence was and wherever the path left the method;
- an observation-derived variable that is not known (the url or the time of an observation that could not be used, the anchor
  time of a record that is not anchored) is written as a fixed phrase, never as an empty hole in the sentence.
"""
import base64
import copy
import json
import re
import unittest

from claim_witness import methods, service
from tests_claim import helpers as h
from tests_claim.fakefetch import post_page, stack
from tests_claim.helpers import claim, obj_item, request
from tests_claim.test_post_by_author import REAL, URL

HANDLE = "mcuban.bsky.social"
HTML = b"<html><body><h1>Statement</h1><p>The text the page shows.</p></body></html>"
PAGE_URL = "https://stmt.example/p"
NO_URL = "an observation that could not be used"
NO_TIME = "an unknown time"
HOLE = re.compile(r"(?:^|\s)[.,:;”)]|\s{2,}|{\w+}|“”")


def no_hole(test, statement):
    test.assertIsNone(HOLE.search(statement), f"an empty hole in the signed sentence: {statement!r}")


class PostByAuthorUntrusted(unittest.TestCase):
    """The live defect, on every early evidence-untrusted path of an observation given to post.by-author."""

    def setUp(self):
        self.s, self.ff, _ = stack()
        self.ff.set(URL, post_page(REAL))
        code, self.obs, _ = self.s.call("POST", "/v1/observe", {"url": URL, "capture": "post", "handle": "bsky.app",
                                                                "visibility": "public"})
        self.assertEqual(code, 200, self.obs)

    def tearDown(self):
        self.s.close()
        self.ff.close()

    def ask(self, item, assertion=True, handle=HANDLE, visibility="public"):
        body = request(claim("post.by-author", {"handle": handle}, assertion), [item], visibility)
        code, out, _ = self.s.witness_call(body)
        self.assertEqual(code, 200, out)
        p = h.payload_of(out["envelope"])["predicate"]
        self.assertEqual((p["finding"], p["outcome"], p["reason"]), (None, "CANNOT_WITNESS", "evidence-untrusted"))
        return p["statement"]

    def item(self, **extra):
        return dict({"slot": "post", "kind": "observation", "id": self.obs["observation_id"], "envelope": self.obs["envelope"]}, **extra)

    def test_one_byte_of_platform_json_changed_still_names_the_handle(self):
        files = {n: h.b64(b) for n, b in self.s.storage.get_observation_files(self.obs["observation_id"]).items()}
        raw = bytearray(base64.b64decode(files["platform.json"]))
        raw[10] ^= 1
        files["platform.json"] = h.b64(bytes(raw))
        self.assertEqual(self.ask(self.item(files=files)), f"The post at {URL} was published by the account {HANDLE}.")
        self.assertEqual(self.ask(self.item(files=files), assertion=False),
                         f"The post at {URL} was not published by the account {HANDLE}.")

    def test_bad_signature_names_the_handle(self):
        env = copy.deepcopy(self.obs["envelope"])
        sig = bytearray(base64.b64decode(env["signatures"][0]["sig"]))
        sig[5] ^= 1
        env["signatures"][0]["sig"] = h.b64(bytes(sig))
        self.assertEqual(self.ask(self.item(envelope=env)), f"The post at {URL} was published by the account {HANDLE}.")

    def test_id_that_is_not_the_payload_hash_names_the_handle(self):
        self.assertEqual(self.ask(self.item(id="b" * 64)), f"The post at {URL} was published by the account {HANDLE}.")

    def test_an_envelope_with_no_readable_payload_names_the_handle_and_an_unknown_url(self):
        env = dict(self.obs["envelope"], payload="!!not base64!!")
        self.assertEqual(self.ask(self.item(envelope=env)), f"The post at {NO_URL} was published by the account {HANDLE}.")

    def test_an_own_stored_observation_with_a_bad_signature_by_id_names_the_handle(self):
        oid = self.obs["observation_id"]
        sig = bytearray(base64.b64decode(self.s.storage.observations[oid]["envelope"]["signatures"][0]["sig"]))
        sig[3] ^= 1
        self.s.storage.observations[oid]["envelope"]["signatures"][0]["sig"] = h.b64(bytes(sig))
        statement = self.ask({"slot": "post", "kind": "observation", "id": oid})
        self.assertEqual(statement, f"The post at {NO_URL} was published by the account {HANDLE}.")

    def test_a_private_claim_discloses_the_same_statement(self):
        env = dict(self.obs["envelope"], payload="!!not base64!!")
        body = request(claim("post.by-author", {"handle": HANDLE}), [self.item(envelope=env)], "private")
        code, out, _ = self.s.witness_call(body)
        self.assertEqual(code, 200, out)
        self.assertEqual(out["disclosure"]["body"]["statement"], f"The post at {NO_URL} was published by the account {HANDLE}.")


class OtherMethodsUntrusted(unittest.TestCase):
    """match.text and judge.supports over evidence that cannot be trusted: the variables the claim does give are filled, the
    ones it cannot know are fixed phrases."""

    def setUp(self):
        self.s, self.ff, _ = stack()

    def tearDown(self):
        self.s.close()
        self.ff.close()

    def test_match_text_with_an_unreadable_observation(self):
        sub = obj_item("submitted", HTML, "text/html", "copy.html")
        env = {"payloadType": "application/vnd.in-toto+json", "payload": "!!not base64!!", "signatures": []}
        obs = {"slot": "page", "kind": "observation", "id": "a" * 64, "envelope": env}
        for assertion, word in ((True, "matches"), (False, "does not match")):
            code, out, _ = self.s.witness_call(request(claim("match.text", {}, assertion), [sub, obs], "public"))
            self.assertEqual(code, 200, out)
            p = h.payload_of(out["envelope"])["predicate"]
            self.assertEqual(p["reason"], "evidence-untrusted")
            self.assertEqual(p["statement"], f"The submitted text {sub['sha256']} {word} the content of {NO_URL} observed at {NO_TIME}.")
            no_hole(self, p["statement"])


class EveryTemplate(unittest.TestCase):
    """The completion of the variables, for every method and both templates, with nothing known from the evidence."""

    PARAMS = {"post.by-author": {"handle": HANDLE}, "quote.in-source": {"quote": "the passage"},
              "tests.pass": {"expect_commit": "abc1234"}, "page.live": {"url": PAGE_URL}}

    def test_params_fill_and_unknown_observation_variables_are_phrases(self):
        for mid, m in methods.METHODS.items():
            for assertion in (True, False):
                if m.templates[assertion] is None:
                    continue
                params = self.PARAMS.get(mid, {})
                vars_ = service.fill_vars(m, assertion, params, {})
                text = m.render(assertion, vars_)
                for value in params.values():
                    self.assertIn(value, text, (mid, assertion))
                no_hole(self, text)

    def test_a_none_or_empty_variable_is_filled_too(self):
        m = methods.METHODS["record.disclose"]
        text = m.render(True, service.fill_vars(m, True, {}, {"id": "a" * 64, "anchor_time": ""}))
        self.assertEqual(text, f"Record {'a' * 64}, sealed at {NO_TIME}, had the content shown here.")
        m = methods.METHODS["page.live"]
        text = m.render(False, service.fill_vars(m, False, {"url": PAGE_URL}, {"url": PAGE_URL, "fetched_at": None}))
        self.assertEqual(text, f"{PAGE_URL} was not live when observed at {NO_TIME}.")

    def test_known_values_and_optional_parts_are_untouched(self):
        m = methods.METHODS["tests.pass"]
        text = m.render(True, service.fill_vars(m, True, {}, {"sha": "f" * 64, "expect_commit": None}))
        self.assertEqual(text, f"The test output {'f' * 64} reports at least one test run and no failures.")
        m = methods.METHODS["page.live"]
        text = m.render(True, service.fill_vars(m, True, {"url": PAGE_URL}, {"url": "https://other.example/", "fetched_at": "2026-11-24T21:21:49Z"}))
        self.assertEqual(text, "https://other.example/ was live when observed at 2026-11-24T21:21:49Z.")

    def test_judge_supports_untrusted_keeps_the_submitters_statement(self):
        m = methods.METHODS["judge.supports"]
        self.assertEqual(m.render(True, service.fill_vars(m, True, {}, {"statement": "It is so."})), "It is so.")
        self.assertEqual(m.render(False, service.fill_vars(m, False, {}, {"statement": "It is so."})), "Asserted false: It is so.")


if __name__ == "__main__":
    unittest.main()
