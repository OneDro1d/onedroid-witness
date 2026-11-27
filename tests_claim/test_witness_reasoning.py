"""M-20261127-WITNESS-MODELS, BRIEF-W3: a per-model `"reasoning": false` setting in the ranked model list.

Measured live 27 Nov: reasoning models answer HTTP 200 with EMPTY content under max_tokens 1024 (the hidden reasoning takes the
whole budget, and the call is still charged). OpenRouter's request field `"reasoning": {"enabled": false}` makes them answer.
Some models refuse that field, so it is per model, never global.

P1  a list entry may carry `"reasoning": false`; absent = today's request, byte for byte; false = every chat call to that model
    adds `"reasoning": {"enabled": false}` and nothing else changes; a decision entry refuses the field at load time (ValueError
    naming it); any other value (true, a string, an object, 0, null) is refused at load time.
P2  GET /v1/models and /v1/price show `"reasoning": false` on that entry only.
P3  an empty answer (200, content empty or missing) stays a run note (no-content), no finding, and the run still counts for the
    price (pinned here; no change).
P4  unlisted ids ({ids} shape) send no reasoning field.

Every model call goes to the local fake (tests_claim/fake_models.py).
"""
import json
import pathlib
import tempfile
import unittest

from claim_witness import judge
from claim_witness.methods import judge_supports as js
from tests_claim import fake_models as fm
from tests_claim import helpers as h
from tests_claim.helpers import claim, obj_item, payload_of, request

PAGE = ("<html><body><h1>Acme Widgets</h1><p>The Model X widget ships with a two-year warranty.</p>"
        "<p>Prices start at 40 EUR.</p></body></html>").encode()
PAGE_TEXT = fm.visible_of(PAGE, "text/html")
STATEMENT = "The Model X widget has a two-year warranty."

THINKER = "anthropic/claude-haiku-5.5"      # a reasoning model listed with "reasoning": false
PLAIN = "acme/judge-1"                       # a listed chat model without the field
DECIDER = "typesafe/jev-1.14"                # a listed decision model
UNLISTED_CHAT = "qwen/qwen3.7-flash"         # a reasoning model named by id, not listed
LISTED = [{"id": THINKER, "vendor": "anthropic", "kind": "chat", "price_factor": 1, "timeout": 3, "reasoning": False,
           "rank_note": "answers with reasoning off"},
          {"id": PLAIN, "vendor": "acme", "kind": "chat", "price_factor": 1, "timeout": 3},
          {"id": DECIDER, "vendor": "typesafe", "kind": "decision", "price_factor": 0.5, "timeout": 3}]
REASONING_OFF = {"enabled": False}


def supports(text=PAGE_TEXT):
    return fm.answer("judged-supports", [fm.quote(0, text, "two-year warranty")])


def thinker(text=PAGE_TEXT):
    """What the live reasoning models did: empty content unless the request turns reasoning off."""
    ok = supports(text)

    def beh(body):
        if body.get("reasoning") == REASONING_OFF:
            return ok(body)
        return ("content", "")
    return beh


def high():
    return fm.decision({"supports": 0.9, "contradicts": 0.05, "silent": 0.05}, confidence=0.88)


def judge_request(**options):
    ev = [obj_item("evidence", PAGE, "text/html", "page.html")]
    return request(claim("judge.supports", {}, True, STATEMENT), ev, "public", **options)


def old_body(model, system, user, max_tokens):
    """The chat request body before this change (judge.py at 5634748), key order included."""
    return {"model": model, "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "temperature": 0, "max_tokens": max_tokens}


def wire(body):
    """The bytes Backend._post sends for a body."""
    return json.dumps(body, ensure_ascii=False).encode("utf-8")


# ============================================================================================================ P1: the list

class ReasoningInTheList(unittest.TestCase):
    def setUp(self):
        self.dir = pathlib.Path(tempfile.mkdtemp(prefix="cw-w3-"))
        self.base = {"id": "a/b", "vendor": "a", "price_factor": 1, "timeout": 5}

    def write(self, doc):
        p = self.dir / "models.json"
        p.write_text(json.dumps(doc))
        return str(p)

    def test_reasoning_false_loads_and_absent_is_none(self):
        ms = judge.load_models(self.write(LISTED))
        self.assertIs(ms[0].reasoning, False)
        self.assertIsNone(ms[1].reasoning)
        self.assertIsNone(ms[2].reasoning)
        self.assertIs(judge.load_models(self.write([dict(self.base, kind="chat", reasoning=False)]))[0].reasoning, False)
        self.assertIs(judge.load_models(self.write([dict(self.base, reasoning=False)]))[0].reasoning, False)

    def test_any_other_value_than_false_is_refused_naming_the_field(self):
        for bad in (True, "false", "off", {"enabled": False}, {}, [], 0, 1, None):
            with self.assertRaises(ValueError, msg=repr(bad)) as cm:
                judge.load_models(self.write([dict(self.base, reasoning=bad)]))
            self.assertIn("reasoning", str(cm.exception), repr(bad))

    def test_a_decision_entry_refuses_the_field(self):
        with self.assertRaises(ValueError) as cm:
            judge.load_models(self.write([dict(self.base, kind="decision", reasoning=False)]))
        self.assertIn("reasoning", str(cm.exception))
        self.assertIn("decision", str(cm.exception))

    def test_unlisted_specs_carry_no_reasoning_setting(self):
        m = judge.ModelSpec(UNLISTED_CHAT, "qwen", None, 60, listed=False)
        self.assertIsNone(m.reasoning)


# ============================================================================================================ P1: the request

class ReasoningRequestBody(unittest.TestCase):
    def setUp(self):
        self.srv = fm.FakeModels()
        self.backend = judge.Backend(self.srv.base_url, self.srv.api_key, max_tokens=512)

    def tearDown(self):
        self.srv.close()

    def test_absent_is_todays_request_byte_for_byte(self):
        m = judge.ModelSpec(PLAIN, "acme", 1, 2)
        self.srv.script(PLAIN, supports())
        out = self.backend.chat(m, "SYSTEM", "USER TEXT")
        self.assertIsNone(out["note"])
        (req,) = self.srv.chat_requests()
        self.assertEqual(req["body"], old_body(PLAIN, "SYSTEM", "USER TEXT", 512))
        self.assertEqual(req["raw"], wire(old_body(PLAIN, "SYSTEM", "USER TEXT", 512)))
        self.assertNotIn(b"reasoning", req["raw"])

    def test_reasoning_false_adds_the_field_and_nothing_else(self):
        m = judge.ModelSpec(THINKER, "anthropic", 1, 2, reasoning=False)
        self.srv.script(THINKER, thinker())
        out = self.backend.chat(m, "SYSTEM", "USER TEXT")
        self.assertIsNone(out["note"])
        self.assertIsNotNone(out["text"])
        (req,) = self.srv.chat_requests()
        expected = dict(old_body(THINKER, "SYSTEM", "USER TEXT", 512), reasoning={"enabled": False})
        self.assertEqual(req["body"], expected)
        self.assertEqual(req["raw"], wire(expected))
        self.assertEqual(req["raw"],
                         b'{"model": "anthropic/claude-haiku-5.5", "messages": [{"role": "system", "content": "SYSTEM"}, '
                         b'{"role": "user", "content": "USER TEXT"}], "temperature": 0, "max_tokens": 512, '
                         b'"reasoning": {"enabled": false}}')

    def test_every_call_carries_it(self):
        m = judge.ModelSpec(THINKER, "anthropic", 1, 2, reasoning=False)
        self.srv.script(THINKER, thinker())
        for _ in range(3):
            self.backend.chat(m, "SYSTEM", "USER TEXT")
        self.assertEqual([r["body"].get("reasoning") for r in self.srv.chat_requests()], [REASONING_OFF] * 3)


# ============================================================================================================ the API

class Base(unittest.TestCase):
    models = LISTED

    def setUp(self):
        self.fake = fm.FakeModels()
        self.fake.catalogue = [fm.catalogue_entry(UNLISTED_CHAT, "0.0000001", "0.0000003")]
        self.dir = pathlib.Path(tempfile.mkdtemp(prefix="cw-w3-api-"))
        (self.dir / "key").write_text(self.fake.api_key)
        (self.dir / "models.json").write_text(json.dumps(self.models))
        self.env = {"WITNESS_JUDGE_BASE_URL": self.fake.base_url, "WITNESS_JUDGE_API_KEY_FILE": str(self.dir / "key"),
                    "WITNESS_JUDGE_MODELS_FILE": str(self.dir / "models.json")}
        self.s = h.Stack(config_overrides={"judge": judge.from_env(self.env)})
        self.fake.script(THINKER, thinker())
        self.fake.script(PLAIN, supports())
        self.fake.script(DECIDER, high())
        self.fake.script(UNLISTED_CHAT, supports())

    def tearDown(self):
        self.s.close()
        self.fake.close()

    def pred(self, body):
        code, out, _ = self.s.witness_call(body)
        self.assertEqual(code, 200, out)
        return payload_of(out["envelope"])["predicate"], out

    def bodies(self, model):
        return [r["body"] for r in self.fake.chat_requests() if r["body"]["model"] == model]


class ReasoningListed(Base):
    def test_p2_v1_models_and_v1_price_show_it_on_that_entry_only(self):
        code, doc, _ = self.s.call("GET", "/v1/models", key=None)
        self.assertEqual(code, 200, doc)
        ms = {m["id"]: m for m in doc["models"]}
        self.assertIs(ms[THINKER]["reasoning"], False)
        self.assertNotIn("reasoning", ms[PLAIN])
        self.assertNotIn("reasoning", ms[DECIDER])
        self.assertEqual(set(ms[PLAIN]), {"rank", "id", "vendor", "kind", "price_factor", "credits_per_run", "timeout_s",
                                          "rank_note"})
        self.assertEqual(set(ms[THINKER]) - set(ms[PLAIN]), {"reasoning"})
        _, pl, _ = self.s.call("GET", "/v1/price", key=None)
        _, reg, _ = self.s.call("GET", "/v1/methods")
        self.assertEqual(pl["models"], doc["models"])
        self.assertEqual(reg["models"], doc["models"])

    def test_a_reasoning_false_model_answers_and_its_request_carries_the_field(self):
        p, out = self.pred(judge_request(models={"count": 1}))
        self.assertEqual(p["outcome"], "SUPPORTED")
        (body,) = self.bodies(THINKER)
        self.assertEqual(body["reasoning"], REASONING_OFF)
        self.assertEqual(set(body), {"model", "messages", "temperature", "max_tokens", "reasoning"})
        self.assertEqual((body["temperature"], body["max_tokens"]), (0, 1024))
        self.assertEqual(body["messages"][0], {"role": "system", "content": js.prompt_text()})

    def test_in_one_panel_only_the_flagged_model_gets_the_field(self):
        p, _ = self.pred(judge_request(models={"count": 3, "require": 3}))
        self.assertEqual(p["outcome"], "SUPPORTED")
        self.assertEqual(self.bodies(THINKER)[0]["reasoning"], REASONING_OFF)
        self.assertNotIn("reasoning", self.bodies(PLAIN)[0])
        (dec,) = self.fake.decision_requests()
        self.assertEqual(set(dec["body"]), {"model", "state", "questions"})
        self.assertEqual(self.bodies(THINKER)[0]["messages"], self.bodies(PLAIN)[0]["messages"])

    def test_p4_an_unlisted_id_sends_no_reasoning_field(self):
        self.fake.costs[UNLISTED_CHAT] = 0.001
        p, _ = self.pred(judge_request(models={"ids": [UNLISTED_CHAT]}))
        self.assertEqual(p["outcome"], "SUPPORTED")
        (req,) = [r for r in self.fake.chat_requests() if r["body"]["model"] == UNLISTED_CHAT]
        self.assertNotIn("reasoning", req["body"])
        self.assertNotIn(b"reasoning", req["raw"])


class EmptyAnswerStaysANote(Base):
    """P3: no change, pinned. A 200 with empty or missing content is run note no-content, no finding, and the run counts."""

    def _assert_no_content_run(self, p, out, model):
        run = p["judgment"]["runs"][0]
        self.assertEqual((run["model"], run["note"], run["finding"]), (model, "no-content", None))
        self.assertNotEqual(p["outcome"], "SUPPORTED")
        return out["price"]

    def test_empty_content_of_a_listed_model_is_a_note_and_still_charged(self):
        self.fake.script(PLAIN, fm.content(""))
        p, out = self.pred(judge_request(models={"ids": [PLAIN]}))
        price = self._assert_no_content_run(p, out, PLAIN)
        self.assertEqual(price["lines"], [{"item": "check", "credits": 1},
                                          {"item": "model-run", "model": PLAIN, "credits": 10}])
        self.assertEqual(price["credits"], 11)

    def test_missing_content_is_the_same(self):
        self.fake.script(PLAIN, fm.completion({"id": "x", "object": "chat.completion", "model": PLAIN + "-2026-11-01",
                                               "choices": [{"index": 0, "message": {"role": "assistant"},
                                                            "finish_reason": "length"}],
                                               "usage": {"prompt_tokens": 900, "completion_tokens": 1024}}))
        p, out = self.pred(judge_request(models={"ids": [PLAIN]}))
        price = self._assert_no_content_run(p, out, PLAIN)
        self.assertEqual(price["credits"], 11)

    def test_whitespace_only_content_is_the_same(self):
        self.fake.script(PLAIN, fm.content("  \n "))
        p, out = self.pred(judge_request(models={"ids": [PLAIN]}))
        self.assertEqual(self._assert_no_content_run(p, out, PLAIN)["credits"], 11)

    def test_an_unlisted_empty_answer_is_charged_at_its_reported_cost(self):
        self.fake.costs[UNLISTED_CHAT] = 0.0042
        self.fake.script(UNLISTED_CHAT, fm.content(""))
        p, out = self.pred(judge_request(models={"ids": [UNLISTED_CHAT]}))
        price = self._assert_no_content_run(p, out, UNLISTED_CHAT)
        line = price["lines"][1]
        self.assertEqual((line["model"], line["credits"], line["unlisted"], line["cost_usd"]), (UNLISTED_CHAT, 7, True, 0.0042))


if __name__ == "__main__":
    unittest.main()
