"""NS-11 (M-20261127-NAME-SITE, BRIEF-NS-11-OCR): the witness method `match.image-text`, "an image shows a given text".

Michal, 27 Nov (Slack C0CDYK0D6KW/1795817936.145609): "build match.image-text: yes, build". The design comes from the OCR eval
(M-20261127-WITNESS-MODELS/eval: eval_vision.py, orch_strict_score.py; ranking page in README_CLAIM.md): a similarity score
misses one-number forgeries (0/14 at match.screenshot's thresholds); the strict token-coverage rule R1 caught 32/32 forgeries
with every model, and seed-2.0-mini and claude-haiku-5.5 (reasoning off) made no false `differs` on 32 honest images.

M1  method match.image-text 1.0.0: params {text: 1..20000 chars}; slot `image` (one PNG, JPEG or WebP object); templates
    "The submitted image {sha} shows the text with sha256 {text_sha256}." / "... does not show ..."; + consistent, - differs;
    no finding: unreadable (empty or illegible transcription), model-unavailable (every model failed), too-large.
M2  the model ONLY transcribes, with the eval's fixed prompt (sha256 c57f8c28...3600, in the record); the claimed text is never
    sent; the witness applies R1 (orch_strict_score.py, ported): a claimed number/date token missing, or >= 3 claimed tokens
    missing, is `differs`.
M3  an ordered transcriber list (WITNESS_IMAGE_TEXT_MODELS_FILE): seed-2.0-mini, claude-haiku-5.5, gemma-4-31b-it, reasoning
    off where the eval needed it; the first that answers is used; the record (its body) names model, provider and version, the
    transcription and its sha256, the missing tokens.
M4  price: the house `check` line (1 credit); the transcription runs are not billed apart; GET /v1/price lists it.
M5  library 1.9.0 -> 1.10.0 (a new method); witness-verify re-runs R1 offline from the record's transcription.

Every model call goes to the local fake (tests_claim/fake_models.py); no test reaches a model provider.
"""
import base64
import difflib
import hashlib
import io
import json
import pathlib
import re
import tempfile
import unicodedata
import unittest

from claim_witness import methods, tarball, verify
from claim_witness.methods import canon, similarity
from tests_claim import fake_models as fm
from tests_claim import helpers as h
from tests_claim.helpers import claim, obj_item, payload_of, request

PROMPT_SHA256 = "c57f8c28c99b4a6993916248ee15026cdc2fe47cafd4c08021c5b91067093600"  # eval_vision.py's start line
EVAL_PROMPT = (  # eval_vision.py PROMPT, copied byte for byte (the witness must send exactly this)
    "Transcribe all of the text visible in this image, exactly as written.\n"
    "Output only the transcribed text: no introduction, no comments, no Markdown, no code fences, no table borders.\n"
    "Keep the reading order, top to bottom and left to right, with each line of the image on its own line.\n"
    "Copy every word, number, amount, currency symbol, date, time, percentage and punctuation mark exactly as it appears, "
    "even if it looks wrong or inconsistent. Do not correct, complete, summarise, translate or explain anything.\n"
    "For a table, write one row per line with its cells in order, separated by single spaces.\n"
    "If a word cannot be read, write [illegible] in its place. If the image has no text, output nothing."
)

SEED, HAIKU, GEMMA = "bytedance-seed/seed-2.0-mini", "anthropic/claude-haiku-5.5", "google/gemma-4-31b-it"
MODELS = [{"id": SEED, "vendor": "bytedance-seed", "timeout": 5, "reasoning": False},
          {"id": HAIKU, "vendor": "anthropic", "timeout": 5, "reasoning": False},
          {"id": GEMMA, "vendor": "google", "timeout": 5}]

INVOICE = ("Invoice 2026-114\nDate: 14 March 2026\nAcme Widgets Ltd, 12 Harbour Road, Gdansk\n"
           "Model X widget, 25 units at EUR 40.00\nTotal due: EUR 1,000.00 by 30 April 2026\nThank you for your order.")
FORGED = INVOICE.replace("1,000.00", "1,600.00")  # one number changed

# ---------------------------------------------------------------------------------------------------- the eval's rule, restated
# orch_strict_score.py lines 18-42 and 66-73, restated here independently of the witness's port (the parity tests compare them)
EVAL_MONTHS = {m.lower() for m in ("January February March April May June July August September October November December "
                                   "Jan Feb Mar Apr Jun Jul Aug Sep Sept Oct Nov Dec").split()}
EVAL_DIGIT = re.compile(r"\d")


def eval_is_num(tok):
    return bool(EVAL_DIGIT.search(tok)) or tok.strip(".,;:()").lower() in EVAL_MONTHS


def eval_missing_tokens(text, transcription):
    t = similarity.tokens(canon.normalise(text))
    o = similarity.tokens(canon.normalise(transcription or ""))
    sm = difflib.SequenceMatcher(None, t, o, autojunk=False)
    covered = set()
    for m in sm.get_matching_blocks():
        covered.update(range(m.a, m.a + m.size))
    miss = [t[i] for i in range(len(t)) if i not in covered]
    return miss, [x for x in miss if eval_is_num(x)], len(t)


def eval_decide(miss, num):
    return "differs" if num >= 1 or miss >= 3 else "consistent"


# ---------------------------------------------------------------------------------------------------- fixtures
def png(text):
    """A stand-in image: the PNG signature, then the text it 'shows' (the fake transcriber reads it back)."""
    return b"\x89PNG\r\n\x1a\n" + b"SHOWS:" + text.encode("utf-8")


def jpeg(text):
    return b"\xff\xd8\xff\xe0" + b"SHOWS:" + text.encode("utf-8")


def shown_text(body):
    """What the fake transcriber 'reads': the text inside the data URL's image, never anything else of the request."""
    url = body["messages"][0]["content"][1]["image_url"]["url"]
    data = base64.b64decode(url.split(",", 1)[1])
    return data.split(b"SHOWS:", 1)[1].decode("utf-8")


def reader(body):
    return ("content", shown_text(body))


def thinker(body):
    """A reasoning model: empty content unless the request turns reasoning off."""
    if body.get("reasoning") != {"enabled": False}:
        return ("content", "")
    return reader(body)


def ev_of(text=None, failed=False, truncated=False):
    tr = None if failed else {"text": text, "truncated": truncated}
    return {"image": {"slot": "image", "kind": "object", "sha256": "1" * 64, "media_type": "image/png", "name": "i.png",
                      "data": b"", "transcription": tr}}


def mit():
    from claim_witness.methods import match_image_text
    return match_image_text


# ============================================================================================================ M2: R1, ported
class RuleR1(unittest.TestCase):
    CASES = [
        (INVOICE, INVOICE),
        (INVOICE, FORGED),
        (INVOICE, "Header line\n" + INVOICE + "\nFooter: page 1 of 1"),           # the block is part of a larger image
        (INVOICE, INVOICE.replace("Thank you for your order.", "Thank you for order.")),  # one word lost
        (INVOICE, INVOICE.replace("Thank you for your order.", "Thanks for order.")),    # three words lost
        (INVOICE, INVOICE.replace("14 March", "14 May")),                          # a month name changed
        (INVOICE, INVOICE.replace("Acme", "[illegible]")),
        ("Don’t pay — it’s 5% off", "Don't pay - it's 5% off"),     # canon/1 unifies quotes and dashes
        ("one two three four", "four three two one"),                                # order matters (difflib)
        ("Totals: (Sept.) 7", "Totals: (Sept.) 7"),
        ("a b c", ""),
        (INVOICE, "Something else entirely, an unrelated receipt of 3 lines."),
    ]

    def test_the_port_gives_the_eval_scripts_answer_on_every_case(self):
        m = mit()
        for text, tr in self.CASES:
            miss, num, n = eval_missing_tokens(text, tr)
            got = m.r1(text, tr)
            self.assertEqual((got["missing_tokens"], got["missing_number_tokens"], got["text_tokens"]), (miss, num, n), text[:30])
            if tr:
                self.assertEqual(got["verdict"], eval_decide(len(miss), len(num)), (text[:30], tr[:30]))

    def test_number_and_date_tokens(self):
        m = mit()
        for tok in ("12", "3.5%", "EUR40", "1,000.00", "2026-114", "March", "march", "Sept.", "(Jan)", "Dec,", "14:05"):
            self.assertTrue(m.is_num(tok), tok)
        for tok in ("widget", "May", "Marching", "Total", "[illegible]"):
            self.assertEqual(m.is_num(tok), eval_is_num(tok), tok)
        self.assertTrue(m.is_num("may") is eval_is_num("may"))  # "may" is not in the eval's month list either

    def test_the_rule_table(self):
        m = mit()
        self.assertEqual(m.decide(0, 0), "consistent")
        self.assertEqual(m.decide(2, 0), "consistent")
        self.assertEqual(m.decide(3, 0), "differs")
        self.assertEqual(m.decide(1, 1), "differs")
        self.assertEqual((m.MAX_MISSING, m.MAX_MISSING_NUMBERS), (2, 0))

    def test_a_one_number_forgery_differs_and_names_the_number(self):
        r = mit().r1(INVOICE, FORGED)
        self.assertEqual(r["verdict"], "differs")
        self.assertEqual(r["missing_number_tokens"], ["1,000.00"])
        self.assertEqual(r["missing_tokens"], ["1,000.00"])

    def test_the_honest_image_with_more_text_around_it_is_consistent(self):
        r = mit().r1(INVOICE, "OneDroid scan\n" + INVOICE + "\nPage 1 of 1")
        self.assertEqual((r["verdict"], r["missing_tokens"]), ("consistent", []))


# ============================================================================================================ M1: the method
class Registry(unittest.TestCase):
    def test_the_method_entry(self):
        m = methods.get("match.image-text")
        self.assertIsNotNone(m)
        self.assertEqual((m.id, m.major, m.version), ("match.image-text", 1, "1.0.0"))
        self.assertEqual(m.slots, {"image": ("object",)})
        self.assertEqual(m.slot_counts, {"image": (1, 1)})
        self.assertEqual(m.params_schema, {"type": "object", "properties": {"text": {"type": "string", "minLength": 1,
                                                                                      "maxLength": 20000}},
                                           "required": ["text"], "additionalProperties": False})
        self.assertEqual(m.templates, {True: "The submitted image {sha} shows the text with sha256 {text_sha256}.",
                                       False: "The submitted image {sha} does not show the text with sha256 {text_sha256}."})
        self.assertEqual(m.findings, {"consistent": "positive", "differs": "negative"})
        self.assertTrue(m.mechanical)
        self.assertTrue(m.pure)  # R1 is pure and ships in the tarball; the model's transcription is recorded and re-used
        self.assertEqual(m.determinism, "model")
        self.assertIn("transcri", m.limits)
        self.assertLessEqual(len(m.limits), 1000)

    def test_params(self):
        m = methods.get("match.image-text")
        m.check_params({"text": "x"})
        m.check_params({"text": "y" * 20000})
        m.check_params({"text": "two\nlines\twith a tab"})
        for bad in ({}, {"text": ""}, {"text": "   "}, {"text": "z" * 20001}, {"text": 5}, {"text": "a", "quote": "b"},
                    {"text": unicodedata.normalize("NFD", "café")}, {"text": "bell\x07"}):
            with self.assertRaises(methods.ParamsError, msg=repr(bad)[:40]):
                m.check_params(bad)

    def test_the_prompt_is_the_evals_byte_for_byte(self):
        self.assertEqual(mit().PROMPT, EVAL_PROMPT)
        self.assertEqual(mit().PROMPT_SHA256, PROMPT_SHA256)
        self.assertEqual(hashlib.sha256(mit().PROMPT.encode("utf-8")).hexdigest(), PROMPT_SHA256)


class Pure(unittest.TestCase):
    def run_it(self, claimed, **kw):
        return methods.run("match.image-text", {"text": claimed}, ev_of(**kw))

    def test_consistent(self):
        r = self.run_it(INVOICE, text=INVOICE)
        self.assertEqual(r.finding, "consistent")
        self.assertEqual(r.vars, {"sha": "1" * 64, "text_sha256": hashlib.sha256(INVOICE.encode()).hexdigest()})
        n = len(INVOICE.split())
        self.assertEqual(r.detail, {"rule": "R1", "text_tokens": n, "transcription_tokens": n, "missing": 0, "missing_numbers": 0,
                                    "truncated": False})

    def test_one_number_differs(self):
        r = self.run_it(INVOICE, text=FORGED)
        self.assertEqual((r.finding, r.detail["missing"], r.detail["missing_numbers"]), ("differs", 1, 1))

    def test_every_model_failed_is_model_unavailable(self):
        r = self.run_it(INVOICE, failed=True)
        self.assertEqual((r.finding, r.reason, r.detail), (None, "model-unavailable", {"transcription": "failed"}))
        self.assertEqual(r.vars["text_sha256"], hashlib.sha256(INVOICE.encode()).hexdigest())

    def test_empty_or_illegible_transcription_is_unreadable(self):
        for tr in ("", "   \n ", "[illegible] [illegible]", "... --- ...", "[illegible] [illegible] [illegible] word"):
            r = self.run_it(INVOICE, text=tr)
            self.assertEqual((r.finding, r.reason), (None, "unreadable"), repr(tr))
        r = self.run_it("word one", text="[illegible] word one")  # one marker in three tokens: read, and R1 decides
        self.assertEqual(r.finding, "consistent")

    def test_a_cut_transcription_never_differs(self):
        cut = INVOICE[:40]
        r = self.run_it(INVOICE, text=cut, truncated=True)
        self.assertEqual((r.finding, r.reason, r.detail["truncated"]), (None, "too-large", True))
        r = self.run_it("Invoice 2026-114", text=INVOICE, truncated=True)  # the block was still covered
        self.assertEqual(r.finding, "consistent")

    def test_templates_render(self):
        r = self.run_it(INVOICE, text=INVOICE)
        t = hashlib.sha256(INVOICE.encode()).hexdigest()
        self.assertEqual(methods.render_statement("match.image-text", True, r.vars),
                         f"The submitted image {'1' * 64} shows the text with sha256 {t}.")
        self.assertEqual(methods.render_statement("match.image-text", False, r.vars),
                         f"The submitted image {'1' * 64} does not show the text with sha256 {t}.")


# ============================================================================================================ M3: the model list
class ModelList(unittest.TestCase):
    def setUp(self):
        self.dir = pathlib.Path(tempfile.mkdtemp(prefix="cw-ns11-"))

    def write(self, doc):
        p = self.dir / "m.json"
        p.write_text(json.dumps(doc))
        return str(p)

    def test_loads_in_order_with_reasoning(self):
        from claim_witness import transcribe
        ms = transcribe.load_models(self.write(MODELS))
        self.assertEqual([m.id for m in ms], [SEED, HAIKU, GEMMA])
        self.assertEqual([m.reasoning for m in ms], [False, False, None])
        self.assertEqual([m.rank for m in ms], [1, 2, 3])
        self.assertEqual(transcribe.load_models(self.write({"models": MODELS}))[0].id, SEED)

    def test_refuses_bad_lists(self):
        from claim_witness import transcribe
        base = {"id": SEED, "vendor": "bytedance-seed", "timeout": 5}
        for bad in ([], [dict(base, id="openrouter/auto")], [dict(base, id="x/y:free")], [dict(base, reasoning=True)],
                    [dict(base, reasoning=None)], [dict(base, kind="decision")], [{"id": SEED, "vendor": "v"}],
                    [dict(base, timeout=0)], [base, base], [dict(base, id=f"v/m{i}") for i in range(6)], {"x": 1}):
            with self.assertRaises(ValueError, msg=repr(bad)[:60]):
                transcribe.load_models(self.write(bad))

    def test_the_example_list_is_the_evals_top_three(self):
        p = pathlib.Path(__file__).resolve().parent.parent / "k8s" / "claim-witness-image-text-models.example.json"
        from claim_witness import transcribe
        ms = transcribe.load_models(str(p))
        self.assertEqual([(m.id, m.reasoning) for m in ms], [(SEED, False), (HAIKU, False), (GEMMA, None)])


# ============================================================================================================ the witness
class Base(unittest.TestCase):
    models = MODELS
    configured = True

    def setUp(self):
        from claim_witness import transcribe
        self.fake = fm.FakeModels()
        self.dir = pathlib.Path(tempfile.mkdtemp(prefix="cw-ns11-api-"))
        (self.dir / "key").write_text(self.fake.api_key)
        (self.dir / "models.json").write_text(json.dumps(self.models))
        self.env = {"WITNESS_JUDGE_BASE_URL": self.fake.base_url, "WITNESS_JUDGE_API_KEY_FILE": str(self.dir / "key"),
                    "WITNESS_IMAGE_TEXT_MODELS_FILE": str(self.dir / "models.json")}
        self.s = h.Stack(config_overrides={"image_text": transcribe.from_env(self.env) if self.configured else None})
        self.fake.script(SEED, thinker)
        self.fake.script(HAIKU, thinker)
        self.fake.script(GEMMA, reader)

    def tearDown(self):
        self.s.close()
        self.fake.close()

    def body(self, img, text=INVOICE, assertion=True, media_type="image/png", visibility="private", **options):
        opts = {"allow_provider": True}
        opts.update(options)
        return request(claim("match.image-text", {"text": text}, assertion), [obj_item("image", img, media_type, "scan.png")],
                       visibility, **opts)

    def ok(self, body, **kw):
        code, out, _ = self.s.witness_call(body, **kw)
        self.assertEqual(code, 200, out)
        return out, out["disclosure"]["body"]

    def refused(self, body, status, error, **kw):
        n, calls = self.s.log_count(), len(self.fake.chat_requests())
        code, out, _ = self.s.witness_call(body, **kw)
        self.assertEqual((code, out.get("error")), (status, error), out)
        self.assertEqual(self.s.log_count(), n, "nothing is signed")
        return out, len(self.fake.chat_requests()) - calls


class Witness(Base):
    def test_supported(self):
        img = png(INVOICE)
        out, b = self.ok(self.body(img))
        self.assertEqual((b["finding"], b["outcome"], b["reason"]), ("consistent", "SUPPORTED", "consistent"))
        tsha = hashlib.sha256(INVOICE.encode()).hexdigest()
        self.assertEqual(b["statement"], f"The submitted image {h.sha(img)} shows the text with sha256 {tsha}.")
        self.assertEqual(b["method"], {"id": "match.image-text", "version": "1.0.0", "code_sha256": tarball.methods_code_sha256(),
                                       "runtime": b["method"]["runtime"]})
        j = b["judgment"]
        self.assertEqual(j["kind"], "transcription")
        self.assertEqual(j["prompt_sha256"], PROMPT_SHA256)
        self.assertEqual(j["served"], {"id": SEED, "provider": "FakeProvider", "version": f"{SEED}-2026-11-01", "rank": 1})
        self.assertEqual(j["transcription"], INVOICE)
        self.assertEqual(j["transcription_sha256"], hashlib.sha256(INVOICE.encode()).hexdigest())
        self.assertEqual((j["rule"], j["missing_tokens"], j["missing_number_tokens"], j["truncated"]), ("R1", [], [], False))
        self.assertEqual(j["text_sha256"], tsha)
        self.assertEqual(j["runs"], [{"model": SEED, "rank": 1, "note": None, "status": None, "finish_reason": "stop"}])
        self.assertEqual(j["sampling"], {"temperature": 0, "max_tokens": 8192})
        self.assertEqual(out["price"], {"credits": 1, "lines": [{"item": "check", "credits": 1}]})
        # the private payload: integers and enums only, no transcription, no model id
        p = payload_of(out["envelope"])["predicate"]
        self.assertEqual(p["visibility"], "private")
        self.assertEqual(p["detail"], b["detail"])
        raw = h.payload_bytes(out["envelope"]).decode()
        for secret in ("Harbour", SEED, "1,000.00"):
            self.assertNotIn(secret, raw)

    def test_the_model_only_transcribes_and_never_sees_the_claimed_text(self):
        claimed = INVOICE.replace("Gdansk", "Sopot")  # what the image does not show
        self.ok(self.body(png(INVOICE), text=claimed))
        reqs = self.fake.chat_requests()
        self.assertEqual(len(reqs), 1)
        r = reqs[0]
        self.assertNotIn(b"Sopot", r["raw"])
        body = r["body"]
        self.assertEqual(list(body), ["model", "temperature", "max_tokens", "usage", "messages", "reasoning"])
        self.assertEqual((body["model"], body["temperature"], body["max_tokens"], body["usage"]), (SEED, 0, 8192, {"include": True}))
        self.assertEqual(body["reasoning"], {"enabled": False})
        self.assertEqual(len(body["messages"]), 1)
        msg = body["messages"][0]
        self.assertEqual(msg["role"], "user")
        self.assertEqual(msg["content"][0], {"type": "text", "text": EVAL_PROMPT})
        self.assertEqual(msg["content"][1]["type"], "image_url")
        self.assertEqual(msg["content"][1]["image_url"]["url"], "data:image/png;base64," + base64.b64encode(png(INVOICE)).decode())
        self.assertEqual(r["authorization"], f"Bearer {self.fake.api_key}")

    def test_not_supported_on_a_one_number_change(self):
        out, b = self.ok(self.body(png(FORGED)))
        self.assertEqual((b["finding"], b["outcome"]), ("differs", "NOT_SUPPORTED"))
        self.assertEqual(b["judgment"]["missing_number_tokens"], ["1,000.00"])
        self.assertEqual((b["detail"]["missing"], b["detail"]["missing_numbers"]), (1, 1))
        out, b = self.ok(self.body(png(FORGED), assertion=False))
        self.assertEqual((b["finding"], b["outcome"]), ("differs", "SUPPORTED"))
        tsha = hashlib.sha256(INVOICE.encode()).hexdigest()
        self.assertTrue(b["statement"].endswith(f"does not show the text with sha256 {tsha}."))

    def test_cannot_witness_when_every_model_fails(self):
        for mid in (SEED, HAIKU, GEMMA):
            self.fake.script(mid, fm.status(503))
        out, b = self.ok(self.body(png(INVOICE)))
        self.assertEqual((b["finding"], b["outcome"], b["reason"]), (None, "CANNOT_WITNESS", "model-unavailable"))
        j = b["judgment"]
        self.assertIsNone(j["served"])
        self.assertIsNone(j["transcription"])
        self.assertIsNone(j["transcription_sha256"])
        self.assertEqual([(x["model"], x["note"], x["status"]) for x in j["runs"]],
                         [(SEED, "model-unavailable", 503), (HAIKU, "model-unavailable", 503), (GEMMA, "model-unavailable", 503)])
        self.assertEqual(out["price"], {"credits": 1, "lines": [{"item": "check", "credits": 1}]})

    def test_the_first_model_that_answers_is_used(self):
        self.fake.script(SEED, fm.status(500))
        out, b = self.ok(self.body(png(INVOICE)))
        self.assertEqual(b["finding"], "consistent")
        self.assertEqual(b["judgment"]["served"]["id"], HAIKU)
        self.assertEqual(b["judgment"]["served"]["rank"], 2)
        self.assertEqual([x["model"] for x in b["judgment"]["runs"]], [SEED, HAIKU])
        self.assertEqual([r["body"]["model"] for r in self.fake.chat_requests()], [SEED, HAIKU])

    def test_an_empty_answer_moves_on_and_gemma_gets_no_reasoning_field(self):
        self.fake.script(SEED, fm.content(""))
        self.fake.script(HAIKU, fm.content("  "))
        out, b = self.ok(self.body(png(INVOICE)))
        self.assertEqual(b["judgment"]["served"]["id"], GEMMA)
        self.assertEqual([x["note"] for x in b["judgment"]["runs"]], ["no-content", "no-content", None])
        self.assertNotIn("reasoning", self.fake.chat_requests()[-1]["body"])

    def test_all_empty_answers_are_unreadable(self):
        for mid in (SEED, HAIKU, GEMMA):
            self.fake.script(mid, fm.content(""))
        out, b = self.ok(self.body(png(INVOICE)))
        self.assertEqual((b["finding"], b["reason"]), (None, "unreadable"))
        self.assertEqual(b["judgment"]["transcription"], "")

    def test_an_illegible_image_is_unreadable(self):
        self.fake.script(SEED, fm.content("[illegible] [illegible] [illegible]"))
        out, b = self.ok(self.body(png(INVOICE)))
        self.assertEqual((b["finding"], b["outcome"], b["reason"]), (None, "CANNOT_WITNESS", "unreadable"))

    def test_a_cut_answer_is_too_large_not_differs(self):
        self.fake.script(SEED, fm.completion({"model": SEED, "provider": "P", "choices": [
            {"message": {"role": "assistant", "content": INVOICE[:50]}, "finish_reason": "length"}]}))
        out, b = self.ok(self.body(png(INVOICE)))
        self.assertEqual((b["finding"], b["reason"]), (None, "too-large"))
        self.assertTrue(b["judgment"]["truncated"])

    def test_a_jpeg_and_a_webp(self):
        out, b = self.ok(self.body(jpeg(INVOICE), media_type="image/jpeg"))
        self.assertEqual(b["finding"], "consistent")
        webp = b"RIFF\x00\x00\x00\x00WEBP" + b"SHOWS:" + INVOICE.encode()
        out, b = self.ok(self.body(webp, media_type="image/webp"))
        self.assertEqual(b["finding"], "consistent")
        self.assertTrue(self.fake.chat_requests()[-1]["body"]["messages"][0]["content"][1]["image_url"]["url"]
                        .startswith("data:image/webp;base64,"))


class Refusals(Base):
    def test_a_private_claim_needs_allow_provider(self):
        out, calls = self.refused(self.body(png(INVOICE), allow_provider=False), 422, "provider-not-allowed")
        self.assertEqual(calls, 0)

    def test_a_public_claim_with_an_image_is_refused(self):
        out, calls = self.refused(self.body(png(INVOICE), visibility="public"), 422, "media-not-allowed")
        self.assertEqual(calls, 0)

    def test_only_png_jpeg_and_webp(self):
        out, calls = self.refused(self.body(b"plain text", media_type="text/plain"), 422, "invalid-evidence")
        self.assertIn("PNG, JPEG or WebP", out["detail"])
        out, calls2 = self.refused(self.body(b"GIF89a....", media_type="image/gif"), 422, "invalid-evidence")
        self.assertEqual(calls + calls2, 0)

    def test_bytes_that_are_not_the_declared_image_are_refused(self):
        out, calls = self.refused(self.body(b"not a png at all", media_type="image/png"), 422, "invalid-evidence")
        self.assertEqual(calls, 0)
        out, calls = self.refused(self.body(png("x"), media_type="image/jpeg"), 422, "invalid-evidence")
        self.assertEqual(calls, 0)

    def test_a_statement_is_refused(self):
        b = self.body(png(INVOICE))
        b["claim"]["statement"] = "my own words"
        self.refused(b, 422, "statement-not-allowed")

    def test_params_are_checked(self):
        self.refused(self.body(png(INVOICE), text="x" * 20001), 422, "invalid-params")

    def test_two_images_are_refused(self):
        b = self.body(png(INVOICE))
        b["evidence"].append(obj_item("image", png("other"), "image/png", "b.png"))
        self.refused(b, 422, "wrong-evidence-slots")


class NotConfigured(Base):
    configured = False

    def test_no_transcriber_is_503_and_nothing_signed(self):
        out, calls = self.refused(self.body(png(INVOICE)), 503, "transcriber-not-configured")
        self.assertEqual(calls, 0)

    def test_methods_says_not_served(self):
        code, reg, _ = self.s.call("GET", "/v1/methods", key=None)
        m = [x for x in reg["methods"] if x["id"] == "match.image-text"][0]
        self.assertFalse(m["served"])
        self.assertEqual(m["models"], [])

    def test_from_env_is_none_without_the_list(self):
        from claim_witness import transcribe
        env = dict(self.env)
        del env["WITNESS_IMAGE_TEXT_MODELS_FILE"]
        self.assertIsNone(transcribe.from_env(env))


class Published(Base):
    def test_v1_methods_lists_it_with_the_prompt_and_the_models(self):
        code, reg, _ = self.s.call("GET", "/v1/methods", key=None)
        self.assertEqual(code, 200)
        m = [x for x in reg["methods"] if x["id"] == "match.image-text"][0]
        self.assertEqual(m["code_sha256"], reg["library"]["code_sha256"])
        self.assertTrue(m["pure"])
        self.assertTrue(m["served"])
        self.assertEqual(m["prompt_sha256"], PROMPT_SHA256)
        self.assertEqual(m["rule"], "R1")
        self.assertEqual(m["models"], [{"rank": 1, "id": SEED, "vendor": "bytedance-seed", "timeout_s": 5, "reasoning": False},
                                       {"rank": 2, "id": HAIKU, "vendor": "anthropic", "timeout_s": 5, "reasoning": False},
                                       {"rank": 3, "id": GEMMA, "vendor": "google", "timeout_s": 5}])

    def test_v1_price_lists_it(self):
        code, doc, _ = self.s.call("GET", "/v1/price", key=None)
        self.assertEqual(code, 200)
        it = doc["image_text"]
        self.assertEqual(it["method"], "match.image-text")
        self.assertEqual(it["credits"], 1)
        self.assertEqual([x["id"] for x in it["models"]], [SEED, HAIKU, GEMMA])
        self.assertIn("check", it["rule"])
        self.assertEqual(doc["check"], 1)


class OwnKey(Base):
    OWN = "sk-or-own-image-text-0123456789"

    def body(self, img, **kw):
        b = super().body(img, **kw)
        b["options"]["billing"] = "own-key"
        return b

    def test_the_users_key_transcribes_and_the_check_is_free(self):
        self.fake.accepted_keys.add(self.OWN)
        out, b = self.ok(self.body(png(INVOICE)), headers={"X-Witness-Model-Key": self.OWN})
        self.assertEqual(b["finding"], "consistent")
        self.assertEqual(self.fake.chat_requests()[-1]["authorization"], f"Bearer {self.OWN}")
        self.assertEqual(out["price"], {"credits": 0, "billing": "own-key", "lines": [{"item": "check", "credits": 0}]})
        self.assertNotIn(self.OWN, json.dumps(out))

    def test_a_key_refused_on_every_run_is_model_key_rejected(self):
        self.fake.key_answers[self.OWN] = (401, b'{"error": "bad key"}')
        code, out, _ = self.s.witness_call(self.body(png(INVOICE)), headers={"X-Witness-Model-Key": self.OWN})
        self.assertEqual((code, out["error"]), (422, "model-key-rejected"), out)


# ============================================================================================================ M5: library, verify
class Library(unittest.TestCase):
    def test_library_moves_to_1_10_0_and_ships_the_method(self):
        self.assertEqual(methods.LIBRARY_VERSION, "1.10.0")
        self.assertEqual(tarball.tarball_name(), "witness-methods-1.10.0.tar.gz")
        lib = verify._load_methods(tarball.build_methods_tarball())
        self.assertEqual(lib.get("match.image-text").version, "1.0.0")
        self.assertEqual(lib.match_image_text.PROMPT_SHA256, PROMPT_SHA256)

    def test_the_1_9_0_tarball_stays_archived_and_the_new_one_is_archived(self):
        idx = json.loads((pathlib.Path(tarball.__file__).parent / "methods_archive" / "index.json").read_text())
        by_sha = {e["sha256"]: e for e in idx["entries"]}
        self.assertEqual(by_sha["518c3fe1da5ade591d51fa27165526fcbb2428ea7c6fcc815ca8596967988140"]["library_version"], "1.9.0")
        self.assertEqual(by_sha[tarball.methods_code_sha256()]["library_version"], "1.10.0")


class Verify(Base):
    def files(self, out, img=None):
        d = pathlib.Path(tempfile.mkdtemp(prefix="cw-ns11-v-"))
        (d / "a.json").write_text(json.dumps(out))
        code, wk, _ = self.s.call("GET", "/.well-known/witness.json", key=None)
        (d / "keys.json").write_text(json.dumps(wk["key_list"]))
        (d / "m.tar.gz").write_bytes(tarball.build_methods_tarball())
        args = ["--envelope", str(d / "a.json"), "--keys", str(d / "keys.json"), "--methods", str(d / "m.tar.gz")]
        if img is not None:
            (d / "img.png").write_bytes(img)
            args += ["--evidence", str(d / "img.png")]
        return args

    def verify(self, args):
        buf = io.StringIO()
        rc = verify.main(args, out=buf)
        return rc, buf.getvalue()

    def test_verify_reruns_r1_and_passes(self):
        img = png(INVOICE)
        out, b = self.ok(self.body(img))
        rc, text = self.verify(self.files(out, img))
        self.assertEqual(rc, 0, text)
        self.assertIn("PASS transcription-sha256", text)
        self.assertIn("PASS transcription-prompt", text)
        self.assertIn("PASS method-rerun: match.image-text 1.0.0 re-ran R1 over the recorded transcription to consistent", text)
        self.assertIn("SKIP transcription-rerun", text)
        self.assertNotIn("FAIL", text)

    def test_verify_passes_a_not_supported_and_a_cannot_witness_record(self):
        out, b = self.ok(self.body(png(FORGED)))
        rc, text = self.verify(self.files(out))
        self.assertEqual(rc, 0, text)
        self.assertIn("re-ran R1 over the recorded transcription to differs", text)
        for mid in (SEED, HAIKU, GEMMA):
            self.fake.script(mid, fm.status(503))
        out, b = self.ok(self.body(png(INVOICE)))
        rc, text = self.verify(self.files(out))
        self.assertEqual(rc, 0, text)
        self.assertIn("re-ran R1 over the recorded transcription to model-unavailable", text)

    def view_of(self, b):
        return dict(b)

    def rerun(self, view):
        buf = io.StringIO()
        r = verify.Report(buf)
        verify.rerun(r, view, [], tarball.build_methods_tarball())
        return r.failed, buf.getvalue()

    def test_a_changed_transcription_or_verdict_fails(self):
        out, b = self.ok(self.body(png(INVOICE)))
        failed, text = self.rerun(b)
        self.assertFalse(failed, text)
        v = json.loads(json.dumps(b))
        v["judgment"]["transcription"] = FORGED  # its sha256 no longer matches
        failed, text = self.rerun(v)
        self.assertTrue(failed)
        self.assertIn("FAIL transcription-sha256", text)
        v = json.loads(json.dumps(b))
        v["judgment"]["transcription"] = FORGED
        v["judgment"]["transcription_sha256"] = hashlib.sha256(FORGED.encode()).hexdigest()  # consistent with itself, not R1
        failed, text = self.rerun(v)
        self.assertTrue(failed)
        self.assertIn("FAIL method-rerun", text)
        v = json.loads(json.dumps(b))
        v["judgment"]["missing_tokens"] = ["Harbour"]
        failed, text = self.rerun(v)
        self.assertTrue(failed)
        self.assertIn("missing_tokens", text)
        v = json.loads(json.dumps(b))
        v["judgment"]["prompt_sha256"] = "0" * 64
        failed, text = self.rerun(v)
        self.assertIn("FAIL transcription-prompt", text)
        v = json.loads(json.dumps(b))
        v["judgment"] = None
        failed, text = self.rerun(v)
        self.assertIn("FAIL method-rerun", text)

    def test_without_the_tarball_it_skips_naming_it(self):
        out, b = self.ok(self.body(png(INVOICE)))
        buf = io.StringIO()
        r = verify.Report(buf)
        verify.rerun(r, b, [], None)
        self.assertIn("SKIP method-rerun: no methods tarball given", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
