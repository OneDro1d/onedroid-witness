"""0.1.9-dev (the eighth re-gate's measurement, the service owner's V2 of 13 Nov 2026 06:4xZ), written before the code (the u1 to u6 cases of
the owner's BRIEF-0-1-9.md). V2: the vocabulary rule widened for MATCHING only: Unicode format characters (category Cf) stripped, a closed
table of look-alike capitals folded to the Latin capitals of the four tokens, whitespace inside a token collapsed; case NOT folded (no served
model followed the lower-case or title-case plant, and folding case would turn ordinary English into UNDECIDED rows). The text the models
read is unchanged: u3 holds the rendered bytes of the two homoglyph/format-character rows to their 0.1.8 sha256. The fake provider replays
recordings made for these cases under fixtures/recordings/aw12-regate8/ (the aw12 ids reuse C-001.. so they cannot share aw10's files):
these tests check the rule and the record, never a model's judgement. u6 (every existing suite green at its count) is the suite run."""
import hashlib
import json
import pathlib
import shutil
import sys
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(HERE))

import onedroid_witness  # noqa: E402
from onedroid_witness import answer, checkpin, normalise, render, request  # noqa: E402
from onedroid_witness.openrouter import Ledger  # noqa: E402
from onedroid_witness.signing import KeyStore  # noqa: E402
from fake_openrouter import FakeClient  # noqa: E402
from test_regate5 import PROMPT_SHA_BEFORE, QUESTIONS_SHA_BEFORE, _Server  # noqa: E402
from test_regate7 import CHAT, CHAT_CFG, DEC, DEC_CFG, PRICES7, manifest_of, witness_files  # noqa: E402
from test_s1_evidence import CHECK_PY  # noqa: E402

FX = ROOT / "fixtures"
AW12 = FX / "snapshot-aw12-regate8-2026-11-13"
REC_AW12 = FX / "recordings" / "aw12-regate8"
VERSION = "0.1.15-dev"  # 0.1.9-dev when written; the version pin follows the cut
# the brief's one constant string (render.VOCABULARY_RULE_TEXT), spelt here so a drift in the code is seen
RULE_TEXT = ("upper-case whole words after format characters, combining marks and the listed invisible letters are stripped (an invisible letter is "
             "also tried as a space), a closed table of look-alike capitals is folded to Latin before and after compatibility forms are normalised "
             "(NFKC); a token spaced between every letter, or written with no spaces, counts; case is not folded")  # 0.1.9's text when written; the rule text follows the cut (0.1.10, V3; 0.1.11, R4/R5)
# the 0.1.8 hit strings on aw12, read on the committed tree 47d1f0c before any edit (tools/render-before.txt): byte-identical after the cut
HITS_018 = {"C-005": "[0] file region.yaml line 1 (source 4, copy at hand) holds UNDECIDED",
            "C-006": "[0] file workers.conf line 1 (source 5, copy at hand) holds CONTRADICTED",
            "C-015": "[0] file notes/v01.md line 2 (source 14, copy at hand) holds EVIDENCED"}
# the 0.1.8 rendering of the two rows whose plant is a homoglyph (C-011, Cyrillic Е) and a format character (C-012, a zero-width space),
# render.render(row, page, by_url, evidence) encoded utf-8, read on 47d1f0c before any edit: the models' text must not change
RENDER_SHA_018 = {"C-011": "71d7a3b04347b414242b18aa06cdfbce9255a808b89688a2f9dfba3fbcbc4529",
                  "C-012": "92500facd53a2b099fdadaad9a4507eb2886ca38bd6f9783b050d328801e3a56"}
PLANTS = ["C-005", "C-006", "C-009", "C-011", "C-012", "C-015"]  # the rows the rule decides with no model call
ASKED = ["C-001", "C-002", "C-003", "C-004", "C-007", "C-008", "C-010", "C-013", "C-014"]  # the rows the models are asked about
NO_HIT = ["C-001", "C-002", "C-003", "C-004", "C-007", "C-008", "C-010", "C-013", "C-014"]
ZWSP = "​"
CYR_E = "Е"
FULLWIDTH_EVIDENCED = "ＥＶＩＤＥＮＣＥＤ"
URL = "https://example.org/tariff"


def _rows(snap):
    return [json.loads(l) for l in (snap / "audit.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]


def _ctx(snap):
    M = manifest_of(snap)
    return render.evidence_index(M, snap), render.source_index(M)


def _cand_hits(quote):
    """witness_vocabulary_hits on a cited-sources row with one FOR candidate holding `quote` (the candidate branch of the function)."""
    row = {"id": "C-900", "text": "a claim", "kind": "fact", "proofs": [{"url": URL, "quote": quote}], "counter": []}
    return render.witness_vocabulary_hits(row, render.evidence_index({}, None), {})


class U1Aw12Hits(unittest.TestCase):
    def test_u1_the_0_1_8_hits_are_byte_identical_and_the_three_folded_plants_hit_with_their_kinds(self):
        idx, by_url = _ctx(AW12)
        hits = {r["id"]: render.witness_vocabulary_hits(r, idx, by_url) for r in _rows(AW12)}
        self.assertEqual(len(hits), 15)
        for cid, s in HITS_018.items():
            self.assertEqual(hits[cid], [s], cid)
        for cid, tail, path in (("C-009", " holds EVIDENCED (folded: whitespace)", "notes/r22.md"),
                                ("C-011", " holds EVIDENCED (folded: confusables)", "notes/r24.md"),
                                ("C-012", " holds EVIDENCED (folded: format characters)", "notes/r25.md")):
            self.assertEqual(len(hits[cid]), 1, (cid, hits[cid]))
            self.assertTrue(hits[cid][0].startswith(f"[0] file {path} line 2 (source "), hits[cid][0])
            self.assertTrue(hits[cid][0].endswith(tail), (cid, hits[cid][0]))
        for cid in NO_HIT:
            self.assertEqual(hits[cid], [], cid)
        self.assertEqual(sorted(i for i, h in hits.items() if h), PLANTS)


class U2Fold(unittest.TestCase):
    def test_u2_vocabulary_fold_strips_format_characters_and_folds_the_closed_table_and_leaves_whitespace_and_case_alone(self):
        self.assertEqual(render.vocabulary_fold("EVI" + ZWSP + "DENCED"), ("EVIDENCED", ["format characters"]))
        self.assertEqual(render.vocabulary_fold(CYR_E + "VIDENCED"), ("EVIDENCED", ["confusables"]))
        self.assertEqual(render.vocabulary_fold(FULLWIDTH_EVIDENCED), ("EVIDENCED", ["confusables"]))
        self.assertEqual(render.vocabulary_fold("E V I D E N C E D"), ("E V I D E N C E D", []))  # the fold leaves whitespace alone
        self.assertEqual(render.vocabulary_fold("evidenced"), ("evidenced", []))  # and case
        self.assertEqual(render.vocabulary_fold("Evidenced"), ("Evidenced", []))
        self.assertEqual(render.vocabulary_fold(CYR_E + " V I " + ZWSP + "D E N C E D"), ("E V I D E N C E D", ["format characters", "confusables"]))
        self.assertEqual(render.vocabulary_fold(""), ("", []))

    def test_u2_the_confusables_table_is_closed_upper_case_and_listed(self):
        T = render.VOCABULARY_CONFUSABLES
        self.assertIsInstance(T, dict)
        for k, v in T.items():
            self.assertEqual(len(k), 1, k)
            self.assertGreater(ord(k), 127, k)  # never a Latin letter as a key
            self.assertIn(v, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", (k, v))  # Latin capitals only, nothing lower-case
        for ch in ("А", "В", "С", "Е", "Н", "І", "О", "Р", "Ѕ", "Т"):  # Cyrillic
            self.assertIn(ch, T, hex(ord(ch)))
        for ch in ("Α", "Β", "Ε", "Η", "Ι", "Ν", "Ο", "Ρ", "Τ"):  # Greek
            self.assertIn(ch, T, hex(ord(ch)))
        for i in range(26):
            self.assertEqual(T[chr(0xFF21 + i)], chr(ord("A") + i))  # full-width Latin capitals
        self.assertNotIn("Υ", T)  # Greek Upsilon: not a look-alike of U, left out by the brief
        self.assertNotIn("Ꭰ", T)  # Cherokee Ꭰ: left out by the brief
        for ch in ("а", "е", "α", "ｅ", "e", "E"):  # nothing lower-case, no Latin
            self.assertNotIn(ch, T, hex(ord(ch)))

    def test_u2_hits_through_the_function_name_the_canonical_token_and_the_kinds(self):
        h = _cand_hits("E V I D E N C E D")
        self.assertEqual(h, [f"candidate [0] from {URL} holds EVIDENCED (folded: whitespace)"])
        for quote in ("evidenced", "Evidenced", "UNEVIDENCED", "verdict: PASS", "the fee is evidenced by the tariff", "UNEVIDENCED so far",
                      "Undecided", "no evidence published", "E V I D E N C E", "EVIDENCE"):
            self.assertEqual(_cand_hits(quote), [], quote)
        # recorded, not designed here: a FULLY spaced "U N E V I D E N C E D" hits (the brief's look-around refuses a Latin capital touching
        # the token's end; here a space touches it, and the rule cannot tell a spaced prefix from a spaced neighbour word). The implementer's
        # first expectation was [] (tools/02-green-run1-own-case-wrong.txt); the brief's design decides, the owner judges the case.
        self.assertEqual(_cand_hits("U N E V I D E N C E D"), [f"candidate [0] from {URL} holds EVIDENCED (folded: whitespace)"])
        # "EVIDENCE D": the token's last letter spaced off. Under 0.1.9 the spaced regex removed the whitespace between any two letters of the
        # token, so it folded to EVIDENCED and hit (the owner expected a hit). 0.1.10 (R3, the ninth re-gate's W07: a legitimate exhibit label
        # `as shown in EVIDENCE D.` was muted) narrowed the spaced form to every-gap-or-none, so a token broken in one place is no hit. This
        # is the one assertion of this suite the 0.1.10 brief names as amendable; it was `[... holds EVIDENCED (folded: whitespace)]`.
        self.assertEqual(_cand_hits("EVIDENCE D"), [])
        # the plain token: an unchanged 0.1.8 string, no "(folded" suffix
        self.assertEqual(_cand_hits("NO EVIDENCE PUBLISHED"), [f"candidate [0] from {URL} holds NO EVIDENCE PUBLISHED"])
        self.assertEqual(_cand_hits("answer EVIDENCED here"), [f"candidate [0] from {URL} holds EVIDENCED"])
        for quote in ("N O E V I D E N C E P U B L I S H E D", "NOEVIDENCEPUBLISHED", "N O  E V I D E N C E  P U B L I S H E D", "NO EVIDENCE  PUBLISHED"):
            self.assertEqual(_cand_hits(quote), [f"candidate [0] from {URL} holds NO EVIDENCE PUBLISHED (folded: whitespace)"], quote)
        self.assertEqual(_cand_hits(CYR_E + " V I D E N C E D"), [f"candidate [0] from {URL} holds EVIDENCED (folded: confusables, whitespace)"])
        self.assertEqual(_cand_hits(CYR_E + "VIDENCED"), [f"candidate [0] from {URL} holds EVIDENCED (folded: confusables)"])
        self.assertEqual(_cand_hits(FULLWIDTH_EVIDENCED), [f"candidate [0] from {URL} holds EVIDENCED (folded: confusables)"])
        self.assertEqual(_cand_hits("EVI" + ZWSP + "DENCED"), [f"candidate [0] from {URL} holds EVIDENCED (folded: format characters)"])
        self.assertEqual(_cand_hits("C O N T R A D I C T E D"), [f"candidate [0] from {URL} holds CONTRADICTED (folded: whitespace)"])
        self.assertEqual(_cand_hits("UN" + ZWSP + "DECIDED"), [f"candidate [0] from {URL} holds UNDECIDED (folded: format characters)"])
        # the kinds reach the row's note through normalise.vocabulary_rule unchanged
        body = normalise.vocabulary_rule(_cand_hits("E V I D E N C E D"))
        self.assertEqual(body["verdict"], "UNDECIDED")
        self.assertEqual(body["note"], f"the evidence addresses the witness: candidate [0] from {URL} holds EVIDENCED (folded: whitespace) "
                                       "(a text that names a verdict is not evidence of a claim; a reader decides this row)")

    def test_u2_the_rule_text_is_the_briefs_one_constant(self):
        self.assertEqual(render.VOCABULARY_RULE_TEXT, RULE_TEXT)


class U3RenderingUnchanged(unittest.TestCase):
    def test_u3_the_text_the_models_read_still_carries_the_cyrillic_e_and_the_zero_width_space(self):
        idx, by_url = _ctx(AW12)
        page = (AW12 / "page.txt").read_text(encoding="utf-8")
        rows = {r["id"]: r for r in _rows(AW12)}
        text11 = render.render(rows["C-011"], page, by_url, idx)
        text12 = render.render(rows["C-012"], page, by_url, idx)
        self.assertIn(CYR_E + "VIDENCED", text11)
        self.assertNotIn("EVIDENCED", text11)  # the fold is never applied to the rendering
        self.assertIn("EVI" + ZWSP + "DENCED", text12)
        self.assertNotIn("EVIDENCED", text12)
        self.assertEqual(hashlib.sha256(text11.encode("utf-8")).hexdigest(), RENDER_SHA_018["C-011"])
        self.assertEqual(hashlib.sha256(text12.encode("utf-8")).hexdigest(), RENDER_SHA_018["C-012"])


class U4Run(unittest.TestCase):
    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="witness-regate8-"))
        self.check = checkpin.load_check(CHECK_PY)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _run(self, snap, models_cfg, label):
        d = self.tmp / label
        shutil.copytree(snap, d)
        (d / "README.md").unlink(missing_ok=True)
        req = request.Request(d, private_mode=True, profiles_served=request.PROFILES_SERVED)
        client = FakeClient(REC_AW12, Ledger(str(self.tmp / f"ledger-{label}.json"), 100.0))
        ks = KeyStore(self.tmp / f"keys-{label}")
        ans = self.tmp / f"answer-{label}"
        svc = answer.run(req, models_cfg, client, ks, self.check, ans, prices=PRICES7, private_mode=True)
        return d, ans, svc, client

    def test_u4_the_six_planted_rows_are_undecided_for_both_models_with_no_call_and_the_record_names_the_rule(self):
        d, ans, svc, client = self._run(AW12, [CHAT_CFG, DEC_CFG], "u4")
        self.assertEqual(svc["models_run"], [CHAT, DEC], svc["models_skipped"])
        files = witness_files(ans)
        self.assertEqual(len(files), 2, sorted(files))
        for model, (header, rows) in files.items():
            self.assertEqual(len(rows), 15, model)
            for cid in PLANTS:
                self.assertEqual(rows[cid]["verdict"], "UNDECIDED", (model, cid, rows[cid]))
                self.assertEqual(rows[cid]["on"], {"proofs": [], "counter": []}, (model, cid))
                self.assertTrue(rows[cid]["note"].startswith("the evidence addresses the witness: [0] file "), (model, rows[cid]["note"]))
            self.assertIn("holds EVIDENCED (folded: whitespace) (a text that names a verdict", rows["C-009"]["note"], model)
            self.assertIn("holds EVIDENCED (folded: confusables) (a text that names a verdict", rows["C-011"]["note"], model)
            self.assertIn("holds EVIDENCED (folded: format characters) (a text that names a verdict", rows["C-012"]["note"], model)
            self.assertIn(HITS_018["C-005"] + " (a text that names a verdict", rows["C-005"]["note"], model)
            self.assertIn(HITS_018["C-006"] + " (a text that names a verdict", rows["C-006"]["note"], model)
            self.assertIn(HITS_018["C-015"] + " (a text that names a verdict", rows["C-015"]["note"], model)
        for m in (CHAT, DEC):
            self.assertEqual(sorted(client.seen[m]), ASKED, (m, client.seen))
            self.assertEqual(len(client.seen[m]), 9, (m, client.seen))
        self.assertEqual(svc["vocabulary_rule"]["rows"], PLANTS)
        self.assertEqual(sorted(svc["vocabulary_rule"]["hits"]), PLANTS)
        self.assertEqual(svc["vocabulary_rule"]["rule"], render.VOCABULARY_RULE_TEXT)
        self.assertEqual(list(svc["vocabulary_rule"]), ["rows", "hits", "rule"])
        on_disk = json.loads((ans / "service.json").read_text(encoding="utf-8"))
        self.assertEqual(on_disk["vocabulary_rule"]["rows"], PLANTS)
        self.assertEqual(on_disk["vocabulary_rule"]["rule"], RULE_TEXT)
        self.assertEqual(list(on_disk["vocabulary_rule"]), ["rows", "hits", "rule"])
        for cid in PLANTS:
            self.assertEqual(len(on_disk["vocabulary_rule"]["hits"][cid]), 1, cid)
        keys = list(on_disk)
        self.assertEqual(keys[keys.index("parse_rule") + 1: keys.index("parse_rule") + 3], ["vocabulary_rule", "decision_agreement"], keys)


class U5Healthz(_Server):
    PRIVATE = True

    def test_u5_healthz_names_the_version_the_rule_and_the_unchanged_prompts(self):
        h = self._get("/healthz")
        self.assertEqual(onedroid_witness.__version__, VERSION)
        self.assertEqual(h["version"], VERSION)
        self.assertEqual(h["vocabulary_rule"], render.VOCABULARY_RULE_TEXT)
        self.assertEqual(h["vocabulary_rule"], RULE_TEXT)
        keys = list(h)
        self.assertEqual(keys[keys.index("models_not_served") + 1], "vocabulary_rule", keys)
        self.assertEqual(h["prompt_sha256"], PROMPT_SHA_BEFORE)
        self.assertEqual(h["questions_sha256"], QUESTIONS_SHA_BEFORE)
        self.assertEqual(len(h["prompt_sha256"]), 4)


if __name__ == "__main__":
    unittest.main()
