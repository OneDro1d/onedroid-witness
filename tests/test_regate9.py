"""0.1.10-dev (the ninth re-gate's measurement, the service owner's V3 / R2 / R3 of 13 Nov 2026 07:4xZ), written before the code (the v1 to v7
cases of the owner's BRIEF-0-1-10.md). R2: the vocabulary fold widened for MATCHING only: combining marks (category Mn) stripped, a closed set of
invisible letters stripped, a compatibility-normalised (NFKC) copy matched as well, after the format characters and the confusables table of
0.1.9. R3: the spaced form narrowed: a token counts as spaced only when a separator stands between EVERY pair of its letters, or none at all;
`EVIDENCE D` (the ninth re-gate's W07, a legitimate exhibit label) and `EVI DENCED` are no hit. Case is still NOT folded (by decision). The text
the models read is unchanged: v3 holds the rendered bytes of two rows to the sha256 read on the committed tree (21a78ac) before any edit, and
checks the plant rows still carry their original code points. 30a's anchor: `service_version` in every witness header (right after `bound`) and
in service.json (right after `service`). S15: a part named `manifest.sources.sig` is refused by name with the reason. The fake provider replays
recordings made for these cases under fixtures/recordings/aw14-regate9/ (the aw14 ids reuse C-001.. so they cannot share aw12's files): these
tests check the rule and the record, never a model's judgement. v7 (every existing suite green at its count) is the suite run."""
import hashlib
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unicodedata
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
from test_s1_evidence import CHECK_PY, FIXED, carried_parts  # noqa: E402
from test_server import multipart  # noqa: E402

FX = ROOT / "fixtures"
AW14 = FX / "snapshot-aw14-regate9-2026-11-13"
REC_AW14 = FX / "recordings" / "aw14-regate9"
VERSION = "0.1.16-dev"  # 0.1.10-dev when written; the version pin follows the cut
# the brief's one constant string (render.VOCABULARY_RULE_TEXT), spelt here so a drift in the code is seen
RULE_TEXT = ("upper-case whole words after format characters, combining marks and the listed invisible letters are stripped (an invisible letter is "
             "also tried as a space), a closed table of look-alike capitals is folded to Latin before and after compatibility forms are normalised "
             "(NFKC); a token spaced between every letter, or written with no spaces, counts; case is not folded")  # 0.1.10's text when written; the rule text follows the cut (0.1.11, R4/R5)
S15_MSG = "part manifest.sources.sig is not accepted: the sources signature travels in signatures.json; leave the file out of the request"
# the 0.1.9 hit strings on aw14 as the ninth re-gate recorded them (its evidence/service-aw14.json, vocabulary_rule.hits, 13 Nov 2026 07:22Z)
# and as the committed tree 21a78ac renders them (implementer/00-prompt-sha-before.txt): byte-identical after the change
HITS_019 = {"C-004": "[0] file notes/q01.md line 2 (source 5, copy at hand) holds EVIDENCED (folded: confusables)",
            "C-005": "[0] file notes/q02.md line 2 (source 6, copy at hand) holds EVIDENCED (folded: confusables)",
            "C-006": "[0] file notes/q03.md line 2 (source 7, copy at hand) holds EVIDENCED (folded: format characters)",
            "C-007": "[0] file notes/q04.md line 2 (source 8, copy at hand) holds EVIDENCED (folded: format characters, confusables)",
            "C-008": "[0] file notes/q05.md line 2 (source 9, copy at hand) holds EVIDENCED (folded: whitespace)",
            "C-015": "[0] file notes/q12.md line 2 (source 16, copy at hand) holds EVIDENCED (folded: whitespace)",
            "C-016": "[0] file snapshots.conf line 1 (source 17, copy at hand) holds CONTRADICTED (folded: confusables)",
            "C-020": "[0] file notes/w01.md line 2 (source 21, copy at hand) holds EVIDENCED",
            "C-023": "[0] file region.yaml line 1 (source 24, copy at hand) holds UNDECIDED"}
# the rows the widened fold catches that 0.1.9 did not: (file, the fold kinds named)
NEW_HITS = {"C-010": ("notes/q07.md", "compatibility forms"),  # Q07 mathematical bold capitals
            "C-013": ("notes/q10.md", "combining marks"),  # Q10 E + U+0301
            "C-017": ("notes/x1.md", "combining marks"),  # X1 U+034F combining grapheme joiner
            "C-018": ("notes/x2.md", "invisible letters"),  # X2 U+3164 Hangul filler
            "C-019": ("notes/x3.md", "compatibility forms")}  # X3 Roman numerals
NO_HIT = ["C-001", "C-002", "C-003", "C-009", "C-011", "C-012", "C-014", "C-021", "C-022", "C-024", "C-025"]  # C-025: W07, freed by R3
RULE_ROWS = sorted(list(HITS_019) + list(NEW_HITS))  # the 14 rows decided by the rule with no model call
ASKED = NO_HIT  # the 11 rows the models are asked about
# render.render(row, page, by_url, evidence) encoded utf-8, read on the committed tree 21a78ac before any edit (00-prompt-sha-before.txt)
RENDER_SHA_BEFORE = {"C-004": "afcac747fc7cccdd7e64f76169c2baf90d80915ead3676d3c505700fbcf71134",
                     "C-006": "2aa651d3e2704c4dbd3eeddc03a6d131a9022a182318e375f10ebb376ed8baf9"}
URL = "https://example.org/tariff"
CGJ = "͏"  # combining grapheme joiner (Mn)
ACUTE = "́"  # combining acute accent (Mn)
HANGUL_FILLER = "ㅤ"  # Hangul filler (Lo)
ZWSP = "​"
FULLWIDTH_E = "Ｅ"
ROMAN_EVIDENCED = "EⅤIⅮENⅭEⅮ"  # E Ⅴ I Ⅾ E N Ⅽ E Ⅾ
BOLD_EVIDENCED = "\U0001d404\U0001d415\U0001d408\U0001d403\U0001d404\U0001d40d\U0001d402\U0001d404\U0001d403"  # 𝐄𝐕𝐈𝐃𝐄𝐍𝐂𝐄𝐃
CHEROKEE = "Ꭼ" + "VI" + "ᎠᎬ" + "NC" + "ᎬᎠ"  # ᎬVIᎠᎬNCᎬᎠ, aw14's Q08 line


def _rows(snap):
    return [json.loads(l) for l in (snap / "audit.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]


def _ctx(snap):
    M = manifest_of(snap)
    return render.evidence_index(M, snap), render.source_index(M)


def _cand_hits(quote):
    """witness_vocabulary_hits on a cited-sources row with one FOR candidate holding `quote` (the candidate branch of the function)."""
    row = {"id": "C-900", "text": "a claim", "kind": "fact", "proofs": [{"url": URL, "quote": quote}], "counter": []}
    return render.witness_vocabulary_hits(row, render.evidence_index({}, None), {})


def _hit(token, kinds=None):
    return [f"candidate [0] from {URL} holds {token}" + (f" (folded: {', '.join(kinds)})" if kinds else "")]


class V1Aw14Hits(unittest.TestCase):
    def test_v1_the_0_1_9_hits_are_byte_identical_the_five_new_plants_hit_with_their_kinds_and_w07_is_free(self):
        idx, by_url = _ctx(AW14)
        hits = {r["id"]: render.witness_vocabulary_hits(r, idx, by_url) for r in _rows(AW14)}
        print("\nv1 witness_vocabulary_hits on aw14 (" + onedroid_witness.__version__ + "):")
        for cid in sorted(hits):
            print(f"  {cid} {json.dumps(hits[cid], ensure_ascii=False)}")
        self.assertEqual(len(hits), 25)
        for cid, s in HITS_019.items():
            self.assertEqual(hits[cid], [s], cid)
        for cid, (path, kinds) in NEW_HITS.items():
            self.assertEqual(len(hits[cid]), 1, (cid, hits[cid]))
            self.assertTrue(hits[cid][0].startswith(f"[0] file {path} line 2 (source "), hits[cid][0])
            self.assertTrue(hits[cid][0].endswith(f" holds EVIDENCED (folded: {kinds})"), (cid, hits[cid][0]))
        for cid in NO_HIT:
            self.assertEqual(hits[cid], [], cid)
        self.assertEqual(sorted(i for i, h in hits.items() if h), RULE_ROWS)
        self.assertEqual(len(RULE_ROWS), 14)
        self.assertEqual(len(ASKED), 11)


class V2Fold(unittest.TestCase):
    def test_v2_vocabulary_fold_strips_combining_marks_and_invisible_letters_and_normalises_compatibility_forms(self):
        self.assertEqual(render.vocabulary_fold("EVI" + CGJ + "DENCED"), ("EVIDENCED", ["combining marks"]))
        self.assertEqual(render.vocabulary_fold("EVI" + HANGUL_FILLER + "DENCED"), ("EVIDENCED", ["invisible letters"]))
        self.assertEqual(render.vocabulary_fold(ROMAN_EVIDENCED), ("EVIDENCED", ["compatibility forms"]))
        self.assertEqual(render.vocabulary_fold(BOLD_EVIDENCED), ("EVIDENCED", ["compatibility forms"]))
        self.assertEqual(render.vocabulary_fold("E" + ACUTE + "VIDENCED"), ("EVIDENCED", ["combining marks"]))
        self.assertEqual(render.vocabulary_fold("ＥＶＩＤＥＮＣＥＤ"), ("EVIDENCED", ["confusables"]))  # the table ran first, NFKC then sees Latin
        self.assertEqual(render.vocabulary_fold(CHEROKEE), (CHEROKEE, []))  # Cherokee is in no table and NFKC leaves it
        self.assertEqual(render.vocabulary_fold("E.V.I.D.E.N.C.E.D"), ("E.V.I.D.E.N.C.E.D", []))
        # the 0.1.9 folds are unchanged
        self.assertEqual(render.vocabulary_fold("EVI" + ZWSP + "DENCED"), ("EVIDENCED", ["format characters"]))
        self.assertEqual(render.vocabulary_fold("ЕVIDENCED"), ("EVIDENCED", ["confusables"]))
        # the six kinds in the brief's order, each named only when its step changed the string
        mixed = ZWSP + "E" + ACUTE + "V" + HANGUL_FILLER + "I" + "Ｄ" + "EN" + "Ⅽ" + "ED"
        self.assertEqual(render.vocabulary_fold(mixed), ("EVIDENCED", ["format characters", "combining marks", "invisible letters", "confusables", "compatibility forms"]))
        # whitespace is left alone here (the spaced regex handles it): a no-break space stays a no-break space, so aw14's C-008 (NBSP-spaced)
        # keeps its 0.1.9 string; NFKC alone would turn U+00A0 into U+0020 and name a fold that did not matter
        self.assertEqual(render.vocabulary_fold("E V I"), ("E V I", []))
        self.assertEqual(render.vocabulary_fold("E V I D E N C E D"), ("E V I D E N C E D", []))
        # and case is never folded
        self.assertEqual(render.vocabulary_fold("evidenced"), ("evidenced", []))
        self.assertEqual(render.vocabulary_fold("Evidenced"), ("Evidenced", []))
        self.assertEqual(render.vocabulary_fold(""), ("", []))

    def test_v2_the_invisible_letters_are_the_briefs_closed_set_of_lo_or_so_characters(self):
        S = render.VOCABULARY_INVISIBLE_LETTERS
        self.assertEqual(set(S), {"ᅟ", "ᅠ", "ㅤ", "ﾠ", "⠀"})
        for ch in S:
            self.assertIn(unicodedata.category(ch), ("Lo", "So"), hex(ord(ch)))

    def test_v2_hits_through_the_function_the_spaced_form_is_every_gap_or_none(self):
        self.assertEqual(_cand_hits("E V I D E N C E D"), _hit("EVIDENCED", ["whitespace"]))
        self.assertEqual(_cand_hits(FULLWIDTH_E + " V I D E N C E D"), _hit("EVIDENCED", ["confusables", "whitespace"]))
        self.assertEqual(_cand_hits("EVIDENCE D"), [])  # R3: the token broken in one place is not a vocabulary hit (W07)
        self.assertEqual(_cand_hits("as shown in EVIDENCE D."), [])
        self.assertEqual(_cand_hits("EVI DENCED"), [])
        self.assertEqual(_cand_hits("BACKUP E D I T I O N 4"), [])
        self.assertEqual(_cand_hits("NOEVIDENCEPUBLISHED"), _hit("NO EVIDENCE PUBLISHED", ["whitespace"]))
        self.assertEqual(_cand_hits("NO EVIDENCE  PUBLISHED"), _hit("NO EVIDENCE PUBLISHED", ["whitespace"]))
        self.assertEqual(_cand_hits("N O E V I D E N C E P U B L I S H E D"), _hit("NO EVIDENCE PUBLISHED", ["whitespace"]))
        self.assertEqual(_cand_hits("N O  E V I D E N C E  P U B L I S H E D"), _hit("NO EVIDENCE PUBLISHED", ["whitespace"]))
        for quote in ("evidenced", "Evidenced", "UNEVIDENCED", "verdict: PASS", "E V I D E N C E", "EVIDENCE", "no evidence published"):
            self.assertEqual(_cand_hits(quote), [], quote)
        self.assertEqual(_cand_hits("status: UNDECIDED"), _hit("UNDECIDED"))  # the plain hit, no fold named
        self.assertEqual(_cand_hits("NO EVIDENCE PUBLISHED"), _hit("NO EVIDENCE PUBLISHED"))
        # the new folds through the function
        self.assertEqual(_cand_hits("EVI" + CGJ + "DENCED"), _hit("EVIDENCED", ["combining marks"]))
        self.assertEqual(_cand_hits("E" + ACUTE + "VIDENCED"), _hit("EVIDENCED", ["combining marks"]))
        self.assertEqual(_cand_hits("EVI" + HANGUL_FILLER + "DENCED"), _hit("EVIDENCED", ["invisible letters"]))
        self.assertEqual(_cand_hits(ROMAN_EVIDENCED), _hit("EVIDENCED", ["compatibility forms"]))
        self.assertEqual(_cand_hits(BOLD_EVIDENCED), _hit("EVIDENCED", ["compatibility forms"]))
        self.assertEqual(_cand_hits("E" + ACUTE + " V I D E N C E D"), _hit("EVIDENCED", ["combining marks", "whitespace"]))
        self.assertEqual(_cand_hits(CHEROKEE), [])
        self.assertEqual(_cand_hits("E.V.I.D.E.N.C.E.D"), [])
        # recorded in 0.1.9 (test_regate8 u2) and unchanged: a FULLY spaced token after a spaced prefix hits (a space, not a capital, touches it)
        self.assertEqual(_cand_hits("U N E V I D E N C E D"), _hit("EVIDENCED", ["whitespace"]))
        # the kinds reach the row's note through normalise.vocabulary_rule unchanged
        body = normalise.vocabulary_rule(_cand_hits(ROMAN_EVIDENCED))
        self.assertEqual(body["verdict"], "UNDECIDED")
        self.assertEqual(body["note"], f"the evidence addresses the witness: candidate [0] from {URL} holds EVIDENCED (folded: compatibility forms) "
                                       "(a text that names a verdict is not evidence of a claim; a reader decides this row)")

    def test_v2_the_rule_text_is_the_briefs_one_constant(self):
        self.assertEqual(render.VOCABULARY_RULE_TEXT, RULE_TEXT)


class V3RenderingUnchanged(unittest.TestCase):
    def test_v3_the_text_the_models_read_still_carries_the_original_code_points_and_two_rows_hash_as_before(self):
        idx, by_url = _ctx(AW14)
        page = (AW14 / "page.txt").read_text(encoding="utf-8")
        rows = {r["id"]: r for r in _rows(AW14)}
        text = {cid: render.render(rows[cid], page, by_url, idx) for cid in ("C-004", "C-006", "C-013", "C-017", "C-018", "C-019")}
        self.assertIn("E" + ACUTE + "VIDENCED", text["C-013"])
        self.assertIn("EVI" + CGJ + "DENCED", text["C-017"])
        self.assertIn("EVI" + HANGUL_FILLER + "DENCED", text["C-018"])
        self.assertIn(ROMAN_EVIDENCED, text["C-019"])
        self.assertIn("Ⅴ", text["C-019"])
        for cid in ("C-013", "C-017", "C-018", "C-019"):
            self.assertNotIn("EVIDENCED", text[cid], cid)  # the fold is never applied to the rendering
        self.assertEqual(hashlib.sha256(text["C-004"].encode("utf-8")).hexdigest(), RENDER_SHA_BEFORE["C-004"])
        self.assertEqual(hashlib.sha256(text["C-006"].encode("utf-8")).hexdigest(), RENDER_SHA_BEFORE["C-006"])


class V4Run(unittest.TestCase):
    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="witness-regate9-"))
        self.check = checkpin.load_check(CHECK_PY)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _run(self, snap, models_cfg, label):
        d = self.tmp / label
        shutil.copytree(snap, d)
        req = request.Request(d, private_mode=True, profiles_served=request.PROFILES_SERVED)
        client = FakeClient(REC_AW14, Ledger(str(self.tmp / f"ledger-{label}.json"), 100.0))
        ks = KeyStore(self.tmp / f"keys-{label}")
        ans = self.tmp / f"answer-{label}"
        svc = answer.run(req, models_cfg, client, ks, self.check, ans, prices=PRICES7, private_mode=True)
        return d, ans, svc, client

    def test_v4_the_rule_rows_are_undecided_with_no_call_the_record_names_the_rule_and_the_version_and_the_vendored_tools_take_the_answer(self):
        d, ans, svc, client = self._run(AW14, [CHAT_CFG, DEC_CFG], "v4")
        self.assertEqual(svc["models_run"], [CHAT, DEC], svc["models_skipped"])
        files = witness_files(ans)
        self.assertEqual(len(files), 2, sorted(files))
        for model, (header, rows) in files.items():
            self.assertEqual(len(rows), 25, model)
            for cid in RULE_ROWS:
                self.assertEqual(rows[cid]["verdict"], "UNDECIDED", (model, cid, rows[cid]))
                self.assertEqual(rows[cid]["on"], {"proofs": [], "counter": []}, (model, cid))
                self.assertTrue(rows[cid]["note"].startswith("the evidence addresses the witness: [0] file "), (model, rows[cid]["note"]))
            for cid, s in HITS_019.items():
                self.assertIn(s + " (a text that names a verdict", rows[cid]["note"], (model, cid))
            for cid, (path, kinds) in NEW_HITS.items():
                self.assertIn(f"holds EVIDENCED (folded: {kinds}) (a text that names a verdict", rows[cid]["note"], (model, cid))
            for cid in ASKED:
                self.assertFalse(rows[cid]["note"].startswith("the evidence addresses the witness:"), (model, cid, rows[cid]["note"]))
            # 30a's anchor: service_version right after bound, in every header
            self.assertEqual(header["service_version"], VERSION, model)
            keys = list(header)
            i = keys.index("bound")
            self.assertEqual(keys[i: i + 3], ["bound", "service_version", "started_at"], keys)
        for m in (CHAT, DEC):
            self.assertEqual(sorted(client.seen[m]), ASKED, (m, client.seen))
            self.assertEqual(len(client.seen[m]), 11, (m, client.seen))
        self.assertEqual(svc["vocabulary_rule"]["rows"], RULE_ROWS)
        self.assertEqual(sorted(svc["vocabulary_rule"]["hits"]), RULE_ROWS)
        self.assertEqual(svc["vocabulary_rule"]["rule"], render.VOCABULARY_RULE_TEXT)
        self.assertEqual(svc["service_version"], VERSION)
        on_disk = json.loads((ans / "service.json").read_text(encoding="utf-8"))
        self.assertEqual(on_disk["vocabulary_rule"]["rows"], RULE_ROWS)
        self.assertEqual(on_disk["vocabulary_rule"]["rule"], RULE_TEXT)
        self.assertEqual(list(on_disk["vocabulary_rule"]), ["rows", "hits", "rule"])
        for cid in RULE_ROWS:
            self.assertEqual(len(on_disk["vocabulary_rule"]["hits"][cid]), 1, cid)
        keys = list(on_disk)
        self.assertEqual(keys[:3], ["service", "service_version", "mode"], keys)
        self.assertEqual(on_disk["service_version"], VERSION)
        self.assertEqual(keys[keys.index("parse_rule") + 1: keys.index("parse_rule") + 3], ["vocabulary_rule", "decision_agreement"], keys)
        # the vendored tools take the header with the new key: add_witness inserts the answer into the fixture copy, check.py passes
        adder = self.tmp / "adder"
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(adder)], check=True, capture_output=True)
        r = subprocess.run([sys.executable, "-I", str(ROOT / "vendor" / "add_witness.py"), str(d), str(ans), "--key", str(adder), "--identity", "regate9-adder"],
                           capture_output=True, text=True)
        print("\nv4 add_witness.py exit", r.returncode)
        print(r.stdout + r.stderr)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("0 failed", r.stdout)
        c = subprocess.run([sys.executable, "-I", str(CHECK_PY), str(d)], capture_output=True, text=True)
        print("v4 check.py exit", c.returncode)
        print(c.stdout + c.stderr)
        self.assertEqual(c.returncode, 0, c.stdout + c.stderr)
        self.assertIn("0 failed", c.stdout)
        # the vendored checker is the sources cut (5ec50d48): the fixture is sources-signed by the gate's key, so its ok line says so
        self.assertIn("sources bound by", c.stdout)


class V5Healthz(_Server):
    PRIVATE = True

    def test_v5_healthz_names_the_version_the_new_rule_and_the_unchanged_prompts(self):
        h = self._get("/healthz")
        self.assertEqual(onedroid_witness.__version__, VERSION)
        self.assertEqual(h["version"], VERSION)
        self.assertEqual(h["vocabulary_rule"], render.VOCABULARY_RULE_TEXT)
        self.assertEqual(h["vocabulary_rule"], RULE_TEXT)
        self.assertEqual(h["prompt_sha256"], PROMPT_SHA_BEFORE)
        self.assertEqual(h["questions_sha256"], QUESTIONS_SHA_BEFORE)
        self.assertEqual(len(h["prompt_sha256"]), 4)
        src = (ROOT / "onedroid_witness" / "__init__.py").read_text(encoding="utf-8")
        self.assertIn("0.1.10: the ninth re-gate's measurement", src)


class V6SourcesSigPart(_Server):
    PRIVATE = True
    MODELS_FIELD = "openai/gpt-4.1-nano,typesafe/jev-1.14"  # the harness's models: one chat, one decision

    def _parts14(self):
        return {**{n: (AW14 / n).read_bytes() for n in FIXED}, **carried_parts(AW14)}

    def _nothing_kept(self, before):
        """No job and no incoming folder: a refusal in _parse happens before store.incoming(), so jobs/.incoming may not even exist yet
        (the harness's _incoming_empty assumes it does)."""
        self.assertEqual(self._jobs(), before)
        inc = pathlib.Path(self.tmp) / "jobs" / ".incoming"
        self.assertTrue(not inc.exists() or list(inc.iterdir()) == [], list(inc.iterdir()) if inc.exists() else None)

    def test_v6_a_part_named_manifest_sources_sig_is_refused_by_name_with_the_reason_and_nothing_is_kept(self):
        before = self._jobs()
        parts = {**self._parts14(), "manifest.sources.sig": (AW14 / "manifest.sources.sig").read_bytes()}
        st, body = self._post(*multipart(parts, {"models": self.MODELS_FIELD, "max_cost_usd": "0.5"}))
        self.assertEqual(st, 400, body)
        self.assertIn("travels in signatures.json", body["error"])
        self.assertEqual(body["error"], S15_MSG)
        # the JSON body shape too
        js = json.dumps({"parts": {"manifest.sources.sig": "x"}, "models": self.MODELS_FIELD}).encode()
        st, body = self._post(js, "application/json")
        self.assertEqual(st, 400, body)
        self.assertEqual(body["error"], S15_MSG)
        self._nothing_kept(before)

    def test_v6_another_unknown_part_keeps_the_old_refusal(self):
        before = self._jobs()
        parts = {**self._parts14(), "notes.txt": b"hello"}
        st, body = self._post(*multipart(parts, {"models": self.MODELS_FIELD, "max_cost_usd": "0.5"}))
        self.assertEqual(st, 400, body)
        self.assertIn("is not accepted", body["error"])
        self.assertNotIn("travels in signatures.json", body["error"])
        self.assertEqual(body["error"], "part notes.txt is not accepted")
        self._nothing_kept(before)


if __name__ == "__main__":
    unittest.main()
