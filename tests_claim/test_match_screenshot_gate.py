"""match.screenshot readability gate (DECISIONS BD19 addendum). An image Tesseract cannot really read gets no finding
(`unreadable`) instead of a low similarity: the OCR text of a half-size full page scored 1343 bp against its own page, which
had forced F down to 1200 and made every one-sentence forgery "no finding". The gate is a property of the image's OCR only
(the mean word confidence of Tesseract's TSV output, x100), so it cannot be tuned per claim; with it F can sit just under the
honest screenshots that pass it.

The table is tests_claim/fixtures/calibration/screenshots2/measured_gate.json, measured INSIDE the live claim-witness image by
measure_gate.py (pod claim-screenshot-cal3, pod log next to it): for every image of the widened set and the regression fixture,
the readability values and the similarity. These tests hold the constants (T, F, G) to it, and test the gate itself."""
import hashlib
import importlib.util
import json
import pathlib
import unittest

from claim_witness import methods, ocr
from claim_witness.methods import match_screenshot
from tests_claim.test_match_screenshot import PARAS, Base, fake_tesseract, image

SET = pathlib.Path(__file__).resolve().parent / "fixtures" / "calibration" / "screenshots2"
LIVE_DIGEST = "4a091d1be242e2e9aeead0578082e898349ce348ece05d30d56b58d8fee492d8"
MARGIN = 250
REGRESSION = "regression-honest-1000x420"


def sha(b):
    return hashlib.sha256(b).hexdigest()


def load(name):
    return json.loads((SET / name).read_text(encoding="utf-8"))


def measure_module():
    spec = importlib.util.spec_from_file_location("screenshot2_measure", SET / "measure.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def gate():
    g = getattr(match_screenshot, "MIN_READABILITY_X100", None)
    assert g is not None, "match_screenshot has no readability gate (MIN_READABILITY_X100)"
    return g


def value(row):
    return row["readability"]["mean_conf_x100"]


def inputs(row):
    """(case dict, image, dom) of a measured row, including the regression fixture."""
    if row["name"] == REGRESSION:
        d = SET / "regression"
        return {"article": "fx", "format": "png", "name": row["name"]}, (d / "honest-1000x420.png").read_bytes(), (d / "page.html").read_bytes()
    c = {x["name"]: x for x in load("cases.json")["cases"]}[row["name"]]
    return c, (SET / c["image"]).read_bytes(), (SET / c["page"]).read_bytes()


class Table(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.doc = load("measured_gate.json")
        cls.rows = cls.doc["cases"]
        cls.texts = {r["name"]: r["ocr_text"] for r in load("measured.json")["cases"]}
        cls.texts[REGRESSION] = (SET / "regression" / "ocr_as_is.txt").read_text(encoding="utf-8")

    def test_measured_in_the_live_image_in_the_calibration_pod(self):
        head = self.doc["head"]
        self.assertTrue(head["image"].endswith("@sha256:" + LIVE_DIGEST), head["image"])
        self.assertEqual(head["pod"], "claim-screenshot-cal3")
        self.assertEqual(head["tesseract_command_tsv"][1:], ["stdin", "stdout", "-l", "eng", "--psm", "3", "tsv"])
        self.assertEqual(head["tesseract_command_text"][1:], ["stdin", "stdout", "-l", "eng", "--psm", "3"])
        self.assertEqual(head["cases_json_sha256"], sha((SET / "cases.json").read_bytes()))
        self.assertEqual(self.doc["measured_by"], "tests_claim/fixtures/calibration/screenshots2/measure_gate.py")

    def test_every_image_of_the_set_and_the_regression_fixture_is_measured_once(self):
        names = [c["name"] for c in load("cases.json")["cases"]] + [REGRESSION]
        self.assertEqual([r["name"] for r in self.rows], names)
        for r in self.rows:
            _, img, _ = inputs(r)
            self.assertEqual(sha(img), r["image_sha256"], r["name"])
            self.assertTrue(r["ocr_text_same_as_measured_json"], r["name"])   # the text path is the one the similarity came from
            self.assertEqual(sha(self.texts[r["name"]].encode("utf-8")), r["ocr_text_sha256"], r["name"])
            for k in ("words", "mean_conf_x100", "share60_bp", "words_per_mpx", "px"):
                self.assertIn(k, r["readability"], r["name"])

    def test_the_recorded_similarity_is_what_the_method_computes_from_the_recorded_text(self):
        m = measure_module()
        for r in self.rows:
            c, img, dom = inputs(r)
            res = methods.run("match.screenshot", {}, m.evidence(c, img, self.texts[r["name"]], dom))
            self.assertEqual(res.detail["similarity_bp"], r["similarity_bp"], r["name"])

    def test_every_honest_image_is_gated_or_at_or_above_f_with_margin(self):
        g, f = gate(), match_screenshot.F_BP
        passing = [r for r in self.rows if r["kind"] == "honest" and value(r) >= g]
        low = [(r["name"], r["similarity_bp"]) for r in passing if r["similarity_bp"] < f + MARGIN]
        self.assertEqual(low, [], f"honest images that pass the gate G={g} but sit under F={f} + {MARGIN} bp")

    def test_f_is_8000_or_more_and_below_t(self):
        self.assertGreaterEqual(match_screenshot.F_BP, 8000)
        self.assertLess(match_screenshot.F_BP, match_screenshot.T_BP)

    def test_no_forgery_or_unrelated_image_that_passes_the_gate_reaches_t_less_margin(self):
        g, t = gate(), match_screenshot.T_BP
        high = [(r["name"], r["similarity_bp"]) for r in self.rows if r["kind"] != "honest" and value(r) >= g
                and r["similarity_bp"] >= t - MARGIN]
        self.assertEqual(high, [], f"forgeries passing the gate G={g} within {MARGIN} bp of T={t}")

    def test_the_gate_does_not_take_honest_images_at_scale_1_or_2(self):
        gated = [r for r in self.rows if r["kind"] == "honest" and value(r) < gate()]
        self.assertTrue(gated)
        self.assertEqual(sorted({r["view"] for r in gated}), ["full-s50", "full-s75"])   # only images resampled to 0.5 / 0.75
        self.assertLessEqual(len(gated), 12)

    def test_the_regression_fixture_passes_the_gate_and_is_not_differs(self):
        r = [x for x in self.rows if x["name"] == REGRESSION][0]
        self.assertEqual(r["similarity_bp"], 9111)
        self.assertGreaterEqual(value(r), gate())
        c, img, dom = inputs(r)
        res = methods.run("match.screenshot", {}, measure_module().evidence(c, img, self.texts[REGRESSION], dom, ocr_readability=value(r)))
        self.assertNotEqual(res.finding, "differs")
        self.assertEqual((res.finding, res.reason), (None, "undecided"))

    def test_the_method_over_the_whole_table(self):
        m, g = measure_module(), gate()
        n = {"differs": 0, "undecided": 0, "unreadable": 0, "consistent": 0}
        for r in self.rows:
            c, img, dom = inputs(r)
            res = methods.run("match.screenshot", {}, m.evidence(c, img, self.texts[r["name"]], dom, ocr_readability=value(r)))
            if value(r) < g:
                self.assertEqual((res.finding, res.reason), (None, "unreadable"), r["name"])
                self.assertEqual(res.detail["readability_x100"], value(r))
            if r["kind"] == "honest":
                self.assertNotEqual(res.finding, "differs", r["name"])
            else:
                self.assertNotEqual(res.finding, "consistent", r["name"])
            n[res.finding or res.reason] += 1
        self.assertGreater(n["differs"], 0)    # forgeries that pass the gate and sit under F are still shown to differ
        self.assertGreater(n["unreadable"], 0)


class Production(unittest.TestCase):
    """measured_gate_prod.json: the same script run in the pod with the branch's claim_witness package on PYTHONPATH, so
    ocr.Ocr.readability and match.screenshot are the ones that ship."""

    @classmethod
    def setUpClass(cls):
        cls.doc = load("measured_gate_prod.json")

    def test_the_witness_value_is_the_table_value_for_every_image(self):
        asis = {r["name"]: r for r in load("measured_gate.json")["cases"]}
        self.assertEqual([r["name"] for r in self.doc["cases"]], list(asis))
        for r in self.doc["cases"]:
            self.assertEqual(r["readability_x100_production"], asis[r["name"]]["readability"]["mean_conf_x100"], r["name"])
            self.assertEqual((r["similarity_bp"], r["ocr_text_sha256"]), (asis[r["name"]]["similarity_bp"], asis[r["name"]]["ocr_text_sha256"]))

    def test_the_findings_the_shipped_code_gave(self):
        g, f, t = gate(), match_screenshot.F_BP, match_screenshot.T_BP
        for r in self.doc["cases"]:
            v, bp = r["readability_x100_production"], r["similarity_bp"]
            if v < g:
                want = (None, "unreadable")
            elif bp >= t:
                want = ("consistent", None)
            elif bp < f:
                want = ("differs", None)
            else:
                want = (None, "undecided")
            self.assertEqual((r["finding_in_image"], r["reason_in_image"]), want, r["name"])

    def test_measured_with_the_branch_code(self):
        head = self.doc["head"]
        self.assertTrue(head["image"].endswith("@sha256:" + LIVE_DIGEST))
        self.assertEqual(head["pod"], "claim-screenshot-cal3")
        self.assertEqual(head["thresholds_in_image"], {"T_bp": match_screenshot.T_BP, "F_bp": match_screenshot.F_BP})
        self.assertNotEqual(head["ocr_module"], "/app/claim_witness/ocr.py")


class TsvParsing(unittest.TestCase):
    HEAD = "level\tpage_num\tblock_num\tpar_num\tline_num\tword_num\tleft\ttop\twidth\theight\tconf\ttext\n"

    def row(self, level, conf, text):
        return f"{level}\t1\t1\t1\t1\t1\t0\t0\t10\t10\t{conf}\t{text}\n"

    def test_mean_word_confidence_x100(self):
        tsv = self.HEAD + self.row(1, -1, "") + self.row(5, 96, "alpha") + self.row(5, 90.5, "beta") + self.row(5, 90, "gamma")
        self.assertEqual(ocr.mean_confidence_x100(tsv), 9217)   # (96 + 90.5 + 90) / 3 = 92.1666..

    def test_rows_that_are_not_words_do_not_count(self):
        tsv = (self.HEAD + self.row(1, -1, "") + self.row(2, -1, "") + self.row(4, -1, "") + self.row(5, 80, "word")
               + self.row(5, 10, "   ") + self.row(5, -1, "ghost"))
        self.assertEqual(ocr.mean_confidence_x100(tsv), 8000)

    def test_no_words_is_none(self):
        self.assertIsNone(ocr.mean_confidence_x100(self.HEAD + self.row(1, -1, "")))
        self.assertIsNone(ocr.mean_confidence_x100(""))
        self.assertIsNone(ocr.mean_confidence_x100("not a tsv at all"))

    def test_the_text_path_is_unchanged_and_readability_runs_the_tsv_config(self):
        o = ocr.Ocr(fake_tesseract())
        img = image("[conf=88]Ferry timetable\nTickets cost four euros.")
        self.assertEqual(o.text(img), "Ferry timetable\nTickets cost four euros.")
        self.assertEqual(o.readability(img), 8800)
        self.assertIsNone(o.readability(b"\x89PNG\r\n\x1a\nnot an ocr fixture"))   # Tesseract failed: no value


class GateInTheMethod(unittest.TestCase):
    def result(self, readability, text=None):
        from tests_claim.test_match_text import obs_ev
        sub = {"slot": "submitted", "kind": "object", "sha256": "1" * 64, "media_type": "image/png", "name": "s", "data": b"",
               "ocr_text": text or "Title One two three four five."}
        if readability is not ...:
            sub["ocr_readability"] = readability
        return methods.run("match.screenshot", {}, {"submitted": sub, "page": obs_ev()})

    def test_low_confidence_is_unreadable_even_when_the_text_matches(self):
        r = self.result(gate() - 1)
        self.assertEqual((r.finding, r.reason), (None, "unreadable"))
        self.assertEqual(r.detail["readability_x100"], gate() - 1)
        self.assertEqual(r.detail["min_readability_x100"], gate())

    def test_the_gate_value_itself_passes(self):
        r = self.result(gate())
        self.assertEqual(r.finding, "consistent")

    def test_no_value_because_tesseract_failed_is_unreadable(self):
        r = self.result(None)
        self.assertEqual((r.finding, r.reason), (None, "unreadable"))

    def test_a_forged_text_over_an_unreadable_image_is_no_finding_not_differs(self):
        r = self.result(gate() - 1, text="Quokkas juggle violet marmots beyond frozen glaciers whenever nobody watches.")
        self.assertEqual((r.finding, r.reason), (None, "unreadable"))
        r = self.result(gate(), text="Quokkas juggle violet marmots beyond frozen glaciers whenever nobody watches.")
        self.assertEqual(r.finding, "differs")


class GateInTheService(Base):
    def test_a_blurry_image_is_unreadable_through_the_api(self):
        out, p = self.check(image("[conf=40]Ferry timetable\n" + "\n".join(PARAS)))
        self.assertEqual((p["finding"], p["reason"]), (None, "unreadable"))
        self.assertEqual(p["detail"]["readability_x100"], 4000)
        out, p = self.check(image("[conf=40]Ferry timetable\n" + "\n".join(PARAS)), assertion=False)
        self.assertEqual((p["finding"], p["reason"]), (None, "unreadable"))

    def test_a_clear_image_is_judged(self):
        out, p = self.check(image("[conf=96]Ferry timetable\n" + "\n".join(PARAS)))
        self.assertEqual(p["finding"], "consistent")
        self.assertEqual(p["detail"]["readability_x100"], 9600)


if __name__ == "__main__":
    unittest.main()
