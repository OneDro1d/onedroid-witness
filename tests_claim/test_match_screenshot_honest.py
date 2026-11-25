"""match.screenshot must not sign `differs` over an honest screenshot (DECISIONS BD19). The widened calibration set
(tests_claim/fixtures/calibration/screenshots2/: widths 1000, 1024, 1440, 1280 and 390, device scale 1 and 2, resampled by 0.75
and 0.5, short pages with an id-like token, PNG and JPEG) was measured by measure.py INSIDE the live claim-witness image
(measured.json, pod.log). These tests hold the constants to that table: F below every honest screenshot, T above every forgery
and unrelated screenshot, so a forgery is never `consistent` and an honest screenshot is never `differs`; and the regression
fixture, an honest 1000 x 420 screenshot of a 45-token page that the first calibration signed `differs` at 9111 bp."""
import hashlib
import importlib.util
import json
import pathlib
import unittest

from claim_witness import methods
from claim_witness.methods import match_screenshot

SET = pathlib.Path(__file__).resolve().parent / "fixtures" / "calibration" / "screenshots2"
LIVE_DIGEST = "4a091d1be242e2e9aeead0578082e898349ce348ece05d30d56b58d8fee492d8"


def sha(b):
    return hashlib.sha256(b).hexdigest()


def measure_module():
    spec = importlib.util.spec_from_file_location("screenshot2_measure", SET / "measure.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def load(name):
    return json.loads((SET / name).read_text(encoding="utf-8"))


class WidenedSet(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = load("cases.json")
        cls.measured = load("measured.json")
        cls.rows = cls.measured["cases"]

    def test_measured_in_the_live_image_with_the_witness_ocr_command(self):
        head = self.measured["head"]
        self.assertTrue(head["image"].endswith("@sha256:" + LIVE_DIGEST), head["image"])
        self.assertEqual(head["pod"], "claim-screenshot-cal2")
        self.assertEqual(head["tesseract_command"][1:], ["stdin", "stdout", "-l", "eng", "--psm", "3"])
        self.assertEqual(head["cases_json_sha256"], sha((SET / "cases.json").read_bytes()))
        self.assertEqual(self.measured["measured_by"], "tests_claim/fixtures/calibration/screenshots2/measure.py")

    def test_every_case_measured_once_with_the_files_it_names(self):
        self.assertEqual([r["name"] for r in self.rows], [c["name"] for c in self.cases["cases"]])
        for c in self.cases["cases"]:
            self.assertEqual(sha((SET / c["image"]).read_bytes()), c["image_sha256"], c["name"])
            self.assertEqual(sha((SET / c["page"]).read_bytes()), c["page_sha256"], c["name"])
        for r in self.rows:
            self.assertEqual(sha(r["ocr_text"].encode("utf-8")), r["ocr_text_sha256"], r["name"])

    def test_the_set_has_the_bd19_shape(self):
        kinds = [r["kind"] for r in self.rows]
        self.assertGreaterEqual(kinds.count("honest"), 40)
        self.assertGreaterEqual(kinds.count("forgery"), 30)
        self.assertGreaterEqual(kinds.count("unrelated"), 1)
        honest = [r for r in self.rows if r["kind"] == "honest"]
        self.assertTrue({1000, 1024, 1440, 1280, 390} <= {r["width"] for r in honest})
        self.assertEqual({r["dpr"] for r in honest}, {1, 2})
        self.assertEqual({r["format"] for r in honest}, {"png", "jpg"})
        self.assertTrue({"full", "crop", "full-s75", "full-s50"} <= {r["view"] for r in honest})
        self.assertTrue(any(r["short"] for r in honest))
        self.assertGreaterEqual({r["width"] for r in self.rows if r["kind"] == "forgery"}, {1000, 1024, 1440})
        pages = {c["page"]: (SET / c["page"]).read_text(encoding="utf-8") for c in self.cases["cases"]}
        self.assertTrue(all("code class=\"ref\"" in html and "—" in html and "·" in html for html in pages.values()))

    def test_the_code_here_reproduces_every_recorded_similarity(self):
        m = measure_module()
        by_name = {c["name"]: c for c in self.cases["cases"]}
        for r in self.rows:
            c = by_name[r["name"]]
            ev = m.evidence(c, (SET / c["image"]).read_bytes(), r["ocr_text"], (SET / c["page"]).read_bytes())
            res = methods.run("match.screenshot", {}, ev)
            self.assertEqual((res.detail["similarity_bp"], res.detail["ocr_tokens"], res.detail["window_tokens"]),
                             (r["similarity_bp"], r["ocr_tokens"], r["window_tokens"]), r["name"])


class ConstantsHoldTheTable(unittest.TestCase):
    T = match_screenshot.T_BP
    F = match_screenshot.F_BP

    @classmethod
    def setUpClass(cls):
        cls.rows = load("measured.json")["cases"]

    def test_every_honest_screenshot_is_at_or_above_f(self):
        low = [(r["name"], r["similarity_bp"]) for r in self.rows if r["kind"] == "honest" and r["similarity_bp"] < self.F]
        self.assertEqual(low, [], f"honest screenshots under F={self.F}: they would be signed `differs`")

    def test_every_forgery_and_unrelated_screenshot_is_below_t(self):
        high = [(r["name"], r["similarity_bp"]) for r in self.rows if r["kind"] != "honest" and r["similarity_bp"] >= self.T]
        self.assertEqual(high, [], f"forgeries at or above T={self.T}: they would be signed `consistent`")

    def test_no_honest_screenshot_differs_and_no_forgery_is_consistent(self):
        m = measure_module()
        by_name = {c["name"]: c for c in load("cases.json")["cases"]}
        for r in self.rows:
            c = by_name[r["name"]]
            res = methods.run("match.screenshot", {}, m.evidence(c, (SET / c["image"]).read_bytes(), r["ocr_text"],
                                                                 (SET / c["page"]).read_bytes()))
            if r["kind"] == "honest":
                self.assertNotEqual(res.finding, "differs", r["name"])
            else:
                self.assertNotEqual(res.finding, "consistent", r["name"])

    def test_f_is_not_above_t(self):
        self.assertLessEqual(self.F, self.T)


class BetweenTheOldAndTheNewF(unittest.TestCase):
    """A similarity just below the first calibration's F (9300) but at or above the new F is no finding (`undecided`)."""

    def result(self, wrong):
        words = [f"word{i}x" for i in range(400)]
        page = "<html><body><p>" + " ".join(words) + "</p></body></html>"
        shot = list(words)
        for i in range(wrong):
            shot[i * (400 // wrong)] = f"misread{i}"
        m = measure_module()
        case = {"article": "u", "format": "png", "name": "u"}
        return methods.run("match.screenshot", {}, m.evidence(case, b"img", " ".join(shot), page.encode("utf-8")))

    def test_9250_is_undecided_not_differs(self):
        r = self.result(30)   # 370 of 400 tokens match: 9250 bp, under the old F
        self.assertEqual(r.detail["similarity_bp"], 9250)
        self.assertLess(r.detail["similarity_bp"], 9300)
        self.assertEqual((r.finding, r.reason), (None, "undecided"))
        self.assertGreaterEqual(r.detail["similarity_bp"], match_screenshot.F_BP)

    def test_a_clearly_different_text_still_differs(self):
        r = self.result(400)   # every token wrong: 0 bp
        self.assertEqual((r.finding, r.detail["similarity_bp"]), ("differs", 0))


class RegressionFixture(unittest.TestCase):
    """The honest 1000 x 420 Chromium screenshot (sha256 4f7c2246...) of a 45-token page, with the text this image's Tesseract
    read from it (ocr_as_is.txt, recorded in the pod): the first calibration scored it 9111 bp and signed `differs`."""

    def test_the_honest_screenshot_is_not_differs(self):
        d = SET / "regression"
        img = (d / "honest-1000x420.png").read_bytes()
        self.assertEqual(sha(img), "4f7c2246a39c4de9c3eeae672fea74768f653f38e5831f4f515b553d8cec6bf7")
        m = measure_module()
        case = {"article": "fx", "format": "png", "name": "honest-1000x420"}
        r = methods.run("match.screenshot", {}, m.evidence(case, img, (d / "ocr_as_is.txt").read_text(encoding="utf-8"),
                                                           (d / "page.html").read_bytes()))
        self.assertEqual(r.detail["similarity_bp"], 9111)
        self.assertNotEqual(r.finding, "differs")


if __name__ == "__main__":
    unittest.main()
