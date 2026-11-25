"""match.screenshot's T and F against its calibration set (tests_claim/fixtures/calibration/screenshots/): real Chromium
screenshots measured INSIDE the claim-witness image (its Tesseract, language data and command line) by measure.py, which
wrote measured.json. These tests check that the table is the image's measurement of this set, that the similarity code
here reproduces every recorded number from the recorded OCR text, and that T and F separate the set: every honest
screenshot >= T, every forgery and unrelated screenshot < F, F <= T."""
import hashlib
import importlib.util
import json
import pathlib
import unittest

from claim_witness import methods, ocr
from claim_witness.methods import match_screenshot

SET = pathlib.Path(__file__).resolve().parent / "fixtures" / "calibration" / "screenshots"
IMAGE_DIGEST = "829dae31e192de5c1a724755c65c1eab7a52205b4f18ac54854649b0f2e48af7"


def sha(b):
    return hashlib.sha256(b).hexdigest()


def load(name):
    return json.loads((SET / name).read_text(encoding="utf-8"))


def measure_module():
    spec = importlib.util.spec_from_file_location("screenshot_measure", SET / "measure.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class CalibrationSet(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = load("cases.json")
        cls.measured = load("measured.json")
        cls.rows = cls.measured["cases"]

    def test_measured_in_the_built_image_with_the_witness_ocr_command(self):
        head = self.measured["head"]
        self.assertTrue(head["image"].endswith("@sha256:" + IMAGE_DIGEST), head["image"])
        self.assertEqual(head["pod"], "claim-screenshot-cal")
        self.assertEqual(head["tesseract_command"][1:], ["stdin", "stdout", "-l", "eng", "--psm", "3"])
        self.assertEqual(head["tesseract_bin"], "/usr/bin/tesseract")
        self.assertRegex(head["tesseract_version"], r"^5\.")
        self.assertEqual(len(head["eng_traineddata"]), 1)
        self.assertEqual(head["cases_json_sha256"], sha((SET / "cases.json").read_bytes()))
        self.assertEqual(self.measured["measured_by"], "tests_claim/fixtures/calibration/screenshots/measure.py")
        self.assertIn("`tesseract stdin stdout -l eng --psm 3`", ocr.__doc__)  # the witness's command line (ocr.Ocr.text)

    def test_every_case_measured_once_with_the_files_it_names(self):
        self.assertEqual([r["name"] for r in self.rows], [c["name"] for c in self.cases["cases"]])
        for c in self.cases["cases"]:
            self.assertEqual(sha((SET / c["image"]).read_bytes()), c["image_sha256"], c["name"])
            self.assertEqual(sha((SET / c["page"]).read_bytes()), c["page_sha256"], c["name"])
        for r in self.rows:
            self.assertIsNotNone(r["ocr_text"], r["name"])
            self.assertEqual(sha(r["ocr_text"].encode("utf-8")), r["ocr_text_sha256"], r["name"])

    def test_the_set_covers_the_spec_11_shape(self):
        kinds = [r["kind"] for r in self.rows]
        self.assertGreaterEqual(kinds.count("honest"), 20)
        self.assertGreaterEqual(kinds.count("forgery"), 20)
        self.assertGreaterEqual(kinds.count("unrelated"), 1)
        honest = [r for r in self.rows if r["kind"] == "honest"]
        self.assertEqual({r["width"] for r in honest}, {1280, 390})
        self.assertEqual({r["format"] for r in honest}, {"png", "jpg"})
        self.assertEqual({r["view"] for r in honest}, {"full", "crop"})
        self.assertEqual(len({r["font"] for r in honest}), 2)

    def test_the_code_here_reproduces_every_recorded_similarity(self):
        m = measure_module()
        by_name = {c["name"]: c for c in self.cases["cases"]}
        for r in self.rows:
            c = by_name[r["name"]]
            ev = m.evidence(c, (SET / c["image"]).read_bytes(), r["ocr_text"], (SET / c["page"]).read_bytes())
            res = methods.run("match.screenshot", {}, ev)
            self.assertEqual((res.detail["similarity_bp"], res.detail["ocr_tokens"], res.detail["window_tokens"]),
                             (r["similarity_bp"], r["ocr_tokens"], r["window_tokens"]), r["name"])


class Thresholds(unittest.TestCase):
    T = methods.get("match.screenshot").thresholds["T_bp"]
    F = methods.get("match.screenshot").thresholds["F_bp"]

    @classmethod
    def setUpClass(cls):
        cls.rows = load("measured.json")["cases"]

    def test_thresholds_are_the_calibrated_integers(self):
        # BD19: F moved from 9300 to 1200 (decision 157) and, with the readability gate, to 8700 (decision 158) and 8490 (decision 159) over the widened
        # set (../screenshots2/, measured_gate.json); T stays 9500
        self.assertEqual((match_screenshot.T_BP, match_screenshot.F_BP), (9500, 8490))
        self.assertEqual((self.T, self.F), (9500, 8490))
        self.assertLessEqual(self.F, self.T)

    def test_every_honest_screenshot_is_at_or_above_f(self):
        # was: every honest screenshot >= T (BD16). Honest screenshots between F and T are `undecided`, never `differs`.
        low = [(r["name"], r["similarity_bp"]) for r in self.rows if r["kind"] == "honest" and r["similarity_bp"] < self.F]
        self.assertEqual(low, [], f"honest screenshots under F={self.F}")

    def test_every_forgery_and_unrelated_screenshot_is_below_t(self):
        # was: below F (BD16). A forgery between F and T gets no finding (BD19); none may be `consistent`.
        high = [(r["name"], r["similarity_bp"]) for r in self.rows if r["kind"] != "honest" and r["similarity_bp"] >= self.T]
        self.assertEqual(high, [], f"forgeries at or above T={self.T}")

    def test_findings_under_the_thresholds(self):
        # was: honest consistent, every forgery and unrelated screenshot differs (BD16)
        m = measure_module()
        by_name = {c["name"]: c for c in load("cases.json")["cases"]}
        for r in self.rows:
            c = by_name[r["name"]]
            res = methods.run("match.screenshot", {}, m.evidence(c, (SET / c["image"]).read_bytes(), r["ocr_text"],
                                                                 (SET / c["page"]).read_bytes()))
            if r["kind"] == "honest":
                self.assertEqual(res.finding, "consistent", r["name"])
            else:
                self.assertNotEqual(res.finding, "consistent", r["name"])


if __name__ == "__main__":
    unittest.main()
