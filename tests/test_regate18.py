"""The eighteenth re-gate's note 1 (the claims session, 13 Nov 2026): a request manifest whose grading.auditor is a string was refused by
the service's older line "manifest grading.auditor is not an object", ahead of the checker's own rule. From 0.1.19 the checker's rule
(check.manifest_shape_faults) runs first in check_manifest_shape, so every fault it names is refused by its own line; the service's own
checks stay after it for what the checker does not name (subject, a source's url)."""
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

from onedroid_witness import request  # noqa: E402

AW6 = ROOT / "fixtures" / "snapshot-aw6-regate5-2026-11-13"


def refusal(fn):
    with tempfile.TemporaryDirectory() as tmp:
        d = pathlib.Path(tmp) / "snap"
        shutil.copytree(AW6, d)
        mp = d / "manifest.json"
        mp.write_text(json.dumps(fn(json.loads(mp.read_text(encoding="utf-8"))), indent=1) + "\n", encoding="utf-8")
        try:
            request.Request(d, private_mode=True, profiles_served=request.PROFILES_SERVED)
        except request.Refused as e:
            return str(e)
    return None


class CheckerLineFirst(unittest.TestCase):
    def test_n1_a_string_auditor_is_refused_by_the_checkers_line(self):
        def fn(M):
            M["grading"]["auditor"] = "a"
            return M
        msg = refusal(fn)
        self.assertIsNotNone(msg)
        self.assertIn("manifest.json: grading.auditor is a JSON string, not an object", msg)
        self.assertIn("the format's checker refuses this shape (K1)", msg)

    def test_n1_a_list_sources_is_refused_by_the_checkers_line(self):
        def fn(M):
            M["sources"] = {"a": 1}
            return M
        msg = refusal(fn)
        self.assertIsNotNone(msg)
        self.assertIn("manifest.json: sources is a JSON object, not a list", msg)

    def test_n1_the_services_own_check_still_refuses_what_the_checker_does_not_name(self):
        def fn(M):
            M["subject"] = "s"
            return M
        msg = refusal(fn)
        self.assertEqual(msg, "manifest subject is not an object")


if __name__ == "__main__":
    unittest.main()
