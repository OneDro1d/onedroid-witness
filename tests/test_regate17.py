"""The seventeenth re-gate's finding F (the claims session, 13 Nov 2026): the service's own request shape check (request.py
check_manifest_shape) was narrower than the vendored check.manifest_shape_faults. A request whose manifest had grading.auditor.file a
number passed the request checks, and so did a genuine request beside a published manifest whose grading.auditor is a string (the binding
does not cover grading.auditor). From 0.1.18 both are refused by the checker's own rule, by name, before anything runs: the request's
manifest in Request, the published manifest in check_published."""
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
AUDIT_URL = "https://example.org/snap/aw6/audit.jsonl"
MANIFEST_URL = "https://example.org/snap/aw6/manifest.json"


def mutated_copy(tmp, fn):
    d = pathlib.Path(tmp) / "snap"
    shutil.copytree(AW6, d)
    mp = d / "manifest.json"
    mp.write_text(json.dumps(fn(json.loads(mp.read_text(encoding="utf-8"))), indent=1) + "\n", encoding="utf-8")
    return d


def set_auditor(k, v):
    def fn(M):
        M["grading"]["auditor"][k] = v
        return M
    return fn


def set_top(k, v):
    def fn(M):
        M[k] = v
        return M
    return fn


class RequestShape(unittest.TestCase):
    def test_f1_a_request_whose_auditor_file_is_a_number_is_refused_by_the_checkers_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = mutated_copy(tmp, set_auditor("file", 5))
            with self.assertRaises(request.Refused) as cm:
                request.Request(d, private_mode=True, profiles_served=request.PROFILES_SERVED)
            self.assertIn("manifest.json: grading.auditor.file is a JSON number, not a string", str(cm.exception))

    def test_f1_a_request_whose_format_is_a_list_is_refused_by_the_checkers_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = mutated_copy(tmp, set_top("format", ["claims-snapshot/0.6"]))
            with self.assertRaises(request.Refused) as cm:
                request.Request(d, private_mode=True, profiles_served=request.PROFILES_SERVED)
            self.assertIn("manifest.json: format is a JSON array, not a string", str(cm.exception))

    def test_f1_the_genuine_request_still_loads(self):
        req = request.Request(AW6, private_mode=True, profiles_served=request.PROFILES_SERVED)
        self.assertEqual(req.manifest["format"], json.loads((AW6 / "manifest.json").read_text(encoding="utf-8"))["format"])


class PublishedShape(unittest.TestCase):
    def _fetch(self, manifest_bytes):
        served = {AUDIT_URL: (AW6 / "audit.jsonl").read_bytes(), MANIFEST_URL: manifest_bytes}
        return lambda url: served[url]

    def test_f2_a_published_manifest_whose_auditor_is_a_string_is_refused_by_name(self):
        req = request.Request(AW6, private_mode=False, profiles_served=request.PROFILES_SERVED)
        M = json.loads((AW6 / "manifest.json").read_text(encoding="utf-8"))
        M["grading"]["auditor"] = "a"
        with self.assertRaises(request.Refused) as cm:
            request.check_published(req, AUDIT_URL, fetch=self._fetch(json.dumps(M).encode()))
        self.assertIn("the published manifest.json", str(cm.exception))
        self.assertIn("grading.auditor is a JSON string, not an object", str(cm.exception))

    def test_f2_the_genuine_published_manifest_still_binds(self):
        req = request.Request(AW6, private_mode=False, profiles_served=request.PROFILES_SERVED)
        out = request.check_published(req, AUDIT_URL, fetch=self._fetch((AW6 / "manifest.json").read_bytes()))
        self.assertEqual(out["mode"], "public")


if __name__ == "__main__":
    unittest.main()
