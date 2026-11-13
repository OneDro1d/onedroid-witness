"""Fourth re-gate G1 (the claims session, 13 Nov 2026, gate/2026-11-13-witness-s1-regate4/RESULT.md): a JSON `models` that is a NUMBER
(5 or 1.5) got no HTTP answer, because _parse admitted int and float for every field and do_POST then called `.split(",")` on the number
outside the catch. Nothing was kept (no folder exists yet), no spend. `models` is a string or a list of strings only now; a number for
`models` answers 400 by name. The gate's notes beside it: `max_cost_usd` "nan" (or inf) ran with no caller limit and NaN landed in the
status: a non-finite value answers 400 by name, on both body shapes. Numbers stay valid for `max_cost_usd`."""
import json
import math
import pathlib
import sys
import unittest

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(HERE))

from onedroid_witness import server  # noqa: E402
from test_gate_s1 import SNAP, ServerRules  # noqa: E402
from test_server import multipart  # noqa: E402


def _text_parts():
    parts = {n: (SNAP / n).read_bytes().decode("utf-8", "replace") for n in ("manifest.json", "audit.jsonl", "allowed_signers", "signatures.json", "page.txt")}
    parts["audit.jsonl.sig"] = (SNAP / "audit.jsonl.sig").read_text(encoding="utf-8")
    return parts


class ParseModels(unittest.TestCase):
    def test_g1_parse_refuses_a_number_for_models_and_keeps_numbers_for_the_cost(self):
        for v in (5, 1.5):
            body = json.dumps({"parts": {}, "models": v}).encode()
            with self.assertRaises(ValueError) as cm:
                server._parse("application/json", body, {})
            self.assertIn("models", str(cm.exception))
        _, params = server._parse("application/json", json.dumps({"parts": {}, "models": "a/b", "max_cost_usd": 0.5}).encode(), {})
        self.assertEqual(params["models"], "a/b")
        self.assertEqual(params["max_cost_usd"], 0.5)
        _, params = server._parse("application/json", json.dumps({"parts": {}, "models": ["a/b", "c/d"]}).encode(), {})
        self.assertEqual(params["models"], "a/b,c/d")


class Regate4Models(ServerRules):
    def _post_raw(self, body, ctype):
        import http.client
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        try:
            c.request("POST", "/witness", body=body, headers={"Content-Type": ctype, "Content-Length": str(len(body))})
            r = c.getresponse()
            return r.status, json.loads(r.read())
        except Exception as e:  # pragma: no cover - the defect itself
            self.fail(f"no HTTP answer ({type(e).__name__}: {e})")

    def test_g1_a_json_models_that_is_a_number_gets_400_by_name_and_nothing_is_kept(self):
        parts = _text_parts()
        before = self._jobs()
        for v in (5, 1.5):
            st, ans = self._post_raw(json.dumps({"parts": parts, "models": v}).encode(), "application/json")
            self.assertEqual(st, 400, (v, ans))
            self.assertIn("models", ans["error"], v)
            self.assertNotIn("job_id", ans, v)
        self.assertEqual(self._jobs(), before)
        self.assertEqual(list((pathlib.Path(self.tmp) / "jobs" / ".incoming").iterdir()), [])

    def test_g1_note_a_non_finite_max_cost_usd_gets_400_on_both_body_shapes(self):
        parts = _text_parts()
        before = self._jobs()
        for v in ("nan", "inf", "-inf", "NaN", "Infinity"):
            st, ans = self._post_raw(json.dumps({"parts": parts, "models": "typesafe/jev-1.14", "max_cost_usd": v}).encode(), "application/json")
            self.assertEqual(st, 400, (v, ans))
            self.assertIn("max_cost_usd", ans["error"], v)
            self.assertNotIn("job_id", ans, v)
        raw = {n: (SNAP / n).read_bytes() for n in ("manifest.json", "audit.jsonl", "audit.jsonl.sig", "allowed_signers", "signatures.json", "page.txt")}
        for v in ("nan", "inf"):
            st, ans = self._post(*multipart(raw, {"models": "typesafe/jev-1.14", "max_cost_usd": v}))
            self.assertEqual(st, 400, (v, ans))
            self.assertIn("max_cost_usd", ans["error"], v)
        # the JSON spelling of a non-finite number that json.dumps emits (NaN, Infinity) is refused by the body parser or by the bound: never a job
        body = b'{"parts": ' + json.dumps(parts).encode() + b', "models": "typesafe/jev-1.14", "max_cost_usd": NaN}'
        st, ans = self._post_raw(body, "application/json")
        self.assertEqual(st, 400, ans)
        self.assertNotIn("job_id", ans)
        self.assertEqual(self._jobs(), before)
        self.assertEqual(list((pathlib.Path(self.tmp) / "jobs" / ".incoming").iterdir()), [])
        self.assertFalse(any(not math.isfinite(float(x)) for x in ("0.5", "1")))  # the finite path is untouched: a number is still a number

    def test_g1_a_finite_max_cost_usd_still_bounds_the_run(self):
        raw = {n: (SNAP / n).read_bytes() for n in ("manifest.json", "audit.jsonl", "audit.jsonl.sig", "allowed_signers", "signatures.json", "page.txt")}
        st, ans = self._post(*multipart(raw, {"models": "typesafe/jev-1.14", "max_cost_usd": "0.000001"}))
        self.assertEqual(st, 422, ans)
        self.assertIn("estimate", ans["error"])


if __name__ == "__main__":
    unittest.main()
