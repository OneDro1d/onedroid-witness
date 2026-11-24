"""B2b (e): `match.text` per SPEC §9.3. Layers: a text/html submission is compared first with the response layer
(response.body after canon/1), then with the rendered layer (text.canonical.txt); text/plain with the rendered layer only.
Ladder per layer: exact (sha256 of a captured file), canonical (canon/1 texts equal), similar (>= T), differs (< F, with the
first differing token offset), undecided (between). Integer basis points; over 50,000 tokens: too-large. T and F come from
the calibration set in tests_claim/fixtures/calibration and are published in /v1/methods. TS-1, TS-2, TS-4 through the API."""
import hashlib
import json
import unittest

from claim_witness import methods, observation
from tests_claim import helpers as h
from tests_claim.fakefetch import build_capture, error, iso, page, stack, url_item
from tests_claim.helpers import claim, obj_item, request

CASES = json.loads((h.ROOT / "tests_claim" / "fixtures" / "calibration" / "cases.json").read_text(encoding="utf-8"))
U = "https://text.example/article"
HTML = ("<html><head><style>.menu{display:none}</style></head><body><nav class='menu'><a>Home</a><a>Login</a></nav>"
        "<h1>Title</h1><p>One two three four five.</p><p>Six seven eight nine ten.</p></body></html>").encode()
RENDERED = ("<html><body><nav class='menu' data-witness-hidden='1'><a>Home</a><a>Login</a></nav>"
            "<h1>Title</h1><p>One two three four five.</p><p>Six seven eight nine ten.</p></body></html>").encode()


def obs_ev(response=HTML, rendered=RENDERED, status=200, media_type="text/html", clock=None):
    clock = clock or h.Clock()
    manifest, files = build_capture(U, page(response, status=status, rendered=rendered, media_type=media_type), iso(clock()))
    pred, files = observation.from_capture(manifest, files, "public")
    return {"slot": "page", "kind": "observation", "id": "f" * 64, "manifest": pred, "files": files}


def sub_ev(data, media_type="text/plain"):
    data = data if isinstance(data, bytes) else data.encode("utf-8")
    return {"slot": "submitted", "kind": "object", "sha256": hashlib.sha256(data).hexdigest(), "media_type": media_type,
            "name": "copy", "data": data}


def run(data, media_type="text/plain", **obs):
    return methods.run("match.text", {}, {"submitted": sub_ev(data, media_type), "page": obs_ev(**obs)})


class Ladder(unittest.TestCase):
    T, F = methods.get("match.text").thresholds["T_bp"], methods.get("match.text").thresholds["F_bp"]

    def test_thresholds_are_fixed_integers_with_f_below_t(self):
        self.assertEqual((self.T, self.F), (9700, 9600))
        self.assertIsInstance(self.T, int)

    def test_exact_at_the_response_layer(self):
        r = run(HTML, "text/html")
        self.assertEqual((r.finding, r.detail["layer"], r.detail["rung"]), ("match", "response", "exact"))
        self.assertEqual(r.detail["similarity_bp"], 10000)

    def test_canonical_at_the_response_layer(self):
        r = run(HTML.replace(b"<p>", b"<p class='x'>  "), "text/html")
        self.assertEqual((r.finding, r.detail["layer"], r.detail["rung"]), ("match", "response", "canonical"))

    def test_plain_text_is_compared_with_the_rendered_layer_only(self):
        r = run("Title\n  One two three four five.\nSix seven  eight nine ten.\n")
        self.assertEqual((r.finding, r.detail["layer"], r.detail["rung"]), ("match", "rendered", "canonical"))
        # the server text (menu included) would not match a plain copy: the copy is judged at the rendered layer
        r = run("Home Login Title One two three four five. Six seven eight nine ten.")
        self.assertEqual(r.detail["layer"], "rendered")

    def test_exact_at_the_rendered_layer(self):
        text = observation.text_canonical(RENDERED, "text/html")
        r = run(text)
        self.assertEqual((r.finding, r.detail["layer"], r.detail["rung"]), ("match", "rendered", "exact"))

    def test_html_that_misses_the_response_layer_falls_to_the_rendered_layer(self):
        shell = b"<html><body><div id='root'></div><script>render()</script></body></html>"
        r = run(RENDERED.replace(b" data-witness-hidden='1'", b" hidden"), "text/html", response=shell)
        self.assertEqual((r.finding, r.detail["layer"]), ("match", "rendered"))

    def _tokens_page(self, n, changed, start=10):
        words = [f"w{i}" for i in range(n)]
        page_text = " ".join(words)
        copy = list(words)
        for i in range(start, start + changed):
            copy[i] = f"x{i}"
        return page_text, " ".join(copy)

    def test_similar_differs_and_undecided(self):
        n = 10000
        for k, finding, rung in ((100, "match", "similar"), (500, "differs", "differs"), (350, None, "undecided")):
            page_text, copy = self._tokens_page(n, k)
            r = run(copy, rendered=("<p>" + page_text + "</p>").encode())
            self.assertEqual((r.finding, r.detail["rung"], r.detail["layer"]), (finding, rung, "rendered"), k)
            self.assertEqual(r.detail["similarity_bp"], (n - k) * 10000 // n)
            if finding is None:
                self.assertEqual(r.reason, "undecided")
            if finding == "differs":
                self.assertEqual(r.detail["first_diff_token"], 10)

    def test_detail_is_integers_and_enums_only(self):
        page_text, copy = self._tokens_page(2000, 300)
        r = run(copy, rendered=("<p>" + page_text + "</p>").encode())
        for k, v in r.detail.items():
            self.assertTrue(isinstance(v, int) or (isinstance(v, str) and len(v) <= 16), (k, v))
        self.assertNotIn("w1", json.dumps(r.detail))

    def test_over_50000_tokens_is_too_large(self):
        big = " ".join(["t"] * 50001)
        r = run(big, rendered=b"<p>small page</p>")
        self.assertEqual((r.finding, r.reason), (None, "too-large"))
        r = run("small copy", rendered=("<p>" + big + "</p>").encode())
        self.assertEqual((r.finding, r.reason), (None, "too-large"))

    def test_binary_submission_is_unreadable(self):
        r = run(b"\x89PNG\r\n\x1a\n\x00\x01", "image/png")
        self.assertEqual((r.finding, r.reason), (None, "unreadable"))

    def test_a_page_that_did_not_answer_2xx_gives_no_finding(self):
        self.assertEqual(run("Title", status=404).reason, "unreachable")
        self.assertEqual(run("Title", status=403).reason, "blocked")
        self.assertEqual(run("Title", status=503).reason, "unreachable")

    def test_templates_and_limits(self):
        m = methods.get("match.text")
        self.assertEqual(m.templates[True], "The submitted text {sha} matches the content of {url} observed at {fetched_at}.")
        self.assertEqual(m.templates[False], "The submitted text {sha} does not match the content of {url} observed at {fetched_at}.")
        self.assertEqual(m.limits, "Compared visible text after canon/1 at the stated layer. Images, scripts and hidden text were not compared.")
        self.assertEqual(m.slots, {"submitted": ("object",), "page": ("url", "observation")})


class Calibration(unittest.TestCase):
    """The calibration set: every honest copy matches, every one-paragraph forgery differs, at T and F of 1.0.0."""

    def test_set_has_twenty_of_each_with_script_and_hidden_menu_pages(self):
        kinds = [c["kind"] for c in CASES]
        self.assertEqual((kinds.count("honest"), kinds.count("forgery")), (20, 20))
        groups = {c["group"] for c in CASES}
        self.assertTrue({"script", "menu"} <= groups)
        self.assertTrue(any("data-witness-hidden" in c["page"]["rendered_html"] for c in CASES))

    def test_honest_match_and_forgeries_differ(self):
        for c in CASES:
            ev = obs_ev(response=c["page"]["response_body"].encode(), rendered=c["page"]["rendered_html"].encode(),
                        media_type=c["page"]["response_media_type"])
            r = methods.run("match.text", {}, {"submitted": sub_ev(c["submitted"]["data"], c["submitted"]["media_type"]), "page": ev})
            want = "match" if c["kind"] == "honest" else "differs"
            self.assertEqual(r.finding, want, f"{c['name']}: {r.detail}")


class Api(unittest.TestCase):
    def setUp(self):
        self.s, self.ff, _ = stack()

    def tearDown(self):
        self.s.close()
        self.ff.close()

    def check(self, submitted, media_type="text/html", page_item=None, assertion=True, visibility="public"):
        body = request(claim("match.text", {}, assertion), [obj_item("submitted", submitted, media_type, "copy.html"),
                                                             page_item or url_item(U)], visibility)
        code, out, _ = self.s.witness_call(body)
        self.assertEqual(code, 200, out)
        return out, h.payload_of(out["envelope"])["predicate"]

    def test_ts1_live_page_and_its_server_html_match_at_the_response_layer(self):
        self.ff.set(U, page(HTML, rendered=RENDERED))
        out, p = self.check(HTML)
        self.assertEqual((p["finding"], p["outcome"], p["detail"]["layer"]), ("match", "SUPPORTED", "response"))
        sha = hashlib.sha256(HTML).hexdigest()
        self.assertEqual(p["statement"], f"The submitted text {sha} matches the content of {U} observed at {h.iso(self.s.clock())}.")
        self.assertEqual(p["evidence"][1]["kind"], "url")

    def test_ts2_one_paragraph_changed_differs(self):
        c = [x for x in CASES if x["kind"] == "forgery" and x["group"] == "saved"][0]
        self.ff.set(U, page(c["page"]["response_body"].encode(), rendered=c["page"]["rendered_html"].encode()))
        out, p = self.check(c["submitted"]["data"].encode())
        self.assertEqual((p["finding"], p["outcome"]), ("differs", "NOT_SUPPORTED"))
        self.assertIn("first_diff_token", p["detail"])
        out, p = self.check(c["submitted"]["data"].encode(), assertion=False)
        self.assertEqual(p["outcome"], "SUPPORTED")

    def test_ts4_unreachable_host_cannot_witness(self):
        self.ff.set(U, error("unreachable", "host-not-found text.example"))
        for assertion in (True, False):
            out, p = self.check(HTML, assertion=assertion)
            self.assertEqual((p["finding"], p["outcome"], p["reason"]), (None, "CANNOT_WITNESS", "unreachable"))
        self.assertEqual(len(self.ff.calls), 2)  # no not-live confirmation for match.text

    def test_observation_evidence_by_id_needs_no_fetch(self):
        self.ff.set(U, page(HTML, rendered=RENDERED))
        code, obs, _ = self.s.call("POST", "/v1/observe", {"url": U, "visibility": "public"})
        self.assertEqual(code, 200, obs)
        out, p = self.check(HTML, page_item={"slot": "page", "kind": "observation", "id": obs["observation_id"]})
        self.assertEqual(p["finding"], "match")
        self.assertEqual(len(self.ff.calls), 1)
        self.assertEqual(p["evidence"][1], {"slot": "page", "kind": "observation", "id": obs["observation_id"]})
        self.assertEqual(p["relied_on"][0]["id"], obs["observation_id"])
        self.assertTrue(p["relied_on"][0]["trusted"])

    def test_registry_publishes_thresholds(self):
        code, reg, _ = self.s.call("GET", "/v1/methods", key=None)
        mt = [m for m in reg["methods"] if m["id"] == "match.text"][0]
        self.assertEqual(mt["thresholds"], {"T_bp": 9700, "F_bp": 9600})
        self.assertEqual(mt["slots"], {"submitted": ["object"], "page": ["url", "observation"]})
        self.assertIn("page.live", [m["id"] for m in reg["methods"]])


if __name__ == "__main__":
    unittest.main()
