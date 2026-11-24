"""B5a: `post.by-author` (SPEC §4, TS-5) for Bluesky, over `capture: post` observations (§2.3 platform fields).

Findings: + author-verified (signature verified AND the claimed handle resolves to the post's author DID both ways);
- author-differs (signature verified AND the claimed handle resolves both ways to another DID); ○ handle-unresolved (the
claimed handle not bidirectional, or not the handle the observation resolved); ○ signature-unverifiable (signature failed
or not-available). LinkedIn, TikTok, X and anything that is not a bsky.app post URL: no finding, method-not-applicable, and
no fetch at all. The pure method is tested over the recorded platform.json of a real post (tests_claim/fixtures/bsky,
captured by the real fetcher 24 Nov 2026); the API through the real witness with the fake fetcher."""
import base64
import io
import json
import pathlib
import tempfile
import unittest

from claim_witness import methods, record, schemas, tarball, verify
from tests_claim import helpers as h
from tests_claim.fakefetch import error, page, post_page, stack, url_item
from tests_claim.helpers import claim, request

FIX = pathlib.Path(__file__).resolve().parent / "fixtures" / "bsky"
REAL = json.loads((FIX / "platform-bsky.app.json").read_text())
URL = "https://bsky.app/profile/bsky.app/post/3n2opitxdyc2j"
AUTHOR = "did:plc:z72i7hdynmk6r22z27h6tvur"
OTHER = "did:plc:ewvi7nxzyoun6zhxrhs64oiz"
T_TEMPLATE = "The post at {url} was published by the account {handle}."
F_TEMPLATE = "The post at {url} was not published by the account {handle}."
LIMITS = ("Proves which account key or platform account published the post, not who controls the account. The post time is "
          "the author's own claim.")
FIELDS = ("name", "post_uri", "author_did", "handle", "handle_resolution", "did_doc_sha256", "signature", "commit_cid",
          "created_at_claimed")


def platform(**changes):
    p = json.loads(json.dumps(REAL))
    hr = changes.pop("handle_resolution", None)
    p.update(changes)
    if hr:
        p["handle_resolution"] = dict(p["handle_resolution"], **hr)
    return p


def other_handle():
    return platform(handle="atproto.com", handle_resolution={"result_did": OTHER, "bidirectional": True})


def obs_evidence(p, url=URL):
    manifest = {"requested_url": url, "final_url": url, "redirects": [], "fetched_at": "2026-11-24T21:21:49Z", "fetch_ms": 9056,
                "status": 200, "platform": None if p is None else {k: p[k] for k in FIELDS}, "files": []}
    files = {} if p is None else {"platform.json": json.dumps(p).encode()}
    return {"slot": "post", "kind": "observation", "id": "a" * 64, "manifest": manifest, "files": files}


def run(handle, ev, assertion=True):
    res = methods.run("post.by-author", {"handle": handle}, {"post": ev})
    fclass = methods.finding_class("post.by-author", res.finding)
    return res, record.outcome_for(fclass, assertion), methods.render_statement("post.by-author", assertion, res.vars)


def post_request(handle="bsky.app", url=URL, assertion=True, visibility="public", max_age=None, **opts):
    return request(claim("post.by-author", {"handle": handle}, assertion), [url_item(url, slot="post", capture="post",
                                                                                     max_age=max_age)], visibility, **opts)


class Method(unittest.TestCase):
    def test_registered_with_slot_templates_findings_and_limits(self):
        m = methods.get("post.by-author")
        self.assertEqual((m.id, m.major, m.version), ("post.by-author", 1, "1.0.0"))
        self.assertEqual(m.slots, {"post": ("url", "observation")})
        self.assertEqual(m.templates, {True: T_TEMPLATE, False: F_TEMPLATE})
        self.assertEqual(m.findings, {"author-verified": "positive", "author-platform": "positive", "author-differs": "negative",
                                      "signature-unverifiable": "neutral", "handle-unresolved": "neutral"})
        self.assertEqual(m.limits, LIMITS)
        self.assertTrue(m.mechanical)
        self.assertEqual(methods.LIBRARY_VERSION, "1.5.0")  # 1.4.0 at B5a (README decision 71); 1.5.0 at B5b (decision 128)

    def test_real_post_by_its_handle_is_author_verified(self):
        res, outcome, statement = run("bsky.app", obs_evidence(REAL))
        self.assertEqual((res.finding, outcome), ("author-verified", "SUPPORTED"))
        self.assertEqual(statement, T_TEMPLATE.format(url=URL, handle="bsky.app"))
        self.assertEqual(res.detail, {"platform": "bluesky", "signature": "verified", "resolution": "dns-txt",
                                      "bidirectional": "yes", "handle_match": "yes", "same_did": "yes"})
        res, outcome, statement = run("bsky.app", obs_evidence(REAL), assertion=False)
        self.assertEqual((res.finding, outcome), ("author-verified", "NOT_SUPPORTED"))
        self.assertEqual(statement, F_TEMPLATE.format(url=URL, handle="bsky.app"))

    def test_handle_compares_case_insensitively_and_the_template_keeps_the_claim(self):
        res, outcome, statement = run("Bsky.App", obs_evidence(REAL))
        self.assertEqual((res.finding, outcome), ("author-verified", "SUPPORTED"))
        self.assertIn("account Bsky.App.", statement)

    def test_another_verified_handle_is_author_differs(self):
        res, outcome, _ = run("atproto.com", obs_evidence(other_handle()))
        self.assertEqual((res.finding, outcome), ("author-differs", "NOT_SUPPORTED"))
        self.assertEqual(res.detail["same_did"], "no")
        res, outcome, statement = run("atproto.com", obs_evidence(other_handle()), assertion=False)
        self.assertEqual((res.finding, outcome), ("author-differs", "SUPPORTED"))
        self.assertEqual(statement, F_TEMPLATE.format(url=URL, handle="atproto.com"))

    def test_handle_not_both_ways_is_handle_unresolved(self):
        for p in (platform(handle_resolution={"bidirectional": False}),                       # DNS no longer points back
                  platform(handle_resolution={"result_did": None, "bidirectional": False}),   # nothing resolved
                  platform(handle="impostor.example.com", handle_resolution={"bidirectional": False}),
                  platform(handle="atproto.com", handle_resolution={"result_did": OTHER, "bidirectional": False})):
            res, outcome, _ = run(p["handle"], obs_evidence(p))
            self.assertEqual((res.finding, outcome), ("handle-unresolved", "CANNOT_WITNESS"), p["handle_resolution"])
            self.assertEqual(run(p["handle"], obs_evidence(p), False)[1], "CANNOT_WITNESS")

    def test_an_observation_of_another_handle_does_not_answer_for_this_one(self):
        res, outcome, _ = run("atproto.com", obs_evidence(REAL))
        self.assertEqual((res.finding, outcome), ("handle-unresolved", "CANNOT_WITNESS"))
        self.assertEqual(res.detail["handle_match"], "no")

    def test_signature_failed_or_not_available_is_signature_unverifiable(self):
        for sig in ("failed", "not-available"):
            res, outcome, _ = run("bsky.app", obs_evidence(platform(signature=sig)))
            self.assertEqual((res.finding, outcome), ("signature-unverifiable", "CANNOT_WITNESS"))
            self.assertEqual(res.detail["signature"], sig)
            res, outcome, _ = run("atproto.com", obs_evidence(dict(other_handle(), signature=sig)))
            self.assertEqual(res.finding, "signature-unverifiable")  # never author-differs without a verified post

    def test_unresolved_handle_is_reported_before_the_signature(self):
        p = platform(signature="not-available", author_did=None, handle_resolution={"result_did": None, "bidirectional": False})
        self.assertEqual(run("bsky.app", obs_evidence(p))[0].finding, "handle-unresolved")

    def test_other_platforms_and_other_urls_are_method_not_applicable(self):
        for url, plat in (("https://x.com/someone/status/1", "x"), ("https://twitter.com/someone/status/1", "x"),
                          ("https://mobile.twitter.com/someone/status/1", "x"),
                          ("https://www.linkedin.com/posts/someone_activity-1", "linkedin"),
                          ("https://www.tiktok.com/@someone/video/1", "tiktok"), ("https://vm.tiktok.com/abc/", "tiktok"),
                          ("https://example.com/post/1", "other"), ("https://bsky.app/profile/bsky.app", "other"),
                          ("http://bsky.app/profile/bsky.app/post/3n2opitxdyc2j", "other")):
            ev = {"slot": "post", "kind": "url", "url": url}
            res, outcome, statement = run("bsky.app", ev)
            self.assertEqual((res.finding, res.reason, outcome), (None, "method-not-applicable", "CANNOT_WITNESS"), url)
            self.assertEqual(res.detail, {"platform": plat}, url)
            self.assertEqual(statement, T_TEMPLATE.format(url=url, handle="bsky.app"))

    def test_an_observation_without_platform_fields_is_method_not_applicable(self):
        res, outcome, _ = run("bsky.app", obs_evidence(None, url="https://example.com/"))
        self.assertEqual((res.reason, outcome), ("method-not-applicable", "CANNOT_WITNESS"))
        self.assertEqual(run("bsky.app", obs_evidence(platform(name="mastodon")))[0].reason, "method-not-applicable")

    def test_a_failed_capture_gives_its_reason(self):
        ev = {"slot": "post", "kind": "url", "url": URL, "failure": {"reason": "timeout", "code": "timeout", "nxdomain": False,
                                                                       "partial": {}, "at": "2026-11-24T21:21:49Z", "dns": []}}
        res, outcome, _ = run("bsky.app", ev)
        self.assertEqual((res.finding, res.reason, outcome), (None, "timeout", "CANNOT_WITNESS"))

    def test_params(self):
        m = methods.get("post.by-author")
        m.check_params({"handle": "bsky.app"})
        for bad in ({}, {"handle": ""}, {"handle": "not a handle"}, {"handle": "bsky"}, {"handle": "a.123"}, {"handle": 3},
                    {"handle": "bsky.app", "url": URL}, {"handle": "x" * 300 + ".com"}, {"handle": "@bsky.app"}):
            with self.assertRaises(methods.ParamsError, msg=bad):
                m.check_params(bad)


class Api(unittest.TestCase):
    def setUp(self):
        self.s, self.ff, _ = stack()

    def tearDown(self):
        self.s.close()
        self.ff.close()

    def check(self, body, **kw):
        code, out, _ = self.s.witness_call(body, **kw)
        self.assertEqual(code, 200, out)
        return out, h.payload_of(out["envelope"])["predicate"]

    def test_supported_author_verified_through_a_post_capture(self):
        self.ff.set(URL, post_page(REAL))
        out, p = self.check(post_request())
        self.assertEqual((p["finding"], p["outcome"], p["reason"]), ("author-verified", "SUPPORTED", "author-verified"))
        self.assertEqual(p["statement"], T_TEMPLATE.format(url=URL, handle="bsky.app"))
        self.assertEqual(p["limits"], LIMITS)
        self.assertEqual(p["method"]["id"], "post.by-author")
        self.assertEqual(p["method"]["code_sha256"], tarball.methods_code_sha256())
        self.assertEqual(self.ff.calls[-1]["capture"], "post")
        self.assertEqual(self.ff.calls[-1]["handle"], "bsky.app")
        ev = p["evidence"]
        self.assertEqual(len(ev), 1)
        self.assertEqual((ev[0]["slot"], ev[0]["kind"], ev[0]["url"], ev[0]["capture"]), ("post", "url", URL, "post"))
        oid = ev[0]["observations"][0]
        self.assertEqual(p["relied_on"], [{"id": oid, "kind": "observation", "signer": self.s.key_id, "trusted": True}])
        row = self.s.storage.get_observation(oid)
        obs = h.payload_of(row["envelope"])["predicate"]
        self.assertEqual(obs["platform"], {k: REAL[k] for k in FIELDS})
        names = [f["name"] for f in obs["files"]]
        self.assertIn("platform.json", names)
        self.assertIn("text.canonical.txt", names)
        schemas.check(schemas.OBSERVATION_TYPE, h.payload_of(row["envelope"]))
        self.assertEqual(out["price"]["fresh_observations"], 1)

    def test_not_supported_author_differs_for_another_real_handle(self):
        self.ff.set(URL, post_page(other_handle()))
        _, p = self.check(post_request(handle="atproto.com"))
        self.assertEqual((p["finding"], p["outcome"]), ("author-differs", "NOT_SUPPORTED"))
        self.assertEqual(p["statement"], T_TEMPLATE.format(url=URL, handle="atproto.com"))
        self.assertEqual(self.ff.calls[-1]["handle"], "atproto.com")

    def test_handle_unresolved_when_dns_no_longer_points_back(self):
        self.ff.set(URL, post_page(platform(handle_resolution={"result_did": OTHER, "bidirectional": False})))
        _, p = self.check(post_request())
        self.assertEqual((p["finding"], p["outcome"]), ("handle-unresolved", "CANNOT_WITNESS"))

    def test_x_linkedin_tiktok_are_never_fetched(self):
        for url in ("https://x.com/someone/status/1", "https://www.linkedin.com/posts/someone_activity-1",
                    "https://www.tiktok.com/@someone/video/1", "https://example.com/post/1"):
            out, p = self.check(post_request(url=url))
            self.assertEqual((p["finding"], p["reason"], p["outcome"]), (None, "method-not-applicable", "CANNOT_WITNESS"), url)
            self.assertEqual(p["evidence"][0]["observations"], [])
            self.assertEqual(p["relied_on"], [])
            self.assertEqual(out["price"]["fresh_observations"], 0)
        self.assertEqual(self.ff.calls, [])

    def test_fetch_failure_is_a_signed_cannot_witness(self):
        self.ff.set(URL, error("timeout", "platform: plc.directory"))
        _, p = self.check(post_request())
        self.assertEqual((p["finding"], p["reason"], p["outcome"]), (None, "timeout", "CANNOT_WITNESS"))

    def test_post_slot_needs_capture_post_and_params_are_checked(self):
        body = request(claim("post.by-author", {"handle": "bsky.app"}), [url_item(URL, slot="post", capture="page")], "public")
        self.assertEqual(self.s.witness_call(body)[0], 422)
        body = request(claim("post.by-author", {"handle": "bsky.app"}), [url_item(URL, slot="page", capture="post")], "public")
        self.assertEqual(self.s.witness_call(body)[1]["error"], "wrong-evidence-slots")
        body = request(claim("post.by-author", {"handle": "no handle"}), [url_item(URL, slot="post", capture="post")], "public")
        self.assertEqual(self.s.witness_call(body)[1]["error"], "invalid-params")
        body = request(claim("post.by-author", {"handle": "bsky.app"}), [h.obj_item("post", b"x")], "public")
        self.assertEqual(self.s.witness_call(body)[0], 422)
        body = post_request()
        body["claim"]["statement"] = "by bsky"
        self.assertEqual(self.s.witness_call(body)[1]["error"], "statement-not-allowed")
        self.assertEqual(self.ff.calls, [])

    def test_observation_reuse_with_max_age_is_per_handle(self):
        self.ff.set(URL, post_page(REAL))
        self.check(post_request(max_age=600))
        self.s.clock.advance(30)
        _, p = self.check(post_request(max_age=600))
        self.assertEqual(p["finding"], "author-verified")
        self.assertEqual(len(self.ff.calls), 1)  # reused
        self.ff.set(URL, post_page(other_handle()))
        _, p = self.check(post_request(handle="atproto.com", max_age=600))
        self.assertEqual(p["finding"], "author-differs")
        self.assertEqual(len(self.ff.calls), 2)  # another handle is another observation

    def test_private_claim_makes_a_private_observation(self):
        self.ff.set(URL, post_page(REAL))
        out, p = self.check(post_request(visibility="private"))
        self.assertEqual((p["visibility"], p["finding"], p["outcome"]), ("private", "author-verified", "SUPPORTED"))
        self.assertNotIn("bsky.app", json.dumps(p))
        body = out["disclosure"]["body"]
        oid = body["evidence"][0]["observations"][0]
        obs = h.payload_of(self.s.storage.get_observation(oid)["envelope"])
        self.assertEqual(obs["predicate"]["visibility"], "private")
        self.assertEqual(set(obs["predicate"]), {"visibility", "body_commitment", "fetched_at", "fetcher"})
        self.assertNotIn(AUTHOR, json.dumps(obs))

    def test_observe_a_post_then_use_it_by_id(self):
        self.ff.set(URL, post_page(REAL))
        code, o, _ = self.s.call("POST", "/v1/observe", {"url": URL, "capture": "post", "handle": "bsky.app",
                                                         "visibility": "public"})
        self.assertEqual(code, 200, o)
        self.assertEqual(self.ff.calls[-1]["capture"], "post")
        body = request(claim("post.by-author", {"handle": "bsky.app"}),
                       [{"slot": "post", "kind": "observation", "id": o["observation_id"]}], "public")
        _, p = self.check(body)
        self.assertEqual((p["finding"], p["outcome"]), ("author-verified", "SUPPORTED"))
        self.assertEqual(p["evidence"], [{"slot": "post", "kind": "observation", "id": o["observation_id"]}])
        for bad in ({"url": URL, "capture": "post", "handle": "no handle"}, {"url": "https://example.com/", "capture": "post"},
                    {"url": URL, "capture": "page", "handle": "bsky.app"}):
            self.assertEqual(self.s.call("POST", "/v1/observe", bad)[0], 422, bad)

    def test_a_page_observation_is_method_not_applicable(self):
        self.ff.set("https://example.com/", page())
        code, o, _ = self.s.call("POST", "/v1/observe", {"url": "https://example.com/", "visibility": "public"})
        self.assertEqual(code, 200, o)
        body = request(claim("post.by-author", {"handle": "bsky.app"}),
                       [{"slot": "post", "kind": "observation", "id": o["observation_id"]}], "public")
        _, p = self.check(body)
        self.assertEqual((p["reason"], p["outcome"]), ("method-not-applicable", "CANNOT_WITNESS"))

    def test_methods_route_lists_post_by_author(self):
        code, reg, _ = self.s.call("GET", "/v1/methods", key=None)
        self.assertEqual(code, 200)
        entry = [m for m in reg["methods"] if m["id"] == "post.by-author"][0]
        self.assertEqual(entry["templates"], {"true": T_TEMPLATE, "false": F_TEMPLATE})
        self.assertEqual(entry["limits"], LIMITS)
        self.assertEqual(reg["library"]["version"], "1.5.0")

    def test_witness_verify_passes_both_records_and_the_observation(self):
        self.ff.set(URL, post_page(REAL))
        out1, p1 = self.check(post_request())
        self.ff.set(URL, post_page(other_handle()))
        out2, p2 = self.check(post_request(handle="atproto.com"))
        self.assertEqual((p1["outcome"], p2["outcome"]), ("SUPPORTED", "NOT_SUPPORTED"))
        d = pathlib.Path(tempfile.mkdtemp(prefix="cw-vpost-"))
        code, wk, _ = self.s.call("GET", "/.well-known/witness.json", key=None)
        (d / "keys.json").write_text(json.dumps(wk["key_list"]))
        (d / "m.tar.gz").write_bytes(tarball.build_methods_tarball())
        for i, out in enumerate((out1, out2)):
            (d / f"r{i}.json").write_text(json.dumps(out))
            buf = io.StringIO()
            rc = verify.main(["--envelope", str(d / f"r{i}.json"), "--keys", str(d / "keys.json"), "--methods", str(d / "m.tar.gz")],
                             out=buf)
            self.assertEqual(rc, 0, buf.getvalue())
            self.assertIn("PASS signature", buf.getvalue())
        oid = p1["evidence"][0]["observations"][0]
        row = self.s.storage.get_observation(oid)
        (d / "obs.json").write_text(json.dumps({"observation_id": oid, "envelope": row["envelope"]}))
        args = ["--envelope", str(d / "obs.json"), "--keys", str(d / "keys.json"), "--methods", str(d / "m.tar.gz")]
        for n, b in self.s.storage.get_observation_files(oid).items():
            (d / n).write_bytes(b)
            args += ["--evidence", str(d / n)]
        buf = io.StringIO()
        self.assertEqual(verify.main(args, out=buf), 0, buf.getvalue())
        self.assertIn("PASS observation-files", buf.getvalue())


class Vectors(unittest.TestCase):
    def test_vectors_cover_post_by_author_and_a_recorded_platform_json(self):
        doc = json.loads((pathlib.Path(methods.__file__).resolve().parent.parent / "vectors" / "vectors.json").read_text())
        cases = [t for t in doc["templates"] if t["method"] == "post.by-author"]
        got = {(t["finding"] or t["reason"], t["assertion"]) for t in cases}
        for want in (("author-verified", True), ("author-verified", False), ("author-differs", True), ("author-differs", False),
                     ("handle-unresolved", True), ("signature-unverifiable", True), ("method-not-applicable", True)):
            self.assertIn(want, got)
        recorded = [t for t in cases if t["evidence"][0].get("kind") == "observation"
                    and base64.b64decode(t["evidence"][0]["files_b64"]["platform.json"]) == (FIX / "platform-bsky.app.json").read_bytes()]
        self.assertTrue(recorded, "one vector decides over the recorded platform.json byte for byte")


if __name__ == "__main__":
    unittest.main()
