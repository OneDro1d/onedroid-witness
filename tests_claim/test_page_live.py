"""B2b (d): `page.live` per SPEC §4 through the real API and a fake fetcher (TS-3, VR-6). live = 2xx with visible canonical
text; not-live = 404/410 on the exact URL, or NXDOMAIN from two resolvers, each confirmed by a second fetch at least 60 s
later (the delay is configurable; the job answers 202 while it waits); 401/403/429, a challenge page, 5xx, a timeout or a
connection error give no finding (blocked, unreachable, timeout). A failed fetch never yields NOT_SUPPORTED, and a fetch
failure is never a 5xx."""
import io
import json
import pathlib
import tempfile
import unittest

from claim_witness import schemas, tarball, verify
from tests_claim import helpers as h
from tests_claim.fakefetch import FakeFetcher, Resolver, error, page, stack, url_item, wait_job
from tests_claim.helpers import claim, request

U = "https://site.example/a"
T_TEMPLATE = "{url} was live when observed at {fetched_at}."
F_TEMPLATE = "{url} was not live when observed at {fetched_at}."
LIMITS = "Live means a 2xx answer with visible text from the witness's network at that time."


def live_request(url=U, assertion=True, visibility="public", evidence_url=None, **opts):
    return request(claim("page.live", {"url": url}, assertion), [url_item(evidence_url or url)], visibility, **opts)


class Base(unittest.TestCase):
    resolvers = None

    def setUp(self):
        self.s, self.ff, self.sleeper = stack(resolvers=self.resolvers)

    def tearDown(self):
        self.s.close()
        self.ff.close()

    def check(self, body, **kw):
        code, out, _ = self.s.witness_call(body, **kw)
        self.assertEqual(code, 200, out)
        return out, h.payload_of(out["envelope"])["predicate"]


class Live(Base):
    def test_live_supported_with_template_detail_and_observation(self):
        self.ff.set(U, page())
        out, p = self.check(live_request())
        self.assertEqual((p["finding"], p["outcome"], p["reason"]), ("live", "SUPPORTED", "live"))
        self.assertEqual(p["statement"], T_TEMPLATE.format(url=U, fetched_at=h.iso(self.s.clock())))
        self.assertEqual(p["limits"], LIMITS)
        self.assertEqual(p["detail"]["status"], 200)
        self.assertGreater(p["detail"]["text_chars"], 0)
        self.assertEqual(p["method"]["id"], "page.live")
        self.assertEqual(p["method"]["code_sha256"], tarball.methods_code_sha256())
        self.assertEqual(len(p["evidence"]), 1)
        ev = p["evidence"][0]
        self.assertEqual((ev["slot"], ev["kind"], ev["url"], ev["capture"]), ("page", "url", U, "page"))
        self.assertEqual(len(ev["observations"]), 1)
        oid = ev["observations"][0]
        self.assertEqual(p["relied_on"], [{"id": oid, "kind": "observation", "signer": self.s.key_id, "trusted": True}])
        log = self.s.storage.signing_log()
        self.assertEqual([r["predicate_type"] for r in log[-2:]], [schemas.OBSERVATION_TYPE, schemas.CLAIM_TYPE])
        self.assertEqual(log[-2]["payload_id"], oid)
        self.assertEqual(self.ff.urls_called(), [U])
        self.assertEqual(out["price"]["credits"], 0)
        self.assertEqual(out["price"]["fresh_observations"], 1)

    def test_assertion_false_on_a_live_page_is_not_supported(self):
        self.ff.set(U, page())
        _, p = self.check(live_request(assertion=False))
        self.assertEqual((p["finding"], p["outcome"]), ("live", "NOT_SUPPORTED"))
        self.assertEqual(p["statement"], F_TEMPLATE.format(url=U, fetched_at=h.iso(self.s.clock())))

    def test_2xx_without_visible_text_is_no_finding(self):
        self.ff.set(U, page(b"<html><body><div hidden>x</div><script>1</script></body></html>"))
        _, p = self.check(live_request())
        self.assertEqual((p["finding"], p["outcome"], p["reason"]), (None, "CANNOT_WITNESS", "unreadable"))

    def test_the_evidence_url_must_be_the_claimed_url(self):
        code, out, _ = self.s.witness_call(live_request(evidence_url="https://other.example/"))
        self.assertEqual((code, out["error"]), (422, "wrong-evidence-slots"))

    def test_invalid_url_params_422(self):
        for bad in ("ftp://site.example/", "https:///nohost", "not a url", "https://site.example/" + "a" * 5000, ""):
            code, out, _ = self.s.witness_call(live_request(url=bad, evidence_url=bad or "x"))
            self.assertEqual(code, 422, bad)
        self.assertEqual(self.ff.calls, [])

    def test_post_capture_and_object_evidence_are_refused(self):
        body = request(claim("page.live", {"url": U}), [url_item(U, capture="post")], "public")
        self.assertEqual(self.s.witness_call(body)[0], 422)
        body = request(claim("page.live", {"url": U}), [h.obj_item("page", b"<p>x</p>")], "public")
        self.assertEqual(self.s.witness_call(body)[0], 422)
        body = request(claim("page.live", {"url": U}), [dict(url_item(U), max_age=-1)], "public")
        self.assertEqual(self.s.witness_call(body)[0], 422)

    def test_statement_is_refused_on_page_live(self):
        body = live_request()
        body["claim"]["statement"] = "it is live"
        self.assertEqual(self.s.witness_call(body)[1]["error"], "statement-not-allowed")

    def test_public_url_with_personal_data_is_refused(self):
        url = "https://site.example/?mail=jane.doe@example.org"
        code, out, _ = self.s.witness_call(live_request(url=url))
        self.assertEqual((code, out["error"]), (422, "personal-data"))
        self.assertEqual(self.ff.calls, [])

    def test_private_page_live_makes_a_private_observation(self):
        self.ff.set(U, page())
        out, p = self.check(live_request(visibility="private"))
        self.assertEqual(p["visibility"], "private")
        self.assertEqual(p["outcome"], "SUPPORTED")
        body = out["disclosure"]["body"]
        oid = body["evidence"][0]["observations"][0]
        obs_log = [r for r in self.s.storage.signing_log() if r["payload_id"] == oid]
        self.assertEqual(obs_log[0]["predicate_type"], schemas.OBSERVATION_TYPE)
        raw = h.payload_bytes(out["envelope"]).decode()
        self.assertNotIn("site.example", raw)
        row = self.s.storage.get_observation(oid)
        self.assertEqual(row["visibility"], "private")
        obs_pred = h.payload_of(row["envelope"])["predicate"]
        self.assertEqual(set(obs_pred), {"visibility", "body_commitment", "fetched_at", "fetcher"})

    def test_attempts_count_requested_urls(self):
        self.ff.set(U, page())
        _, p1 = self.check(live_request())
        _, p2 = self.check(live_request())
        self.assertEqual((p1["attempt"]["n"], p2["attempt"]["n"]), (1, 2))
        self.assertEqual(p2["attempt"]["prior"]["SUPPORTED"], 1)

    def test_agent_signature_covers_the_requested_url_and_verifies(self):
        self.ff.set(U, page())
        aseed = h.seed(40)
        code, reg, _ = self.s.call("POST", "/v1/agent-keys", {"public_key": h.b64(h.public_of(aseed))})
        body = live_request()
        body["agent"] = h.agent_block(aseed, reg["agent_key_id"], "witness:test", body["claim"], body["evidence"],
                                      "nonce-live-00001", h.iso(self.s.clock()))
        out, p = self.check(body)
        self.assertEqual(p["submitter"]["agent_key_id"], reg["agent_key_id"])
        d = pathlib.Path(tempfile.mkdtemp())
        (d / "a.json").write_text(json.dumps(out))
        code, wk, _ = self.s.call("GET", "/.well-known/witness.json", key=None)
        (d / "keys.json").write_text(json.dumps(wk["key_list"]))
        (d / "ak.json").write_text(json.dumps({"agent_key_id": reg["agent_key_id"], "public_key": h.b64(h.public_of(aseed))}))
        buf = io.StringIO()
        rc = verify.main(["--envelope", str(d / "a.json"), "--keys", str(d / "keys.json"), "--agent-key", str(d / "ak.json")], out=buf)
        self.assertEqual(rc, 0, buf.getvalue())
        self.assertIn("PASS agent-signature", buf.getvalue())
        self.assertIn("SKIP method-rerun", buf.getvalue())


class NotLive(Base):
    def test_404_confirmed_after_60s_is_not_live(self):
        self.ff.set(U, page(b"<h1>Not found</h1>", status=404))
        out, p = self.check(live_request(wait=30))
        self.assertEqual((p["finding"], p["outcome"], p["reason"]), ("not-live", "NOT_SUPPORTED", "not-live"))
        self.assertEqual(len(self.ff.calls), 2)
        self.assertGreaterEqual(self.ff.calls[1]["at"] - self.ff.calls[0]["at"], 60)
        self.assertEqual(sum(self.sleeper.calls), 60)
        self.assertEqual(p["detail"]["status"], 404)
        self.assertGreaterEqual(p["detail"]["confirm_after_s"], 60)
        ev = p["evidence"][0]
        self.assertEqual(len(ev["observations"]), 2)
        self.assertEqual({r["id"] for r in p["relied_on"]}, set(ev["observations"]))
        self.assertEqual(p["statement"], T_TEMPLATE.format(url=U, fetched_at=h.iso(self.s.clock())))
        self.assertEqual(out["price"]["fresh_observations"], 2)

    def test_404_with_assertion_false_is_supported_with_the_f_template(self):
        self.ff.set(U, page(status=404))
        _, p = self.check(live_request(assertion=False, wait=30))
        self.assertEqual((p["finding"], p["outcome"]), ("not-live", "SUPPORTED"))
        self.assertEqual(p["statement"], F_TEMPLATE.format(url=U, fetched_at=h.iso(self.s.clock())))

    def test_410_is_not_live(self):
        self.ff.set(U, page(status=410))
        _, p = self.check(live_request(wait=30))
        self.assertEqual(p["finding"], "not-live")

    def test_404_then_200_is_not_confirmed(self):
        self.ff.set(U, page(status=404), page())
        _, p = self.check(live_request(wait=30))
        self.assertEqual((p["finding"], p["outcome"], p["reason"]), (None, "CANNOT_WITNESS", "undecided"))

    def test_404_after_a_redirect_is_not_on_the_exact_url(self):
        self.ff.set(U, page(status=404, final_url="https://site.example/elsewhere",
                            redirects=[{"url": U, "status": 301, "location": "https://site.example/elsewhere"}]))
        _, p = self.check(live_request(wait=30))
        self.assertEqual((p["finding"], p["reason"]), (None, "unreachable"))
        self.assertEqual(len(self.ff.calls), 1)

    def test_the_job_answers_202_while_it_waits(self):
        self.ff.set(U, page(status=404))
        self.sleeper.gate.clear()
        code, out, _ = self.s.witness_call(live_request(wait=1))
        self.assertEqual(code, 202, out)
        self.sleeper.gate.set()
        job = wait_job(self.s, out["job_id"])
        self.assertEqual(job["state"], "done", job)
        p = h.payload_of(job["answer"]["envelope"])["predicate"]
        self.assertEqual(p["finding"], "not-live")

    def test_the_delay_is_configurable(self):
        self.s.close()
        self.ff.close()
        self.s, self.ff, self.sleeper = stack(confirm_delay_s=5)
        self.ff.set(U, page(status=404))
        _, p = self.check(live_request(wait=30))
        self.assertEqual(self.sleeper.calls, [5])
        self.assertEqual(p["finding"], "not-live")


class NxDomain(Base):
    def setUp(self):
        self.r1, self.r2 = Resolver(), Resolver()
        self.resolvers = [self.r1, self.r2]
        super().setUp()

    def test_nxdomain_from_two_resolvers_confirmed_is_not_live(self):
        self.ff.set(U, error("unreachable", "host-not-found site.example"))
        _, p = self.check(live_request(wait=30))
        self.assertEqual((p["finding"], p["outcome"]), ("not-live", "NOT_SUPPORTED"))
        self.assertEqual(p["detail"]["dns"], "nxdomain")
        self.assertEqual(p["detail"]["resolvers"], 2)
        self.assertGreaterEqual(p["detail"]["confirm_after_s"], 60)
        self.assertEqual(len(self.ff.calls), 2)
        self.assertEqual(self.r1.asked, ["site.example", "site.example"])
        self.assertEqual(self.r2.asked, ["site.example", "site.example"])
        self.assertEqual(p["evidence"][0]["observations"], [])
        self.assertEqual(p["relied_on"], [])

    def test_one_resolver_that_finds_the_name_is_unreachable(self):
        self.r2.default = "exists"
        self.ff.set(U, error("unreachable", "host-not-found site.example"))
        _, p = self.check(live_request(wait=30))
        self.assertEqual((p["finding"], p["outcome"], p["reason"]), (None, "CANNOT_WITNESS", "unreachable"))
        self.assertEqual(len(self.ff.calls), 1)

    def test_a_resolver_error_is_unreachable(self):
        self.r1.default = "error"
        self.ff.set(U, error("unreachable", "host-not-found site.example"))
        _, p = self.check(live_request(wait=30))
        self.assertEqual(p["reason"], "unreachable")


class NoFinding(Base):
    def outcome(self, answer, assertion=True):
        self.ff.set(U, answer)
        _, p = self.check(live_request(assertion=assertion, wait=30))
        return p

    def test_http_statuses_give_no_finding(self):
        for status, reason in ((401, "blocked"), (403, "blocked"), (429, "blocked"), (500, "unreachable"), (503, "unreachable")):
            for assertion in (True, False):
                p = self.outcome(page(status=status), assertion)
                self.assertEqual((p["finding"], p["outcome"], p["reason"]), (None, "CANNOT_WITNESS", reason), status)
                self.assertEqual(p["detail"]["status"], status)

    def test_a_challenge_page_is_blocked(self):
        challenge = (b"<html><head><title>Just a moment...</title></head><body><p>Checking your browser before accessing "
                     b"site.example.</p><div id='challenge-platform'></div></body></html>")
        for status in (200, 403, 503):
            p = self.outcome(page(challenge, status=status))
            self.assertEqual((p["finding"], p["reason"]), (None, "blocked"), status)

    def test_fetch_failures_map_to_reasons_never_not_supported(self):
        cases = (("timeout", "timeout"), ("blocked", "blocked"), ("robots-disallowed", "robots-disallowed"),
                 ("too-large", "too-large"), ("unreachable", "unreachable"))
        for code, reason in cases:
            for assertion in (True, False):
                p = self.outcome(error(code, "x"), assertion)
                self.assertEqual((p["finding"], p["outcome"], p["reason"]), (None, "CANNOT_WITNESS", reason), code)
                self.assertEqual(p["detail"]["fetch_error"], code)

    def test_partial_manifest_is_recorded_in_detail(self):
        partial = {"requested_url": U, "redirects": [{"url": U, "status": 302, "location": "http://169.254.169.254/"}],
                   "fetched_at": h.iso(self.s.clock()), "fetch_ms": 30, "resolved_ips": [], "robots": "allowed"}
        p = self.outcome(error("blocked", "redirect to a refused address", manifest=partial))
        self.assertEqual((p["reason"], p["detail"]["redirects"], p["detail"]["robots"]), ("blocked", 1, "allowed"))
        self.assertNotIn("169.254", json.dumps(p))

    def test_fetcher_down_is_a_signed_cannot_witness(self):
        self.s.close()
        self.ff.close()
        from claim_witness import fetcher
        self.s, self.ff, self.sleeper = stack(fetcher=fetcher.FetcherClient("http://127.0.0.1:1", "x" * 20, busy_delay_s=0))
        code, out, _ = self.s.witness_call(live_request())
        self.assertEqual(code, 200, out)
        p = h.payload_of(out["envelope"])["predicate"]
        self.assertEqual((p["outcome"], p["reason"], p["detail"]["fetch_error"]), ("CANNOT_WITNESS", "unreachable", "fetcher-unavailable"))
        self.assertEqual(out["price"]["credits"], 0)


class NoFetcherConfigured(unittest.TestCase):
    def test_without_a_fetcher_url_evidence_is_503_and_nothing_signed(self):
        s = h.Stack()
        try:
            n = s.log_count()
            code, out, _ = s.witness_call(live_request())
            self.assertEqual((code, out["error"]), (503, "fetcher-not-configured"))
            self.assertEqual(s.log_count(), n)
        finally:
            s.close()


if __name__ == "__main__":
    unittest.main()
