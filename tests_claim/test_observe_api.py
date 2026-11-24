"""B2b (b, c, g): POST /v1/observe and GET /v1/observations/{id}; `max_age` reuse of only the observations the reader may see
(public ones, or the same account's private ones); observation files kept 24 h; the free quota (50 fresh observations per
account per day, then 5 credits each; a reused observation is free; BD3)."""
import hashlib
import unittest

from claim_witness import ids, schemas, service
from tests_claim import helpers as h
from tests_claim.fakefetch import error, page, stack, url_item
from tests_claim.helpers import claim, request

U = "https://reuse.example/p"
B = "dev-key-b-0123456789abcdef"


class Base(unittest.TestCase):
    overrides = {}

    def setUp(self):
        self.s, self.ff, self.sleeper = stack(**self.overrides)
        self.ff.set(U, page())

    def tearDown(self):
        self.s.close()
        self.ff.close()

    def observe(self, url=U, visibility="public", key="dev-key-a-0123456789abcdef", **extra):
        body = {"url": url, "capture": "page", "visibility": visibility}
        body.update(extra)
        return self.s.call("POST", "/v1/observe", body, key=key)

    def live(self, visibility="public", max_age=None, key="dev-key-a-0123456789abcdef"):
        code, out, _ = self.s.witness_call(request(claim("page.live", {"url": U}), [url_item(U, max_age=max_age)], visibility), key=key)
        self.assertEqual(code, 200, out)
        return out, (out.get("disclosure") or {}).get("body") or h.payload_of(out["envelope"])["predicate"]


class Observe(Base):
    def test_public_observe_signs_and_stores_an_observation(self):
        code, out, _ = self.observe()
        self.assertEqual(code, 200, out)
        oid = out["observation_id"]
        self.assertEqual(oid, ids.record_id(h.payload_bytes(out["envelope"])))
        stmt = h.payload_of(out["envelope"])
        self.assertEqual(stmt["predicateType"], schemas.OBSERVATION_TYPE)
        self.assertEqual(stmt["subject"][0]["name"], U)
        self.assertEqual(self.s.storage.signing_log()[-1]["payload_id"], oid)
        self.assertFalse(out["reused"])
        self.assertEqual(out["price"]["credits"], 0)
        code, got, _ = self.s.call("GET", f"/v1/observations/{oid}", key=B)
        self.assertEqual(code, 200, got)
        self.assertEqual(got["envelope"], out["envelope"])
        names = {f["name"] for f in stmt["predicate"]["files"]}
        self.assertIn("text.canonical.txt", got["files"])
        self.assertEqual(set(got["files"]), names)
        req_ = __import__("urllib.request").request.Request(self.s.url(f"/v1/observations/{oid}/files/text.canonical.txt"))
        with __import__("urllib.request").request.urlopen(req_, timeout=10) as r:
            data = r.read()
        want = [f["sha256"] for f in stmt["predicate"]["files"] if f["name"] == "text.canonical.txt"][0]
        self.assertEqual(hashlib.sha256(data).hexdigest(), want)

    def test_private_observe_returns_a_disclosure_and_is_owner_only(self):
        code, out, _ = self.observe(visibility="private")
        self.assertEqual(code, 200, out)
        self.assertEqual(out["disclosure"]["body"]["requested_url"], U)
        oid = out["observation_id"]
        self.assertEqual(self.s.call("GET", f"/v1/observations/{oid}", key=B)[0], 404)
        self.assertEqual(self.s.call("GET", f"/v1/observations/{oid}/files/response.body", key=B)[0], 404)
        self.assertEqual(self.s.call("GET", f"/v1/observations/{oid}/files/response.body", key=None)[0], 404)
        code, got, _ = self.s.call("GET", f"/v1/observations/{oid}")
        self.assertEqual(code, 200)
        self.assertEqual(got["body"]["requested_url"], U)

    def test_a_failed_fetch_signs_nothing(self):
        self.ff.set(U, error("timeout", "wall time"))
        n = self.s.log_count()
        code, out, _ = self.observe()
        self.assertEqual((code, out["error"]), (422, "timeout"))
        self.assertEqual(self.s.log_count(), n)

    def test_bad_observe_requests(self):
        for body in ({"url": "ftp://x.example/"}, {"url": U, "capture": "post"}, {"url": U, "extra": 1}, {"url": U, "max_age": -1},
                     {"url": U, "visibility": "secret"}, {}):
            code, out, _ = self.s.call("POST", "/v1/observe", body)
            self.assertEqual(code, 422, body)
        self.assertEqual(self.s.call("POST", "/v1/observe", {"url": U}, key=None)[0], 401)

    def test_observation_files_go_after_24h(self):
        code, out, _ = self.observe()
        oid = out["observation_id"]
        self.s.clock.advance(service.DAY + 1)
        self.s.witness.purge()
        self.assertEqual(self.s.call("GET", f"/v1/observations/{oid}")[0], 404)
        self.assertEqual(self.s.storage.get_observation_files(oid), {})
        self.assertIn(oid, [r["payload_id"] for r in self.s.storage.signing_log()])  # the log row and leaf stay


class Reuse(Base):
    def test_max_age_reuses_a_public_observation_for_free(self):
        code, first, _ = self.observe()
        self.s.clock.advance(100)
        out, p = self.live(max_age=3600)
        self.assertEqual(len(self.ff.calls), 1)
        self.assertEqual(p["evidence"][0]["observations"], [first["observation_id"]])
        self.assertEqual(p["outcome"], "SUPPORTED")
        self.assertEqual((out["price"]["credits"], out["price"]["fresh_observations"], out["price"]["reused_observations"]), (0, 0, 1))

    def test_max_age_older_than_the_observation_fetches_fresh(self):
        self.observe()
        self.s.clock.advance(100)
        out, p = self.live(max_age=50)
        self.assertEqual(len(self.ff.calls), 2)
        self.assertEqual(out["price"]["fresh_observations"], 1)

    def test_max_age_zero_is_fresh(self):
        self.observe()
        self.live()
        self.live(max_age=0)
        self.assertEqual(len(self.ff.calls), 3)

    def test_another_accounts_private_observation_is_never_reused(self):
        self.observe(visibility="private")
        out, p = self.live(visibility="private", max_age=3600, key=B)
        self.assertEqual(len(self.ff.calls), 2)

    def test_own_private_observation_is_reused_by_a_private_claim_not_a_public_one(self):
        code, mine, _ = self.observe(visibility="private")
        out, p = self.live(visibility="private", max_age=3600)
        self.assertEqual(len(self.ff.calls), 1)
        self.assertEqual(p["evidence"][0]["observations"], [mine["observation_id"]])
        self.live(visibility="public", max_age=3600)
        self.assertEqual(len(self.ff.calls), 2)

    def test_a_public_observation_is_reused_by_another_account(self):
        code, pub, _ = self.observe()
        out, p = self.live(visibility="private", max_age=3600, key=B)
        self.assertEqual(len(self.ff.calls), 1)
        self.assertEqual(p["evidence"][0]["observations"], [pub["observation_id"]])

    def test_observe_itself_reuses_with_max_age(self):
        code, a, _ = self.observe()
        code, b, _ = self.observe(max_age=600)
        self.assertTrue(b["reused"])
        self.assertEqual(b["observation_id"], a["observation_id"])
        self.assertEqual(b["price"]["credits"], 0)
        self.assertEqual(len(self.ff.calls), 1)


class Quota(Base):
    overrides = {"free_observations_per_day": 2}

    def test_defaults_are_bd3(self):
        cfg = service.Config(witness_id="w", attempt_key=b"A" * 32, master_key=b"M" * 32)
        self.assertEqual((cfg.free_observations_per_day, cfg.observation_price), (50, 5))

    def test_free_then_paid_then_free_again_tomorrow(self):
        prices = [self.observe()[1]["price"]["credits"] for _ in range(3)]
        self.assertEqual(prices, [0, 0, 5])
        out, _ = self.live()
        self.assertEqual(out["price"]["credits"], 5)
        self.assertEqual(out["price"]["free_left_today"], 0)
        out, _ = self.live(max_age=3600)
        self.assertEqual(out["price"]["credits"], 0)  # reused: free
        self.assertEqual(self.observe(key=B)[1]["price"]["credits"], 0)  # per account
        self.s.clock.advance(service.DAY)
        self.assertEqual(self.observe()[1]["price"]["credits"], 0)

    def test_methods_registry_publishes_the_observation_price(self):
        code, reg, _ = self.s.call("GET", "/v1/methods", key=None)
        self.assertEqual(reg["observations"], {"free_per_day": 2, "price": 5})


class FiftyFree(unittest.TestCase):
    def test_the_51st_fresh_observation_of_a_day_costs_5(self):
        s, ff, _ = stack()
        try:
            ff.set(U, page())
            prices = [s.call("POST", "/v1/observe", {"url": U})[1]["price"]["credits"] for _ in range(51)]
            self.assertEqual(prices, [0] * 50 + [5])
        finally:
            s.close()
            ff.close()


if __name__ == "__main__":
    unittest.main()
