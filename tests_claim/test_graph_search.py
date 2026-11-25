"""B7: the record graph (W3C PROV-O edges, GET /v1/records/{id}/graph) and search (GET /v1/search), through the real HTTP API on
memory storage (and again on real Postgres in test_graph_search_pg.py).

Graph (SPEC §3, §10 VR-10 and VR-20, §11 TS-6 and TS-15): when a record is signed the witness writes PROV-O edges from it to
what it relied on (`used` an observation, `wasAttributedTo` the witness and, for a public record, its agent, `wasDerivedFrom`
a disclosed record: the B5b hook). An edge takes the visibility of its most private end. A reader sees the public nodes and
edges and their own private ones; another account's private node, edge or count is never visible (an answer with and without
it is byte-identical), and no account id or agent key reaches a non-owner.

Search: Postgres full text (a tsvector) over public kept records, a safe query parser, filters outcome / method / since (422 on
a bad value), pagination, the reader's own private records listed (never content-matched), and an explicit answer for
mode=semantic|hybrid when no embedder is configured."""
import json
import unittest

try:
    from claim_witness import graph as graph_mod
    from claim_witness import search as search_mod
except ImportError:  # RED: the modules do not exist yet, so each test fails on its own
    graph_mod = search_mod = None
from tests_claim import helpers as h
from tests_claim.fakefetch import page, stack
from tests_claim.helpers import claim, obj_item, request

A, B = "dev-key-a-0123456789abcdef", "dev-key-b-0123456789abcdef"
OP = "dev-key-op-0123456789abcdef"
U1, U2, U3 = "https://graph.example/one", "https://graph.example/two", "https://graph.example/three"
HTML = b"<html><body><h1>Graph</h1><p>The text the page shows.</p></body></html>"
CANARY = "Zbigniewcanary7Q"
PRIVATE_OBS_CANARY = "Privateobservationcanary9K"


class Base:
    """self.make_storage() gives a fresh storage; self.s is a Stack with a fake fetcher."""

    embedder = None

    def make_storage(self):
        return None

    def setUp(self):
        clock = h.Clock()
        extra = {"embedder": self.embedder} if self.embedder is not None else {}
        self.s, self.ff, _ = stack(clock=clock, storage=self.make_storage(), operator_accounts=["acct_op"],
                                   link_base="https://evidence.example", **extra)
        self.s.auth.dev_keys.mapping[OP] = "acct_op"
        for u, body in ((U1, HTML), (U2, HTML + b"2"), (U3, HTML + b"3")):
            self.ff.set(u, page(body))
        self.n = 0

    def tearDown(self):
        self.s.close()
        self.ff.close()

    # ---------------------------------------------------------------------------------------------------- helpers

    def observe(self, url=U1, visibility="public", key=A):
        code, out, _ = self.s.call("POST", "/v1/observe", {"url": url, "capture": "page", "visibility": visibility}, key=key)
        self.assertEqual(code, 200, out)
        return out["observation_id"]

    def check(self, oid=None, visibility="public", key=A, statement=None, label=None, agent=False):
        self.n += 1
        # A mechanical method has no free statement: its text is the template. Over an observation: match.text (the page url
        # is in the template). Without one: quote.in-source, whose params carry the words the search tests look for.
        if oid is not None:
            ev = [obj_item("submitted", HTML + b"<!-- %d -->" % self.n, "text/html", "copy.html"), {"slot": "page", "kind": "observation", "id": oid}]
            c = claim("match.text", {}, True, None)
        else:
            phrase = statement or f"statement number {self.n} is documented"
            ev = [obj_item("source", phrase.encode("utf-8"), "text/plain", "source.txt")]
            c = claim("quote.in-source", {"quote": phrase}, True, None)
        body = request(c, ev, visibility)
        if label:
            body["label"] = label
        if agent:
            seed = h.seed(40 + self.n)
            code, reg, _ = self.s.call("POST", "/v1/agent-keys", {"public_key": h.b64(h.public_of(seed))}, key=key)
            body["agent"] = h.agent_block(seed, reg["agent_key_id"], "witness:test", c, ev, f"nonce-b7-{self.n}", h.iso(self.s.clock()))
            self.agent = {"agent_key_id": reg["agent_key_id"], "agent": reg["agent"], "public_key": h.b64(h.public_of(seed))}
        code, out, _ = self.s.witness_call(body, key=key)
        self.assertEqual(code, 200, out)
        return out

    def keep(self, out, key=A):
        body = {"envelope": out["envelope"]}
        if "disclosure" in out:
            body["disclosure"] = out["disclosure"]
        code, k, _ = self.s.call("POST", f"/v1/records/{out['record_id']}/keep", body, key=key)
        self.assertEqual(code, 200, k)
        return k

    def graph(self, rid, key=None, depth=None, token=None):
        q = []
        if depth is not None:
            q.append(f"depth={depth}")
        if token:
            q.append(f"token={token}")
        return self.s.call("GET", f"/v1/records/{rid}/graph" + ("?" + "&".join(q) if q else ""), key=key)

    def search(self, key=None, **params):
        import urllib.parse
        qs = urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})
        return self.s.call("GET", "/v1/search" + ("?" + qs if qs else ""), key=key)

    @staticmethod
    def ids_of(g):
        return {n["id"] for n in g["nodes"]}

    @staticmethod
    def edge_set(g, rel=None):
        return {(e["from"], e["to"], e["rel"]) for e in g["edges"] if rel is None or e["rel"] == rel}

    def result_ids(self, res):
        return [r["record_id"] for r in res["records"]]

    def assert_clean(self, obj, *needles):
        """The grep of a non-owner answer: no account id, agent key, key name or private canary."""
        text = json.dumps(obj)
        for n in ("acct_a", "acct_b", "acct_op", "ak_", "agent_key_id", "agent_sig", "dev-key-", CANARY, PRIVATE_OBS_CANARY) + needles:
            self.assertNotIn(n, text)


class GraphEdges(Base):
    def test_ts6_six_records_over_two_observations(self):
        o1, o2 = self.observe(U1), self.observe(U2)
        r = [self.check(o1) for _ in range(3)] + [self.check(o2) for _ in range(3)]
        rid = [x["record_id"] for x in r]
        code, g, _ = self.graph(rid[0], depth=2)
        self.assertEqual(code, 200, g)
        self.assertEqual(g["model"], "W3C PROV-O")
        self.assertEqual(g["root"], rid[0])
        self.assertEqual(g["depth"], 2)
        self.assertFalse(g["truncated"])
        self.assertEqual({rid[0], rid[1], rid[2], o1} <= self.ids_of(g), True)
        self.assertFalse({rid[3], rid[4], rid[5], o2} & self.ids_of(g))
        self.assertEqual(self.edge_set(g, "prov:used"), {(rid[i], o1, "prov:used") for i in range(3)})
        code, g2, _ = self.graph(o2, depth=1)
        self.assertEqual(self.edge_set(g2, "prov:used"), {(rid[i], o2, "prov:used") for i in range(3, 6)})
        self.assertFalse({rid[0], rid[1], rid[2], o1} & self.ids_of(g2))
        nodes = {n["id"]: n for n in g["nodes"]}
        self.assertEqual(nodes[o1]["kind"], "observation")
        self.assertEqual(nodes[rid[0]]["kind"], "record")
        self.assertEqual(nodes[rid[0]]["outcome"], h.payload_of(r[0]["envelope"])["predicate"]["outcome"])
        self.assertEqual(nodes[rid[0]]["method"], "match.text")

    def test_every_record_is_attributed_to_the_witness_and_a_public_one_to_its_agent(self):
        out = self.check(agent=True)
        code, g, _ = self.graph(out["record_id"])
        self.assertEqual(code, 200, g)
        wit = [n for n in g["nodes"] if n["kind"] == "witness"]
        self.assertEqual([n["id"] for n in wit], ["witness:test"])
        self.assertIn((out["record_id"], "witness:test", "prov:wasAttributedTo"), self.edge_set(g))
        self.assertIn((out["record_id"], self.agent["agent"], "prov:wasAttributedTo"), self.edge_set(g))
        text = json.dumps(g)
        self.assertNotIn(self.agent["agent_key_id"], text)  # no agent key id, no public key, no account
        self.assertNotIn(self.agent["public_key"], text)
        self.assertNotIn("acct_a", text)

    def test_the_witness_node_is_a_leaf(self):
        a, b = self.check(), self.check()
        code, g, _ = self.graph(a["record_id"], depth=5)
        self.assertNotIn(b["record_id"], self.ids_of(g))  # two records are not "connected" by the witness that signed both

    def test_was_derived_from_hook(self):
        base = self.check()
        derived = "c" * 64
        pred = {"evidence": [{"slot": "prior", "kind": "record", "id": base["record_id"]}], "relied_on": [],
                "method": {"id": "judge.supports"}, "outcome": "SUPPORTED", "witnessed_at": h.iso(self.s.clock()),
                "submitter": {"account": "acct_a"}, "witness": {"id": "witness:test"}}
        self.s.witness.graph.record_signed(derived, pred, "public", "acct_a")
        code, g, _ = self.graph(derived)
        self.assertEqual(code, 200, g)
        self.assertIn((derived, base["record_id"], "prov:wasDerivedFrom"), self.edge_set(g))
        self.assertIn(base["record_id"], self.ids_of(g))

    def test_record_signing_twice_writes_one_edge(self):
        o = self.observe()
        out = self.check(o)
        pred = h.payload_of(out["envelope"])["predicate"]
        self.s.witness.graph.record_signed(out["record_id"], pred, "public", "acct_a")  # again: idempotent
        code, g, _ = self.graph(out["record_id"])
        self.assertEqual(len(g["edges"]), len({(e["from"], e["to"], e["rel"]) for e in g["edges"]}))


class GraphDepth(Base):
    def test_depth_bounds(self):
        o = self.observe()
        a, b = self.check(o), self.check(o)
        code, g, _ = self.graph(a["record_id"], depth=0)
        self.assertEqual((code, self.ids_of(g)), (200, {a["record_id"]}))
        self.assertEqual(g["edges"], [])
        code, g1, _ = self.graph(a["record_id"], depth=1)
        self.assertNotIn(b["record_id"], self.ids_of(g1))
        code, g2, _ = self.graph(a["record_id"])  # the default is 2
        self.assertEqual(g2["depth"], 2)
        self.assertIn(b["record_id"], self.ids_of(g2))
        code, g5, _ = self.graph(a["record_id"], depth=graph_mod.MAX_DEPTH)
        self.assertEqual(code, 200)
        for bad in (graph_mod.MAX_DEPTH + 1, 99, -1, "x", "1.5", ""):
            code, got, _ = self.graph(a["record_id"], depth=bad)
            self.assertEqual(code, 422, (bad, got))

    def test_node_cap_sets_truncated_from_what_the_reader_can_see(self):
        o = self.observe()
        for _ in range(5):
            self.check(o)
        old = graph_mod.MAX_NODES
        graph_mod.MAX_NODES = 4
        try:
            code, g, _ = self.graph(o, depth=1)
        finally:
            graph_mod.MAX_NODES = old
        self.assertEqual(code, 200)
        self.assertLessEqual(len(g["nodes"]), 4)
        self.assertTrue(g["truncated"])
        code, g, _ = self.graph(o, depth=1)
        self.assertFalse(g["truncated"])


class GraphVisibility(Base):
    def test_ts15_another_accounts_private_record_over_a_shared_public_observation_is_invisible(self):
        o = self.observe(U1)
        ra = self.check(o, statement="public record by a")
        before = {k: self.graph(o, key=k)[1] for k in (None, A)}
        before_search = {k: self.search(key=k)[1] for k in (None, A)}
        rb = self.check(o, visibility="private", key=B, statement=f"{CANARY} private", label=f"label {CANARY}")
        self.keep(rb, key=B)
        for key in (None, A):
            code, g, _ = self.graph(o, key=key)
            self.assertEqual(code, 200, g)
            self.assertEqual(g, before[key])  # byte-identical: no node, edge, count or flag moved
            self.assertNotIn(rb["record_id"], json.dumps(g))
            self.assertIn(ra["record_id"], self.ids_of(g))
            self.assert_clean(g)
            code, res, _ = self.search(key=key)
            self.assertEqual(res, before_search[key])
            code, res, _ = self.search(key=key, q=CANARY.lower())
            self.assertEqual(res["records"], [])
            self.assert_clean(res)
        self.assertEqual(self.graph(rb["record_id"], key=None)[0], 404)
        self.assertEqual(self.graph(rb["record_id"], key=A)[0], 404)
        code, mine, _ = self.graph(o, key=B)
        self.assertIn(rb["record_id"], self.ids_of(mine))
        self.assertIn((rb["record_id"], o, "prov:used"), self.edge_set(mine))
        code, mine, _ = self.graph(rb["record_id"], key=B)
        self.assertEqual(code, 200, mine)
        for n in mine["nodes"]:
            if n["id"] == rb["record_id"]:
                self.assertEqual(n["visibility"], "private")

    def test_private_record_graph_needs_the_owner_or_a_share_token(self):
        o = self.observe()
        out = self.check(o, visibility="private", statement=f"{CANARY} moved")
        self.keep(out)
        rid = out["record_id"]
        code, g, _ = self.graph(rid, key=A)
        self.assertEqual(code, 200, g)
        self.assertEqual(self.ids_of(g), {rid, o, "witness:test"})
        self.assertEqual(self.graph(rid)[0], 404)
        self.assertEqual(self.graph(rid, key=B)[0], 404)
        self.assertEqual(self.graph(rid, token="wst_notatoken0000000000")[0], 403)
        code, sh, _ = self.s.call("POST", f"/v1/records/{rid}/shares", {}, key=A)
        code, g, _ = self.graph(rid, token=sh["token"])
        self.assertEqual(code, 200, g)
        self.assertIn(o, self.ids_of(g))
        self.assert_clean(g)
        self.assertEqual(self.graph(rid, key=B, token=sh["token"])[0], 200)
        # the token opens this record's graph, not another private record's
        other = self.check(o, visibility="private", statement="second")
        self.keep(other)
        self.assertEqual(self.graph(other["record_id"], token=sh["token"])[0], 403)
        # and the token holder does not see the owner's other private records around the shared observation
        code, g, _ = self.graph(o, token=sh["token"])
        self.assertNotIn(rid, self.ids_of(g))

    def test_a_private_edge_has_the_visibility_of_its_most_private_end(self):
        po = self.observe(U1, visibility="private")
        out = self.check(po, visibility="private", statement="over private obs")
        self.keep(out)
        pub = self.check(statement="public unrelated")
        code, g, _ = self.graph(out["record_id"], key=A)
        self.assertEqual(code, 200, g)
        self.assertIn(po, self.ids_of(g))
        self.assertEqual(self.graph(po)[0], 404)  # a private observation: same answer as an unknown id
        self.assertEqual(self.graph(po, key=B)[0], 404)
        code, g, _ = self.graph(po, key=A)
        self.assertEqual(code, 200, g)
        self.assertIn(out["record_id"], self.ids_of(g))
        code, g, _ = self.graph(pub["record_id"])
        self.assertNotIn(po, self.ids_of(g))

    def test_no_key_reads_and_bad_keys(self):
        o = self.observe()
        out = self.check(o)
        self.assertEqual(self.graph(out["record_id"], key=None)[0], 200)
        self.assertEqual(self.graph(o, key=None)[0], 200)
        code, got, _ = self.graph(out["record_id"], key="dev-key-nope-0123456789abcdef")
        self.assertEqual(code, 401)

    def test_unknown_and_malformed_ids_are_404(self):
        for rid in ("0" * 64, "a" * 63, "A" * 64, "nonsense", "witness:test"):
            code, got, _ = self.s.call("GET", f"/v1/records/{rid}/graph", key=None)
            self.assertEqual(code, 404, (rid, got))
        out = self.check()
        code, got, _ = self.graph("witness:test")
        self.assertEqual(code, 404)

    def test_public_answers_carry_no_account_or_key(self):
        out = self.check(agent=True)  # (helpers.agent_block does not sign observation ids: an agent check has object evidence)
        self.keep(out)
        for key in (None, B):
            code, g, _ = self.graph(out["record_id"], key=key)
            self.assertEqual(code, 200, g)
            text = json.dumps(g)
            for n in ("acct_a", "acct_b", self.agent["agent_key_id"], self.agent["public_key"], "dev-key-"):
                self.assertNotIn(n, text)
            self.assertFalse({"account", "owner", "hidden", "count", "n_hidden"} & set(g))
            for n in g["nodes"]:
                self.assertFalse({"account", "owner", "agent_key_id"} & set(n))

    def test_takedown_removes_the_record_from_others_graphs(self):
        o = self.observe()
        out = self.check(o)
        self.keep(out)
        stay = self.check(o)
        rid = out["record_id"]
        code, td, _ = self.s.call("POST", f"/v1/records/{rid}/takedown", {}, key=OP)
        self.assertEqual(code, 200, td)
        for key in (None, B):
            code, g, _ = self.graph(o, key=key)
            self.assertNotIn(rid, json.dumps(g))
            self.assertIn(stay["record_id"], self.ids_of(g))
            code, got, _ = self.graph(rid, key=key)
            self.assertEqual(code, 410, got)
        code, mine, _ = self.graph(rid, key=A)  # the owner still reads it, flagged
        self.assertEqual(code, 200, mine)
        node = [n for n in mine["nodes"] if n["id"] == rid][0]
        self.assertTrue(node["taken_down"])
        code, g, _ = self.graph(o, key=A)
        self.assertIn(rid, self.ids_of(g))

    def test_owner_delete_removes_the_private_edges_and_observations(self):
        po = self.observe(U1, visibility="private")
        o = self.observe(U2)
        out = self.check(po, visibility="private", statement=f"{CANARY} del")
        self.keep(out)
        out2 = self.check(o, visibility="private", statement="del two")
        self.keep(out2)
        rid, rid2 = out["record_id"], out2["record_id"]
        code, d, _ = self.s.call("DELETE", f"/v1/records/{rid}", key=A)
        self.assertEqual(code, 200, d)
        code, d, _ = self.s.call("DELETE", f"/v1/records/{rid2}", key=A)
        self.assertEqual(code, 200, d)
        self.assertEqual(self.graph(po, key=A)[0], 404)  # the private observation is deleted with the record
        code, g, _ = self.graph(rid, key=A)
        self.assertEqual(code, 200, g)
        self.assertEqual(g["edges"], [])
        self.assertEqual(self.ids_of(g), {rid})
        self.assertTrue(g["nodes"][0]["deleted"])
        code, g, _ = self.graph(o, key=A)
        self.assertNotIn(rid2, json.dumps(g))
        for key in (None, B):
            self.assertEqual(self.graph(rid, key=key)[0], 404)
            self.assertEqual(self.graph(rid2, key=key)[0], 404)
        self.assert_clean(self.graph(o)[1])
        self.assertNotIn(CANARY, json.dumps(self.graph(rid, key=A)[1]))


class GraphBackfill(Base):
    def snapshot(self, rids, keys=(None, A, B)):
        return {(r, k): self.graph(r, key=k, depth=3) for r in rids for k in keys}

    def test_records_signed_before_this_slice_get_their_edges_idempotently(self):
        o = self.observe(U1)
        po = self.observe(U2, visibility="private")
        pub = self.check(o)
        self.keep(pub)
        unkept = self.check(o)  # still within the job's 24 h: its answer holds the envelope
        priv = self.check(po, visibility="private", statement=f"{CANARY} old")
        self.keep(priv)
        rids = [pub["record_id"], unkept["record_id"], priv["record_id"], o, po]
        before = self.snapshot(rids)
        self.assertEqual(before[(rids[0], None)][0], 200)
        self.s.storage.clear_graph()
        self.assertEqual(self.graph(rids[0])[0], 404)  # nothing is there: this is a database from before the slice
        n1 = self.s.witness.graph.backfill()
        self.assertEqual(self.snapshot(rids), before)
        n2 = self.s.witness.graph.backfill()
        self.assertEqual(self.snapshot(rids), before)
        self.assertEqual(n2["edges"], n1["edges"])
        self.assertGreater(n1["edges"], 0)

    def test_backfill_skips_a_deleted_private_record_without_a_body(self):
        o = self.observe(U1)
        out = self.check(o, visibility="private", statement="to delete")
        self.keep(out)
        self.s.call("DELETE", f"/v1/records/{out['record_id']}", key=A)
        self.s.storage.clear_graph()
        self.s.witness.graph.backfill()
        code, g, _ = self.graph(out["record_id"], key=A)
        self.assertEqual(g["edges"] if code == 200 else [], [])
        self.assertNotIn(out["record_id"], json.dumps(self.graph(o)[1]) if self.graph(o)[0] == 200 else "")


class SearchPublic(Base):
    def kept(self, statement, **kw):
        out = self.check(statement=statement, **kw)
        self.keep(out, key=kw.get("key", A))
        return out["record_id"]

    def test_keyword_search_over_public_kept_records_needs_no_key(self):
        r1 = self.kept("The Gdansk shipyard opened in 1834")
        r2 = self.kept("The Hamburg harbour opened in 1189")
        self.check(statement="An unkept Gdansk claim")  # public but not kept: not in the index
        code, res, _ = self.search(q="gdansk")
        self.assertEqual(code, 200, res)
        self.assertEqual(self.result_ids(res), [r1])
        item = res["records"][0]
        self.assertEqual(item["visibility"], "public")
        self.assertEqual(item["method"], "match.text")
        self.assertIn("Gdansk", item["statement"])
        self.assertEqual(item["link"], f"https://evidence.example/r/{r1}")
        self.assertEqual(self.result_ids(self.search(q="OPENED")[1]), [r2, r1])  # newest kept first
        self.assertEqual(self.result_ids(self.search(q="opened 1189")[1]), [r2])  # every word
        self.assertEqual(self.result_ids(self.search(q="opened nowhere")[1]), [])
        self.assertEqual(self.result_ids(self.search(q="gdansk", key=B)[1]), [r1])
        self.assert_clean(res)

    def test_keyword_search_is_case_and_accent_insensitive_and_unicode_safe(self):
        r = self.kept("Zażółć gęślą jaźń in Łódź")
        self.assertEqual(self.result_ids(self.search(q="ŁÓDŹ")[1]), [r])
        self.assertEqual(self.result_ids(self.search(q="lodz")[1]), [])  # casefolded NFKC, not transliterated
        self.assertEqual(self.search(q="日本語")[0], 200)

    def test_filters_outcome_method_since(self):
        r1 = self.kept("first filtered record")
        self.s.clock.advance(7200)
        since = h.iso(self.s.clock() - 3600)
        r2 = self.kept("second filtered record")
        outcome = h.payload_of(self.s.storage.get_kept(r1)["envelope"])["predicate"]["outcome"]
        other = [o for o in ("SUPPORTED", "NOT_SUPPORTED", "CANNOT_WITNESS") if o != outcome][0]
        self.assertEqual(sorted(self.result_ids(self.search(q="filtered", outcome=outcome)[1])), sorted([r1, r2]))
        self.assertEqual(self.search(q="filtered", outcome=other)[1]["records"], [])
        self.assertEqual(self.result_ids(self.search(q="filtered", method="match.text")[1]), [r2, r1])
        self.assertEqual(self.search(q="filtered", method="match.exact")[1]["records"], [])
        self.assertEqual(self.result_ids(self.search(q="filtered", since=since)[1]), [r2])
        for bad in ({"outcome": "MAYBE"}, {"method": "no.such-method"}, {"since": "yesterday"}, {"since": "2026-13-45T00:00:00Z"},
                    {"limit": "0"}, {"limit": "101"}, {"limit": "x"}, {"offset": "-1"}, {"offset": "x"}):
            code, got, _ = self.search(q="filtered", **bad)
            self.assertEqual(code, 422, (bad, got))

    def test_pagination(self):
        rids = [self.kept(f"paged record {i}") for i in range(5)]
        seen, off, pages = [], 0, 0
        while off is not None:
            code, res, _ = self.search(q="paged", limit=2, offset=off)
            self.assertEqual(code, 200, res)
            self.assertLessEqual(len(res["records"]), 2)
            seen += self.result_ids(res)
            off = res["next_offset"]
            pages += 1
        self.assertEqual(seen, list(reversed(rids)))
        self.assertEqual(pages, 3)
        self.assertEqual(self.search(q="paged", offset=99)[1]["records"], [])
        self.assertNotIn("total", self.search(q="paged")[1])  # no totals: a count could include what the reader cannot see

    def test_metacharacters_empty_and_huge_queries_never_500(self):
        r = self.kept("harmless searchable words here")
        nasty = ["'; DROP TABLE kept_records; --", "a & | ! ( ) : * <-> \\ \" '", "))((", ":*", "!!", "&", "|", "<->", "a:*b",
                 "\\", "' OR '1'='1", "harmless:*", "!harmless", "harmless & !words", "😀", "%00", "\x01\x02", "'''", '"""',
                 "{}[]", "word " * 30, "x" * 500]
        for q in nasty:
            code, got, _ = self.search(q=q)
            self.assertIn(code, (200, 422), (q, got))
            self.assertLess(code, 500)
        self.assertEqual(self.search(q="&")[1]["records"], [])  # only punctuation: no words, nothing matches
        self.assertEqual(self.result_ids(self.search(q="harmless & !words")[1]), [r])  # operators are just separators
        self.assertEqual(self.result_ids(self.search(q="harmless:*")[1]), [r])
        code, got, _ = self.search(q="x" * 501)
        self.assertEqual(code, 422)
        code, got, _ = self.search(q=" ".join(f"w{i}" for i in range(search_mod.MAX_WORDS + 1)))
        self.assertEqual(code, 422)
        self.assertEqual(self.result_ids(self.search(q="")[1]), [r])  # empty q lists, newest first
        self.assertEqual(self.result_ids(self.search()[1]), [r])
        self.assertEqual(self.result_ids(self.search(q="harmless")[1]), [r])  # still standing

    def test_takedown_removes_a_record_from_search_for_everyone(self):
        r = self.kept("takedown searchable thing")
        self.assertEqual(self.result_ids(self.search(q="takedown")[1]), [r])
        code, td, _ = self.s.call("POST", f"/v1/records/{r}/takedown", {}, key=OP)
        self.assertEqual(code, 200, td)
        for key in (None, A, B):
            self.assertEqual(self.search(q="takedown", key=key)[1]["records"], [])
            self.assertNotIn(r, json.dumps(self.search(key=key)[1]))
        self.assertIsNone(self.s.storage.get_search_doc(r))  # the indexed text is gone too

    def test_a_public_record_taken_down_by_its_owner_too(self):
        r = self.kept("owner takedown thing")
        self.s.call("POST", f"/v1/records/{r}/takedown", {}, key=A)
        self.assertEqual(self.search(q="owner")[1]["records"], [])


class SearchPrivate(Base):
    def test_the_readers_own_private_records_are_listed_never_content_matched(self):
        priv = self.check(visibility="private", statement=f"{CANARY} moved to Gdansk", label=f"label {CANARY}")
        self.keep(priv)
        rid = priv["record_id"]
        pub = self.check(statement="public gdansk thing")
        self.keep(pub)
        code, res, _ = self.search(key=A)  # no q: listed with the public ones
        self.assertEqual(code, 200, res)
        self.assertEqual(sorted(self.result_ids(res)), sorted([rid, pub["record_id"]]))
        item = [r for r in res["records"] if r["record_id"] == rid][0]
        self.assertEqual(item["visibility"], "private")
        self.assertFalse({"statement", "label"} & set(item))  # listed, not read
        self.assertNotIn(CANARY, json.dumps(res))
        # a query never matches private content, not even the owner's
        for q in (CANARY.lower(), "gdansk", "label"):
            code, res, _ = self.search(q=q, key=A)
            self.assertEqual(code, 200)
            self.assertNotIn(rid, self.result_ids(res))
            self.assertFalse(res["private"]["searched"])
            self.assertIn("/v1/records?q=", res["private"]["note"])
        self.assertEqual(self.result_ids(self.search(q="gdansk", key=A)[1]), [pub["record_id"]])
        # filters apply to the listing
        outcome = h.payload_of(priv["envelope"])["predicate"]["outcome"]
        self.assertIn(rid, self.result_ids(self.search(key=A, outcome=outcome)[1]))
        self.assertNotIn(rid, self.result_ids(self.search(key=A, method="match.exact")[1]))
        # nobody else sees it, with or without a key
        for key in (None, B):
            code, res, _ = self.search(key=key)
            self.assertNotIn(rid, json.dumps(res))
            self.assert_clean(res)
            self.assertNotIn("private", res)
        # the owner's plaintext search is still the B3 route
        code, res, _ = self.s.call("GET", f"/v1/records?q={CANARY}", key=A)
        self.assertEqual([r["record_id"] for r in res["records"]], [rid])

    def test_a_deleted_private_record_is_not_listed(self):
        priv = self.check(visibility="private", statement="to be deleted")
        self.keep(priv)
        self.s.call("DELETE", f"/v1/records/{priv['record_id']}", key=A)
        self.assertEqual(self.search(key=A)[1]["records"], [])


class SearchModes(Base):
    def kept(self, statement):
        out = self.check(statement=statement)
        self.keep(out)
        return out["record_id"]

    def test_without_an_embedder_hybrid_is_keyword_with_a_flag_and_semantic_is_503(self):
        r = self.kept("modes thing")
        code, res, _ = self.search(q="modes")  # the default is hybrid
        self.assertEqual(code, 200, res)
        self.assertEqual((res["mode"], res["mode_used"], res["degraded"]), ("hybrid", "keyword", True))
        self.assertIn("embedder", res["note"])
        self.assertEqual(self.result_ids(res), [r])
        code, res, _ = self.search(q="modes", mode="hybrid")
        self.assertEqual((res["mode_used"], res["degraded"]), ("keyword", True))
        code, res, _ = self.search(q="modes", mode="keyword")
        self.assertEqual((code, res["mode"], res["mode_used"], res["degraded"]), (200, "keyword", "keyword", False))
        self.assertNotIn("note", res)
        code, res, _ = self.search(q="modes", mode="semantic")
        self.assertEqual(code, 503, res)
        self.assertEqual(res["error"], "semantic-unavailable")
        self.assertNotIn("records", res)
        code, res, _ = self.search(q="modes", mode="fuzzy")
        self.assertEqual(code, 422)
        code, res, _ = self.search(q="modes", mode="HYBRID")
        self.assertEqual(code, 422)

    def test_the_embedder_comes_from_one_env_var(self):
        self.assertIsNone(search_mod.embedder_from_env({}))
        self.assertIsNone(search_mod.embedder_from_env({"WITNESS_EMBEDDER_URL": "  "}))
        emb = search_mod.embedder_from_env({"WITNESS_EMBEDDER_URL": "http://embedder.invalid/v1/embeddings",
                                            "WITNESS_EMBEDDER_MODEL": "m"})
        self.assertTrue(callable(emb.embed))  # built without any network call


class FakeEmbedder:
    """Four orthogonal topics; synonyms share an axis. A flag makes it fail."""
    AXES = (("car", "automobile", "vehicle"), ("fruit", "banana", "apple"), ("ship", "vessel", "boat"), ("law", "statute", "act"))

    def __init__(self):
        self.fail = False
        self.calls = 0

    def embed(self, text):
        self.calls += 1
        if self.fail:
            raise OSError("embedder down")
        words = text.lower().split()
        return [float(sum(w in axis for w in words)) for axis in self.AXES]


class SearchWithEmbedder(Base):
    embedder = FakeEmbedder()

    def setUp(self):
        self.embedder.fail = False
        super().setUp()

    def kept(self, statement):
        out = self.check(statement=statement)
        self.keep(out)
        return out["record_id"]

    def test_semantic_and_hybrid_work_when_an_embedder_is_configured(self):
        car = self.kept("the automobile is red")
        fruit = self.kept("the banana is ripe")
        code, res, _ = self.search(q="vehicle", mode="semantic")
        self.assertEqual(code, 200, res)
        self.assertEqual((res["mode"], res["mode_used"], res["degraded"]), ("semantic", "semantic", False))
        self.assertEqual(self.result_ids(res), [car])  # no word in common; the zero-similarity record is not returned
        code, res, _ = self.search(q="vehicle")  # hybrid: fused
        self.assertEqual((res["mode_used"], res["degraded"]), ("hybrid", False))
        self.assertEqual(self.result_ids(res), [car])
        code, res, _ = self.search(q="banana", mode="hybrid")
        self.assertEqual(self.result_ids(res)[0], fruit)
        code, res, _ = self.search(q="banana", mode="keyword")
        self.assertEqual((res["mode_used"], self.result_ids(res)), ("keyword", [fruit]))

    def test_a_record_kept_while_the_embedder_was_down_is_found_by_keyword_and_embedded_later(self):
        self.embedder.fail = True
        r = self.kept("the vessel is large")
        self.assertIsNone(self.s.storage.get_search_doc(r)["embedding"])
        self.assertEqual(self.result_ids(self.search(q="vessel", mode="keyword")[1]), [r])
        self.embedder.fail = False
        self.assertEqual(self.search(q="boat", mode="semantic")[1]["records"], [])
        self.s.witness.search.embed_missing()
        self.assertEqual(self.result_ids(self.search(q="boat", mode="semantic")[1]), [r])

    def test_embedder_down_at_query_time(self):
        r = self.kept("the statute is old")
        self.embedder.fail = True
        code, res, _ = self.search(q="statute", mode="hybrid")
        self.assertEqual(code, 200, res)
        self.assertEqual((res["mode_used"], res["degraded"]), ("keyword", True))
        self.assertIn("embedder", res["note"])
        self.assertEqual(self.result_ids(res), [r])
        code, res, _ = self.search(q="statute", mode="semantic")
        self.assertEqual(code, 503, res)
        self.assertEqual(res["error"], "embedder-unavailable")

    def test_private_records_are_never_sent_to_the_embedder(self):
        before = self.embedder.calls
        out = self.check(visibility="private", statement=f"{CANARY} automobile")
        self.keep(out)
        self.assertEqual(self.embedder.calls, before)
        self.assertEqual(self.search(q="automobile", mode="semantic", key=A)[1]["records"], [])
        self.assertIsNone(self.s.storage.get_search_doc(out["record_id"]))


del_names = ("Base",)


def _bind():
    for cls in (GraphEdges, GraphDepth, GraphVisibility, GraphBackfill, SearchPublic, SearchPrivate, SearchModes, SearchWithEmbedder):
        globals()["Memory" + cls.__name__] = type("Memory" + cls.__name__, (cls, unittest.TestCase), {})


_bind()

if __name__ == "__main__":
    unittest.main()
