"""NS-4A (M-20261127-NAME-SITE, NS-3-SPEC.md sections 2-4, 7, 9): the browse index in the witness, through the real HTTP API on
memory storage (and again on real Postgres in test_browse_pg.py).

Subjects are canonical URLs at three levels (page, site, profile; Table 1 canon, Table 2 platform hosts, Table 3 sources per
method). Keywords are extracted with no model (the search tokeniser, a stop list generated from the methods registry, at most 8
a record) and listed only at 3 listed records from 2 accounts. Every record has one type. The index is written at keep, removed
at takedown in the same request and back-filled at start. A record is listed iff it is public, kept, not taken down, not deleted
and not in unlisted_records (seeded with the 28 test record ids of the site's seo-exclude.ts). /v1/browse/* answers are the same
for every reader; /v1/search gains the subject, keyword and type filters and two hit fields.

The fixture records (spec section 9) are planted straight into storage the way keep stores them (a kept row and browse.index for
a public one), so every method of Table 3 is covered without a fetch or a model; the keep and takedown hooks are tested through
the real routes in KeepAndTakedown."""
import base64
import hashlib
import http.client
import json
import unittest
import urllib.parse

try:
    from claim_witness import browse
except ImportError:  # RED: the module does not exist yet, so each test fails on its own
    browse = None
from claim_witness import dsse, ids, jcs, methods
from claim_witness.schemas import CLAIM_TYPE
from tests_claim import helpers as h
from tests_claim.fakefetch import page, stack, url_item
from tests_claim.helpers import claim, request

A, B = "dev-key-a-0123456789abcdef", "dev-key-b-0123456789abcdef"
OP = "dev-key-op-0123456789abcdef"
R1_URL = "https://WWW.Example.COM:443/about/?utm_source=x&b=2&a=1#top"
R2_URL = "http://example.com/about?a=1&b=2"
ABOUT = "example.com/about?a=1&b=2"


def sid_of(kind, key):
    return hashlib.sha256((kind + "\n" + key).encode("utf-8")).hexdigest()[:32]


class Base:
    """self.s is a Stack with a fake fetcher; plant() stores a record the way keep does."""

    def make_storage(self):
        return None

    def setUp(self):
        self.s, self.ff, _ = stack(clock=h.Clock(), storage=self.make_storage(), operator_accounts=["acct_op"],
                                   link_base="https://evidence.example")
        self.s.auth.dev_keys.mapping[OP] = "acct_op"
        self.n = 0

    def tearDown(self):
        self.s.close()
        self.ff.close()

    # ---------------------------------------------------------------------------------------------------- planting

    def plant_obs(self, url, final_url=None, visibility="public"):
        self.n += 1
        t = h.T0 + 100 * self.n
        pred = {"visibility": visibility, "requested_url": url, "final_url": final_url or url, "redirects": [],
                "fetched_at": h.iso(t), "status": 200, "files": [], "fetcher": {"id": "onedroid-fetcher", "version": "1.0.0"}}
        stmt = {"_type": dsse.STATEMENT_TYPE, "subject": [{"name": final_url or url, "digest": {"sha256": "0" * 64}}],
                "predicateType": "https://onedroid.ai/witness/observation/v1", "predicate": pred}
        raw = jcs.canonical(stmt)
        oid = ids.record_id(raw)
        env = {"payloadType": dsse.PAYLOAD_TYPE, "payload": base64.b64encode(raw).decode(), "signatures": []}
        self.s.storage.put_observation({"id": oid, "account": "acct_b", "visibility": visibility, "lookup_tag": "lt" + oid[:30],
                                        "fetched_at": t, "created_at": t, "envelope": env, "body_box": None,
                                        "signer": "witness:test", "kept": True}, {})
        return oid

    def predicate(self, account, method, params=None, evidence=(), outcome="SUPPORTED", visibility="public", statement=None,
                  t=None):
        return {"visibility": visibility,
                "claim": {"method": method, "method_major": 1, "params": params or {}, "assertion": True, "statement": statement},
                "statement": f"template text of {method} number {self.n}", "evidence": list(evidence),
                "method": {"id": method, "version": "1.0.0", "code_sha256": "0" * 64}, "finding": None, "outcome": outcome,
                "reason": None, "detail": None, "limits": "", "judgment": None, "attempt": None, "relied_on": [],
                "submitter": {"account": account, "agent": "agt_fixture", "agent_key_id": "ak_fixture", "agent_sig": "c2ln",
                              "nonce": "nonce-fixture", "agent_time": h.iso(t or h.T0)},
                "options_used": {}, "witnessed_at": h.iso(t or h.T0), "witness": {"id": "witness:test"}, "label": None}

    def plant(self, account, method, params=None, evidence=(), outcome="SUPPORTED", visibility="public", statement=None,
              rid=None, index=True):
        """A kept record as keep stores it: the kept row, then (public only) browse.index. Returns the record id."""
        self.n += 1
        t = h.T0 + 100 * self.n
        pred = self.predicate(account, method, params, evidence, outcome, visibility, statement, t)
        if visibility == "public":
            env_pred = pred
        else:  # a private envelope holds commitments only
            env_pred = {"visibility": "private", "body_commitment": hashlib.sha256(jcs.canonical(pred)).hexdigest(),
                        "method": pred["method"], "outcome": outcome, "witnessed_at": pred["witnessed_at"]}
        stmt = {"_type": dsse.STATEMENT_TYPE, "subject": [{"name": "claim", "digest": {"sha256": "1" * 64}}],
                "predicateType": CLAIM_TYPE, "predicate": env_pred}
        raw = jcs.canonical(stmt)
        rid = rid or ids.record_id(raw)
        env = {"payloadType": dsse.PAYLOAD_TYPE, "payload": base64.b64encode(raw).decode(), "signatures": []}
        self.s.storage.put_kept({"record_id": rid, "account": account, "visibility": visibility, "method": method,
                                 "outcome": outcome, "witnessed_at": pred["witnessed_at"], "envelope": env, "wrapped_key": None,
                                 "body_box": None, "evidence_key_box": None, "evidence_expires_at": None,
                                 "evidence_deleted_at": None, "kept_at": t, "deleted_at": None, "taken_down_at": None,
                                 "takedown_by": None, "ndim": {"chain": None, "record": {"state": "not-configured"}, "evidence": None}})
        if visibility == "public" and index:
            self.s.witness.browse.index(rid, pred)
        self.preds = getattr(self, "preds", {})
        self.preds[rid] = pred
        return rid

    # the section 9 fixture, one record at a time
    def r1(self):
        return self.plant("acct_a", "page.live", {"url": R1_URL},
                          [{"slot": "page", "kind": "url", "url": R1_URL, "capture": "page", "observations": []}])

    def r2(self):
        oid = self.plant_obs(R2_URL, "https://example.com/login")
        self.r2_obs = oid
        return self.plant("acct_b", "match.text", {}, [
            {"slot": "submitted", "kind": "object", "sha256": "2" * 64, "media_type": "text/plain", "name": "copy-of-acme.txt"},
            {"slot": "page", "kind": "observation", "id": oid}], outcome="NOT_SUPPORTED")

    def quote(self, account, text, **kw):
        return self.plant(account, "quote.in-source", {"quote": text}, [
            {"slot": "source", "kind": "object", "sha256": hashlib.sha256(text.encode()).hexdigest(), "media_type": "text/plain",
             "name": "terms-sourcefile.txt"}], **kw)

    def r3(self):
        return self.quote("acct_a", "The refund window is thirty days")

    def r4(self):
        return self.quote("acct_b", "Refund window: thirty days for every order")

    def r5(self):
        oid = self.plant_obs("https://example.com/terms")
        return self.plant("acct_c", "judge.supports", {}, [{"slot": "evidence", "kind": "observation", "id": oid}],
                          outcome="CANNOT_WITNESS", statement="Refunds are paid within thirty days")

    def r6(self):
        u = "https://bsky.app/profile/did:plc:abc123/post/3kxyz"
        return self.plant("acct_a", "post.by-author", {"handle": "Example.COM"},
                          [{"slot": "post", "kind": "url", "url": u, "capture": "post", "observations": []}])

    def r7(self):
        u = "https://example.com/secret-launch"
        return self.plant("acct_a", "page.live", {"url": u}, [{"slot": "page", "kind": "url", "url": u, "capture": "page",
                                                                "observations": []}], visibility="private")

    def r8(self):
        u = "https://twitter.com/ExampleCo/status/42"
        return self.plant("acct_c", "page.live", {"url": u}, [{"slot": "page", "kind": "url", "url": u, "capture": "page",
                                                                "observations": []}], outcome="CANNOT_WITNESS")

    def r9(self):
        return self.plant("acct_a", "tests.pass", {}, [{"slot": "log", "kind": "object", "sha256": "9" * 64,
                                                         "media_type": "application/json", "name": "go-test.json"}])

    def r10(self, of):
        return self.plant("acct_b", "record.valid", {}, [{"slot": "record", "kind": "record", "id": of},
                                                          {"slot": "key_list", "kind": "object", "sha256": "a" * 64,
                                                           "media_type": "application/json", "name": "keys.json"}])

    def r11(self):
        u = "https://onedroid.ai/"
        return self.plant("acct_a", "page.live", {"url": u}, [{"slot": "page", "kind": "url", "url": u, "capture": "page",
                                                                "observations": []}])

    def r12(self):
        return [self.quote("acct_a", f"zorblat zorblat zorblat {w}") for w in ("ka", "kb", "kc")]

    def fixture(self):
        f = {"r1": self.r1(), "r2": self.r2(), "r3": self.r3(), "r4": self.r4(), "r5": self.r5(), "r6": self.r6(),
             "r7": self.r7(), "r8": self.r8(), "r9": self.r9()}
        f["r10"] = self.r10(f["r1"])
        f["r11"] = self.r11()
        f["r12"] = self.r12()
        return f

    # ---------------------------------------------------------------------------------------------------- reading

    def get(self, path, key=None, headers=None):
        return self.s.call("GET", path, key=key, headers=headers)

    def ok(self, path, key=None):
        code, out, _ = self.get(path, key=key)
        self.assertEqual(code, 200, (path, out))
        return out

    def raw_get(self, path, headers=None):
        """A GET that does not follow redirects: (status, headers, body bytes)."""
        c = http.client.HTTPConnection("127.0.0.1", self.s.port, timeout=10)
        c.request("GET", path, headers=headers or {})
        r = c.getresponse()
        body = r.read()
        c.close()
        return r.status, {k.lower(): v for k, v in r.getheaders()}, body

    def subjects(self, **q):
        return self.ok("/v1/browse/subjects?" + urllib.parse.urlencode(q))

    def subject(self, sid):
        return self.ok(f"/v1/browse/subjects/{sid}")

    def by_key(self, kind):
        out, offset = {}, 0
        while offset is not None:
            res = self.subjects(kind=kind, limit=100, offset=offset)
            for s in res["subjects"]:
                out[s["key"]] = s
            offset = res["next_offset"]
        return out

    def keywords(self, **q):
        return self.ok("/v1/browse/keywords" + ("?" + urllib.parse.urlencode(q) if q else ""))

    def listed_words(self):
        return [k["word"] for k in self.keywords(limit=100)["keywords"]]

    def rec(self, rid):
        return self.get(f"/v1/browse/records/{rid}")

    def search(self, key=None, **params):
        return self.s.call("GET", "/v1/search?" + urllib.parse.urlencode({k: v for k, v in params.items() if v is not None}),
                           key=key)

    def every_answer(self, f=None):
        """Every browse answer for the current data, as text: the lists, each subject, each keyword, the categories and each
        fixture record."""
        out = []
        for kind in ("page", "site", "profile"):
            res = self.subjects(kind=kind, limit=100)
            out.append(json.dumps(res, sort_keys=True))
            for s in res["subjects"]:
                out.append(json.dumps(self.subject(s["sid"]), sort_keys=True))
        kw = self.keywords(limit=100)
        out.append(json.dumps(kw, sort_keys=True))
        for k in kw["keywords"]:
            out.append(json.dumps(self.ok("/v1/browse/keywords/" + urllib.parse.quote(k["word"], safe="")), sort_keys=True))
        out.append(json.dumps(self.ok("/v1/browse/categories"), sort_keys=True))
        for rid in (f or {}).values():
            for r in (rid if isinstance(rid, list) else [rid]):
                code, body, _ = self.rec(r)
                out.append(f"{code} {json.dumps(body, sort_keys=True)}")
        return out


# ======================================================================================================= canon (Table 1)

TABLE1 = [  # (step, input, key)
    (1, "ftp://x/", None),
    (2, "https://u:p@ex.com/", "ex.com/"),
    (3, "https://EX.com./", "ex.com/"),
    (3, "https://xn--bcher-kva.de/", "xn--bcher-kva.de/"),
    (4, "https://www.ex.com/", "ex.com/"),
    (4, "https://www.com/", "www.com/"),
    (5, "https://ex.com:443/", "ex.com/"),
    (5, "https://ex.com:8080/", "ex.com:8080/"),
    (6, "https://ex.com/a/./b/../C/", "ex.com/a/C"),
    (6, "https://ex.com/%7euser", "ex.com/~user"),
    (7, "https://ex.com/?utm_source=x&b=2&a=1", "ex.com/?a=1&b=2"),
    (8, "https://ex.com/#top", "ex.com/"),
    (9, "http://ex.com/about/", "ex.com/about"),
    (9, "https://www.ex.com/about", "ex.com/about"),
]


class Canon(unittest.TestCase):
    def test_s2_table1_every_example_gives_its_output_and_canon_is_idempotent(self):
        for step, u, want in TABLE1:
            self.assertEqual(browse.canon(u), want, (step, u))
            if want is not None:
                self.assertEqual(browse.canon("https://" + want), want, (step, u))

    def test_s2_more_cases_are_idempotent(self):
        for u in ("https://Ex.com/%7E%41b%2f?Q=%7e&q=a+b&gclid=1&FBCLID=2&mc_cid=3&z=", "https://ex.com/a//",
                  "https://www.www.ex.com/x/../../y", "https://[2001:db8::1]:8443/p?b=1&a=2&a=1", "https://ex.com/café bar",
                  "https://ex.com/?&&a=1&&", "https://ex.com/p%2e/./q", "HTTPS://EX.COM/A%2Fb"):
            k = browse.canon(u)
            self.assertIsNotNone(k, u)
            self.assertEqual(browse.canon("https://" + k), k, u)

    def test_s2_details_of_each_step(self):
        self.assertEqual(browse.canon("https://ex.com"), "ex.com/")
        self.assertEqual(browse.canon("https://ex.com/a%2fb"), "ex.com/a%2Fb")  # other escapes kept, hex upper-cased
        self.assertEqual(browse.canon("https://ex.com/?a=1&UTM_Medium=y&gclid=g&dclid=d&gbraid=1&wbraid=2&msclkid=3&yclid=4"
                                      "&twclid=5&igshid=6&mc_eid=7&_hsenc=8&_hsmi=9&ref_src=r&ref_url=u"), "ex.com/?a=1")
        self.assertEqual(browse.canon("https://ex.com/?q=a+b"), "ex.com/?q=a%20b")
        self.assertEqual(browse.canon("https://ex.com/?b=2&a=2&a=1"), "ex.com/?a=1&a=2&b=2")
        self.assertEqual(browse.canon("http://ex.com:80/x"), "ex.com/x")
        self.assertEqual(browse.canon("https://[2001:db8::1]/"), "[2001:db8::1]/")
        self.assertEqual(browse.canon("https://192.0.2.1:8080/x/"), "192.0.2.1:8080/x")

    def test_s3_only_http_and_https_make_subjects(self):
        for u in ("ftp://example.com/x", "mailto:a@b.c", "javascript:alert(1)", "file:///etc/passwd", "data:text/plain,x", "",
                  "not a url", "https://", None, 42):
            self.assertIsNone(browse.canon(u), u)
        self.assertEqual(browse.canon("http://example.com/x"), browse.canon("https://example.com/x"))

    def test_s4_userinfo_is_dropped(self):
        self.assertEqual(browse.canon("https://u:secret@example.com/"), "example.com/")
        subs = browse.subjects_for_url("https://u:secret@example.com/")
        self.assertNotIn("secret", json.dumps(subs))

    def test_s5_idn_stored_as_a_label_displayed_as_u_label(self):
        subs = browse.subjects_for_url("https://BÜCHER.de/")
        page_, site = subs
        self.assertEqual((page_["kind"], page_["key"], page_["display"]), ("page", "xn--bcher-kva.de/", "bücher.de/"))
        self.assertEqual((site["kind"], site["key"], site["display"]), ("site", "xn--bcher-kva.de", "bücher.de"))

    def test_s15_sid_is_the_first_32_hex_of_sha256_of_kind_newline_key(self):
        want = hashlib.sha256(b"page\nexample.com/about?a=1&b=2").hexdigest()[:32]
        self.assertEqual(browse.sid("page", ABOUT), want)
        self.assertEqual(browse.sid("page", ABOUT), sid_of("page", ABOUT))
        self.assertRegex(want, r"^[0-9a-f]{32}$")


class Platforms(unittest.TestCase):
    def kinds(self, u):
        return [(s["kind"], s["key"], s["platform"]) for s in browse.subjects_for_url(u)]

    def test_s8_bsky_post_url_is_a_page_under_its_profile_and_no_bsky_site(self):
        subs = browse.subjects_for_url("https://bsky.app/profile/did:plc:abc123/post/3kxyz")
        self.assertEqual([(s["kind"], s["key"]) for s in subs], [("page", "bsky.app/profile/did:plc:abc123/post/3kxyz"),
                                                                 ("profile", "bsky.app/profile/did:plc:abc123")])
        self.assertEqual(subs[0]["parent_sid"], subs[1]["sid"])
        self.assertEqual(subs[1]["parent_sid"], None)
        self.assertEqual(self.kinds("https://bsky.app/profile/Example.COM"),
                         [("page", "bsky.app/profile/example.com", "bsky"), ("profile", "bsky.app/profile/example.com", "bsky")])
        self.assertEqual(browse.subjects_for_url("https://bsky.app/profile/Example.COM")[1]["display"], "@example.com on Bluesky")

    def test_s9_twitter_aliases_to_x_and_no_x_site(self):
        for u in ("https://twitter.com/ExampleCo/status/42", "https://mobile.twitter.com/ExampleCo/status/42",
                  "https://www.twitter.com/ExampleCo/status/42", "https://mobile.x.com/exampleco/status/42"):
            self.assertEqual(self.kinds(u), [("page", "x.com/exampleco/status/42", "x"), ("profile", "x.com/exampleco", "x")], u)

    def test_s10_x_reserved_paths_have_no_profile(self):
        self.assertEqual(self.kinds("https://x.com/search?q=foo"), [("page", "x.com/search?q=foo", "x")])
        for name in ("home", "i", "explore", "settings", "intent", "share", "hashtag", "login"):
            self.assertEqual([k for k, _key, _p in self.kinds(f"https://x.com/{name}/x")], ["page"], name)

    def test_v7_the_other_platforms_of_table2(self):
        self.assertEqual(self.kinds("https://www.linkedin.com/in/Jane-Doe/details"),
                         [("page", "linkedin.com/in/jane-doe/details", "linkedin"), ("profile", "linkedin.com/in/jane-doe", "linkedin")])
        self.assertEqual(self.kinds("https://m.linkedin.com/company/Acme"),
                         [("page", "linkedin.com/company/acme", "linkedin"), ("profile", "linkedin.com/company/acme", "linkedin")])
        self.assertEqual(self.kinds("https://linkedin.com/jobs/view/1"), [("page", "linkedin.com/jobs/view/1", "linkedin")])
        self.assertEqual(self.kinds("https://github.com/OneDro1d/onedroid-witness/blob/main/README.md"),
                         [("page", "github.com/onedro1d/onedroid-witness/blob/main/README.md", "github"),
                          ("profile", "github.com/onedro1d", "github")])
        self.assertEqual(self.kinds("https://m.youtube.com/@Chan/videos"),
                         [("page", "youtube.com/@chan/videos", "youtube"), ("profile", "youtube.com/@chan", "youtube")])
        self.assertEqual(self.kinds("https://www.youtube.com/watch?v=abc"), [("page", "youtube.com/watch?v=abc", "youtube")])
        self.assertEqual(self.kinds("https://tiktok.com/@Some.One/video/77"),
                         [("page", "tiktok.com/@some.one/video/77", "tiktok"), ("profile", "tiktok.com/@some.one", "tiktok")])
        self.assertEqual(self.kinds("https://instagram.com/Acme"),
                         [("page", "instagram.com/acme", "instagram"), ("profile", "instagram.com/acme", "instagram")])
        self.assertEqual(self.kinds("https://instagram.com/p/XyZ"), [("page", "instagram.com/p/XyZ", "instagram")])
        self.assertEqual(self.kinds("https://m.facebook.com/Acme"),
                         [("page", "facebook.com/acme", "facebook"), ("profile", "facebook.com/acme", "facebook")])
        self.assertEqual(self.kinds("https://facebook.com/groups/x"), [("page", "facebook.com/groups/x", "facebook")])

    def test_v9_a_platform_host_never_has_a_site(self):
        for u in ("https://bsky.app/", "https://x.com/", "https://github.com/", "https://instagram.com/p/1"):
            self.assertNotIn("site", [k for k, _key, _p in self.kinds(u)], u)

    def test_v10_an_ordinary_page_has_its_host_as_parent(self):
        subs = browse.subjects_for_url("https://Example.com:8080/x/")
        self.assertEqual([(s["kind"], s["key"], s["platform"]) for s in subs],
                         [("page", "example.com:8080/x", None), ("site", "example.com:8080", None)])
        self.assertEqual(subs[0]["parent_sid"], sid_of("site", "example.com:8080"))
        self.assertEqual(subs[0]["sid"], sid_of("page", "example.com:8080/x"))


class Keywords(unittest.TestCase):
    def test_s16_the_stop_list_holds_function_words_url_noise_and_every_template_word(self):
        stop = browse.STOP_WORDS
        for w in ("the", "is", "and", "of", "www", "http", "https", "html", "htm", "php", "asp", "aspx", "index", "amp", "com",
                  "org", "net", "live", "when", "observed", "matches", "content", "submitted", "text", "file", "byte", "identical",
                  "contains", "passage", "published", "account", "post", "asserted", "false", "record", "validly", "sealed"):
            self.assertIn(w, stop, w)
        for w in ("refund", "window", "thirty", "days", "paid", "within", "terms", "refunds"):
            self.assertNotIn(w, stop, w)
        # generated from the registry: every fixed word of every T and F template
        import re
        for m in methods.METHODS.values():
            for tmpl in m.templates.values():
                if tmpl:
                    for w in re.findall(r"[^\W_]+", re.sub(r"\{[a-z_]+\}", " ", tmpl).casefold()):
                        if len(w) >= 3:
                            self.assertIn(w, stop, (m.id, w))

    def test_v16_v17_candidates(self):
        self.assertEqual(browse.candidates("The refund window is thirty days"), ["refund", "window", "thirty", "days"])
        self.assertEqual(browse.candidates("ab abc a1bc 2026 ＡＢＣＤ x_y " + "q" * 33 + " " + "r" * 32), ["abc", "abcd", "r" * 32])
        self.assertEqual(browse.candidates("<script>alert(1)</script>"), ["script", "alert"])

    def test_s20_at_most_8_keywords_the_first_8_distinct_in_order(self):
        letters = "bcdfghjklmnpqrstvwz"
        words = [f"{letters[i % 19]}{letters[(i // 19) % 19]}ark" for i in range(40)]
        self.assertEqual(len(set(words)), 40)
        pred = {"claim": {"method": "quote.in-source", "params": {"quote": " ".join(words)}, "statement": None},
                "evidence": []}
        self.assertEqual(browse.keywords_of(pred, []), words[:8])


# ======================================================================================================= the index and API

class Subjects(Base):
    def test_s1_r1_and_r2_share_one_page_under_the_site_with_its_counts(self):
        r1, r2 = self.r1(), self.r2()
        pages, sites = self.by_key("page"), self.by_key("site")
        self.assertEqual(set(pages), {ABOUT})
        self.assertEqual(set(sites), {"example.com"})
        p, s = pages[ABOUT], sites["example.com"]
        self.assertEqual(p["sid"], sid_of("page", ABOUT))
        self.assertEqual(p["parent_sid"], s["sid"])
        self.assertEqual(s["counts"], {"SUPPORTED": 1, "NOT_SUPPORTED": 1, "CANNOT_WITNESS": 0})
        self.assertEqual(list(s["counts"]), ["SUPPORTED", "NOT_SUPPORTED", "CANNOT_WITNESS"])
        self.assertEqual(s["records"], 2)
        self.assertEqual(p["records"], 2)
        for subj in (p, s):
            self.assertEqual(set(subj), {"sid", "kind", "key", "display", "platform", "parent_sid", "href", "records", "counts",
                                         "first_witnessed_at", "last_witnessed_at"})
        self.assertEqual(s["href"], None)
        self.assertEqual(s["parent_sid"], None)
        self.assertEqual((p["first_witnessed_at"], p["last_witnessed_at"]),
                         (self.preds[r1]["witnessed_at"], self.preds[r2]["witnessed_at"]))

    def test_s41_href_is_the_url_as_the_most_recent_listed_record_wrote_it(self):
        self.r1()
        self.r2()
        self.assertEqual(self.by_key("page")[ABOUT]["href"], R2_URL)

    def test_s6_the_subject_is_the_requested_url_not_the_final_url(self):
        self.r2()
        keys = set(self.by_key("page"))
        self.assertEqual(keys, {ABOUT})
        self.assertNotIn("login", json.dumps(self.every_answer()))

    def test_s7_an_unreadable_observation_gives_no_subject_the_record_is_still_listed(self):
        r2 = self.plant("acct_b", "match.text", {}, [{"slot": "page", "kind": "observation", "id": "f" * 64}],
                        outcome="NOT_SUPPORTED", index=False)
        oid = self.plant_obs("https://example.com/private-one", visibility="private")
        r2b = self.plant("acct_b", "match.text", {}, [{"slot": "page", "kind": "observation", "id": oid}], index=False)
        self.s.witness.browse.backfill()
        self.assertEqual(self.by_key("page"), {})
        self.assertEqual(self.by_key("site"), {})
        for rid in (r2, r2b):
            code, body, _ = self.rec(rid)
            self.assertEqual(code, 200, body)
            self.assertEqual((body["type"], body["subjects"]), ("document", []))
        self.assertEqual(set(r["record_id"] for r in self.search()[1]["records"]), {r2, r2b})

    def test_s8_post_by_author_profile_is_the_handle_the_claim_names(self):
        r6 = self.r6()
        profiles, pages = self.by_key("profile"), self.by_key("page")
        self.assertEqual(set(profiles), {"bsky.app/profile/example.com"})
        self.assertEqual(set(pages), {"bsky.app/profile/did:plc:abc123/post/3kxyz"})
        self.assertEqual(pages["bsky.app/profile/did:plc:abc123/post/3kxyz"]["parent_sid"],
                         profiles["bsky.app/profile/example.com"]["sid"])
        self.assertEqual(self.by_key("site"), {})
        self.assertEqual(self.rec(r6)[1]["type"], "social-post")
        self.assertEqual(profiles["bsky.app/profile/example.com"]["platform"], "bsky")

    def test_s9_r8_twitter_is_x(self):
        r8 = self.r8()
        self.assertEqual(set(self.by_key("profile")), {"x.com/exampleco"})
        self.assertEqual(set(self.by_key("page")), {"x.com/exampleco/status/42"})
        self.assertEqual(self.by_key("site"), {})
        self.assertEqual(self.rec(r8)[1]["type"], "social-post")

    def test_s11_object_records_have_no_subject_and_their_types(self):
        r3, r9 = self.r3(), self.r9()
        self.assertEqual(self.rec(r3)[1]["subjects"], [])
        self.assertEqual(self.rec(r3)[1]["type"], "document")
        self.assertEqual(self.rec(r9)[1]["type"], "test-run")
        self.assertEqual(self.by_key("page"), {})

    def test_s12_record_valid_inherits_and_loses_its_subjects_with_the_takedown(self):
        r1 = self.r1()
        r10 = self.r10(r1)
        code, body, _ = self.rec(r10)
        self.assertEqual(body["type"], "record")
        self.assertEqual({s["key"] for s in body["subjects"]}, {ABOUT, "example.com"})
        self.assertEqual(self.by_key("site")["example.com"]["records"], 2)
        code, out, _ = self.s.call("POST", f"/v1/records/{r1}/takedown", {}, key=A)
        self.assertEqual(code, 200, out)
        code, body, _ = self.rec(r10)
        self.assertEqual((code, body["subjects"]), (200, []))
        self.assertEqual(self.by_key("site"), {})

    def test_s13_record_disclose_has_the_subjects_of_the_disclosed_body(self):
        priv = self.r7()
        body = self.predicate("acct_a", "page.live", {"url": "https://example.com/x"},
                              [{"slot": "page", "kind": "url", "url": "https://example.com/x", "capture": "page", "observations": []}],
                              visibility="private")
        d = self.plant("acct_a", "record.disclose", {}, [
            {"slot": "record", "kind": "record", "id": priv},
            {"slot": "disclosure", "kind": "object", "sha256": "d" * 64, "media_type": "application/json", "name": "disclosure.json",
             "content": {"salt": "c2FsdHNhbHRzYWx0c2FsdA", "body": body}}])
        self.assertEqual(set(self.by_key("page")), {"example.com/x"})
        self.assertEqual(self.rec(d)[1]["type"], "record")
        self.assertEqual(self.rec(priv)[0], 404)
        self.assertNotIn("secret-launch", json.dumps(self.every_answer()))

    def test_s14_judge_supports_takes_the_first_5_distinct_urls(self):
        ev = [{"slot": "evidence", "kind": "url", "url": f"https://s{i}.example/p", "capture": "page", "observations": []}
              for i in range(7)]
        ev.insert(2, dict(ev[0]))  # a repeat is not a 6th
        rid = self.plant("acct_a", "judge.supports", {}, ev, statement="Seven sources agree")
        self.assertEqual(set(self.by_key("page")), {f"s{i}.example/p" for i in range(5)})
        self.assertEqual(len([s for s in self.rec(rid)[1]["subjects"] if s["kind"] == "page"]), 5)

    def test_v1_statement_names_and_labels_never_make_a_subject(self):
        self.plant("acct_a", "quote.in-source", {"quote": "see https://acme.example/claims"}, [
            {"slot": "source", "kind": "object", "sha256": "e" * 64, "media_type": "text/html", "name": "https://acme.example/x"}],
            statement=None)
        self.assertEqual(self.by_key("page"), {})
        self.assertEqual(self.by_key("site"), {})

    def test_s34_subject_lists_are_in_display_order_whatever_the_counts(self):
        for host, n in (("zeta.example", 3), ("alpha.example", 1), ("mid.example", 2)):
            for i in range(n):
                u = f"https://{host}/p{i}"
                self.plant("acct_a", "page.live", {"url": u}, [{"slot": "page", "kind": "url", "url": u, "capture": "page",
                                                                "observations": []}], outcome="NOT_SUPPORTED" if i else "SUPPORTED")
        sites = self.subjects(kind="site")["subjects"]
        self.assertEqual([s["display"] for s in sites], ["alpha.example", "mid.example", "zeta.example"])
        pages = self.subjects(kind="page")["subjects"]
        self.assertEqual([s["display"] for s in pages], sorted(s["display"] for s in pages))
        self.assertEqual(self.get("/v1/browse/subjects?kind=site&sort=records")[0], 422)

    def test_list_paging_parent_and_prefix(self):
        for i in range(5):
            u = f"https://pager.example/p{i}"
            self.plant("acct_a", "page.live", {"url": u}, [{"slot": "page", "kind": "url", "url": u, "capture": "page",
                                                            "observations": []}])
        self.r11()
        site = sid_of("site", "pager.example")
        first = self.subjects(kind="page", parent=site, limit=2)
        self.assertEqual([s["key"] for s in first["subjects"]], ["pager.example/p0", "pager.example/p1"])
        self.assertEqual(first["next_offset"], 2)
        last = self.subjects(kind="page", parent=site, limit=2, offset=4)
        self.assertEqual(([s["key"] for s in last["subjects"]], last["next_offset"]), (["pager.example/p4"], None))
        self.assertEqual([s["key"] for s in self.subjects(kind="site", prefix="o")["subjects"]], ["onedroid.ai"])
        self.assertEqual([s["key"] for s in self.subjects(kind="site", prefix="p")["subjects"]], ["pager.example"])
        self.assertEqual(self.subjects(kind="site", prefix="other")["subjects"], [])
        detail = self.subject(site)
        self.assertEqual(set(detail), {"subject", "parent", "children", "types"})
        self.assertEqual((detail["children"], detail["parent"], detail["types"]), (5, None, [{"value": "web-page", "records": 5}]))
        p0 = self.subject(sid_of("page", "pager.example/p0"))
        self.assertEqual(p0["parent"], {"sid": site, "kind": "site", "key": "pager.example", "display": "pager.example",
                                        "platform": None, "parent_sid": None})
        self.assertEqual(p0["children"], 0)

    def test_subject_404_unknown_and_422_malformed(self):
        self.assertEqual(self.get("/v1/browse/subjects/" + "0" * 32)[0], 404)
        self.assertEqual(self.get("/v1/browse/subjects/XYZ")[0], 422)
        self.assertEqual(self.get("/v1/browse/subjects/" + "0" * 32 + "?x=1")[0], 422)


class KeywordIndex(Base):
    def test_s16_fixture_keywords(self):
        f = self.fixture()
        stored = self.s.witness.browse.record_words
        self.assertEqual(stored(f["r3"]), ["refund", "window", "thirty", "days"])
        self.assertEqual(stored(f["r5"]), ["refunds", "paid", "within", "thirty", "days", "terms"])
        everything = set()
        for rid in [v for k, v in f.items() if k not in ("r7", "r12")]:
            everything |= set(stored(rid))
        for bad in ("live", "observed", "matches", "example", "com", "bsky", "app", "twitter", "onedroid", "copy", "acme", "txt",
                    "sourcefile", "keys", "json", "exampleco", "abc", "plc", "did", "template", "fixture", "agt", "nonce"):
            self.assertNotIn(bad, everything, bad)

    def test_s17_thirty_is_listed_at_3_records_from_3_accounts(self):
        f = self.fixture()
        words = self.listed_words()
        self.assertIn("thirty", words)
        self.assertIn("days", words)
        self.assertNotIn("refund", words)  # two records only
        kw = self.ok("/v1/browse/keywords/thirty")
        self.assertEqual(set(kw), {"keyword", "subjects"})
        self.assertEqual(kw["keyword"]["word"], "thirty")
        self.assertEqual(kw["keyword"]["records"], 3)
        self.assertEqual(kw["keyword"]["last_witnessed_at"], self.preds[f["r5"]]["witnessed_at"])
        self.assertEqual(kw["subjects"], 1)  # the site example.com, through R5
        self.assertEqual(self.rec(f["r3"])[1]["keywords"], ["thirty", "days"])

    def test_s18_one_account_alone_cannot_list_a_keyword(self):
        f = self.fixture()
        self.assertNotIn("zorblat", self.listed_words())
        self.assertEqual(self.get("/v1/browse/keywords/zorblat")[0], 404)
        for rid in f["r12"]:
            self.assertNotIn("zorblat", self.rec(rid)[1]["keywords"])

    def test_v19_two_accounts_three_records_is_the_line(self):
        self.quote("acct_a", "quillon marrowcrest")
        self.quote("acct_a", "quillon fable")
        self.assertNotIn("quillon", self.listed_words())
        self.quote("acct_a", "quillon third")
        self.assertNotIn("quillon", self.listed_words())  # 3 records, 1 account
        self.quote("acct_b", "quillon fourth")
        self.assertIn("quillon", self.listed_words())
        self.assertNotIn("acct_", json.dumps(self.keywords()))

    def test_s19_a_denylisted_word_is_never_listed_or_shown(self):
        f = self.fixture()
        self.s.witness.cfg.keyword_denylist = {"thirty"}
        self.assertNotIn("thirty", self.listed_words())
        self.assertEqual(self.get("/v1/browse/keywords/thirty")[0], 404)
        self.assertNotIn("thirty", self.rec(f["r3"])[1]["keywords"])
        self.assertEqual(self.search(keyword="thirty")[1]["records"], [])

    def test_denylist_file_is_one_word_a_line(self):
        import os
        import tempfile
        d = tempfile.mkdtemp()
        p = os.path.join(d, "deny.txt")
        with open(p, "w", encoding="utf-8") as fh:
            fh.write("Thirty\n\n  zorblat  \n# a comment\n")
        self.assertEqual(browse.denylist_from_env({"WITNESS_KEYWORD_DENYLIST_FILE": p}), {"thirty", "zorblat"})
        self.assertEqual(browse.denylist_from_env({}), set())

    def test_s21_a_non_canonical_spelling_answers_301_to_the_canonical_word(self):
        self.fixture()
        status, hdrs, body = self.raw_get("/v1/browse/keywords/THIRTY")
        self.assertEqual(status, 301)
        self.assertEqual(hdrs["location"], "/v1/browse/keywords/thirty")
        self.assertEqual(json.loads(body), {"canonical": "thirty"})
        status, hdrs, _ = self.raw_get("/v1/browse/keywords/" + urllib.parse.quote("ｔｈｉｒｔｙ"))
        self.assertEqual((status, hdrs["location"]), (301, "/v1/browse/keywords/thirty"))
        self.assertEqual(self.raw_get("/v1/browse/keywords/" + urllib.parse.quote("<script>"))[0], 404)
        self.assertEqual(self.raw_get("/v1/browse/keywords/%FF")[0], 404)

    def test_s22_any_script_greek_is_listed_under_other(self):
        for acct, extra in (("acct_a", "πρώτη"), ("acct_b", "δεύτερη"), ("acct_a", "τρίτη")):
            self.quote(acct, f"Η πολιτική επιστροφής {extra}")
        other = [k["word"] for k in self.keywords(prefix="other")["keywords"]]
        self.assertEqual(other, sorted(["πολιτική", "επιστροφήσ"]))
        self.assertEqual(self.keywords(prefix="p")["keywords"], [])

    def test_keywords_sort_alpha_and_records(self):
        for acct, q in (("acct_a", "gamma beta"), ("acct_b", "gamma beta"), ("acct_a", "gamma beta"), ("acct_b", "gamma alpha"),
                        ("acct_a", "alpha"), ("acct_b", "alpha delta")):
            self.quote(acct, q)
        self.assertEqual(self.listed_words(), ["alpha", "beta", "gamma"])
        by = self.keywords(sort="records")["keywords"]
        self.assertEqual([(k["word"], k["records"]) for k in by], [("gamma", 4), ("alpha", 3), ("beta", 3)])
        self.assertEqual(set(by[0]), {"word", "records", "last_witnessed_at"})
        self.assertEqual(self.get("/v1/browse/keywords?sort=outcome")[0], 422)


class Categories(Base):
    def test_s23_types_sum_to_the_listed_records_and_methods_have_records(self):
        f = self.fixture()
        cats = self.ok("/v1/browse/categories")
        facets = {x["facet"]: x["values"] for x in cats["facets"]}
        self.assertEqual(list(facets), ["type", "method"])
        types = {v["value"]: v["records"] for v in facets["type"]}
        listed = 14 - 1  # every fixture record but the private R7
        self.assertEqual(sum(types.values()), listed)
        self.assertEqual(types, {"record": 1, "test-run": 1, "social-post": 2, "web-page": 4, "document": 5})
        for v in facets["type"] + facets["method"]:
            self.assertEqual(set(v), {"facet", "value", "label", "records"})
            self.assertGreaterEqual(v["records"], 1)
        meth = {v["value"]: v["records"] for v in facets["method"]}
        self.assertEqual(meth, {"page.live": 3, "match.text": 1, "quote.in-source": 5, "judge.supports": 1, "post.by-author": 1,
                                "tests.pass": 1, "record.valid": 1})
        self.assertTrue(set(meth) <= set(methods.METHODS))
        self.assertNotIn("outcome", facets)
        self.assertEqual({v["value"]: v["label"] for v in facets["type"]}["web-page"], "Web page")

    def test_s24_v24_a_method_not_in_the_registry_is_in_no_method_category(self):
        self.plant("acct_a", "nosuch.method", {}, [])
        facets = {x["facet"]: x["values"] for x in self.ok("/v1/browse/categories")["facets"]}
        self.assertEqual(facets["method"], [])
        self.assertEqual([v["value"] for v in facets["type"]], ["document"])

    def test_empty_witness_has_empty_lists(self):
        self.assertEqual(self.ok("/v1/browse/categories"), {"facets": [{"facet": "type", "values": []},
                                                                       {"facet": "method", "values": []}]})
        self.assertEqual(self.subjects(kind="site"), {"subjects": [], "next_offset": None})
        self.assertEqual(self.keywords(), {"keywords": [], "next_offset": None})


class Api(Base):
    def test_s26_bad_parameters_are_422(self):
        self.r1()
        for q in ("kind=site&sort=outcome", "kind=site&limit=0", "kind=site&limit=101", "kind=site&offset=10001", "kind=user",
                  "", "kind=site&prefix=ab", "kind=site&prefix=A", "kind=site&parent=" + "0" * 32, "kind=page&parent=xyz",
                  "kind=site&limit=1.5", "kind=site&offset=-1", "kind=site&foo=bar"):
            code, out, _ = self.get("/v1/browse/subjects?" + q)
            self.assertEqual(code, 422, q)
            self.assertEqual(out["error"], "invalid-request", q)
        for q in ("sort=x", "limit=0", "offset=10001", "prefix=zz", "q=a"):
            self.assertEqual(self.get("/v1/browse/keywords?" + q)[0], 422, q)
        self.assertEqual(self.get("/v1/browse/categories?x=1")[0], 422)
        self.assertEqual(self.get("/v1/browse/records/" + "a" * 64 + "?x=1")[0], 422)
        self.assertEqual(self.get("/v1/browse/nothing")[0], 404)
        self.assertEqual(self.get("/v1/browse/records/nothex")[0], 404)
        self.assertEqual(self.subjects(kind="site", limit=100, offset=10000)["subjects"], [])
        self.assertEqual(self.s.call("POST", "/v1/browse/subjects?kind=site", {}, key=None)[0], 404)

    def test_s29_lists_have_next_offset_and_never_a_total(self):
        self.fixture()
        for path in ("/v1/browse/subjects?kind=site", "/v1/browse/subjects?kind=page", "/v1/browse/keywords"):
            out = self.ok(path)
            self.assertIn("next_offset", out)
            self.assertFalse({"total", "count"} & set(out), path)
        s = self.by_key("site")["example.com"]
        self.assertIn("records", s)
        self.assertIn("counts", s)
        self.assertEqual(sum(s["counts"].values()), s["records"])

    def test_s25_v27_a_private_record_changes_nothing_and_every_reader_gets_the_same_bytes(self):
        f = {"r1": self.r1(), "r2": self.r2(), "r3": self.r3(), "r6": self.r6()}
        before = self.every_answer(f)
        self.r7()
        after = self.every_answer(f)
        self.assertEqual(before, after)
        self.assertNotIn("secret-launch", json.dumps(after))
        for path in ("/v1/browse/subjects?kind=site", "/v1/browse/subjects?kind=page", "/v1/browse/keywords",
                     "/v1/browse/categories", f"/v1/browse/records/{f['r1']}", f"/v1/browse/subjects/{sid_of('site', 'example.com')}"):
            anon = self.raw_get(path)
            for hdrs in ({"Authorization": f"Bearer {A}"}, {"Authorization": "Bearer nope"},
                         {"X-Witness-Account": "acct_a"}, {"X-Store-Signature": "AAAA", "X-Witness-Account": "acct_a"}):
                got = self.raw_get(path, hdrs)
                self.assertEqual((got[0], got[2]), (anon[0], anon[2]), (path, hdrs))

    def test_s28_no_submitter_field_or_label_in_any_answer(self):
        f = self.fixture()
        text = "\n".join(self.every_answer(f))
        for needle in ("acct_", "agt_", "ak_fixture", "agent_key_id", "agent_sig", "nonce", "submitter", "label", "c2ln",
                       "copy-of-acme", "terms-sourcefile"):
            self.assertNotIn(needle, text, needle)
        hits = json.dumps(self.search(subject=sid_of("site", "example.com"))[1])
        for needle in ("acct_", "agt_", "agent_key_id", "nonce"):
            self.assertNotIn(needle, hits, needle)

    def test_browse_record_answer(self):
        f = self.fixture()
        code, body, _ = self.rec(f["r1"])
        self.assertEqual(code, 200)
        self.assertEqual(set(body), {"record_id", "type", "subjects", "keywords", "method"})
        self.assertEqual((body["record_id"], body["type"], body["method"]), (f["r1"], "web-page", "page.live"))
        self.assertEqual([(s["kind"], s["key"]) for s in body["subjects"]], [("page", ABOUT), ("site", "example.com")])
        for s in body["subjects"]:
            self.assertEqual(set(s), {"sid", "kind", "key", "display", "platform", "parent_sid"})
        self.assertEqual(self.rec(f["r7"])[0], 404)
        self.assertEqual(self.rec("b" * 64)[0], 404)
        self.s.call("POST", f"/v1/records/{f['r3']}/takedown", {}, key=A)
        self.assertEqual(self.rec(f["r3"])[0], 410)


class Search(Base):
    def test_s27_search_filters_subject_keyword_type(self):
        f = self.fixture()
        site = sid_of("site", "example.com")
        ids_ = lambda res: [r["record_id"] for r in res[1]["records"]]  # noqa: E731
        self.assertEqual(ids_(self.search(subject=sid_of("page", ABOUT), mode="keyword")), [f["r10"], f["r2"], f["r1"]])
        self.assertEqual(ids_(self.search(subject=site, mode="keyword")), [f["r10"], f["r5"], f["r2"], f["r1"]])
        self.assertEqual(ids_(self.search(subject=site, outcome="NOT_SUPPORTED", mode="keyword")), [f["r2"]])
        self.assertEqual(ids_(self.search(keyword="thirty", mode="keyword")), [f["r5"], f["r4"], f["r3"]])
        self.assertEqual(ids_(self.search(keyword="thirty", q="refund", mode="keyword")), [])  # q needs the search text index
        self.assertEqual(ids_(self.search(type="test-run")), [f["r9"]])
        self.assertEqual(ids_(self.search(type="social-post", method="page.live")), [f["r8"]])
        self.assertEqual(ids_(self.search(keyword="zorblat")), [])
        self.assertEqual(ids_(self.search(subject="0" * 32)), [])
        for bad in ({"subject": "XYZ"}, {"type": "nosuch"}, {"keyword": ""}, {"keyword": "x" * 129}):
            self.assertEqual(self.search(**bad)[0], 422, bad)

    def test_s27_v31_v32_hits_gain_type_and_subjects_and_nothing_else_changes(self):
        f = self.fixture()
        res = self.search(mode="keyword")[1]
        self.assertEqual(set(res), {"query", "mode", "mode_used", "degraded", "records", "next_offset"})
        hits = {r["record_id"]: r for r in res["records"]}
        self.assertNotIn(f["r7"], hits)
        for rid, hit in hits.items():
            self.assertEqual(set(hit), {"record_id", "visibility", "method", "outcome", "witnessed_at", "link", "statement", "type",
                                        "subjects"})
        self.assertEqual(hits[f["r1"]]["type"], "web-page")
        self.assertEqual([s["key"] for s in hits[f["r1"]]["subjects"]], [ABOUT, "example.com"])
        self.assertEqual((hits[f["r3"]]["type"], hits[f["r3"]]["subjects"]), ("document", []))
        mine = {r["record_id"]: r for r in self.search(key=A)[1]["records"]}
        self.assertEqual((mine[f["r7"]]["type"], mine[f["r7"]]["subjects"]), (None, []))

    def test_v31_with_a_browse_filter_only_listed_records_match(self):
        r1 = self.r1()
        self.s.storage.unlist(r1, h.T0, "operator")
        self.assertEqual(self.search(type="web-page")[1]["records"], [])
        hit = [r for r in self.search()[1]["records"] if r["record_id"] == r1][0]
        self.assertEqual((hit["type"], hit["subjects"]), (None, []))  # still in search, but not listed


class Listing(Base):
    def test_s30_takedown_drops_the_rows_in_the_same_request(self):
        r1, r2 = self.r1(), self.r2()
        site = sid_of("site", "example.com")
        self.assertTrue(self.s.storage.has_browse(r1))
        code, out, _ = self.s.call("POST", f"/v1/records/{r1}/takedown", {}, key=A)
        self.assertEqual(code, 200, out)
        self.assertFalse(self.s.storage.has_browse(r1))
        self.assertEqual(self.subject(site)["subject"]["counts"], {"SUPPORTED": 0, "NOT_SUPPORTED": 1, "CANNOT_WITNESS": 0})
        self.assertEqual(self.subject(sid_of("page", ABOUT))["subject"]["records"], 1)
        self.assertEqual(self.by_key("page")[ABOUT]["href"], R2_URL)
        self.s.witness.browse.backfill()  # a taken-down record is never indexed again
        self.assertFalse(self.s.storage.has_browse(r1))

    def test_s31_both_taken_down_the_subjects_are_404(self):
        r1, r2 = self.r1(), self.r2()
        for rid, key in ((r1, A), (r2, B)):
            self.assertEqual(self.s.call("POST", f"/v1/records/{rid}/takedown", {}, key=key)[0], 200)
        self.assertEqual(self.get(f"/v1/browse/subjects/{sid_of('site', 'example.com')}")[0], 404)
        self.assertEqual(self.get(f"/v1/browse/subjects/{sid_of('page', ABOUT)}")[0], 404)
        self.assertEqual(self.subjects(kind="site")["subjects"], [])

    def test_s32_the_28_seeded_ids_are_unlisted(self):
        seed = browse.SEED_UNLISTED
        self.assertEqual(len(seed), 28)
        self.assertEqual(len(set(seed)), 28)
        self.assertIn("8a6361088a23c4bbce5c581e4ca6a8d7e6fe857095df746e82420f5fa77d91d0", seed)
        self.assertIn("c8df58c9bea03790d99472230f60eb24f7760462866b12820e3142973009cd8f", seed)
        self.assertEqual(set(self.s.storage.unlisted_ids()), set(seed))
        u = "https://onedroid.ai/test-page"
        rid = self.plant("acct_a", "page.live", {"url": u}, [{"slot": "page", "kind": "url", "url": u, "capture": "page",
                                                              "observations": []}], rid=seed[0])
        self.assertEqual(self.subjects(kind="site")["subjects"], [])
        self.assertEqual(self.subjects(kind="page")["subjects"], [])
        self.assertEqual(self.rec(rid)[0], 404)
        self.assertEqual(self.ok("/v1/browse/categories")["facets"][0]["values"], [])
        self.assertEqual(self.get(f"/v1/records/{rid}", key=None)[0], 200)  # its own page stays readable

    def test_seed_matches_the_migration(self):
        import pathlib
        import re
        sql = (pathlib.Path(browse.__file__).parent / "migrations" / "009_browse.sql").read_text(encoding="utf-8")
        self.assertEqual(set(re.findall(r"'([0-9a-f]{64})'", sql)), set(browse.SEED_UNLISTED))

    def test_s33_unlist_is_for_operators_only(self):
        r1, r2 = self.r1(), self.r2()
        site = sid_of("site", "example.com")
        for key in (A, B):
            code, out, _ = self.s.call("POST", f"/v1/records/{r1}/unlist", {}, key=key)
            self.assertEqual((code, out["error"]), (403, "not-operator"))
        self.assertEqual(self.s.call("POST", f"/v1/records/{r1}/unlist", {}, key=None)[0], 401)
        self.assertEqual(self.subject(site)["subject"]["records"], 2)
        code, out, _ = self.s.call("POST", f"/v1/records/{r1}/unlist", {}, key=OP)
        self.assertEqual(code, 200, out)
        self.assertEqual((out["record_id"], out["unlisted"]), (r1, True))
        self.assertEqual(self.subject(site)["subject"]["counts"], {"SUPPORTED": 0, "NOT_SUPPORTED": 1, "CANNOT_WITNESS": 0})
        self.assertEqual(self.s.call("POST", f"/v1/records/{r1}/unlist", {}, key=OP)[0], 200)  # again: the same answer
        self.assertEqual(self.s.call("POST", f"/v1/records/{'c' * 64}/unlist", {}, key=OP)[0], 404)
        self.assertEqual(self.s.call("POST", f"/v1/records/{r2}/unlist", {"reason": 3}, key=OP)[0], 422)
        self.assertEqual(self.get(f"/v1/records/{r1}", key=None)[0], 200)

    def test_v34_a_deleted_record_is_not_listed(self):
        r1 = self.r1()
        self.s.storage.update_kept(r1, deleted_at=h.T0)
        self.assertEqual(self.subjects(kind="site")["subjects"], [])

    def test_backfill_indexes_what_is_missing_once(self):
        r1 = self.plant("acct_a", "page.live", {"url": R1_URL},
                        [{"slot": "page", "kind": "url", "url": R1_URL, "capture": "page", "observations": []}], index=False)
        self.r7()
        self.assertEqual(self.subjects(kind="site")["subjects"], [])
        self.assertEqual(self.s.witness.browse.backfill(), 1)
        self.assertEqual(self.s.witness.browse.backfill(), 0)
        self.assertEqual(set(self.by_key("page")), {ABOUT})
        self.assertTrue(self.s.storage.has_browse(r1))


class KeepAndTakedown(Base):
    """The hooks through the real routes: keep (public) writes the rows, keep (private) writes none, takedown removes them."""

    def test_keep_of_a_public_page_live_indexes_it(self):
        u = "https://Keep.Example/Landing/"
        self.ff.set(u, page())
        code, out, _ = self.s.witness_call(request(claim("page.live", {"url": u}), [url_item(u)], "public"))
        self.assertEqual(code, 200, out)
        rid = out["record_id"]
        self.assertEqual(self.rec(rid)[0], 404)  # signed, not kept: not listed
        code, k, _ = self.s.call("POST", f"/v1/records/{rid}/keep", {"envelope": out["envelope"]}, key=A)
        self.assertEqual(code, 200, k)
        code, body, _ = self.rec(rid)
        self.assertEqual(code, 200, body)
        self.assertEqual([(s["kind"], s["key"]) for s in body["subjects"]], [("page", "keep.example/Landing"), ("site", "keep.example")])
        self.assertEqual(self.by_key("page")["keep.example/Landing"]["href"], u)
        self.assertEqual(self.s.call("POST", f"/v1/records/{rid}/takedown", {}, key=A)[0], 200)
        self.assertFalse(self.s.storage.has_browse(rid))
        self.assertEqual(self.by_key("site"), {})

    def test_keep_of_a_private_record_writes_no_row(self):
        u = "https://example.com/secret-launch"
        self.ff.set(u, page())
        code, out, _ = self.s.witness_call(request(claim("page.live", {"url": u}), [url_item(u)], "private"))
        self.assertEqual(code, 200, out)
        before = self.every_answer()
        code, k, _ = self.s.call("POST", f"/v1/records/{out['record_id']}/keep",
                                 {"envelope": out["envelope"], "disclosure": out["disclosure"]}, key=A)
        self.assertEqual(code, 200, k)
        self.assertFalse(self.s.storage.has_browse(out["record_id"]))
        self.assertEqual(self.every_answer(), before)
        self.assertNotIn("secret-launch", json.dumps(self.every_answer()))


def _bind():
    for cls in (Subjects, KeywordIndex, Categories, Api, Search, Listing, KeepAndTakedown):
        globals()["Memory" + cls.__name__] = type("Memory" + cls.__name__, (cls, unittest.TestCase), {})


_bind()

if __name__ == "__main__":
    unittest.main()
