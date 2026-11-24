"""B2b (b): a capture becomes an observation (SPEC §2.3): text.canonical.txt from rendered.html with canon/1 at the rendered
layer, EXCLUDING every element marked data-witness-hidden; hidden-nodes.json kept; the subject digest is H(canonical
manifest); signed as observation/v1. A private observation's payload follows §2.6."""
import base64
import hashlib
import json
import unittest

from claim_witness import ids, jcs, observation, schemas, signer, storage
from tests_claim import helpers as h
from tests_claim.fakefetch import build_capture, iso, page

U = "https://news.example/story"
RENDERED = ('<html><body><nav data-witness-hidden="1"><a>Menu Home</a><a>Menu Login</a></nav>'
            '<h1>Story</h1><p>First visible paragraph.</p><div data-witness-hidden="1">secret promo</div>'
            '<p>Second paragraph.</p></body></html>')
HIDDEN = [{"xpath": "/html/body/nav", "excerpt": "Menu Home Menu Login", "sha256": "d" * 64, "reason": "display"}]


def capture(clock, **kw):
    kw.setdefault("rendered", RENDERED)
    kw.setdefault("hidden", HIDDEN)
    return build_capture(U, page(b"<html><body><p>server</p></body></html>", **kw), iso(clock()))


class FromCapture(unittest.TestCase):
    def setUp(self):
        self.clock = h.Clock()

    def test_text_canonical_excludes_hidden_nodes(self):
        manifest, files = capture(self.clock)
        pred, out = observation.from_capture(manifest, files, "public")
        self.assertEqual(out["text.canonical.txt"].decode(), "Story\nFirst visible paragraph.\nSecond paragraph.")
        self.assertNotIn(b"Menu", out["text.canonical.txt"])
        self.assertNotIn(b"secret promo", out["text.canonical.txt"])
        self.assertEqual(out["hidden-nodes.json"], files["hidden-nodes.json"])
        self.assertEqual(json.loads(out["hidden-nodes.json"]), HIDDEN)

    def test_manifest_is_the_spec_shape(self):
        manifest, files = capture(self.clock)
        pred, out = observation.from_capture(manifest, files, "public")
        self.assertEqual(set(pred), set(schemas.OBS_PUBLIC_KEYS))
        self.assertEqual(pred["canonicaliser"], "canon/1")
        self.assertIsNone(pred["platform"])
        self.assertEqual(pred["visibility"], "public")
        self.assertEqual(set(pred["fetcher"]), {"id", "version", "browser", "viewport"})
        names = [f["name"] for f in pred["files"]]
        for n in ("capture.wacz", "response.body", "screenshot.png", "rendered.html", "hidden-nodes.json", "text.canonical.txt"):
            self.assertIn(n, names)
        for f in pred["files"]:
            self.assertEqual(f["sha256"], hashlib.sha256(out[f["name"]]).hexdigest(), f["name"])
        for k in ("requested_url", "final_url", "redirects", "fetched_at", "fetch_ms", "status", "resolved_ips", "tls", "robots"):
            self.assertEqual(pred[k], manifest[k], k)
        jcs.canonical(pred)  # integers only

    def test_plain_text_page_takes_its_text_from_the_body(self):
        manifest, files = build_capture(U, page(b"plain  words\nhere", media_type="text/plain"), iso(self.clock()))
        pred, out = observation.from_capture(manifest, files, "public")
        self.assertEqual(out["text.canonical.txt"], b"plain words\nhere")

    def test_public_statement_subject_is_the_manifest_digest(self):
        manifest, files = capture(self.clock)
        pred, _ = observation.from_capture(manifest, files, "public")
        stmt, disclosure = observation.statement(pred)
        self.assertIsNone(disclosure)
        self.assertEqual(stmt["predicateType"], schemas.OBSERVATION_TYPE)
        self.assertEqual(stmt["subject"], [{"name": U, "digest": {"sha256": hashlib.sha256(jcs.canonical(pred)).hexdigest()}}])
        self.assertEqual(stmt["predicate"], pred)
        schemas.check(schemas.OBSERVATION_TYPE, stmt)

    def test_private_statement_holds_only_commitments(self):
        manifest, files = capture(self.clock)
        pred, _ = observation.from_capture(manifest, files, "private")
        salt = bytes(range(16))
        stmt, disclosure = observation.statement(pred, salt=salt)
        p = stmt["predicate"]
        self.assertEqual(set(p), {"visibility", "body_commitment", "fetched_at", "fetcher"})
        self.assertEqual(p["fetcher"], {"id": "onedroid-fetcher", "version": "1.0.0"})
        self.assertEqual(stmt["subject"], [{"name": "observation", "digest": {"sha256": p["body_commitment"]}}])
        self.assertEqual(p["body_commitment"], ids.body_commitment(salt, disclosure["body"]))
        self.assertEqual(disclosure["body"]["visibility"], "private")
        self.assertEqual(disclosure["body"]["requested_url"], U)
        raw = jcs.canonical(stmt).decode()
        for secret in (U, "93.184.215.14", "news.example"):
            self.assertNotIn(secret, raw)
        schemas.check(schemas.OBSERVATION_TYPE, stmt)

    def test_signer_signs_it_and_refuses_a_wrong_subject_digest(self):
        st = storage.MemoryStorage()
        signer.keylist_init(st, h.seed(1), "w:k", "w", clock=self.clock)
        core = signer.SignerCore(h.seed(1), "w:k", "w", st, clock=self.clock)
        manifest, files = capture(self.clock)
        pred, _ = observation.from_capture(manifest, files, "public")
        stmt, _ = observation.statement(pred)
        out = core.sign(schemas.OBSERVATION_TYPE, stmt)
        self.assertEqual(out["payload_id"], ids.record_id(base64.b64decode(out["envelope"]["payload"])))
        self.assertEqual(st.signing_log()[-1]["predicate_type"], schemas.OBSERVATION_TYPE)
        bad = json.loads(json.dumps(stmt))
        bad["subject"][0]["digest"]["sha256"] = "0" * 64
        with self.assertRaises(signer.Refused):
            core.sign(schemas.OBSERVATION_TYPE, bad)


if __name__ == "__main__":
    unittest.main()
