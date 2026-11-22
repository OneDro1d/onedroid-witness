"""R4c: W2, the model witness, on a claims-snapshot 0.9 "document" package (the mission's R4c-w2-document-witness-spec.md, R4c-1 to R4c-8).

The format is argus's claims-snapshot/0.9 profile "document" (OneDro1d/onedroid-claims PR #35 head a5ce040, SPEC.md section 17; check.py
sha256 ff304606...). Fixtures: the two a5ce040 example folders with their witnesses removed (fixtures/README-document-fixtures.md), variants
made from them in a temp dir and re-signed with throwaway keys (document_fixtures.edit_audit), and recorded model answers
(fixtures/recordings-document*, the FakeClient format). Offline: no live model, no network (the published-path fetch is a DictFetcher).
"""
import base64
import hashlib
import http.client
import io
import json
import pathlib
import re
import shutil
import sys
import tarfile
import tempfile
import threading
import time
import unittest
from http.server import ThreadingHTTPServer

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(HERE))

import onedroid_witness  # noqa: E402
from onedroid_witness import answer, checkpin, normalise, prompts, render, request, respsign  # noqa: E402
from onedroid_witness.jobs import JobStore, Worker  # noqa: E402
from onedroid_witness.openrouter import Ledger  # noqa: E402
from onedroid_witness.server import make_handler  # noqa: E402
from onedroid_witness.signing import KeyStore  # noqa: E402
from fake_openrouter import FakeClient  # noqa: E402
from test_server import multipart  # noqa: E402
from test_sig3 import raw_public, sign_request, verify_resp  # noqa: E402
from test_regate5 import DictFetcher  # noqa: E402
import document_fixtures as df  # noqa: E402
from document_fixtures import make_key  # noqa: E402  (idempotent: a second call with the same name reuses the key, never prompts)

PIN = "ff30460696c8656075864a5874c1d1f10d5a45befe68addc5944981c511eedec"
ADD_WITNESS_A5CE040 = "965d4e8b64e9ff6e344d99e20f80e29caf7026c0c723f6815207cc0f0880d4a3"
SIGN_A5CE040 = "37b979525814cb564fa294343e18c0e515bff9179273d130b80ea24eb4c17718"
VERSION = "0.1.21-dev"
CHAT_SERVED, DEC_SERVED = "openai/gpt-4.1-mini-2025-04-14", "typesafe/jev-1.14-20261014"
W_CHAT, W_DEC = "onedroid-witness-openai-gpt-4-1-mini-2025-04-14", "onedroid-witness-typesafe-jev-1-14-20261014"
REC_RESTATE = df.FIXTURES / "recordings-document-restatement"
RESTATE_C001 = {"where": "document", "file": "page.md", "kind": "restatement", "quote": "The Example Widget weighs 120 grams."}
RESTATE_C002 = {"where": "document", "file": "page.md", "kind": "restatement", "quote": "The Example Widget ships within 3 days."}
RESTATE_C003 = {"where": "document", "file": "page.md", "kind": "restatement", "quote": "The Example Widget is sold in 40 countries."}
NEP_CLAIMED = {"verdict": "NO EVIDENCE PUBLISHED", "on": {"proofs": [], "counter": []}, "note": "An example with invented content, not a real audit: a restatement only."}
AUDITOR_NOTES = ("the specification table in the document says 120 g", "the sales table in the document totals 12 countries",
                 "the document gives no record of the shipping time", "the certificate page, saved beside this record, says so in words",
                 "neither the document nor a saved source records the shipping time")
DOC_MODEL_IDS = f"{df.CHAT},{df.DECISION}"


class RecordingFake(FakeClient):
    """The FakeClient (recorded answers) that also keeps every text a model was sent: the system prompt and the data for a chat model,
    the state and the questions for a decision model."""

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.texts = []

    def chat(self, model, system_prompt, user_text, max_tokens, providers=None):
        self.texts.append(system_prompt + "\n" + user_text)
        return super().chat(model, system_prompt, user_text, max_tokens, providers)

    def decide(self, model, state, questions, providers=None):
        self.texts.append(state + "\n" + json.dumps(questions, ensure_ascii=False))
        return super().decide(model, state, questions, providers)


def premint(keystore):
    """The service holds a model identity's key before it answers (SPEC 14: the key list's window covers started_at)."""
    for m in (CHAT_SERVED, DEC_SERVED):
        keystore.key_for(m)


def witness_rows(ans):
    out = {}
    for f in sorted((pathlib.Path(ans) / "witness").glob("*.jsonl")):
        lines = [json.loads(l) for l in f.read_text(encoding="utf-8").splitlines() if l.strip()]
        out[f.stem] = {"header": lines[0], **{r["id"]: r for r in lines[1:]}}
    return out


def restatement_variant(snap, keydir):
    """C-001 gains a restatement at proofs[0] (its artefact moves to proofs[1]); C-002 gains a restatement as its only candidate."""
    def mutate(rows):
        rows[0]["proofs"] = [dict(RESTATE_C001)] + rows[0]["proofs"]
        rows[0]["claimed"]["on"]["proofs"] = [1]
        rows[1]["proofs"] = [dict(RESTATE_C002)]
    return df.edit_audit(snap, keydir, mutate)


def all_restatement_variant(snap, keydir):
    """Every claim of the in-document fixture has restatements only (no artefact proof, no counter), so every claimed verdict is NEP."""
    def mutate(rows):
        for r, q in zip(rows, (RESTATE_C001, RESTATE_C002, RESTATE_C003)):
            r["proofs"], r["counter"], r["claimed"] = [dict(q)], [], json.loads(json.dumps(NEP_CLAIMED))
    return df.edit_audit(snap, keydir, mutate)


def without_c002(snap, keydir):
    return df.edit_audit(snap, keydir, lambda rows: rows.pop(1))


class _Tmp(unittest.TestCase):
    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="witness-r4c-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.keydir = self.tmp / "throwaway-keys"
        self.keydir.mkdir()

    def copy(self, src, name=None):
        return df.copy_fixture(src, self.tmp, name)

    def run_answer(self, snap, rec=df.DOC_REC, models=None, name="answer", ledger_cap=100.0):
        check = checkpin.load_check(df.CHECK_PY)
        ledger = Ledger(str(self.tmp / f"ledger-{name}.json"), ledger_cap)
        client = RecordingFake(rec, ledger)
        keystore = KeyStore(self.tmp / "keys")
        premint(keystore)
        req = request.Request(snap, private_mode=True, profiles_served=request.PROFILES_SERVED)
        ans = self.tmp / name
        svc = answer.run(req, models or df.DOC_MODELS, client, keystore, check, ans, prices=df.DOC_PRICES, private_mode=True)
        return svc, client, keystore, ans, ledger


# ---------------------------------------------------------------------------------------------------------------------------- R4c-1
class R4c1Repin(unittest.TestCase):
    def test_r4c1_vendor_check_py_is_the_a5ce040_checker_and_checkpin_pins_it(self):
        self.assertEqual(hashlib.sha256((ROOT / "vendor" / "check.py").read_bytes()).hexdigest(), PIN)
        self.assertEqual(checkpin.CHECK_PY_SHA256, PIN)
        check = checkpin.load_check(ROOT / "vendor" / "check.py")
        self.assertEqual(check.DOCUMENT_PROFILE, "document")  # the 0.9 checker reads the document profile (SPEC 17)

    def test_r4c1_vendor_add_witness_and_sign_are_the_a5ce040_bytes(self):
        # add_witness.py runs vendor/sign.py and imports vendor/check.py beside it, so the three move together
        self.assertEqual(hashlib.sha256((ROOT / "vendor" / "add_witness.py").read_bytes()).hexdigest(), ADD_WITNESS_A5CE040)
        self.assertEqual(hashlib.sha256((ROOT / "vendor" / "sign.py").read_bytes()).hexdigest(), SIGN_A5CE040)

    def test_r4c1_ci_pins_the_same_checker_and_the_version_moves_with_the_cut(self):
        self.assertIn(f"{PIN}  vendor/check.py", (ROOT / ".github" / "workflows" / "tests.yml").read_text(encoding="utf-8"))
        self.assertEqual(onedroid_witness.__version__, VERSION)


# ---------------------------------------------------------------------------------------------------------------------------- R4c-2
class R4c2DocumentProfile(_Tmp):
    def test_r4c2_document_is_served_by_default(self):
        self.assertIn("document", request.PROFILES)
        self.assertIn("document", request.PROFILES_SERVED)
        self.assertIn("document", prompts.PROFILES)
        req = request.Request(self.copy(df.DOC_IN), private_mode=True, profiles_served=request.PROFILES_SERVED)
        self.assertEqual(req.profile, "document")

    def test_r4c2_the_request_carries_the_pages_and_the_source_copies_hash_checked(self):
        req = request.Request(self.copy(df.DOC_EXT), private_mode=True, profiles_served=request.PROFILES_SERVED)
        M = df.load(df.DOC_EXT / "manifest.json")
        self.assertEqual(req.pages, {"page.md": (df.DOC_EXT / "page.md").read_text(encoding="utf-8")})
        self.assertEqual(req.page_hashes, {"page.md": M["pages"][0]["sha256"]})
        self.assertIn("sources/001.txt", req.carried)
        # a page part changed after the manifest was written is refused by name; a page the manifest names and the request lacks too
        snap = self.copy(df.DOC_IN, "tampered")
        (snap / "page.md").write_text((snap / "page.md").read_text(encoding="utf-8").replace("12 countries", "40 countries"), encoding="utf-8")
        with self.assertRaises(request.Refused) as cm:
            request.Request(snap, private_mode=True)
        self.assertIn("part page.md sha256 differs from the manifest's", str(cm.exception))
        (snap / "page.md").unlink()
        with self.assertRaises(request.Refused) as cm:
            request.Request(snap, private_mode=True)
        self.assertIn("part page.md is named by the manifest's pages and was not sent", str(cm.exception))

    def test_r4c2_a_page_txt_no_page_names_and_a_pre_09_format_are_refused_by_name(self):
        snap = self.copy(df.DOC_IN, "extra-page")
        (snap / "page.txt").write_text("a page no entry names\n", encoding="utf-8")
        with self.assertRaises(request.Refused) as cm:
            request.Request(snap, private_mode=True)
        self.assertIn("part page.txt is named by no page of the manifest", str(cm.exception))
        snap = self.copy(df.DOC_IN, "fmt08")
        M = df.load(snap / "manifest.json")
        M["format"] = "claims-snapshot/0.8"
        df.dump(snap / "manifest.json", M)
        with self.assertRaises(request.Refused) as cm:
            request.Request(snap, private_mode=True)
        self.assertIn("claims-snapshot/0.9", str(cm.exception))

    def test_r4c2_the_rendering_shows_each_candidate_with_where_kind_source_quote_and_its_surrounding_lines(self):
        req = request.Request(self.copy(df.DOC_IN), private_mode=True)
        didx = render.document_index(req)
        rows = {r["id"]: r for r in req.audit}
        t1 = render.render_document(rows["C-001"], didx)
        self.assertTrue(t1.startswith("claim id: C-001\n"), t1)
        self.assertIn("claim text: The Example Widget weighs 120 grams.", t1)
        self.assertIn("page.md line 3: The Example Widget weighs 120 grams.", t1)  # where the document makes the claim
        self.assertIn('[0] artefact', t1)
        self.assertIn("in the document, page.md", t1)
        self.assertIn('quote "row 1: weight 120 g"', t1)
        for n, line in ((5, "The Example Widget is sold in 40 countries."), (6, "Specification table, row 1: weight 120 g."), (7, "Sales table, total: 12 countries.")):
            self.assertIn(f"  line {n}: {line}", t1)  # the quote's line and its neighbours, from the page
        self.assertIn("candidates AGAINST (0)", t1)
        t3 = render.render_document(rows["C-003"], didx)
        self.assertIn('quote "Sales table, total: 12 countries"', t3)
        self.assertIn("candidates FOR (0)", t3)
        req = request.Request(self.copy(df.DOC_EXT), private_mode=True)
        didx = render.document_index(req)
        t1 = render.render_document(req.audit[0], didx)
        self.assertIn("at an external source [1] https://example.org/labs/certificate.html", t1)
        self.assertIn("sources/001.txt", t1)
        self.assertIn("copy: text", t1)
        self.assertIn('quote "the Example Widget is certified by Example Labs"', t1)
        self.assertIn("  line 2: Example Labs certifies the Example Widget, model EW-1, in 2026: the Example Widget is certified by Example Labs.", t1)
        self.assertIn("  line 1: Example Labs certificate page", t1)

    def test_r4c2_the_models_never_see_the_auditors_claimed_verdict_or_note(self):
        for src in (df.DOC_IN, df.DOC_EXT):
            svc, client, _, _, _ = self.run_answer(self.copy(src), name=f"answer-{src.name}")
            self.assertEqual(sorted(svc["models_run"]), sorted([df.CHAT, df.DECISION]))
            self.assertTrue(client.texts)
            for t in client.texts:
                self.assertNotIn("claimed", t.lower())
                for note in AUDITOR_NOTES:
                    self.assertNotIn(note, t)
                self.assertNotIn("An example with invented content, not a real audit: ", t)  # every claimed note starts so

    def test_r4c2_the_server_takes_the_manifest_named_pages_and_refuses_any_other_part(self):
        from onedroid_witness.server import _parse
        parts = df.parts_of(df.DOC_IN)
        body, ctype = multipart(parts, {"models": DOC_MODEL_IDS})
        got, params = _parse(ctype, body, {})
        self.assertIn("page.md", got)
        self.assertEqual(params["models"], DOC_MODEL_IDS)
        body, ctype = multipart({**parts, "notes.md": b"not named\n"}, {"models": DOC_MODEL_IDS})
        with self.assertRaises(ValueError) as cm:
            _parse(ctype, body, {})
        self.assertIn("part notes.md is not accepted", str(cm.exception))
        # a page name is never one of the job's own files
        M = df.load(df.DOC_IN / "manifest.json")
        M["pages"][0]["file"] = "params.json"
        others = {k: v for k, v in parts.items() if k != "page.md"}
        body, ctype = multipart({**others, "manifest.json": json.dumps(M).encode(), "params.json": b"{}"}, {"models": DOC_MODEL_IDS})
        with self.assertRaises(ValueError) as cm:
            _parse(ctype, body, {})
        self.assertIn("part params.json is not accepted", str(cm.exception))


# ---------------------------------------------------------------------------------------------------------------------------- R4c-3
class R4c3RestatementRule(_Tmp):
    def test_r4c3_a_claim_with_no_candidate_is_nep_by_rule_and_no_model_is_asked(self):
        svc, client, _, ans, _ = self.run_answer(self.copy(df.DOC_IN))
        for m in (df.CHAT, df.DECISION):
            self.assertNotIn("C-002", client.seen.get(m, []), m)
        w = witness_rows(ans)
        for name in (W_CHAT, W_DEC):
            r = w[name]["C-002"]
            self.assertEqual(r["verdict"], "NO EVIDENCE PUBLISHED")
            self.assertEqual(r["on"], {"proofs": [], "counter": []})
            self.assertIn("no artefact proof and no counter", r["note"])
            self.assertIn("no model was asked", r["note"])

    def test_r4c3_a_restatement_only_claim_is_nep_by_rule_and_no_model_is_asked(self):
        snap = restatement_variant(self.copy(df.DOC_IN), self.keydir)
        svc, client, _, ans, _ = self.run_answer(snap, rec=REC_RESTATE)
        for m in (df.CHAT, df.DECISION):
            self.assertNotIn("C-002", client.seen.get(m, []), m)
        for name in (W_CHAT, W_DEC):
            r = witness_rows(ans)[name]["C-002"]
            self.assertEqual(r["verdict"], "NO EVIDENCE PUBLISHED")
            self.assertIn("restatement", r["note"])
            self.assertIn("no model was asked", r["note"])

    def test_r4c3_a_claim_with_an_artefact_proof_or_a_counter_goes_to_the_models(self):
        svc, client, _, _, _ = self.run_answer(self.copy(df.DOC_IN))
        for m in (df.CHAT, df.DECISION):
            self.assertEqual(sorted(client.seen[m]), ["C-001", "C-003"], m)


# ---------------------------------------------------------------------------------------------------------------------------- R4c-4
class R4c4WitnessVocabulary(_Tmp):
    def test_r4c4_recorded_answers_become_09_witness_rows(self):
        svc, _, _, ans, _ = self.run_answer(self.copy(df.DOC_IN))
        w = witness_rows(ans)
        self.assertEqual(sorted(w), [W_CHAT, W_DEC])
        for name in (W_CHAT, W_DEC):
            self.assertEqual(w[name]["header"]["kind"], "model")
            self.assertEqual(w[name]["header"]["method"], "classify")
            self.assertEqual(w[name]["header"]["carried"], {"page.md": df.load(df.DOC_IN / "manifest.json")["pages"][0]["sha256"]})
            self.assertEqual((w[name]["C-001"]["verdict"], w[name]["C-001"]["on"]), ("EVIDENCED", {"proofs": [0], "counter": []}))
            self.assertEqual((w[name]["C-003"]["verdict"], w[name]["C-003"]["on"], w[name]["C-003"]["confidence"]),
                             ("CONTRADICTED", {"proofs": [], "counter": [0]}, "high"))
        entries = {e["name"]: e for e in df.load(ans / "manifest-entry.json")}
        for name in (W_CHAT, W_DEC):
            self.assertEqual(entries[name]["agreement"], {"with": "auditor", "decided": 3, "same": 3, "pct": 100})
            self.assertFalse(entries[name]["primary"])

    def test_r4c4_evidenced_on_a_restatement_alone_is_undecided_with_the_reason(self):
        snap = restatement_variant(self.copy(df.DOC_IN), self.keydir)
        svc, _, _, ans, _ = self.run_answer(snap, rec=REC_RESTATE)
        w = witness_rows(ans)
        r = w[W_CHAT]["C-001"]
        self.assertEqual(r["verdict"], "UNDECIDED")
        self.assertEqual(r["on"], {"proofs": [], "counter": []})
        self.assertIn("restatement", r["note"])
        self.assertIn("the model said: The document says the widget weighs 120 grams.", r["note"])
        # the decision model scored the restatement highest: the service's candidate for a document EVIDENCED is the best ARTEFACT proof
        self.assertEqual((w[W_DEC]["C-001"]["verdict"], w[W_DEC]["C-001"]["on"]), ("EVIDENCED", {"proofs": [1], "counter": []}))

    def test_r4c4_answers_that_break_the_vocabulary_are_undecided_never_a_near_miss(self):
        row = {"id": "C-001", "text": "t", "proofs": [dict(RESTATE_C001), {"where": "document", "file": "page.md", "kind": "artefact", "quote": "q"}],
               "counter": [{"where": "document", "file": "page.md", "kind": "artefact", "quote": "c"}]}

        def chat(v, p=(), c=(), note="a reason"):
            body, _ = normalise.chat_answer(json.dumps({"verdict": v, "on": {"proofs": list(p), "counter": list(c)}, "note": note}), "stop", row)
            return normalise.document_rules(body, row)
        b = chat("EVIDENCED", [0])
        self.assertEqual(b["verdict"], "UNDECIDED")
        self.assertIn("restatement", b["note"])
        self.assertEqual(chat("EVIDENCED", [0, 1])["verdict"], "EVIDENCED")  # an artefact named: it stands as the model said it
        self.assertEqual(chat("EVIDENCED", [0, 1])["on"]["proofs"], [0, 1])
        b = chat("EVIDENCED", [5])
        self.assertEqual(b["verdict"], "UNDECIDED")
        self.assertIn("index that does not exist", b["note"])
        for word in ("EVIDENCE AVAILABLE ON REQUEST", "WITHDRAWN"):
            b = chat(word)
            self.assertEqual(b["verdict"], "UNDECIDED", word)
            self.assertIn(word, b["note"])
            b = normalise.document_rules({"verdict": word, "on": {"proofs": [], "counter": []}, "note": "passed through"}, row)
            self.assertEqual(b["verdict"], "UNDECIDED", word)
            self.assertIn("not a document-profile verdict", b["note"])
        self.assertEqual(chat("CONTRADICTED", c=[0])["verdict"], "CONTRADICTED")
        self.assertEqual(chat("NO EVIDENCE PUBLISHED")["verdict"], "NO EVIDENCE PUBLISHED")
        # a decision model's EVIDENCED names the best-scoring artefact; with no artefact asked about it is UNDECIDED
        ans = {"verdict": {"choice": "EVIDENCED", "probabilities": {"EVIDENCED": 0.9}, "confidence": 0.9}, "proof_0": {"noul": 0.99}, "proof_1": {"noul": 0.6}}
        b, _ = normalise.decision_answer(ans, row, proofs_allowed={1})
        self.assertEqual(b["on"]["proofs"], [1])
        b, _ = normalise.decision_answer({"verdict": ans["verdict"], "proof_0": {"noul": 0.99}}, row, proofs_allowed={1})
        self.assertEqual(b["verdict"], "UNDECIDED")

    def test_r4c4_a_row_marked_on_request_or_withdrawn_is_undecided_in_the_document_profile(self):
        for flag in ("on_request", "withdrawn"):
            snap = df.edit_audit(self.copy(df.DOC_IN, flag), self.keydir, lambda rows, f=flag: rows[0].update({f: True} if f == "withdrawn" else {f: {"holder": "x", "bundle_sha256": "0" * 64}}))
            _, client, _, ans, _ = self.run_answer(snap, name=f"answer-{flag}")
            for name in (W_CHAT, W_DEC):
                r = witness_rows(ans)[name]["C-001"]
                self.assertEqual(r["verdict"], "UNDECIDED", (flag, name))
                self.assertIn("not a document-profile verdict", r["note"])


# ---------------------------------------------------------------------------------------------------------------------------- R4c-5
AUDIT_KID = "sk_r4caudit0000001"


class _PublicServer(_Tmp):
    """The witness in PUBLIC mode on a local port, the fake provider, SIG3 receipts signed; caller keys as the audit service publishes
    them (GET /audit/v1/keys: {service, namespace, keys: [{key_id, public_key, ssh}]}) behind WITNESS_CALLER_KEYS_URL."""
    CALLER_KEYS = True

    def setUp(self):
        super().setUp()
        self.audit_key = make_key(self.tmp, "audit-service")
        doc = {"service": "onedroid-audit", "namespace": "onedroid-resp",
               "keys": [{"key_id": AUDIT_KID, "public_key": base64.b64encode(raw_public(self.audit_key)).decode(), "ssh": "ssh-ed25519 x"}]}
        env = {"WITNESS_RESP_SIGNING_KEY": str(make_key(self.tmp, "svc"))}
        if self.CALLER_KEYS:
            env["WITNESS_CALLER_KEYS_URL"] = "http://onedroid-audit.audit-dev.svc.cluster.local/audit/v1/keys"
        self.store = JobStore(self.tmp / "jobs")
        self.wiring = respsign.from_env(env, self.store, "test", private_mode=False, caller_fetch=lambda: json.dumps(doc).encode())
        check = checkpin.load_check(df.CHECK_PY)
        self.ledger = Ledger(str(self.tmp / "ledger.json"), 100.0)
        self.client = RecordingFake(df.DOC_REC, self.ledger)
        self.keystore = KeyStore(self.tmp / "keys")
        premint(self.keystore)
        known = {m["id"]: m for m in df.DOC_MODELS}
        self.worker = Worker(self.store, self.client, self.keystore, check, lambda ids: [known[i] for i in ids], df.DOC_PRICES, private_mode=False,
                             finish=self.wiring.responder.finish)
        self.worker.start()
        self.fetcher = DictFetcher({})
        saved = (request._resolve_once, request._connect_and_get)
        request._resolve_once, request._connect_and_get = self.fetcher.resolve, self.fetcher.connect
        self.addCleanup(setattr, request, "_resolve_once", saved[0])
        self.addCleanup(setattr, request, "_connect_and_get", saved[1])
        cfg = {"store": self.store, "worker": self.worker, "models_cfg": df.DOC_MODELS, "prices": df.DOC_PRICES, "ledger": self.ledger,
               "keystore": self.keystore, "private_mode": False, "version": "test", "responder": self.wiring.responder,
               "verifier": self.wiring.verifier, "require_key": self.wiring.require_key, "caller_verifier": self.wiring.caller_verifier,
               "fetch": self.fetcher}
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(cfg))
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.addCleanup(self.httpd.server_close)
        self.addCleanup(self.httpd.shutdown)

    def post(self, parts, fields, sign_with=None, kid=AUDIT_KID):
        body, ctype = multipart(parts, fields)
        h = {"Content-Type": ctype, "Content-Length": str(len(body))}
        if sign_with is not None:
            h.update(sign_request(sign_with, kid, body)[0])
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        c.request("POST", "/witness", body=body, headers=h)
        r = c.getresponse()
        return r.status, json.loads(r.read())

    def get(self, path):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        c.request("GET", path)
        r = c.getresponse()
        return r.status, dict(r.getheaders()), r.read()

    def wait(self, jid):
        for _ in range(600):
            s = json.loads(self.get(f"/witness/{jid}")[2])
            if s["state"] in ("done", "refused", "failed"):
                return s
            time.sleep(0.1)
        self.fail("job did not finish")

    def jobs(self):
        return sorted(p.name for p in (self.tmp / "jobs").iterdir() if p.is_dir() and not p.name.startswith("."))

    def assert_nothing_kept(self, before):
        self.assertEqual(self.jobs(), before)
        inc = self.tmp / "jobs" / ".incoming"
        self.assertEqual(list(inc.iterdir()) if inc.exists() else [], [])


class R4c5CallerSignature(_PublicServer):
    def test_r4c5_an_unpublished_document_part_from_a_verified_caller_runs_and_the_receipt_names_the_caller(self):
        st, ans = self.post(df.parts_of(df.DOC_IN), {"models": DOC_MODEL_IDS, "max_cost_usd": "0.5"}, sign_with=self.audit_key)
        self.assertEqual(st, 202, ans)
        caller = ans["receipt"]["caller"]
        self.assertEqual(caller["key_id"], AUDIT_KID)
        self.assertEqual(caller["owner"], "onedroid-audit")
        self.assertEqual(caller["key_source"], "caller")
        self.assertTrue(caller["signed_line"].startswith("onedroid-req/1 onedroid-witness POST /witness sha256:"))
        self.assertTrue(verify_resp({"service": self.wiring.responder.keys_doc()}, ans["receipt"], ans["signature"]))
        s = self.wait(ans["job_id"])
        self.assertEqual(s["state"], "done", s)
        self.assertEqual(self.fetcher.connects, [])  # nothing was fetched: the part is unpublished and its caller verified
        svc = df.load(self.tmp / "jobs" / ans["job_id"] / "answer" / "service.json")
        self.assertEqual(svc["mode"], "public")
        self.assertEqual(svc["published"]["published"], None)
        self.assertEqual(svc["published"]["unpublished_from_verified_caller"]["key_id"], AUDIT_KID)
        # the answer the service produced goes into the received folder and the pinned checker passes it
        st, headers, tar_bytes = self.get(f"/witness/{ans['job_id']}/answer.tar")
        out = self.tmp / "unpacked"
        out.mkdir()
        with tarfile.open(fileobj=io.BytesIO(tar_bytes)) as tar:
            tar.extractall(out, filter="data")
        snap = self.copy(df.DOC_IN, "received")
        keys = df.model_keys_file(self.keystore, self.tmp / "model-keys.jsonl")
        r = df.add_witness(snap, out, make_key(self.keydir, "adder"), keys=keys)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        c = df.run_check(snap, keys=keys)
        self.assertEqual(c.returncode, 0, c.stdout)

    def test_r4c5_an_unpublished_document_part_with_no_caller_signature_is_refused_by_name(self):
        before = self.jobs()
        st, ans = self.post(df.parts_of(df.DOC_IN), {"models": DOC_MODEL_IDS})
        self.assertEqual(st, 422, ans)
        self.assertIn("unpublished document part", ans["error"])
        self.assertIn("caller signature", ans["error"])
        self.assertIn("WITNESS_CALLER_KEYS_URL", ans["error"])
        self.assert_nothing_kept(before)
        self.assertEqual(self.client.calls, [])

    def test_r4c5_a_caller_signature_that_does_not_verify_is_401(self):
        before = self.jobs()
        stranger = make_key(self.tmp, "stranger")
        st, ans = self.post(df.parts_of(df.DOC_IN), {"models": DOC_MODEL_IDS}, sign_with=stranger)  # the listed key id, another key
        self.assertEqual(st, 401, ans)
        st, ans = self.post(df.parts_of(df.DOC_IN), {"models": DOC_MODEL_IDS}, sign_with=self.audit_key, kid="sk_notlisted00001")
        self.assertEqual(st, 401, ans)
        self.assert_nothing_kept(before)

    def test_r4c5_a_published_document_part_keeps_todays_path(self):
        base = "https://example.org/r4c/document-in-document-proof-2026-11-22/"
        self.fetcher.served.update({base + "audit.jsonl": (200, (df.DOC_IN / "audit.jsonl").read_bytes()),
                                    base + "manifest.json": (200, (df.DOC_IN / "manifest.json").read_bytes())})
        st, ans = self.post(df.parts_of(df.DOC_IN), {"models": DOC_MODEL_IDS, "published_url": base + "audit.jsonl"})
        self.assertEqual(st, 202, ans)
        self.assertIsNone(ans["receipt"]["caller"])
        s = self.wait(ans["job_id"])
        self.assertEqual(s["state"], "done", s)
        self.assertEqual(self.fetcher.calls, [base + "audit.jsonl", base + "manifest.json"])  # the server's check, then the worker's below
        self.assertEqual(self.fetcher.connects.count(base + "audit.jsonl"), 2)
        svc = df.load(self.tmp / "jobs" / ans["job_id"] / "answer" / "service.json")
        self.assertEqual(svc["published"]["published"]["url"], base + "audit.jsonl")
        # a published part whose bound manifest differs is refused as today
        M = df.load(df.DOC_IN / "manifest.json")
        M["subject"]["title"] = "another title"
        st, ans = self.post({**df.parts_of(df.DOC_IN), "manifest.json": json.dumps(M, indent=1).encode()}, {"models": DOC_MODEL_IDS, "published_url": base + "audit.jsonl"})
        self.assertEqual(st, 422, ans)
        self.assertIn("subject differs from the published snapshot's", ans["error"])

    def test_r4c5_another_profile_unpublished_is_refused_as_today_even_from_a_verified_caller(self):
        snap = ROOT / "fixtures" / "snapshot-agentic-age-2026-11-11"
        parts = {n: (snap / n).read_bytes() for n in ("manifest.json", "audit.jsonl", "audit.jsonl.sig", "allowed_signers", "signatures.json", "page.txt")}
        st, ans = self.post(parts, {"models": DOC_MODEL_IDS}, sign_with=self.audit_key)
        self.assertEqual(st, 422, ans)
        self.assertIn("the public service takes published parts only", ans["error"])


class R4c5NoCallerKeys(_PublicServer):
    CALLER_KEYS = False

    def test_r4c5_without_WITNESS_CALLER_KEYS_URL_an_unpublished_document_part_is_refused_by_name(self):
        self.assertIsNone(self.wiring.caller_verifier)
        before = self.jobs()
        st, ans = self.post(df.parts_of(df.DOC_IN), {"models": DOC_MODEL_IDS})
        self.assertEqual(st, 422, ans)
        self.assertIn("unpublished document part", ans["error"])
        self.assertIn("WITNESS_CALLER_KEYS_URL is not set", ans["error"])
        self.assert_nothing_kept(before)


class R4c5Env(unittest.TestCase):
    def test_r4c5_from_env_reads_WITNESS_CALLER_KEYS_URL(self):
        tmp = pathlib.Path(tempfile.mkdtemp(prefix="witness-r4c-env-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        store = JobStore(tmp / "jobs")
        self.assertIsNone(respsign.from_env({}, store, "test").caller_verifier)
        w = respsign.from_env({"WITNESS_CALLER_KEYS_URL": "http://onedroid-audit.audit-dev.svc.cluster.local/audit/v1/keys"}, store, "test",
                              caller_fetch=lambda: b'{"keys": []}')
        self.assertIsInstance(w.caller_verifier, respsign.CallerKeys)
        with self.assertRaises(SystemExit):
            respsign.from_env({"WITNESS_CALLER_KEYS_URL": "file:///etc/passwd"}, store, "test")


# ---------------------------------------------------------------------------------------------------------------------------- R4c-6
class R4c6Insertion(_Tmp):
    def insert_and_check(self, snap, ans, keystore):
        keys = df.model_keys_file(keystore, self.tmp / f"model-keys-{snap.name}.jsonl")
        r = df.add_witness(snap, ans, make_key(self.keydir, "adder"), keys=keys)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        c = df.run_check(snap, keys=keys)
        self.assertEqual(c.returncode, 0, c.stdout)
        return c.stdout

    def test_r4c6_the_answer_inserted_into_each_fixture_passes_the_pinned_checker(self):
        for src in (df.DOC_IN, df.DOC_EXT):
            snap = self.copy(src)
            svc, _, keystore, ans, _ = self.run_answer(snap, name=f"answer-{src.name}")
            out = self.insert_and_check(snap, ans, keystore)
            self.assertRegex(out, r"(?m)^SUMMARY: 16 checks, 0 failed")
            for w, model in ((W_CHAT, CHAT_SERVED), (W_DEC, DEC_SERVED)):
                self.assertIn(f"witness/{w}.jsonl: signed by {w}, verified", out)  # K13 verifies the model witness's signature
                self.assertIn(f"witness/{w}.jsonl: principal {w} bound to {model} in --keys", out)  # bound in the key list (SPEC 14)
                self.assertIn(f"witness '{w}' agrees with the auditor's claimed verdict on 3 of 3 checkable claims it decided", out)  # K12
            self.assertRegex(out, r"(?m)^K12 PASS")
            self.assertRegex(out, r"(?m)^K13 PASS")

    def test_r4c6_the_restatement_variant_inserted_passes_and_k12_prints_the_disagreement(self):
        snap = restatement_variant(self.copy(df.DOC_IN), self.keydir)
        svc, _, keystore, ans, _ = self.run_answer(snap, rec=REC_RESTATE)
        out = self.insert_and_check(snap, ans, keystore)
        self.assertIn(f"witness '{W_CHAT}' agrees with the auditor's claimed verdict on 2 of 2 checkable claims it decided", out)  # C-001 UNDECIDED
        self.assertIn(f"witness '{W_DEC}' agrees with the auditor's claimed verdict on 3 of 3 checkable claims it decided", out)


# ---------------------------------------------------------------------------------------------------------------------------- R4c-7
class R4c7Spend(_Tmp):
    def test_r4c7_the_estimate_counts_only_the_claims_sent_to_models(self):
        full = request.Request(self.copy(df.DOC_IN), private_mode=True)
        cut = request.Request(without_c002(self.copy(df.DOC_IN, "cut"), self.keydir), private_mode=True)
        e_full, e_cut = answer.estimate_request(full, df.DOC_MODELS, df.DOC_PRICES), answer.estimate_request(cut, df.DOC_MODELS, df.DOC_PRICES)
        self.assertEqual(e_full, e_cut)  # C-002 is settled by the restatement rule: it adds nothing
        self.assertGreater(e_full[1], 0)
        svc, _, _, _, _ = self.run_answer(self.copy(df.DOC_IN, "run"))
        self.assertEqual(svc["estimate_usd"]["per_model"], e_full[0])
        self.assertEqual(svc["per_model"][df.CHAT]["calls"], 2)

    def test_r4c7_claims_settled_by_the_rule_cost_nothing(self):
        snap = all_restatement_variant(self.copy(df.DOC_IN), self.keydir)
        req = request.Request(snap, private_mode=True)
        per_model, total = answer.estimate_request(req, df.DOC_MODELS, df.DOC_PRICES)
        self.assertEqual(total, 0)
        self.assertEqual(per_model, {df.CHAT: 0, df.DECISION: 0})
        svc, client, keystore, ans, ledger = self.run_answer(snap)
        self.assertEqual(client.calls, [])
        self.assertEqual(svc["total_cost_usd"], 0)
        self.assertEqual(ledger.remaining(), 100.0)
        for name in witness_rows(ans):
            self.assertEqual({k: v["verdict"] for k, v in witness_rows(ans)[name].items() if k != "header"},
                             {"C-001": "NO EVIDENCE PUBLISHED", "C-002": "NO EVIDENCE PUBLISHED", "C-003": "NO EVIDENCE PUBLISHED"})
        self.assertRegex(self_insert(self, snap, ans, keystore), r"(?m)^SUMMARY: 16 checks, 0 failed")


def self_insert(tc, snap, ans, keystore):
    keys = df.model_keys_file(keystore, tc.tmp / "model-keys.jsonl")
    r = df.add_witness(snap, ans, make_key(tc.keydir, "adder"), keys=keys)
    tc.assertEqual(r.returncode, 0, r.stdout + r.stderr)
    c = df.run_check(snap, keys=keys)
    tc.assertEqual(c.returncode, 0, c.stdout)
    return c.stdout


class R4c7SpendServer(_PublicServer):
    def test_r4c7_the_per_request_bound_still_applies_and_a_settled_folder_fits_any_bound(self):
        before = self.jobs()
        st, ans = self.post(df.parts_of(df.DOC_IN), {"models": DOC_MODEL_IDS, "max_cost_usd": "0.0000001"}, sign_with=self.audit_key)
        self.assertEqual(st, 422, ans)
        self.assertIn("estimate", ans["error"])
        self.assert_nothing_kept(before)
        snap = all_restatement_variant(self.copy(df.DOC_IN), self.keydir)
        st, ans = self.post(df.parts_of(snap), {"models": DOC_MODEL_IDS, "max_cost_usd": "0.0000001"}, sign_with=self.audit_key)
        self.assertEqual(st, 202, ans)
        self.assertEqual(ans["estimate_total_usd"], 0)
        self.assertEqual(self.wait(ans["job_id"])["state"], "done")
        self.assertEqual(self.client.calls, [])


# ---------------------------------------------------------------------------------------------------------------------------- R4c-8
class R4c8FixturesAndReadme(unittest.TestCase):
    def test_r4c8_the_fixtures_are_the_a5ce040_examples_before_any_witness(self):
        for src, audit_sha in ((df.DOC_IN, "a4d7f6c769824985f40ad39cfd0918d21223fb47767261eb923a700378050a75"),
                               (df.DOC_EXT, "da72d694455fe67f0bd4472298cce74888d05755153413d277f5c73456db4362")):
            self.assertFalse((src / "witness").exists())
            self.assertEqual(df.sha(src / "audit.jsonl"), audit_sha)  # the auditor's part byte for byte as published at a5ce040
            M = df.load(src / "manifest.json")
            self.assertEqual(M["grading"]["witnesses"], [])
            c = df.run_check(src)
            self.assertEqual(c.returncode, 0, c.stdout)

    def test_r4c8_readme_names_the_document_profile_and_the_caller_key_list(self):
        t = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("document", re.search(r"`profiles_served`\s+defaults to ([^.]*)", t).group(1))
        self.assertIn("WITNESS_CALLER_KEYS_URL", t)
        self.assertIn("restatement", t)
        self.assertIn(PIN[:8], t)


if __name__ == "__main__":
    unittest.main()
