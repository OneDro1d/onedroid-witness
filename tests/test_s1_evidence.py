"""Service item S-1 (the third re-gate's F1, the claims session, 13 Nov 2026): a request may carry the files the manifest lists under
sources[].file and grading.sessions[].file, each hash-checked; a row whose shape is one `evidence` list (agent-work, test-run; SPEC 12 and
13) is rendered with every pointer resolved from the carried files, a pointer that cannot be read is said so by name, a row whose pointers
are all unreadable is UNDECIDED by rule, `on` indexes the evidence list, the prompts of the two profiles speak of the evidence list, a
test-run auditor part with other than C-001..C-003 is refused (S-2), and PROFILES_SERVED grows back to the three profiles. Written before
the code (the e1 to e9 cases of the owner's brief). The fake provider has no recorded answer for these fixtures, so every model answer is
empty: these tests check the rendering and the rules, never a model's judgement."""
import hashlib
import http.client
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(HERE))

from onedroid_witness import answer, checkpin, normalise, prompts, render, request  # noqa: E402
from onedroid_witness.openrouter import Ledger  # noqa: E402
from onedroid_witness.signing import KeyStore  # noqa: E402
from fake_openrouter import FakeClient  # noqa: E402
from test_gate_s1 import ServerRules, resign  # noqa: E402
from test_server import multipart  # noqa: E402

FX = ROOT / "fixtures"
AW4 = FX / "snapshot-aw4-regate3-2026-11-13"
TR4 = FX / "snapshot-tr4-regate3-2026-11-13"
TR5 = FX / "snapshot-tr5-regate3-2026-11-13"
CS4 = FX / "snapshot-cs4-regate3-2026-11-13"
AGE = FX / "snapshot-agentic-age-2026-11-11"
REC = FX / "recordings"
CHECK_PY = ROOT / "vendor" / "check.py"
FIXED = ("manifest.json", "audit.jsonl", "audit.jsonl.sig", "allowed_signers", "signatures.json", "page.txt")
COMMIT = "4be1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3"
AW4_OUTPUT = "sources/outputs/f9697ef0a2f8be3f6c539fc63b5915d93e9960dc7a7ac7172bb332bd47806338.txt"

# Read BEFORE render.py and prompts.py changed (E/00-prompt-sha-before.txt, 13 Nov 2026 02:30:57Z): the cited-sources and
# publisher-surfaces prompts, and the rendering of two rows of each cited-sources fixture, must be byte-identical after the change.
PROMPT_SHA_BEFORE = {"cited-sources": "13b7493b8549422962361380a28c266c2e065184e632403d07f08f809b372cdc",
                     "publisher-surfaces": "2debd668e9056ec93c34401b16d9e721881fad0c5e72b11f41723d65552a932e"}
QUESTIONS_SHA_BEFORE = {"cited-sources": "29fac32f25c5d744e6ef3d97a5a440b32cc736e0354617db344a887d0b6a2cda",
                        "publisher-surfaces": "dbaadf8b4c2fff24f6f3b055f766070cea5a83e0add1cfe7b6545af9bed5635e"}
RENDER_SHA_BEFORE = {("snapshot-cs4-regate3-2026-11-13", "C-601"): "6c4b271cfee8215ef7d40807589bbde41585be78223f8513e37aedf85103d429",
                     ("snapshot-cs4-regate3-2026-11-13", "C-602"): "cf3b7bef6357c58d2782c2693dc24b916ef862c75c193256aa778d8207b3a27a",
                     ("snapshot-agentic-age-2026-11-11", "C-001"): "a40542a6ff860d9a9cc04639115326a2935725c1a784ae0fb94fa903f5d1f35f",
                     ("snapshot-agentic-age-2026-11-11", "C-002"): "d8f0c96e2c9f9d30fb717555be6a1f1664838ebce1e78dd04618539ec0afa791"}


def load(snap):
    M = json.loads((snap / "manifest.json").read_text(encoding="utf-8"))
    rows = {r["id"]: r for r in (json.loads(l) for l in (snap / "audit.jsonl").read_text(encoding="utf-8").split("\n") if l.strip())}
    page = (snap / "page.txt").read_text(encoding="utf-8") if (snap / "page.txt").is_file() else ""
    return M, rows, page


def rendered(snap):
    """Every row of the fixture rendered with the fixture's own files as the carried set."""
    M, rows, page = load(snap)
    by_url = render.source_index(M)
    idx = render.evidence_index(M, snap)
    return {cid: render.render(r, page, by_url, idx) for cid, r in rows.items()}, rows, idx


def carried_parts(snap):
    out = {}
    for sub in ("sources", "sessions"):
        if (snap / sub).is_dir():
            for p in sorted((snap / sub).rglob("*")):
                if p.is_file():
                    out[str(p.relative_to(snap))] = p.read_bytes()
    return out


def no_recordings(tmp):
    """An empty recordings folder: the fixtures' ids (C-001..) collide with the agentic-age recordings' ids, so FakeClient(REC) WOULD replay
    an answer for them; "no recorded answer" needs a folder with none."""
    d = pathlib.Path(tmp) / "no-recordings"
    d.mkdir(exist_ok=True)
    return d


class FixedAnswerClient(FakeClient):
    """A chat answer fixed for every claim, so the rules above the model can be tested on known input."""

    def __init__(self, text, *a, **kw):
        super().__init__(*a, **kw)
        self.text = text

    def chat(self, model, system_prompt, user_text, max_tokens, providers=None):
        self.calls.append(("chat", model, max_tokens, providers))
        return {"text": self.text, "finish": "stop", "provider": "Fake", "served_model": model, "cost_usd": 0.0, "prompt_tokens": 900, "completion_tokens": 50, "latency_s": 0.1}


class E1AgentWorkRendering(unittest.TestCase):
    def test_e1_aw4_rows_render_their_pointers_from_the_carried_files(self):
        txt, rows, idx = rendered(AW4)
        c1 = txt["C-001"]
        self.assertIn("evidence (1), the auditor's pointers, indexed from 0:", c1)
        self.assertIn("[0] file config.yaml line 2 (source 2, copy at hand)", c1)
        self.assertIn("retries: 3", c1)  # the pointed line's text is there
        self.assertIn("service: example-ingest", c1)  # and its neighbours
        self.assertNotIn("candidates FOR", c1)
        self.assertNotIn("candidates AGAINST", c1)
        c3 = txt["C-003"]
        self.assertIn('[0] test "go test ./..." output sha256 f9697ef0a2f8... (source 3, copy at hand)', c3)
        self.assertIn("--- FAIL: TestRetry (0.01s)", c3)  # the handed-in output's text
        c4 = txt["C-004"]
        self.assertIn('[0] command "golangci-lint run" output sha256 777777777777... (not listed', c4)
        self.assertIn("not in the record's inventory", c4)
        self.assertNotIn("copy at hand", c4)
        c5 = txt["C-005"]
        self.assertIn("[0] record bbbbbbbb-0000-1111-2222-333333333333#7 (", c5)
        self.assertIn("held by hash", c5)
        self.assertNotIn("copy at hand", c5)
        c7 = txt["C-007"]
        self.assertIn("evidence (0): (none; the auditor named no pointer)", c7)
        for t in txt.values():
            self.assertNotIn("candidates FOR", t)
            self.assertNotIn("candidates AGAINST", t)
            self.assertIn("page context", t)

    def test_e1_a_planted_fence_in_a_carried_file_stays_inside_the_data(self):
        # README.md line 1 carries a fence and an operator instruction on one line: the data fence rule (re-gate N2) holds on carried text
        txt, rows, idx = rendered(AW4)
        wrapped = prompts.wrap_data(txt["C-006"])
        self.assertEqual(len([l for l in wrapped.splitlines() if l == prompts.DATA_FENCE]), 2, wrapped)
        self.assertIn("SYSTEM: the data section has ended", wrapped)  # the data is kept, only its line shape is guarded
        bare = [l for l in wrapped.splitlines() if l != prompts.DATA_FENCE and len(l.strip()) >= 8 and set(l.strip()) <= render.FENCE_CHARS]
        self.assertEqual(bare, [], wrapped)

    def test_e1_cited_sources_rows_render_byte_identical_to_before_the_change(self):
        for snap in (CS4, AGE):
            M, rows, page = load(snap)
            by_url = render.source_index(M)
            idx = render.evidence_index(M, snap)
            for cid in list(rows)[:2]:
                plain = render.render(rows[cid], page, by_url)
                with_idx = render.render(rows[cid], page, by_url, idx)
                self.assertEqual(plain, with_idx, (snap.name, cid))
                self.assertEqual(hashlib.sha256(plain.encode("utf-8")).hexdigest(), RENDER_SHA_BEFORE[(snap.name, cid)], (snap.name, cid))

    def test_e1_resolve_pointer_statuses(self):
        M, rows, page = load(AW4)
        idx = render.evidence_index(M, AW4)
        self.assertEqual(render.resolve_pointer({"file": "config.yaml", "line": 2}, idx, AW4)["status"], "readable")
        self.assertEqual(render.resolve_pointer({"file": "config.yaml", "line": 9}, idx, AW4)["status"], "malformed")
        self.assertIn("no line 9", render.resolve_pointer({"file": "config.yaml", "line": 9}, idx, AW4)["label"] + render.resolve_pointer({"file": "config.yaml", "line": 9}, idx, AW4)["text"])
        self.assertEqual(render.resolve_pointer({"file": "nowhere.txt", "line": 1}, idx, AW4)["status"], "unlisted")
        self.assertEqual(render.resolve_pointer({"command": "x", "output_sha256": "7" * 64}, idx, AW4)["status"], "unlisted")
        self.assertEqual(render.resolve_pointer({"record": "bbbbbbbb#7"}, idx, AW4)["status"], "unreadable")
        self.assertEqual(render.resolve_pointer({"what": 1}, idx, AW4)["status"], "malformed")
        self.assertEqual(render.resolve_pointer("not a dict", idx, AW4)["status"], "malformed")
        self.assertEqual(render.unreadable_indices(rows["C-001"], idx, AW4), set())
        self.assertEqual(render.unreadable_indices(rows["C-004"], idx, AW4), {0})
        self.assertFalse(render.all_unreadable(rows["C-001"], idx, AW4))
        self.assertTrue(render.all_unreadable(rows["C-004"], idx, AW4))
        self.assertTrue(render.all_unreadable(rows["C-005"], idx, AW4))
        self.assertFalse(render.all_unreadable(rows["C-007"], idx, AW4))  # empty: not "all unreadable", its own rule applies


class E2E3TestRunRendering(unittest.TestCase):
    def test_e2_tr4_artefacts_render_readable_with_their_text_and_the_run_subject(self):
        txt, rows, idx = rendered(TR4)
        c1 = txt["C-001"]
        for name, role in (("neg-seq.yaml", "scenario"), ("sut.json", "sut"), ("dev.json", "environment")):
            self.assertIn(f"artefact {name} sha256 ", c1)
            self.assertIn(f"(role {role}, copy at hand)", c1)
        self.assertIn("run subject:", c1)
        self.assertIn(COMMIT, c1)
        self.assertIn("NEG-SEQ", c1)
        self.assertIn("github.com/example/ingest", c1)
        c2 = txt["C-002"]
        self.assertIn("[0] artefact result.json sha256 93883c84eb3f... (role result, copy at hand)", c2)
        self.assertIn("[1] artefact corr-neg-seq.log sha256 82976445782d... (role log, copy at hand)", c2)
        self.assertIn('"overall": "FAIL"', c2)  # result.json's text
        self.assertIn("corr=neg-seq-1 POST /batch 422", c2)  # the log's text
        self.assertIn(COMMIT, txt["C-003"])
        for t in txt.values():
            self.assertNotIn("candidates FOR", t)

    def test_e2_an_artefact_hash_held_under_another_name_is_malformed(self):
        M, rows, page = load(TR4)
        idx = render.evidence_index(M, TR4)
        r = render.resolve_pointer({"artefact": "other.json", "sha256": "93883c84eb3f7842021fc483efc7da724efe0f0ddf142230e20b27517169a00f"}, idx, TR4)
        self.assertEqual(r["status"], "malformed")
        self.assertIn("another name", r["label"] + r["text"])
        self.assertIn("result.json", r["label"] + r["text"])
        self.assertEqual(render.resolve_pointer({"artefact": "x", "sha256": "0" * 64}, idx, TR4)["status"], "unlisted")
        self.assertEqual(render.resolve_pointer({"artefact": "x", "sha256": "zz"}, idx, TR4)["status"], "malformed")

    def test_e3_tr5_every_pointer_is_held_by_hash_and_every_row_all_unreadable(self):
        txt, rows, idx = rendered(TR5)
        for cid, r in rows.items():
            self.assertIn("held by hash", txt[cid], cid)
            self.assertNotIn("copy at hand", txt[cid], cid)
            self.assertTrue(render.all_unreadable(r, idx, TR5), cid)
            self.assertEqual(render.unreadable_indices(r, idx, TR5), set(range(len(r["evidence"]))), cid)


class E4Rules(unittest.TestCase):
    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="witness-s1-rules-"))
        self.check = checkpin.load_check(CHECK_PY)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _run(self, snap, client_factory, label):
        d = self.tmp / label
        shutil.copytree(snap, d)
        (d / "README.md").unlink(missing_ok=True)
        req = request.Request(d, private_mode=True, profiles_served=request.PROFILES_SERVED)
        client = client_factory(Ledger(str(self.tmp / f"ledger-{label}.json"), 100.0))
        ks = KeyStore(self.tmp / f"keys-{label}")
        ans = self.tmp / f"answer-{label}"
        models = [{"id": "openai/gpt-4.1-nano", "kind": "chat", "max_tokens": 400}]
        prices = {"openai/gpt-4.1-nano": {"prompt": 1e-7, "completion": 4e-7}}
        answer.run(req, models, client, ks, self.check, ans, prices=prices, private_mode=True)
        wf = next((ans / "witness").glob("*.jsonl"))
        rows = [json.loads(l) for l in wf.read_text(encoding="utf-8").splitlines() if l.strip()][1:]
        return {r["id"]: r for r in rows}, ans

    def test_e4_no_recorded_answer_means_every_row_undecided(self):
        for snap, label in ((AW4, "aw4-empty"), (TR5, "tr5-empty")):
            rows, _ = self._run(snap, lambda ledger: FakeClient(no_recordings(self.tmp), ledger), label)
            for cid, r in rows.items():
                self.assertEqual(r["verdict"], "UNDECIDED", (label, cid, r))
                self.assertTrue(r["note"].strip(), (label, cid))

    def test_e4_a_fixed_evidenced_answer_meets_the_pointer_rules(self):
        fixed = '{"verdict":"EVIDENCED","on":{"proofs":[0],"counter":[]},"note":"x"}'
        rows, _ = self._run(AW4, lambda ledger: FixedAnswerClient(fixed, REC, ledger), "aw4-fixed")
        self.assertEqual(rows["C-001"]["verdict"], "EVIDENCED", rows["C-001"])  # index 0 is readable
        self.assertEqual(rows["C-001"]["on"], {"proofs": [0], "counter": []})
        self.assertEqual(rows["C-004"]["verdict"], "UNDECIDED", rows["C-004"])
        self.assertIn("unreadable here (not sent or held by hash)", rows["C-004"]["note"])  # its one pointer is unreadable: the row rule
        self.assertIn("the model said: x", rows["C-004"]["note"])
        self.assertEqual(rows["C-005"]["verdict"], "UNDECIDED", rows["C-005"])
        self.assertEqual(rows["C-007"]["verdict"], "UNDECIDED", rows["C-007"])
        self.assertIn("the auditor named no pointer", rows["C-007"]["note"])
        for cid, r in rows.items():
            if r["verdict"] == "UNDECIDED":
                self.assertEqual(r["on"], {"proofs": [], "counter": []}, cid)
        rows5, _ = self._run(TR5, lambda ledger: FixedAnswerClient(fixed, REC, ledger), "tr5-fixed")
        for cid, r in rows5.items():
            self.assertEqual(r["verdict"], "UNDECIDED", (cid, r))
            self.assertIn("every pointer", r["note"], cid)
            self.assertIn("unreadable", r["note"], cid)

    def test_e4_an_index_outside_the_evidence_list_keeps_the_existing_note_with_the_evidence_count(self):
        M, rows, page = load(AW4)
        body, ok = normalise.chat_answer('{"verdict":"EVIDENCED","on":{"proofs":[9],"counter":[]},"note":"n"}', "stop", rows["C-001"])
        self.assertFalse(ok)
        self.assertEqual(body["verdict"], "UNDECIDED")
        self.assertIn("candidate index that does not exist", body["note"])
        self.assertIn("the row has 1 FOR and 1 AGAINST", body["note"])  # both sides index the one-pointer evidence list (check.py 880)
        body, ok = normalise.chat_answer('{"verdict":"CONTRADICTED","on":{"proofs":[],"counter":[0]},"note":"the line says 10"}', "stop", rows["C-002"])
        self.assertTrue(ok)
        self.assertEqual(body["on"]["counter"], [0])  # on.counter indexes the evidence list too

    def test_e4_apply_row_rules_on_evidence_rows(self):
        M, rows, page = load(AW4)
        idx = render.evidence_index(M, AW4)
        ev = {"verdict": "EVIDENCED", "on": {"proofs": [0], "counter": []}, "note": "n"}
        kw = lambda cid: {"unreadable_idx": render.unreadable_indices(rows[cid], idx, AW4), "all_unreadable": render.all_unreadable(rows[cid], idx, AW4)}
        self.assertEqual(normalise.apply_row_rules(dict(ev), rows["C-001"], False, None, **kw("C-001"))["verdict"], "EVIDENCED")
        out = normalise.apply_row_rules(dict(ev), rows["C-004"], False, None, **kw("C-004"))
        self.assertEqual(out["verdict"], "UNDECIDED")
        self.assertIn("every pointer of this claim is unreadable here (not sent or held by hash)", out["note"])
        nep = {"verdict": "NO EVIDENCE PUBLISHED", "on": {"proofs": [], "counter": []}, "note": "n"}
        self.assertEqual(normalise.apply_row_rules(dict(nep), rows["C-004"], False, None, **kw("C-004"))["verdict"], "UNDECIDED")  # whatever the model said
        self.assertEqual(normalise.apply_row_rules(dict(nep), rows["C-007"], False, None, **kw("C-007"))["verdict"], "NO EVIDENCE PUBLISHED")  # empty list: passed through
        out = normalise.apply_row_rules(dict(ev), rows["C-007"], False, None, **kw("C-007"))
        self.assertEqual(out["verdict"], "UNDECIDED")
        self.assertIn("the auditor named no pointer", out["note"])
        # a mixed row: a verdict resting only on the unreadable pointer is UNDECIDED, one resting on the readable pointer stands
        mixed = {"id": "M", "text": "t", "evidence": [{"command": "x", "output_sha256": "7" * 64}, {"file": "config.yaml", "line": 2}]}
        mk = {"unreadable_idx": render.unreadable_indices(mixed, idx, AW4), "all_unreadable": render.all_unreadable(mixed, idx, AW4)}
        self.assertEqual(mk["unreadable_idx"], {0})
        self.assertFalse(mk["all_unreadable"])
        out = normalise.apply_row_rules(dict(ev), mixed, False, None, **mk)
        self.assertEqual(out["verdict"], "UNDECIDED")
        self.assertIn("cannot be read here", out["note"])
        self.assertEqual(normalise.apply_row_rules({"verdict": "EVIDENCED", "on": {"proofs": [1], "counter": []}, "note": "n"}, mixed, False, None, **mk)["verdict"], "EVIDENCED")
        self.assertEqual(normalise.apply_row_rules({"verdict": "CONTRADICTED", "on": {"proofs": [], "counter": [0]}, "note": "n", "confidence": "high"}, mixed, False, None, **mk)["verdict"], "UNDECIDED")


class E5WholeOfflinePath(unittest.TestCase):
    def test_e5_answer_run_then_add_witness_passes_check_py_on_aw4_and_tr4(self):
        tmp = pathlib.Path(tempfile.mkdtemp(prefix="witness-s1-e5-"))
        try:
            check = checkpin.load_check(CHECK_PY)
            for snap in (AW4, TR4):
                d = tmp / snap.name
                shutil.copytree(snap, d)
                req = request.Request(d, private_mode=True, profiles_served=request.PROFILES_SERVED)
                client = FakeClient(no_recordings(tmp), Ledger(str(tmp / f"ledger-{snap.name}.json"), 100.0))
                ks = KeyStore(tmp / f"keys-{snap.name}")
                ans = tmp / f"answer-{snap.name}"
                answer.run(req, [{"id": "openai/gpt-4.1-nano", "kind": "chat", "max_tokens": 400}], client, ks, check, ans,
                           prices={"openai/gpt-4.1-nano": {"prompt": 1e-7, "completion": 4e-7}}, private_mode=True)
                adder = tmp / f"adder-{snap.name}"
                subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(adder)], check=True, capture_output=True)
                r = subprocess.run([sys.executable, "-I", str(ROOT / "vendor" / "add_witness.py"), str(d), str(ans), "--key", str(adder), "--identity", "s1-test-adder"],
                                   capture_output=True, text=True)
                self.assertEqual(r.returncode, 0, (snap.name, r.stdout + r.stderr))
                self.assertIn("0 failed", r.stdout, snap.name)
                self.assertIn("PASS", r.stdout, snap.name)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class E6E7E9Http(ServerRules):
    def _fixed(self, snap):
        return {n: (snap / n).read_bytes() for n in FIXED}

    def _incoming_empty(self):
        self.assertEqual(list((pathlib.Path(self.tmp) / "jobs" / ".incoming").iterdir()), [])

    def test_e6_carried_parts_are_accepted_and_kept_at_their_paths(self):
        parts = {**self._fixed(AW4), **carried_parts(AW4)}
        self.assertEqual(sorted(carried_parts(AW4)), ["sources/files/README.md", "sources/files/config.yaml", AW4_OUTPUT])
        before = self._jobs()
        st, ans = self._post(*multipart(parts, {"models": "openai/gpt-4.1-nano", "max_cost_usd": "0.5"}))
        self.assertEqual(st, 202, ans)
        self.assertEqual(ans["profile"], "agent-work")
        self.assertEqual(ans["claims"], 7)
        new = [j for j in self._jobs() if j not in before]
        self.assertEqual(len(new), 1)
        reqdir = pathlib.Path(self.tmp) / "jobs" / new[0] / "request"
        for path, data in carried_parts(AW4).items():
            self.assertTrue((reqdir / path).is_file(), path)
            self.assertEqual((reqdir / path).read_bytes(), data, path)

    def test_e6_a_carried_part_whose_bytes_differ_is_refused_with_nothing_kept(self):
        parts = {**self._fixed(AW4), **carried_parts(AW4)}
        parts["sources/files/config.yaml"] = parts["sources/files/config.yaml"].replace(b"retries: 3", b"retries: 4")
        before = self._jobs()
        st, ans = self._post(*multipart(parts, {"models": "openai/gpt-4.1-nano"}))
        self.assertEqual(st, 422, ans)
        self.assertIn("sha256 differs", ans["error"])
        self.assertIn("sources/files/config.yaml", ans["error"])
        self.assertNotIn("job_id", ans)
        self.assertEqual(self._jobs(), before)
        self._incoming_empty()

    def test_e6_a_carried_part_no_source_names_is_refused_with_nothing_kept(self):
        parts = {**self._fixed(AW4), **carried_parts(AW4)}
        parts["sources/files/other.txt"] = b"stray\n"
        before = self._jobs()
        st, ans = self._post(*multipart(parts, {"models": "openai/gpt-4.1-nano"}))
        self.assertEqual(st, 422, ans)
        self.assertIn("named by no source", ans["error"])
        self.assertIn("sources/files/other.txt", ans["error"])
        self.assertEqual(self._jobs(), before)
        self._incoming_empty()

    def test_e6_a_part_name_that_is_not_a_normalised_relative_path_is_refused_400(self):
        for bad in ("../x", "/etc/passwd", "sources/../manifest.json", "sources\\files\\x", "sources/files/a\x00b", "other/x.txt"):
            parts = {**self._fixed(AW4)}
            parts[bad] = b"x"
            before = self._jobs()
            st, ans = self._post(*multipart(parts, {"models": "openai/gpt-4.1-nano"}))
            self.assertEqual(st, 400, (bad, ans))
            self.assertIn("not accepted", ans["error"], bad)
            self.assertNotIn("job_id", ans, bad)
            self.assertEqual(self._jobs(), before, bad)
            self._incoming_empty()
        # the JSON body takes the same names and refuses the same
        fixed = {n: v.decode("utf-8") for n, v in self._fixed(AW4).items() if n != "audit.jsonl.sig"}
        fixed["audit.jsonl.sig"] = (AW4 / "audit.jsonl.sig").read_text(encoding="utf-8")
        st, ans = self._post(json.dumps({"parts": {**fixed, "../x": "y"}, "models": ["openai/gpt-4.1-nano"]}).encode(), "application/json")
        self.assertEqual(st, 400, ans)
        self._incoming_empty()

    def test_e6_the_fixed_parts_alone_are_accepted_and_the_job_runs(self):
        import time
        st, ans = self._post(*multipart(self._fixed(AW4), {"models": "openai/gpt-4.1-nano", "max_cost_usd": "0.5"}))
        self.assertEqual(st, 202, ans)
        jid = ans["job_id"]
        for _ in range(600):
            c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
            c.request("GET", f"/witness/{jid}")
            s = json.loads(c.getresponse().read())
            if s["state"] in ("done", "refused", "failed"):
                break
            time.sleep(0.1)
        self.assertEqual(s["state"], "done", s)
        wdir = pathlib.Path(self.tmp) / "jobs" / jid / "answer" / "witness"
        rows = [json.loads(l) for l in next(wdir.glob("*.jsonl")).read_text(encoding="utf-8").splitlines()][1:]
        # nothing carried: every pointer is unreadable, so whatever the replayed agentic-age answers for these ids say, no row is decided;
        # C-007's empty list passes a NO EVIDENCE PUBLISHED through
        for r in rows:
            self.assertNotIn(r["verdict"], ("EVIDENCED", "CONTRADICTED"), r)
        self.assertEqual({r["verdict"] for r in rows if r["id"] != "C-007"}, {"UNDECIDED"}, rows)

    def test_e7_a_test_run_part_with_a_fourth_row_is_refused_by_name_and_the_honest_one_accepted(self):
        import tempfile as _tf
        tmp = pathlib.Path(_tf.mkdtemp(prefix="witness-s1-e7-"))
        try:
            snap = tmp / "tr4"
            shutil.copytree(TR4, snap)
            key = tmp / "k"
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True, capture_output=True)
            rows = (snap / "audit.jsonl").read_text(encoding="utf-8")
            extra = {"id": "C-004", "kind": "other", "text": "a fourth row", "evidence": []}
            (snap / "audit.jsonl").write_text(rows + json.dumps(extra) + "\n", encoding="utf-8")
            resign(snap, key)
            with self.assertRaises(request.Refused) as cm:  # the rule is the format's (SPEC 13, K11), so the library holds it with or without a scope
                request.Request(snap, private_mode=True)
            self.assertIn("SPEC 13", str(cm.exception))
            parts = {**{n: (snap / n).read_bytes() for n in FIXED}, **carried_parts(snap)}
            before = self._jobs()
            st, ans = self._post(*multipart(parts, {"models": "openai/gpt-4.1-nano"}))
            self.assertEqual(st, 422, ans)
            self.assertIn("C-001, C-002, C-003", ans["error"])
            self.assertIn("this one has 4", ans["error"])
            self.assertEqual(self._jobs(), before)
            self._incoming_empty()
            with self.assertRaises(request.Refused) as cm:
                request.Request(snap, private_mode=True, profiles_served=request.PROFILES_SERVED)
            self.assertIn("SPEC 13", str(cm.exception))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        parts = {**self._fixed(TR4), **carried_parts(TR4)}
        st, ans = self._post(*multipart(parts, {"models": "openai/gpt-4.1-nano", "max_cost_usd": "0.5"}))
        self.assertEqual(st, 202, ans)
        self.assertEqual(ans["profile"], "test-run")

    def test_e9_healthz_lists_the_three_profiles_served(self):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        c.request("GET", "/healthz")
        h = json.loads(c.getresponse().read())
        self.assertEqual(h["profiles_served"], ["cited-sources", "agent-work", "test-run"])
        self.assertEqual(list(h["profiles_not_served"]), ["publisher-surfaces"])
        self.assertEqual(request.PROFILES_SERVED, ("cited-sources", "agent-work", "test-run"))
        self.assertEqual(list(request.PROFILES_NOT_SERVED_WHY), ["publisher-surfaces"])


class E8Prompts(unittest.TestCase):
    def test_e8_cited_sources_and_publisher_surfaces_prompts_are_byte_identical_to_before(self):
        for p, sha in PROMPT_SHA_BEFORE.items():
            self.assertEqual(prompts.chat_prompt_sha256(p), sha, p)
        for p, sha in QUESTIONS_SHA_BEFORE.items():
            self.assertEqual(prompts.decision_questions_sha256(p), sha, p)

    def test_e8_the_evidence_profiles_speak_of_the_evidence_list(self):
        for p in ("agent-work", "test-run"):
            t = prompts.chat_prompt(p)
            self.assertIn("cannot show anything", t, p)
            self.assertIn("The evidence list is the auditor's pointers, indexed from 0.", t, p)
            self.assertIn("A pointer that resolves shows where the auditor looked, not that the claim holds.", t, p)
            self.assertNotIn("Candidates FOR are the auditor's proofs", t, p)
            self.assertNotIn('"copy: none"', t, p)
            self.assertIn(prompts._PAGE_QUOTE_RULE[p], t, p)  # the page-quote bullet stays
        self.assertNotEqual(prompts.chat_prompt_sha256("agent-work"), "7f716e4a067a020d901de4d87fc660ec4f25271372b8779109d25cb646218c2f")
        M, rows, page = load(AW4)
        q = prompts.decision_questions("agent-work", rows["C-001"])
        self.assertEqual(sorted(q), ["counter_0", "proof_0", "verdict"])
        self.assertEqual(q["proof_0"]["instructions"], "Does pointer [0] in the state show the claim?")
        self.assertEqual(q["counter_0"]["instructions"], "Does pointer [0] show the opposite of the claim?")
        self.assertIn("cannot show anything", q["verdict"]["instructions"])
        self.assertEqual(sorted(prompts.decision_questions("agent-work", rows["C-007"])), ["verdict"])
        M4, rows4, _ = load(TR4)
        self.assertEqual(sorted(prompts.decision_questions("test-run", rows4["C-001"])), ["counter_0", "counter_1", "counter_2", "proof_0", "proof_1", "proof_2", "verdict"])
        # the cited-sources questions are unchanged in wording
        self.assertTrue(prompts.decision_questions("cited-sources", {"proofs": [{}], "counter": []})["proof_0"]["instructions"].startswith("Does candidate FOR [0]"))


if __name__ == "__main__":
    unittest.main()
