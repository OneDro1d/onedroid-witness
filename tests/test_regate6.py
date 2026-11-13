"""0.1.7-dev (the sixth re-gate's J1 and the gist note, the claims session, 13 Nov 2026), written before the code (the s1 to s7 cases of
the owner's brief). J1: the audited page a model reads is bound like every other carried file: page.txt is hash-checked against the
manifest's `pages` entry, `pages` is a bound section in public mode, and page.txt is recorded in `carried` in service.json and in every
witness header. G1: the refusal of a published manifest.json that is not a JSON object names the bytes fetched and says when they are the
audit's own bytes (a raw gist URL names one blob under any file name). M1: the configuration names the models the service does NOT serve
with the reason, shown on /healthz and /models and refused by name on a request. The fake provider has no recorded answer for these
fixtures: these tests check the request rules, the record and the configuration, never a model's judgement."""
import hashlib
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(HERE))

import onedroid_witness  # noqa: E402
from onedroid_witness import answer, checkpin, cli, request  # noqa: E402
from onedroid_witness.openrouter import Ledger, refuse_routers  # noqa: E402
from onedroid_witness.signing import KeyStore  # noqa: E402
from fake_openrouter import FakeClient  # noqa: E402
from test_gate_s1 import MODELS  # noqa: E402
from test_regate5 import PROMPT_SHA_BEFORE, QUESTIONS_SHA_BEFORE, _Server, manifest_sha, sha256  # noqa: E402
from test_s1_evidence import AGE, AW4, CHECK_PY, FIXED, carried_parts, no_recordings  # noqa: E402
from test_server import multipart  # noqa: E402

FX = ROOT / "fixtures"
CS10 = FX / "snapshot-cs10-regate6-2026-11-13"
FORGED = FX / "snapshot-cs10-forged-page-2026-11-13"
CS10_AUDIT_URL = "https://example.org/snap/cs10/audit.jsonl"
CS10_MANIFEST_URL = "https://example.org/snap/cs10/manifest.json"
MODEL = "openai/gpt-4.1-nano"
NOT_SERVED = {MODEL: "reason text"}
DEV_YAML = ROOT / "k8s" / "dev.yaml"


def page_sha(snap):
    return sha256((snap / "page.txt").read_bytes())


def recorded_hashes(snap):
    """What 0.1.7 records in `carried`: every file under sources/ and sessions/ plus page.txt, by path, keys sorted."""
    out = {p: sha256(b) for p, b in carried_parts(snap).items()}
    if (snap / "page.txt").is_file():
        out["page.txt"] = page_sha(snap)
    return dict(sorted(out.items()))


def cs10_served():
    return {CS10_AUDIT_URL: (200, (CS10 / "audit.jsonl").read_bytes()), CS10_MANIFEST_URL: (200, (CS10 / "manifest.json").read_bytes())}


class S1PageBoundOffline(unittest.TestCase):
    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="witness-regate6-s1-"))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _copy(self, label):
        d = self.tmp / label
        shutil.copytree(CS10, d)
        return d

    def _request(self, snap):
        return request.Request(snap, private_mode=True, profiles_served=request.PROFILES_SERVED)

    def test_s1_the_forged_page_with_its_manifest_changed_to_match_is_accepted_offline(self):
        # the forger's own manifest names the forged page's hash: nothing offline can tell; J1c (public mode) is what catches it
        M = json.loads((FORGED / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(M["pages"][0], {**M["pages"][0], "file": "page.txt", "sha256": page_sha(FORGED)})
        self.assertNotEqual(page_sha(FORGED), page_sha(CS10))
        req = self._request(FORGED)
        self.assertEqual(req.page_sha256, page_sha(FORGED))
        self.assertTrue(req.page.startswith("The annual fee is 0 EUR."), req.page[:40])
        # and the genuine one, for the record
        req = self._request(CS10)
        self.assertEqual(req.page_sha256, page_sha(CS10))
        self.assertEqual(req.page_sha256, "e324fe8c7bfbce0f53c248892f736b5439d24459146c755dfe10884b99f04ff1")

    def test_s1_a_page_altered_with_the_manifest_unchanged_is_refused_by_name(self):
        d = self._copy("altered")
        lines = (d / "page.txt").read_text(encoding="utf-8").split("\n")
        self.assertEqual(lines[0], "The annual fee is 49 EUR [1].")
        lines[0] = "The annual fee is 0 EUR."
        (d / "page.txt").write_text("\n".join(lines), encoding="utf-8")
        with self.assertRaises(request.Refused) as cm:
            self._request(d)
        self.assertEqual(str(cm.exception), "part page.txt sha256 differs from the manifest's")

    def test_s1_a_page_named_by_no_pages_entry_is_refused_by_name(self):
        d = self._copy("unnamed")
        M = json.loads((d / "manifest.json").read_text(encoding="utf-8"))
        M["pages"] = []
        (d / "manifest.json").write_text(json.dumps(M, indent=1, ensure_ascii=False), encoding="utf-8")
        with self.assertRaises(request.Refused) as cm:
            self._request(d)
        self.assertEqual(str(cm.exception), "part page.txt is named by no page of the manifest")
        # the same with `pages` absent altogether
        del M["pages"]
        (d / "manifest.json").write_text(json.dumps(M, indent=1, ensure_ascii=False), encoding="utf-8")
        with self.assertRaises(request.Refused) as cm:
            self._request(d)
        self.assertEqual(str(cm.exception), "part page.txt is named by no page of the manifest")

    def test_s1_a_pages_entry_without_a_sha256_is_accepted_and_the_hash_still_recorded(self):
        d = self._copy("no-sha")
        M = json.loads((d / "manifest.json").read_text(encoding="utf-8"))
        del M["pages"][0]["sha256"]
        (d / "manifest.json").write_text(json.dumps(M, indent=1, ensure_ascii=False), encoding="utf-8")
        req = self._request(d)
        self.assertEqual(req.page_sha256, page_sha(CS10))

    def test_s1_a_request_without_a_page_is_what_it_was_before_and_no_new_refusal(self):
        # recorded for the owner: today (0.1.6) a missing page.txt is accepted with an empty page (request.py `_text_optional(...) or ""`)
        # 0.1.8 (J4): since the manifest's pages names page.txt, the deleted page is now refused by name (test_regate7 t7 has the accepted case)
        d = self._copy("no-page")
        (d / "page.txt").unlink()
        with self.assertRaises(request.Refused) as cm:
            self._request(d)
        self.assertEqual(str(cm.exception), "part page.txt is named by the manifest's pages and was not sent")


class S2S4Public(_Server):
    PRIVATE = False

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.fetcher.served.update(cs10_served())

    def setUp(self):
        self.fetcher.served.update(cs10_served())
        self.fetcher.calls.clear()

    def test_s2_the_genuine_cs10_with_its_published_url_runs_to_done(self):
        parts = self._parts(CS10)
        self.assertEqual(sorted(parts), sorted(list(FIXED) + ["sources/fees.txt"]))
        st, ans = self._post(*multipart(parts, {"models": MODEL + ",typesafe/jev-1.14", "max_cost_usd": "0.5", "published_url": CS10_AUDIT_URL}))
        self.assertEqual(st, 202, ans)
        self.assertEqual(self.fetcher.calls, [CS10_AUDIT_URL, CS10_MANIFEST_URL])
        s = self._wait(ans["job_id"])
        self.assertEqual(s["state"], "done", s)
        svc = json.loads((pathlib.Path(self.tmp) / "jobs" / ans["job_id"] / "answer" / "service.json").read_text(encoding="utf-8"))
        self.assertEqual(svc["carried"], recorded_hashes(CS10))
        self.assertEqual(svc["carried"]["page.txt"], page_sha(CS10))

    def test_s2_the_forged_page_against_the_genuine_publication_is_refused_naming_pages_with_no_model_call(self):
        calls_before = len(self.client.calls)
        remaining = self.ledger.remaining()
        parts = self._parts(FORGED)
        self.assertEqual(sha256(parts["page.txt"]), page_sha(FORGED))
        ans = self._refused(parts, {"models": MODEL + ",typesafe/jev-1.14", "published_url": CS10_AUDIT_URL}, "pages", "differs from the published snapshot's", CS10_MANIFEST_URL)
        self.assertEqual(ans["error"], f"the manifest's pages differs from the published snapshot's at {CS10_MANIFEST_URL}")
        self.assertEqual(self.fetcher.calls, [CS10_AUDIT_URL, CS10_MANIFEST_URL])
        self.assertEqual(len(self.client.calls), calls_before)  # no model call
        self.assertEqual(self.ledger.remaining(), remaining)

    def test_s4_a_manifest_url_that_serves_the_audit_bytes_is_refused_naming_the_gist_blob(self):
        self.fetcher.served[CS10_MANIFEST_URL] = (200, (CS10 / "audit.jsonl").read_bytes())
        n = len((CS10 / "audit.jsonl").read_bytes())
        ans = self._refused(self._parts(CS10), {"models": MODEL + ",typesafe/jev-1.14", "published_url": CS10_AUDIT_URL},
                            "is not a JSON object", f"({n} bytes, sha256 {sha256((CS10 / 'audit.jsonl').read_bytes())[:16]}...",
                            "is byte-equal to the published audit.jsonl", "revision URL", "raw/<revision>/manifest.json")
        self.assertIn(CS10_MANIFEST_URL, ans["error"])

    def test_s4_a_manifest_body_that_is_not_an_object_names_its_bytes_and_not_the_gist(self):
        self.fetcher.served[CS10_MANIFEST_URL] = (200, b"[1,2]")
        ans = self._refused(self._parts(CS10), {"models": MODEL + ",typesafe/jev-1.14", "published_url": CS10_AUDIT_URL},
                            "is not a JSON object (5 bytes, sha256 " + sha256(b"[1,2]")[:16] + "...")
        self.assertNotIn("byte-equal", ans["error"])
        self.assertIn("the published manifest.json", ans["error"])


class S3Recorded(unittest.TestCase):
    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="witness-regate6-s3-"))
        self.check = checkpin.load_check(CHECK_PY)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _run(self, snap, label):
        d = self.tmp / label
        shutil.copytree(snap, d)
        (d / "README.md").unlink(missing_ok=True)
        req = request.Request(d, private_mode=True, profiles_served=request.PROFILES_SERVED)
        client = FakeClient(no_recordings(self.tmp), Ledger(str(self.tmp / f"ledger-{label}.json"), 100.0))
        ks = KeyStore(self.tmp / f"keys-{label}")
        ans = self.tmp / f"answer-{label}"
        svc = answer.run(req, [{"id": MODEL, "kind": "chat", "max_tokens": 400}], client, ks, self.check, ans,
                         prices={MODEL: {"prompt": 1e-7, "completion": 4e-7}}, private_mode=True)
        return d, ans, svc

    @staticmethod
    def _headers(ans):
        return [json.loads(wf.read_text(encoding="utf-8").splitlines()[0]) for wf in sorted((ans / "witness").glob("*.jsonl"))]

    def test_s3_service_json_and_every_witness_header_record_page_txt_beside_the_carried_files(self):
        for snap, n in ((CS10, 2), (AW4, 4)):
            d, ans, svc = self._run(snap, snap.name)
            want = recorded_hashes(snap)
            self.assertEqual(len(want), n, snap.name)
            self.assertEqual(want["page.txt"], page_sha(snap))
            on_disk = json.loads((ans / "service.json").read_text(encoding="utf-8"))
            self.assertEqual(on_disk["carried"], want, snap.name)
            self.assertEqual(list(on_disk["carried"]), sorted(want), snap.name)  # keys sorted
            self.assertEqual(on_disk["manifest_sha256"], manifest_sha(snap), snap.name)
            headers = self._headers(ans)
            self.assertEqual(len(headers), 1, snap.name)
            for h in headers:
                self.assertEqual(h["carried"], want, snap.name)
                self.assertEqual(list(h["carried"]), sorted(want), snap.name)
                keys = list(h)
                self.assertEqual(keys[keys.index("over") + 1: keys.index("over") + 3], ["manifest_sha256", "carried"], keys)

    def test_s3_the_checker_accepts_a_witness_whose_header_carries_page_txt(self):
        for snap in (CS10, AW4, AGE):
            d, ans, svc = self._run(snap, "chk-" + snap.name)
            adder = self.tmp / f"adder-{snap.name}"
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(adder)], check=True, capture_output=True)
            r = subprocess.run([sys.executable, "-I", str(ROOT / "vendor" / "add_witness.py"), str(d), str(ans), "--key", str(adder), "--identity", "regate6-adder"],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, (snap.name, r.stdout + r.stderr))
            self.assertIn("0 failed", r.stdout, snap.name)
            self.assertIn("PASS", r.stdout, snap.name)
            c = subprocess.run([sys.executable, "-I", str(CHECK_PY), str(d)], capture_output=True, text=True)
            self.assertEqual(c.returncode, 0, (snap.name, c.stdout + c.stderr))
            self.assertIn("0 failed", c.stdout, snap.name)
            self.assertIn("PASS", c.stdout, snap.name)
            M = json.loads((d / "manifest.json").read_text(encoding="utf-8"))
            inserted = [w for w in M["grading"]["witnesses"] if w.get("kind") == "model"]
            self.assertEqual(len(inserted), 1, snap.name)
            header = json.loads((d / inserted[0]["file"]).read_text(encoding="utf-8").splitlines()[0])
            self.assertEqual(header["carried"], recorded_hashes(snap), snap.name)
            self.assertEqual(header["carried"]["page.txt"], page_sha(snap), snap.name)


class S5ModelsNotServed(_Server):
    PRIVATE = False

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        # the handler reads cfg at request time, so the harness's dict is changed in place: nano out of models_cfg, named in models_not_served
        cls.cfg["models_cfg"] = [m for m in MODELS if m["id"] != MODEL]
        cls.cfg["models_not_served"] = dict(NOT_SERVED)

    def test_s5_healthz_and_models_name_the_models_not_served_with_the_reason(self):
        h = self._get("/healthz")
        self.assertEqual(h["models_not_served"], NOT_SERVED)
        keys = list(h)
        self.assertEqual(keys[keys.index("profiles_not_served") + 1], "models_not_served")  # placed after profiles_not_served
        m = self._get("/models")
        self.assertEqual(m["not_served"], NOT_SERVED)
        self.assertNotIn(MODEL, [x["id"] for x in m["models"]])
        self.assertEqual([x["id"] for x in m["models"]], ["typesafe/jev-1.14"])

    def test_s5_a_request_naming_a_model_not_served_is_refused_by_name_with_the_reason_and_no_job(self):
        before = self._jobs()
        st, ans = self._post(*multipart(self._parts(CS10), {"models": MODEL, "max_cost_usd": "0.5"}))
        self.assertEqual(st, 400, ans)
        self.assertEqual(ans["error"], f"{MODEL} is not served by this service: reason text")
        self.assertNotIn("job_id", ans)
        self.assertEqual(self._jobs(), before)
        # the refusal comes before store.incoming(): nothing is kept, and in a class with no accepted request .incoming does not even exist yet
        incoming = pathlib.Path(self.tmp) / "jobs" / ".incoming"
        self.assertEqual(list(incoming.iterdir()) if incoming.is_dir() else [], [])
        # a model in neither list: the existing refusal
        st, ans = self._post(*multipart(self._parts(CS10), {"models": "openai/gpt-5-nano", "max_cost_usd": "0.5"}))
        self.assertEqual(st, 400, ans)
        self.assertIn("openai/gpt-5-nano is not one of the service's models", ans["error"])
        # a model in BOTH lists: the refusal wins
        self.cfg["models_cfg"] = list(MODELS)
        try:
            st, ans = self._post(*multipart(self._parts(CS10), {"models": MODEL, "max_cost_usd": "0.5"}))
            self.assertEqual(st, 400, ans)
            self.assertEqual(ans["error"], f"{MODEL} is not served by this service: reason text")
        finally:
            self.cfg["models_cfg"] = [m for m in MODELS if m["id"] != MODEL]
        self.assertEqual(self._jobs(), before)


class S6Healthz(_Server):
    PRIVATE = False

    def test_s6_healthz_names_the_version_the_profiles_the_unchanged_prompts_and_an_empty_not_served_by_default(self):
        h = self._get("/healthz")
        self.assertEqual(onedroid_witness.__version__, "0.1.20-dev")  # 0.1.7-dev when written; the version pin follows the cut
        self.assertEqual(h["version"], "0.1.20-dev")
        self.assertEqual(h["mode"], "public")
        self.assertEqual(h["profiles_served"], ["cited-sources", "agent-work", "test-run"])
        self.assertEqual(h["prompt_sha256"], PROMPT_SHA_BEFORE)
        self.assertEqual(h["questions_sha256"], QUESTIONS_SHA_BEFORE)
        self.assertEqual(h["models_not_served"], {})  # a cfg without the key
        self.assertNotIn("fetch", h)
        m = self._get("/models")
        self.assertEqual(m["not_served"], {})


def dev_config_json():
    """The ConfigMap's config.json text: the lines between `config.json: |` and the next `---`, dedented."""
    lines = DEV_YAML.read_text(encoding="utf-8").split("\n")
    start = next(i for i, l in enumerate(lines) if l.strip() == "config.json: |") + 1
    end = next(i for i in range(start, len(lines)) if lines[i].startswith("---"))
    return textwrap.dedent("\n".join(lines[start:end]))


class S7DevConfigMap(unittest.TestCase):
    def test_s7_the_dev_configmap_takes_nano_out_of_models_and_names_it_in_models_not_served(self):
        cfg = json.loads(dev_config_json())
        ids = [m["id"] for m in cfg["models"]]
        self.assertNotIn(MODEL, ids)
        self.assertIn(MODEL, cfg["models_not_served"])
        self.assertIn("planted instruction", cfg["models_not_served"][MODEL])
        self.assertIn("sixth re-gate", cfg["models_not_served"][MODEL])
        # the owner's live plant regression of 0.1.7 (13 Nov 2026 04:48Z, fixture aw8ctl, seven served models): mistral-small-3.2 answered
        # EVIDENCED on the broken-fence plant row C-008 (1 of 7), so it joined models_not_served; six models stay served
        MISTRAL = "mistralai/mistral-small-3.2-24b-instruct"
        self.assertNotIn(MISTRAL, ids)
        self.assertIn(MISTRAL, cfg["models_not_served"])
        self.assertIn("plant regression", cfg["models_not_served"][MISTRAL])
        self.assertEqual(len(ids), 6)
        for i in ids:
            refuse_routers(i)
        self.assertEqual(sorted(set(ids)), sorted(ids))
        self.assertEqual(list(cfg).index("models_not_served"), list(cfg).index("models") + 1)  # placed after models
        # load_cfg reads the key
        tmp = pathlib.Path(tempfile.mkdtemp(prefix="witness-regate6-s7-"))
        try:
            p = tmp / "config.json"
            p.write_text(dev_config_json(), encoding="utf-8")
            loaded = cli.load_cfg(str(p))
            self.assertEqual(loaded["models_not_served"], cfg["models_not_served"])
            self.assertNotIn(MODEL, [m["id"] for m in loaded["models"]])
            p.write_text(json.dumps({"models": [{"id": "typesafe/jev-1.14", "kind": "decision"}]}), encoding="utf-8")
            self.assertEqual(cli.load_cfg(str(p))["models_not_served"], {})  # the default
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
