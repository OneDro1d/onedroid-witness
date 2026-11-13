"""The whole model step offline: the 11 Nov snapshot as the request, recorded answers as the provider, the answer inserted by the public
add_witness.py and read by the public check.py. Plus the refusals the contract names (sections 4, 3c.8, 3e.1, 3b.1)."""
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

from onedroid_witness import answer, checkpin, request  # noqa: E402
from onedroid_witness.openrouter import Ledger, RouterRefused, refuse_routers  # noqa: E402
from onedroid_witness.signing import KeyStore  # noqa: E402
from fake_openrouter import FakeClient  # noqa: E402

SNAP = ROOT / "fixtures" / "snapshot-agentic-age-2026-11-11"
REC = ROOT / "fixtures" / "recordings"
CHECK_PY = ROOT / "vendor" / "check.py"
ADD_WITNESS = ROOT / "vendor" / "add_witness.py"
MODELS = [{"id": "openai/gpt-4.1-nano", "kind": "chat", "max_tokens": 400}, {"id": "google/gemma-4-26b-a4b-it", "kind": "chat", "max_tokens": 400},
          {"id": "typesafe/jev-1.14", "kind": "decision"}, {"id": "perplexity/pplx-decider-v1.2", "kind": "decision"}]
PRICES = {"openai/gpt-4.1-nano": {"prompt": 1e-7, "completion": 4e-7}, "google/gemma-4-26b-a4b-it": {"prompt": 9e-8, "completion": 2.8e-7},
          "typesafe/jev-1.14": {"prompt": 4.2e-8, "completion": 0}, "perplexity/pplx-decider-v1.2": {"prompt": 2e-8, "completion": 0}}


def fresh_snapshot(tmp):
    dst = pathlib.Path(tmp) / "snap"
    shutil.copytree(SNAP, dst)
    return dst


class RunFixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="witness-test-")
        self.check = checkpin.load_check(CHECK_PY)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _run(self, models=MODELS, client=None, private=True, **kw):
        snap = fresh_snapshot(self.tmp)
        req = request.Request(snap, private_mode=private)
        client = client or FakeClient(REC, Ledger(str(pathlib.Path(self.tmp) / "ledger.json"), 100.0))
        ks = KeyStore(pathlib.Path(self.tmp) / "keys")
        ans = pathlib.Path(self.tmp) / "answer"
        svc = answer.run(req, models, client, ks, self.check, ans, prices=PRICES, private_mode=private, **kw)
        return snap, ans, svc, ks

    def test_four_models_answered_inserted_and_checked(self):
        snap, ans, svc, ks = self._run()
        self.assertEqual(sorted(svc["models_run"]), sorted(m["id"] for m in MODELS))
        self.assertEqual(svc["models_skipped"], [])
        wfiles = sorted(p.name for p in (ans / "witness").glob("*.jsonl"))
        self.assertEqual(len(wfiles), 4)
        self.assertIn("onedroid-witness-typesafe-jev-1-14-20261014.jsonl", wfiles)  # the served dated id, not the asked alias
        entries = json.loads((ans / "manifest-entry.json").read_text())
        self.assertTrue(all(e["kind"] == "model" and e["method"] == "classify" and e["primary"] is False for e in entries))
        nano = svc["per_model"]["openai/gpt-4.1-nano"]
        # the probe measured 69 of 70: its one disagreement was NO EVIDENCE PUBLISHED on an all copy-none row, which the service turns
        # UNDECIDED by the rule of 3d.3, so the service decides 69 and agrees on 69
        self.assertEqual(nano["agrees_with_primary"], "66 of 66 decided")  # 0.1.8 (A1): three nano EVIDENCED rows with no decision model EVIDENCED on them are UNDECIDED now
        self.assertEqual(nano["max_tokens"], 400)
        jev = svc["per_model"]["typesafe/jev-1.14"]
        self.assertTrue(jev["agrees_with_primary"].startswith("57 of "), jev["agrees_with_primary"])  # the argmax rule of 3e.4, as measured
        self.assertIsNone(jev["max_tokens"])
        # the answer inserted by the public inserter and read by the public checker
        adder = pathlib.Path(self.tmp) / "adder"
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(adder)], check=True)
        r = subprocess.run([sys.executable, "-I", str(ADD_WITNESS), str(snap), str(ans), "--key", str(adder), "--identity", "witness-service-test-adder"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("SUMMARY: 15 checks, 0 failed", r.stdout)
        self.assertIn("PASS", r.stdout)

    def test_every_note_is_in_the_contract_words(self):
        snap, ans, svc, ks = self._run()
        rows = [json.loads(l) for l in (ans / "witness" / "onedroid-witness-mistralai-ministral-14b-2512.jsonl").read_text().splitlines()[1:]] if (ans / "witness" / "onedroid-witness-mistralai-ministral-14b-2512.jsonl").exists() else []
        self.assertEqual(rows, [])  # not asked
        gemma = [json.loads(l) for l in (ans / "witness" / "onedroid-witness-google-gemma-4-26b-a4b-it.jsonl").read_text().splitlines()[1:]]
        notes = [r["note"] for r in gemma if r["verdict"] == "UNDECIDED"]
        self.assertTrue(any("candidate index that does not exist" in n for n in notes))
        self.assertFalse(any(n == "model answer not parseable" for n in notes if "index" in n))

    def test_vocabulary_near_miss_is_named_not_normalised(self):
        snap, ans, svc, ks = self._run(models=[{"id": "mistralai/ministral-14b-2512", "kind": "chat", "max_tokens": 400}])
        rows = [json.loads(l) for l in (ans / "witness" / "onedroid-witness-mistralai-ministral-14b-2512.jsonl").read_text().splitlines()[1:]]
        word = [r for r in rows if "not in the vocabulary: NO_EVIDENCE_PUBLISHED" in r["note"]]
        self.assertEqual(len(word), 9)
        self.assertTrue(all(r["verdict"] == "UNDECIDED" for r in word))

    def test_empty_content_is_named_with_its_finish_reason(self):
        snap, ans, svc, ks = self._run(models=[{"id": "qwen/qwen3.7-flash", "kind": "chat", "max_tokens": 400}])
        rows = [json.loads(l) for l in (ans / "witness" / "onedroid-witness-qwen-qwen3-7-flash.jsonl").read_text().splitlines()[1:]]
        self.assertEqual(sum(1 for r in rows if r["note"] == "no content returned (finish: length)"), 74)
        self.assertEqual(svc["per_model"]["qwen/qwen3.7-flash"]["undecided"], 74)

    def test_a_router_id_is_refused_before_any_call(self):
        for bad in ("typesafe/jev-router", "~typesafe/jev-latest", "openrouter/auto", "perplexity/pplx-decider-v1.3:free", "~liquid/d1-latest"):
            with self.assertRaises(RouterRefused):
                refuse_routers(bad)
        refuse_routers("typesafe/jev-1.14")

    def test_an_id_served_by_two_models_is_skipped_as_a_router(self):
        client = FakeClient(REC, Ledger(str(pathlib.Path(self.tmp) / "ledger.json"), 100.0))
        # make the recording look like a router: odd claims served by one model, even by another
        rec = client.rec["openai-gpt-4-1-nano"]
        for i, (cid, row) in enumerate(sorted(rec.items())):
            row["served_model"] = "openai/gpt-6-luna" if i % 2 else "deepseek/deepseek-v4.1-flash-1017"
        snap, ans, svc, ks = self._run(models=[{"id": "openai/gpt-4.1-nano", "kind": "chat", "max_tokens": 400}], client=client)
        self.assertEqual(svc["models_run"], [])
        self.assertEqual(svc["models_skipped"][0]["reason"], "router")

    def test_provider_failure_is_a_skipped_model_not_a_silent_file(self):
        client = FakeClient(REC, Ledger(str(pathlib.Path(self.tmp) / "ledger.json"), 100.0), fail_models={"typesafe/jev-1.14"})
        snap, ans, svc, ks = self._run(models=[{"id": "typesafe/jev-1.14", "kind": "decision"}, {"id": "openai/gpt-4.1-nano", "kind": "chat", "max_tokens": 400}], client=client)
        self.assertEqual(svc["models_run"], ["openai/gpt-4.1-nano"])
        self.assertEqual(svc["models_skipped"][0]["model"], "typesafe/jev-1.14")
        self.assertEqual(svc["models_skipped"][0]["reason"], "provider error")
        self.assertFalse((ans / "witness" / "onedroid-witness-typesafe-jev-1-14.jsonl").exists())

    def test_estimate_over_the_bound_skips_the_model_and_names_it(self):
        snap, ans, svc, ks = self._run(max_cost_usd=0.0001)
        self.assertEqual(svc["models_run"], [])
        self.assertEqual({s["reason"] for s in svc["models_skipped"]}, {"estimate"})
        self.assertEqual(len(svc["models_skipped"]), 4)

    def test_daily_cap_bounds_the_run(self):
        client = FakeClient(REC, Ledger(str(pathlib.Path(self.tmp) / "ledger.json"), 0.0))
        snap, ans, svc, ks = self._run(client=client)
        self.assertEqual(svc["models_run"], [])
        self.assertTrue(all(s["reason"] == "estimate" for s in svc["models_skipped"]))

    def test_keys_list_records_every_key_with_a_window_and_a_retire_keeps_it(self):
        snap, ans, svc, ks = self._run(models=[{"id": "typesafe/jev-1.14", "kind": "decision"}])
        # since 0.1.1 the service's own key (principal onedroid-witness-service, which signs service.json) is listed beside the model keys
        model_keys = [k for k in ks.keys_list()["keys"] if k["principal"] != "onedroid-witness-service"]
        self.assertEqual(len(model_keys), 1)
        self.assertEqual(model_keys[0]["model"], "typesafe/jev-1.14-20261014")
        self.assertIsNone(model_keys[0]["valid_to"])
        self.assertEqual(sum(1 for k in ks.keys_list()["keys"] if k["principal"] == "onedroid-witness-service"), 1)
        ks.retire("typesafe/jev-1.14-20261014")
        model_keys = [k for k in ks.keys_list()["keys"] if k["principal"] != "onedroid-witness-service"]
        self.assertEqual(len(model_keys), 1)
        self.assertIsNotNone(model_keys[0]["valid_to"])
        ks.key_for("typesafe/jev-1.14-20261014")
        self.assertEqual(len([k for k in ks.keys_list()["keys"] if k["principal"] != "onedroid-witness-service"]), 2)


class Refusals(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="witness-refuse-")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_unsigned_part_is_refused(self):
        snap = fresh_snapshot(self.tmp)
        (snap / "audit.jsonl.sig").unlink()
        with self.assertRaises(request.Refused) as cm:
            request.Request(snap, private_mode=True)
        self.assertIn("unsigned", str(cm.exception))

    def test_forged_signature_is_refused(self):
        snap = fresh_snapshot(self.tmp)
        b = (snap / "audit.jsonl").read_bytes()
        (snap / "audit.jsonl").write_bytes(b.replace(b'"C-001"', b'"C-001"', 1) + b"\n")  # one extra byte changes the hash
        with self.assertRaises(request.Refused):
            request.Request(snap, private_mode=True)

    def test_decision_field_in_the_auditor_part_is_refused(self):
        snap = fresh_snapshot(self.tmp)
        lines = (snap / "audit.jsonl").read_text().splitlines()
        row = json.loads(lines[0])
        row["verdict"] = "EVIDENCED"
        lines[0] = json.dumps(row, ensure_ascii=False)
        (snap / "audit.jsonl").write_text("\n".join(lines) + "\n")
        with self.assertRaises(request.Refused) as cm:
            request.Request(snap, private_mode=True)
        self.assertTrue("decision field" in str(cm.exception) or "sha256" in str(cm.exception))

    def test_size_cap(self):
        snap = fresh_snapshot(self.tmp)
        rows = [json.loads(l) for l in (snap / "audit.jsonl").read_text().splitlines() if l.strip()]
        big = []
        for k in range(1200):
            r = dict(rows[k % len(rows)])
            r["id"] = f"C-{k:04d}"
            big.append(r)
        (snap / "audit.jsonl").write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in big))
        with self.assertRaises(request.Refused) as cm:
            request.Request(snap, private_mode=True)
        self.assertIn("exceed the cap", str(cm.exception))

    def test_public_mode_needs_a_published_part(self):
        snap = fresh_snapshot(self.tmp)
        req = request.Request(snap, private_mode=False)
        with self.assertRaises(request.Refused):
            request.check_published(req)

    def test_ssrf_rules_refuse_before_any_fetch(self):
        calls = []

        def fetch(url):
            calls.append(url)
            return b""
        for url in ("http://example.com/audit.jsonl", "https://127.0.0.1/audit.jsonl", "https://169.254.169.254/latest", "https://localhost/x", "https://10.0.0.1/x"):
            with self.assertRaises(request.Refused):
                request.fetch_published(url)
        self.assertEqual(calls, [])

    def test_published_copy_must_match_byte_for_byte(self):
        snap = fresh_snapshot(self.tmp)
        req = request.Request(snap, private_mode=False)
        # 0.1.6 (H1): the published manifest.json is fetched beside audit.jsonl, so the fake serves both; the assertions are unchanged
        serve = lambda u: req.audit_bytes if u.endswith("/audit.jsonl") else req.manifest_bytes  # noqa: E731
        out = request.check_published(req, "https://example.com/audit.jsonl", fetch=serve)
        self.assertEqual(out["published"]["sha256"], req.audit_sha256)
        with self.assertRaises(request.Refused):
            request.check_published(req, "https://example.com/audit.jsonl", fetch=lambda u: req.audit_bytes + b"\n" if u.endswith("/audit.jsonl") else req.manifest_bytes)

    def test_catalogue_record_is_enough(self):
        snap = fresh_snapshot(self.tmp)
        req = request.Request(snap, private_mode=False)
        # 0.1.6 (H1): a catalogue record is enough when it carries the request manifest's sha256 too (tests/test_regate5.py r6 has the refusals)
        out = request.check_published(req, catalogue_lookup=lambda h: {"id": "rec-1", "sha256": h, "manifest_sha256": req.manifest_sha256})
        self.assertEqual(out["published"]["catalogue"]["id"], "rec-1")

    def test_check_py_pin(self):
        with self.assertRaises(RuntimeError):
            checkpin.load_check(ADD_WITNESS)
        self.assertTrue(hasattr(checkpin.load_check(CHECK_PY), "evidence_score"))


if __name__ == "__main__":
    unittest.main()
