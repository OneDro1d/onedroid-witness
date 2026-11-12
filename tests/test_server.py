"""The HTTP surface end to end on a local port with the fake provider: POST /witness (multipart and JSON) → 202 → the worker runs → GET the
status → GET the tar whose sha256 matches the announced one → add_witness.py takes the unpacked answer and check.py passes. Plus the
refusals the surface makes before a job runs."""
import http.client
import io
import json
import pathlib
import shutil
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import unittest
import uuid
from http.server import ThreadingHTTPServer

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(HERE))

from onedroid_witness import checkpin  # noqa: E402
from onedroid_witness.jobs import JobStore, Worker  # noqa: E402
from onedroid_witness.openrouter import Ledger  # noqa: E402
from onedroid_witness.server import make_handler  # noqa: E402
from onedroid_witness.signing import KeyStore  # noqa: E402
from fake_openrouter import FakeClient  # noqa: E402

SNAP = ROOT / "fixtures" / "snapshot-agentic-age-2026-11-11"
REC = ROOT / "fixtures" / "recordings"
MODELS = [{"id": "openai/gpt-4.1-nano", "kind": "chat", "max_tokens": 400}, {"id": "typesafe/jev-1.14", "kind": "decision"}]
PRICES = {"openai/gpt-4.1-nano": {"prompt": 1e-7, "completion": 4e-7}, "typesafe/jev-1.14": {"prompt": 4.2e-8, "completion": 0}}
PARTS = ("manifest.json", "audit.jsonl", "audit.jsonl.sig", "allowed_signers", "signatures.json", "page.txt")


def multipart(parts, fields):
    boundary = "----witness" + uuid.uuid4().hex
    out = io.BytesIO()
    for k, v in fields.items():
        out.write(f"--{boundary}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n".encode())
    for name, data in parts.items():
        out.write(f"--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"; filename=\"{name}\"\r\nContent-Type: application/octet-stream\r\n\r\n".encode())
        out.write(data)
        out.write(b"\r\n")
    out.write(f"--{boundary}--\r\n".encode())
    return out.getvalue(), f"multipart/form-data; boundary={boundary}"


class ServerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="witness-server-")
        check = checkpin.load_check(ROOT / "vendor" / "check.py")
        ledger = Ledger(str(pathlib.Path(cls.tmp) / "ledger.json"), 100.0)
        client = FakeClient(REC, ledger)
        keystore = KeyStore(pathlib.Path(cls.tmp) / "keys")
        cls.store = JobStore(pathlib.Path(cls.tmp) / "jobs")
        known = {m["id"]: m for m in MODELS}
        cls.worker = Worker(cls.store, client, keystore, check, lambda ids: [known[i] for i in ids], PRICES, private_mode=True)
        cls.worker.start()
        cls.cfg = {"store": cls.store, "worker": cls.worker, "models_cfg": MODELS, "prices": PRICES, "ledger": ledger, "keystore": keystore, "private_mode": True, "version": "test"}
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(cls.cfg))
        cls.port = cls.httpd.server_address[1]
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def _conn(self):
        return http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)

    def _get(self, path):
        c = self._conn()
        c.request("GET", path)
        r = c.getresponse()
        return r.status, dict(r.getheaders()), r.read()

    def _post(self, body, ctype):
        c = self._conn()
        c.request("POST", "/witness", body=body, headers={"Content-Type": ctype, "Content-Length": str(len(body))})
        r = c.getresponse()
        return r.status, json.loads(r.read())

    def _parts(self):
        return {n: (SNAP / n).read_bytes() for n in PARTS}

    def _wait(self, jid):
        for _ in range(600):
            st, _, body = self._get(f"/witness/{jid}")
            s = json.loads(body)
            if s["state"] in ("done", "refused", "failed"):
                return s
            time.sleep(0.1)
        self.fail("job did not finish")

    def test_healthz_models_keys(self):
        st, _, body = self._get("/healthz")
        self.assertEqual(st, 200)
        h = json.loads(body)
        self.assertEqual(h["check_py_sha256"], checkpin.CHECK_PY_SHA256)
        self.assertIn("cited-sources", h["prompt_sha256"])
        st, _, body = self._get("/models")
        self.assertEqual([m["id"] for m in json.loads(body)["models"]], ["openai/gpt-4.1-nano", "typesafe/jev-1.14"])
        st, _, body = self._get("/keys")
        self.assertEqual(st, 200)
        self.assertIn("keys", json.loads(body))

    def test_multipart_job_runs_and_the_tar_matches_its_sha(self):
        body, ctype = multipart(self._parts(), {"models": "openai/gpt-4.1-nano,typesafe/jev-1.14", "max_cost_usd": "1.0"})
        st, ans = self._post(body, ctype)
        self.assertEqual(st, 202, ans)
        self.assertEqual(ans["claims"], 74)
        self.assertIn("estimate_total_usd", ans)
        s = self._wait(ans["job_id"])
        self.assertEqual(s["state"], "done", s)
        self.assertEqual(sorted(s["models_run"]), ["openai/gpt-4.1-nano", "typesafe/jev-1.14"])
        st, headers, tar_bytes = self._get(f"/witness/{ans['job_id']}/answer.tar")
        self.assertEqual(st, 200)
        import hashlib
        self.assertEqual(hashlib.sha256(tar_bytes).hexdigest(), s["answer_sha256"])
        self.assertEqual(headers.get("X-Answer-SHA256"), s["answer_sha256"])
        # the unpacked answer is what add_witness.py takes
        out = pathlib.Path(self.tmp) / "unpacked"
        out.mkdir(exist_ok=True)
        with tarfile.open(fileobj=io.BytesIO(tar_bytes)) as tar:
            tar.extractall(out, filter="data")
        snap = pathlib.Path(self.tmp) / "snap-for-insert"
        shutil.copytree(SNAP, snap)
        adder = pathlib.Path(self.tmp) / "adder"
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(adder)], check=True)
        r = subprocess.run([sys.executable, "-I", str(ROOT / "vendor" / "add_witness.py"), str(snap), str(out), "--key", str(adder), "--identity", "witness-server-test-adder"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("0 failed", r.stdout)

    def test_json_body_works_too(self):
        parts = {n: v.decode("utf-8") for n, v in self._parts().items() if n != "audit.jsonl.sig"}
        parts["audit.jsonl.sig"] = (SNAP / "audit.jsonl.sig").read_text()
        body = json.dumps({"parts": parts, "models": ["typesafe/jev-1.14"]}).encode()
        st, ans = self._post(body, "application/json")
        self.assertEqual(st, 202, ans)
        s = self._wait(ans["job_id"])
        self.assertEqual(s["state"], "done", s)

    def test_refusals_before_any_job(self):
        parts = self._parts()
        body, ctype = multipart(parts, {"models": "typesafe/jev-router"})
        st, ans = self._post(body, ctype)
        self.assertEqual(st, 400)
        self.assertIn("router", ans["error"])
        body, ctype = multipart(parts, {"models": "openai/gpt-5"})
        st, ans = self._post(body, ctype)
        self.assertEqual(st, 400)
        body, ctype = multipart({k: v for k, v in parts.items() if k != "audit.jsonl.sig"}, {"models": "typesafe/jev-1.14"})
        st, ans = self._post(body, ctype)
        self.assertEqual(st, 400)
        self.assertIn("missing parts", ans["error"])
        broken = dict(parts)
        broken["audit.jsonl"] = parts["audit.jsonl"] + b"\n"
        body, ctype = multipart(broken, {"models": "typesafe/jev-1.14"})
        st, ans = self._post(body, ctype)
        self.assertEqual(st, 422)
        self.assertIn("sha256", ans["error"])
        body, ctype = multipart(parts, {"models": "typesafe/jev-1.14", "max_cost_usd": "0.000001"})
        st, ans = self._post(body, ctype)
        self.assertEqual(st, 422)
        self.assertIn("estimate", ans["error"])
        st, _, body = self._get("/witness/no-such-job")
        self.assertEqual(st, 404)
        st, _, body = self._get("/witness/../../etc/passwd")
        self.assertIn(st, (400, 404))


if __name__ == "__main__":
    unittest.main()
