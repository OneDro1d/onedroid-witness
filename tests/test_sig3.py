"""E2E-SIG3: the witness service keeps its caller's signature and signs its receipts and results (rules R1-R7 of the spec).

Every key here is a throwaway ed25519 key made by ssh-keygen in a temp dir, never committed. Verification of what the service signs uses
only `ssh-keygen -Y verify -n onedroid-resp` against a line built from GET /keys, as a stranger would.
"""
import base64
import hashlib
import http.client
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
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
from test_server import MODELS, PRICES, PARTS, SNAP, REC, multipart  # noqa: E402

MODEL_ARGS = {"models": "openai/gpt-4.1-nano,typesafe/jev-1.14", "max_cost_usd": "1.0"}


def canonical(obj):
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def make_key(directory, name, kind="ed25519"):
    path = pathlib.Path(directory) / name
    subprocess.run(["ssh-keygen", "-q", "-t", kind, "-N", "", "-C", name, "-f", str(path)], check=True)
    return path


def raw_public(path):
    out = subprocess.run(["ssh-keygen", "-y", "-P", "", "-f", str(path)], capture_output=True, text=True, check=True).stdout.split()
    blob = base64.b64decode(out[1])
    return blob[-32:]


def sign_request(keypath, kid, body, ts=None, service="onedroid-witness", path="/witness", method="POST"):
    ts = str(int(time.time()) if ts is None else ts)
    line = f"onedroid-req/1 {service} {method} {path} sha256:{hashlib.sha256(body).hexdigest()} {ts}"
    armored = subprocess.run(["ssh-keygen", "-Y", "sign", "-n", "onedroid-req", "-f", str(keypath)], input=line.encode(), capture_output=True, check=True).stdout
    return {"X-Store-Key": kid, "X-Store-Time": ts, "X-Store-Signature": base64.b64encode(armored).decode()}, line


def verify_resp(keys_doc, obj, signature_b64):
    """ssh-keygen -Y verify -n onedroid-resp against an allowed_signers line built ONLY from a GET /keys body: True or False."""
    entry = keys_doc["service"]["keys"][0]
    tmp = tempfile.mkdtemp(prefix="sig3-verify-")
    try:
        signers = pathlib.Path(tmp) / "allowed_signers"
        signers.write_text(f'onedroid-witness namespaces="{keys_doc["service"]["namespace"]}" {entry["ssh"]}\n')
        sig = pathlib.Path(tmp) / "x.sig"
        sig.write_bytes(base64.b64decode(signature_b64))
        data = obj if isinstance(obj, bytes) else canonical(obj)
        r = subprocess.run(["ssh-keygen", "-Y", "verify", "-f", str(signers), "-I", "onedroid-witness", "-n", "onedroid-resp", "-s", str(sig)],
                           input=data, capture_output=True)
        return r.returncode == 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


class Base(unittest.TestCase):
    """A witness server per test on a local port, private mode, the fake provider. serve() takes the SIG3 wiring."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="witness-sig3-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.httpd = None

    def tearDown(self):
        if self.httpd is not None:
            self.httpd.shutdown()
            self.httpd.server_close()

    def make_signing_key(self, name="svc"):
        return make_key(self.tmp, name)

    def serve(self, env=None, verifier_fetch=None, start_worker=True, models_of=None):
        from onedroid_witness import respsign
        env = dict(env or {})
        check = checkpin.load_check(ROOT / "vendor" / "check.py")
        ledger = Ledger(str(pathlib.Path(self.tmp) / "ledger.json"), 100.0)
        client = FakeClient(REC, ledger)
        keystore = KeyStore(pathlib.Path(self.tmp) / "keys")
        self.store = JobStore(pathlib.Path(self.tmp) / "jobs")
        known = {m["id"]: m for m in MODELS}
        wiring = respsign.from_env(env, self.store, "test", private_mode=True, fetch=verifier_fetch)
        self.wiring = wiring
        self.worker = Worker(self.store, client, keystore, check, models_of or (lambda ids: [known[i] for i in ids]), PRICES, private_mode=True,
                             finish=wiring.responder.finish)
        if start_worker:
            self.worker.start()
        cfg = {"store": self.store, "worker": self.worker, "models_cfg": MODELS, "prices": PRICES, "ledger": ledger, "keystore": keystore,
               "private_mode": True, "version": "test", "responder": wiring.responder, "verifier": wiring.verifier, "require_key": wiring.require_key}
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(cfg))
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def conn(self):
        return http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)

    def get(self, path):
        c = self.conn()
        c.request("GET", path)
        r = c.getresponse()
        return r.status, dict(r.getheaders()), r.read()

    def get_json(self, path):
        st, _, body = self.get(path)
        return st, json.loads(body)

    def post(self, body=None, ctype=None, headers=None, args=None):
        if body is None:
            body, ctype = multipart({n: (SNAP / n).read_bytes() for n in PARTS}, args or MODEL_ARGS)
        h = {"Content-Type": ctype, "Content-Length": str(len(body))}
        h.update(headers or {})
        c = self.conn()
        c.request("POST", "/witness", body=body, headers=h)
        r = c.getresponse()
        return r.status, json.loads(r.read()), body

    def wait_result(self, jid):
        for _ in range(600):
            st, doc = self.get_json(f"/witness/{jid}/result")
            if st == 200:
                return doc
            time.sleep(0.1)
        self.fail("no result")

    def keys(self):
        return self.get_json("/keys")[1]

    def job_dirs(self):
        return [p for p in (pathlib.Path(self.tmp) / "jobs").iterdir() if not p.name.startswith(".")]

    def incoming_left(self):
        inc = pathlib.Path(self.tmp) / "jobs" / ".incoming"
        return list(inc.iterdir()) if inc.exists() else []

    def signed_env(self):
        return {"WITNESS_RESP_SIGNING_KEY": str(self.make_signing_key())}

    def caller_setup(self, scopes=("witness",), require=True, owner="vaibhav"):
        """A caller key listed on a fake store key list; returns (keypath, kid, env, fetch)."""
        key = make_key(self.tmp, "caller")
        kid = "ak_test1234"
        doc = {"keys": [{"key_id": kid, "public_key": base64.b64encode(raw_public(key)).decode(), "owner": owner, "scopes": list(scopes), "state": "active"}]}
        fetch = lambda: json.dumps(doc).encode()  # noqa: E731
        env = dict(self.signed_env(), WITNESS_KEY_SOURCE="store", WITNESS_STORE_KEYS_URL="http://127.0.0.1:1/keys")
        if require:
            env["WITNESS_REQUIRE_KEY"] = "1"
        return key, kid, env, fetch


class R1ServiceKey(Base):
    def test_r1_unset_signs_nothing_and_says_why(self):
        self.serve({})
        st, ans, _ = self.post()
        self.assertEqual(st, 202, ans)
        self.assertIsNone(ans["signature"])
        self.assertEqual(ans["unsigned"], "no signing key configured")
        self.assertIsInstance(ans["receipt"], dict)
        res = self.wait_result(ans["job_id"])
        self.assertIsNone(res["signature"])
        self.assertEqual(res["unsigned"], "no signing key configured")
        self.assertEqual(res["result"]["state"], "done")

    def test_r1_set_signs_receipt_and_result(self):
        self.serve(self.signed_env())
        st, ans, _ = self.post()
        self.assertEqual(st, 202, ans)
        self.assertIsInstance(ans["signature"], str)
        self.assertNotIn("unsigned", ans)
        res = self.wait_result(ans["job_id"])
        self.assertIsInstance(res["signature"], str)

    def test_r1_unreadable_key_refuses_to_start(self):
        from onedroid_witness import respsign
        with self.assertRaises(SystemExit):
            respsign.from_env({"WITNESS_RESP_SIGNING_KEY": str(pathlib.Path(self.tmp) / "no-such-key")}, JobStore(pathlib.Path(self.tmp) / "j"), "test")

    def test_r1_not_ed25519_refuses_to_start(self):
        from onedroid_witness import respsign
        key = make_key(self.tmp, "ecdsa", kind="ecdsa")
        with self.assertRaises(SystemExit):
            respsign.from_env({"WITNESS_RESP_SIGNING_KEY": str(key)}, JobStore(pathlib.Path(self.tmp) / "j"), "test")

    def test_r1_model_keystore_untouched_and_private_key_never_kept_or_served(self):
        env = self.signed_env()
        key = pathlib.Path(env["WITNESS_RESP_SIGNING_KEY"])
        secret_body = key.read_text()
        self.serve(env)
        st, ans, _ = self.post()
        self.wait_result(ans["job_id"])
        keys = self.keys()
        principals = sorted(k["principal"] for k in keys["keys"])
        self.assertEqual(principals, ["onedroid-witness-openai-gpt-4-1-nano", "onedroid-witness-typesafe-jev-1-14"])
        for k in keys["keys"]:
            self.assertEqual(k["valid_to"], None)
        self.assertNotIn("PRIVATE KEY", json.dumps(keys))
        for p in pathlib.Path(self.tmp, "jobs").rglob("*"):
            if p.is_file():
                self.assertNotIn(b"BEGIN OPENSSH PRIVATE KEY", p.read_bytes(), str(p))
                self.assertNotIn(secret_body.encode().splitlines()[1], p.read_bytes(), str(p))
        # the model signatures are still under claims-snapshot: the answer folder's audit signatures verify as before
        answer = pathlib.Path(self.tmp, "jobs", ans["job_id"], "answer")
        self.assertTrue(any(answer.rglob("*.sig")) or any(answer.rglob("*")))


class R2Keys(Base):
    def test_r2_keys_keeps_the_list_and_gains_a_service_entry(self):
        env = self.signed_env()
        self.serve(env)
        keys = self.keys()
        self.assertIn("keys", keys)
        svc = keys["service"]
        self.assertEqual(svc["service"], "onedroid-witness")
        self.assertEqual(svc["namespace"], "onedroid-resp")
        self.assertEqual(len(svc["keys"]), 1)
        k = svc["keys"][0]
        raw = raw_public(env["WITNESS_RESP_SIGNING_KEY"])
        self.assertEqual(k["key_id"], "sk_" + hashlib.sha256(raw).hexdigest()[:16])
        self.assertEqual(base64.b64decode(k["public_key"]), raw)
        self.assertTrue(k["ssh"].startswith("ssh-ed25519 AAAA"))

    def test_r2_unsigned_service_lists_no_keys(self):
        self.serve({})
        svc = self.keys()["service"]
        self.assertEqual(svc["keys"], [])
        self.assertEqual(svc["namespace"], "onedroid-resp")


class R3Caller(Base):
    def test_r3_signed_request_is_kept_in_the_job_folder(self):
        key, kid, env, fetch = self.caller_setup()
        self.serve(env, verifier_fetch=fetch)
        body, ctype = multipart({n: (SNAP / n).read_bytes() for n in PARTS}, MODEL_ARGS)
        headers, line = sign_request(key, kid, body)
        st, ans, _ = self.post(body, ctype, headers)
        self.assertEqual(st, 202, ans)
        kept = json.loads((pathlib.Path(self.tmp, "jobs", ans["job_id"]) / "receipt.json").read_text())
        caller = kept["caller"]
        self.assertEqual(caller["key_id"], kid)
        self.assertEqual(caller["owner"], "vaibhav")
        self.assertEqual(caller["signed_line"], line)
        self.assertEqual(caller["signature"], headers["X-Store-Signature"])
        self.assertEqual(caller["time"], int(headers["X-Store-Time"]))

    def test_r3_require_key_refuses_unsigned_before_anything_is_written(self):
        key, kid, env, fetch = self.caller_setup()
        self.serve(env, verifier_fetch=fetch)
        st, ans, _ = self.post()
        self.assertEqual(st, 401, ans)
        self.assertNotIn("receipt", ans)
        self.assertEqual(self.job_dirs(), [])
        self.assertEqual(self.incoming_left(), [])

    def test_r3_tampered_body_is_401(self):
        key, kid, env, fetch = self.caller_setup()
        self.serve(env, verifier_fetch=fetch)
        body, ctype = multipart({n: (SNAP / n).read_bytes() for n in PARTS}, MODEL_ARGS)
        headers, _ = sign_request(key, kid, body)
        st, ans, _ = self.post(body + b" ", ctype, headers)
        self.assertEqual(st, 401, ans)
        self.assertEqual(self.job_dirs(), [])

    def test_r3_wrong_service_in_the_line_is_401(self):
        key, kid, env, fetch = self.caller_setup()
        self.serve(env, verifier_fetch=fetch)
        body, ctype = multipart({n: (SNAP / n).read_bytes() for n in PARTS}, MODEL_ARGS)
        headers, _ = sign_request(key, kid, body, service="onedroid-audit")
        st, ans, _ = self.post(body, ctype, headers)
        self.assertEqual(st, 401, ans)

    def test_r3_scope_witness_is_required(self):
        key, kid, env, fetch = self.caller_setup(scopes=("submit", "audit"))
        self.serve(env, verifier_fetch=fetch)
        body, ctype = multipart({n: (SNAP / n).read_bytes() for n in PARTS}, MODEL_ARGS)
        headers, _ = sign_request(key, kid, body)
        st, ans, _ = self.post(body, ctype, headers)
        self.assertEqual(st, 403, ans)
        self.assertEqual(self.job_dirs(), [])

    def test_r3_without_require_key_an_unsigned_request_runs_with_caller_null(self):
        key, kid, env, fetch = self.caller_setup(require=False)
        self.serve(env, verifier_fetch=fetch)
        st, ans, _ = self.post()
        self.assertEqual(st, 202, ans)
        self.assertIsNone(ans["receipt"]["caller"])
        self.assertIsNone(json.loads((pathlib.Path(self.tmp, "jobs", ans["job_id"]) / "receipt.json").read_text())["caller"])

    def test_r3_without_require_key_a_bad_signature_is_still_401(self):
        key, kid, env, fetch = self.caller_setup(require=False)
        self.serve(env, verifier_fetch=fetch)
        body, ctype = multipart({n: (SNAP / n).read_bytes() for n in PARTS}, MODEL_ARGS)
        headers, _ = sign_request(key, kid, body)
        st, ans, _ = self.post(body + b" ", ctype, headers)
        self.assertEqual(st, 401, ans)

    def test_r3_key_list_down_is_503(self):
        key, kid, env, fetch = self.caller_setup()

        def down():
            raise OSError("no list")
        self.serve(env, verifier_fetch=down)
        body, ctype = multipart({n: (SNAP / n).read_bytes() for n in PARTS}, MODEL_ARGS)
        headers, _ = sign_request(key, kid, body)
        st, ans, _ = self.post(body, ctype, headers)
        self.assertEqual(st, 503, ans)
        self.assertEqual(self.job_dirs(), [])

    def test_r3_the_signature_is_never_logged(self):
        import io
        import contextlib
        key, kid, env, fetch = self.caller_setup()
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.serve(env, verifier_fetch=fetch)
            body, ctype = multipart({n: (SNAP / n).read_bytes() for n in PARTS}, MODEL_ARGS)
            headers, _ = sign_request(key, kid, body)
            st, ans, _ = self.post(body, ctype, headers)
            self.wait_result(ans["job_id"])
        self.assertEqual(st, 202)
        self.assertNotIn(headers["X-Store-Signature"], buf.getvalue())
        self.assertNotIn("BEGIN SSH SIGNATURE", buf.getvalue())

    def test_r3_bad_configuration_refuses_to_start(self):
        from onedroid_witness import respsign
        store = JobStore(pathlib.Path(self.tmp) / "j")
        with self.assertRaises(SystemExit):
            respsign.from_env({"WITNESS_KEY_SOURCE": "nonsense"}, store, "test")
        with self.assertRaises(SystemExit):
            respsign.from_env({"WITNESS_REQUIRE_KEY": "1"}, store, "test")  # require a key but no key source
        with self.assertRaises(SystemExit):
            respsign.from_env({"WITNESS_KEY_SOURCE": "store", "WITNESS_STORE_KEYS_URL": "ftp://x/y"}, store, "test")


class R4Receipt(Base):
    def test_r4_receipt_on_202_is_signed_and_binds_the_body(self):
        key, kid, env, fetch = self.caller_setup()
        self.serve(env, verifier_fetch=fetch)
        body, ctype = multipart({n: (SNAP / n).read_bytes() for n in PARTS}, MODEL_ARGS)
        headers, _ = sign_request(key, kid, body)
        st, ans, sent = self.post(body, ctype, headers)
        self.assertEqual(st, 202, ans)
        self.assertEqual(list(ans)[0], "job_id")
        for old in ("status_url", "claims", "profile", "models_run_planned", "models_skipped", "estimate_usd", "estimate_total_usd"):
            self.assertIn(old, ans)
        r = ans["receipt"]
        self.assertEqual(r["format"], "onedroid-receipt/1")
        self.assertEqual(r["service"], "onedroid-witness")
        self.assertEqual(r["service_version"], "test")
        self.assertEqual(r["job_id"], ans["job_id"])
        self.assertEqual(r["request_sha256"], hashlib.sha256(sent).hexdigest())
        self.assertRegex(r["received_at"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
        self.assertIn(r["visibility"], ("private", "public"))
        self.assertNotIn("signature", r["caller"])
        self.assertEqual(r["caller"]["signature_sha256"], hashlib.sha256(headers["X-Store-Signature"].encode()).hexdigest())
        self.assertEqual(r["caller"]["key_id"], kid)
        self.assertTrue(verify_resp(self.keys(), r, ans["signature"]))
        kept = json.loads((pathlib.Path(self.tmp, "jobs", ans["job_id"]) / "receipt.json").read_text())
        self.assertEqual(kept["receipt"], r)
        self.assertEqual(kept["receipt_signature"], ans["signature"])

    def test_r4_a_refused_request_gets_no_receipt_and_keeps_nothing(self):
        self.serve(self.signed_env())
        body, ctype = multipart({n: (SNAP / n).read_bytes() for n in PARTS}, {"models": "typesafe/jev-router"})
        st, ans, _ = self.post(body, ctype)
        self.assertEqual(st, 400)
        self.assertNotIn("receipt", ans)
        self.assertNotIn("signature", ans)
        parts = {n: (SNAP / n).read_bytes() for n in PARTS}
        parts["audit.jsonl"] += b"\n"
        body, ctype = multipart(parts, MODEL_ARGS)
        st, ans, _ = self.post(body, ctype)
        self.assertEqual(st, 422)
        self.assertNotIn("receipt", ans)
        self.assertEqual(self.job_dirs(), [])
        self.assertEqual(self.incoming_left(), [])


class R5Result(Base):
    def test_r5_result_of_a_done_job(self):
        self.serve(self.signed_env())
        st, ans, _ = self.post()
        res = self.wait_result(ans["job_id"])
        result = res["result"]
        self.assertEqual(result["format"], "onedroid-result/1")
        self.assertEqual(result["service"], "onedroid-witness")
        self.assertEqual(result["service_version"], "test")
        self.assertEqual(result["job_id"], ans["job_id"])
        self.assertEqual(result["receipt_sha256"], hashlib.sha256(canonical(ans["receipt"])).hexdigest())
        self.assertEqual(result["state"], "done")
        st, status = self.get_json(f"/witness/{ans['job_id']}")
        self.assertEqual(result["status"], status)
        _, headers, tar_bytes = self.get(f"/witness/{ans['job_id']}/answer.tar")
        self.assertEqual(result["outputs"]["answer.tar"], hashlib.sha256(tar_bytes).hexdigest())
        self.assertEqual(result["outputs"]["answer.tar"], headers["X-Answer-SHA256"])
        self.assertEqual(sorted(result["models"]["run"]), ["openai/gpt-4.1-nano", "typesafe/jev-1.14"])
        self.assertEqual(result["models"]["skipped"], [])
        self.assertEqual(result["spend_usd"], status["total_cost_usd"])
        self.assertRegex(result["finished_at"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
        self.assertTrue(verify_resp(self.keys(), result, res["signature"]))

    def test_r5_result_json_is_the_canonical_bytes_that_were_signed(self):
        self.serve(self.signed_env())
        st, ans, _ = self.post()
        res = self.wait_result(ans["job_id"])
        d = pathlib.Path(self.tmp, "jobs", ans["job_id"])
        self.assertEqual((d / "result.json").read_bytes(), canonical(res["result"]))
        self.assertEqual(base64.b64encode((d / "result.sig").read_bytes()).decode(), res["signature"])

    def test_r5_skipped_models_are_named(self):
        self.serve(self.signed_env())
        # a bound too small for both models: the first that fits runs, the other is skipped (3b.1)
        st, ans, _ = self.post(args={"models": "openai/gpt-4.1-nano,typesafe/jev-1.14", "max_cost_usd": str(ans_estimate(self))})
        self.assertEqual(st, 202, ans)
        res = self.wait_result(ans["job_id"])
        self.assertEqual(res["result"]["models"]["run"], ans["models_run_planned"])
        self.assertEqual([s["model"] for s in res["result"]["models"]["skipped"]], [s["model"] for s in ans["models_skipped"]])

    def test_r5_a_failed_job_gets_a_signed_result_too(self):
        def boom(ids):
            raise RuntimeError("worker broke")
        self.serve(self.signed_env(), models_of=boom)
        st, ans, _ = self.post()
        self.assertEqual(st, 202, ans)
        res = self.wait_result(ans["job_id"])
        self.assertEqual(res["result"]["state"], "failed")
        self.assertIn("worker broke", res["result"]["failure"])
        self.assertNotIn("answer.tar", res["result"]["outputs"])
        self.assertTrue(verify_resp(self.keys(), res["result"], res["signature"]))

    def test_r5_409_while_queued_and_404_for_an_unknown_id(self):
        self.serve(self.signed_env(), start_worker=False)
        st, ans, _ = self.post()
        self.assertEqual(st, 202, ans)
        st, doc = self.get_json(f"/witness/{ans['job_id']}/result")
        self.assertEqual(st, 409, doc)
        st, doc = self.get_json("/witness/no-such-job/result")
        self.assertEqual(st, 404, doc)

    def test_r5_409_while_running(self):
        self.serve(self.signed_env(), start_worker=False)
        st, ans, _ = self.post()
        status = self.store.status(ans["job_id"])
        status["state"] = "running"
        self.store.write_status(ans["job_id"], status)
        st, doc = self.get_json(f"/witness/{ans['job_id']}/result")
        self.assertEqual(st, 409, doc)


def ans_estimate(test):
    """A max_cost_usd that fits the first model's estimate but not both: half way between the two estimates' sum and the first."""
    st, ans, _ = test.post(args={"models": "openai/gpt-4.1-nano,typesafe/jev-1.14", "max_cost_usd": "1.0"})
    per = ans["estimate_usd"]
    test.wait_result(ans["job_id"])
    return per["openai/gpt-4.1-nano"] + per["typesafe/jev-1.14"] / 2


class R6Reproducible(Base):
    def test_r6_verify_from_keys_only_and_one_byte_fails(self):
        self.serve(self.signed_env())
        st, ans, _ = self.post()
        res = self.wait_result(ans["job_id"])
        keys = self.keys()
        self.assertTrue(verify_resp(keys, ans["receipt"], ans["signature"]))
        self.assertTrue(verify_resp(keys, res["result"], res["signature"]))
        for obj, sig in ((ans["receipt"], ans["signature"]), (res["result"], res["signature"])):
            data = bytearray(canonical(obj))
            data[len(data) // 2] ^= 1
            self.assertFalse(verify_resp(keys, bytes(data), sig))
        bad = dict(ans["receipt"], received_at="2020-01-01T00:00:00Z")
        self.assertFalse(verify_resp(keys, bad, ans["signature"]))
        bad = json.loads(json.dumps(res["result"]))
        bad["outputs"]["answer.tar"] = "0" * 64
        self.assertFalse(verify_resp(keys, bad, res["signature"]))


class R7Unchanged(Base):
    def test_r7_unconfigured_service_answers_as_before_plus_the_receipt(self):
        self.serve({})
        st, ans, _ = self.post()
        self.assertEqual(st, 202, ans)
        self.assertEqual(ans["claims"], 74)
        st, status = self.get_json(f"/witness/{ans['job_id']}")
        self.wait_result(ans["job_id"])
        st, status = self.get_json(f"/witness/{ans['job_id']}")
        self.assertEqual(status["state"], "done")
        self.assertIn("answer_sha256", status)
        st, h = self.get_json("/healthz")
        self.assertEqual(h["check_py_sha256"], checkpin.CHECK_PY_SHA256)
        self.assertEqual(h["mode"], "private")
        st, _, _ = self.get(f"/witness/{ans['job_id']}/answer.tar")
        self.assertEqual(st, 200)

    def test_r7_server_without_responder_wiring_still_works(self):
        """The cfg of the older tests (no responder, verifier or require_key keys) keeps working: no receipt, no result."""
        check = checkpin.load_check(ROOT / "vendor" / "check.py")
        ledger = Ledger(str(pathlib.Path(self.tmp) / "ledger.json"), 100.0)
        keystore = KeyStore(pathlib.Path(self.tmp) / "keys")
        self.store = JobStore(pathlib.Path(self.tmp) / "jobs")
        known = {m["id"]: m for m in MODELS}
        worker = Worker(self.store, FakeClient(REC, ledger), keystore, check, lambda ids: [known[i] for i in ids], PRICES, private_mode=True)
        worker.start()
        cfg = {"store": self.store, "worker": worker, "models_cfg": MODELS, "prices": PRICES, "ledger": ledger, "keystore": keystore, "private_mode": True, "version": "test"}
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(cfg))
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        st, ans, _ = self.post()
        self.assertEqual(st, 202, ans)
        self.assertNotIn("receipt", ans)
        st, keys = self.get_json("/keys")
        self.assertEqual(st, 200)
        self.assertIn("keys", keys)


if __name__ == "__main__":
    unittest.main()
