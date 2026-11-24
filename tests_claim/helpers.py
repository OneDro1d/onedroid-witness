"""Shared fixtures for the claim witness tests: a fake clock, Ed25519 test keys, an in-process stack (storage, signer, witness,
HTTP server) and a small HTTP client. Standard library plus the package under test."""
import base64
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import tempfile
import threading
import urllib.error
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
T0 = 1795600000  # 2026-11-24T... a fixed epoch second for the fake clock

GO_TEST_PASS = b"\n".join([
    b'{"Time":"2026-11-24T10:00:00Z","Action":"run","Package":"example.com/x","Test":"TestA"}',
    b'{"Time":"2026-11-24T10:00:00Z","Action":"output","Package":"example.com/x","Test":"TestA","Output":"=== RUN   TestA\\n"}',
    b'{"Time":"2026-11-24T10:00:00Z","Action":"pass","Package":"example.com/x","Test":"TestA","Elapsed":0}',
    b'{"Time":"2026-11-24T10:00:00Z","Action":"run","Package":"example.com/x","Test":"TestB"}',
    b'{"Time":"2026-11-24T10:00:00Z","Action":"pass","Package":"example.com/x","Test":"TestB","Elapsed":0}',
    b'{"Time":"2026-11-24T10:00:00Z","Action":"pass","Package":"example.com/x","Elapsed":0.01}',
]) + b"\n"

GO_TEST_FAIL = b"\n".join([
    b'{"Action":"run","Package":"example.com/x","Test":"TestA"}',
    b'{"Action":"pass","Package":"example.com/x","Test":"TestA","Elapsed":0}',
    b'{"Action":"run","Package":"example.com/x","Test":"TestBroken"}',
    b'{"Action":"output","Package":"example.com/x","Test":"TestBroken","Output":"    x_test.go:9: want 1 got 2\\n"}',
    b'{"Action":"fail","Package":"example.com/x","Test":"TestBroken","Elapsed":0}',
    b'{"Action":"fail","Package":"example.com/x","Elapsed":0.01}',
]) + b"\n"


class Clock:
    def __init__(self, t=T0):
        self.t = float(t)

    def __call__(self):
        return self.t

    def advance(self, seconds):
        self.t += seconds


def sha(data):
    return hashlib.sha256(data).hexdigest()


def b64(data):
    return base64.b64encode(data).decode("ascii")


def seed(n):
    """A deterministic 32-byte Ed25519 seed for test key n."""
    return hashlib.sha256(b"claim-witness-test-key-%d" % n).digest()


def iso(t):
    import time
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))


def obj_item(slot, data, media_type="text/plain", name=None, inline=True):
    item = {"slot": slot, "kind": "object", "sha256": sha(data), "media_type": media_type, "name": name or f"{slot}.txt"}
    if inline:
        item["content_b64"] = b64(data)
    return item


def claim(method, params=None, assertion=True, statement=None, major=1):
    return {"method": method, "method_major": major, "params": params if params is not None else {}, "assertion": assertion,
            "statement": statement}


def request(c, evidence, visibility="public", **options):
    opts = {"visibility": visibility}
    opts.update(options)
    return {"claim": c, "evidence": evidence, "options": opts}


def exact_request(a=b"same bytes\n", b=None, assertion=True, visibility="public", **options):
    b = a if b is None else b
    return request(claim("match.exact", {}, assertion), [obj_item("submitted", a), obj_item("target", b)], visibility, **options)


class Stack:
    """An in-process witness: memory (or given) storage, a signer core with test key 1, a bootstrapped key list, the witness
    service, and its HTTP server on 127.0.0.1 with dev keys acct_a and acct_b."""

    DEV_KEYS = {"dev-key-a-0123456789abcdef": "acct_a", "dev-key-b-0123456789abcdef": "acct_b"}

    def __init__(self, storage=None, clock=None, redact_bin=None, config_overrides=None, caller_keys=None, serve=True):
        from claim_witness import service, signer, storage as storage_mod, api
        self.clock = clock or Clock()
        self.tmp = tempfile.mkdtemp(prefix="cw-test-")
        self.storage = storage if storage is not None else storage_mod.MemoryStorage()
        self.seed = seed(1)
        self.key_id = "witness:test:2026a"
        self.witness_id = "witness:test"
        signer.keylist_init(self.storage, self.seed, self.key_id, self.witness_id, clock=self.clock)
        self.core = signer.SignerCore(self.seed, self.key_id, self.witness_id, self.storage, clock=self.clock)
        self.signer = signer.LocalSignerClient(self.core)
        if redact_bin is None:
            redact_bin = fake_redact_bin()
        cfg = dict(witness_id=self.witness_id, attempt_key=b"A" * 32, master_key=b"M" * 32, redact_bin=redact_bin,
                   clock=self.clock)
        cfg.update(config_overrides or {})
        self.witness = service.Witness(self.storage, self.signer, service.Config(**cfg))
        keys_file = pathlib.Path(self.tmp) / "dev-keys.json"
        keys_file.write_text(json.dumps(self.DEV_KEYS))
        self.auth = api.Auth(dev_keys=api.DevKeys.from_file(str(keys_file)), caller_keys=caller_keys)
        self.server = None
        if serve:
            self.server = api.make_server(self.witness, self.auth, "127.0.0.1", 0)
            self.port = self.server.server_address[1]
            self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
            self.thread.start()

    def close(self):
        if self.server is not None:
            self.server.shutdown()
            self.server.server_close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def url(self, path):
        return f"http://127.0.0.1:{self.port}{path}"

    def call(self, method, path, body=None, key="dev-key-a-0123456789abcdef", headers=None, raw=None, content_type=None):
        h = {}
        if key is not None:
            h["Authorization"] = f"Bearer {key}"
        if raw is None and body is not None:
            raw = json.dumps(body).encode("utf-8")
            content_type = content_type or "application/json"
        if content_type:
            h["Content-Type"] = content_type
        h.update(headers or {})
        req = urllib.request.Request(self.url(path), data=raw, method=method, headers=h)
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = resp.read()
                return resp.status, (json.loads(data) if data else None), dict(resp.headers)
        except urllib.error.HTTPError as e:
            data = e.read()
            try:
                parsed = json.loads(data) if data else None
            except ValueError:
                parsed = {"raw": data.decode("utf-8", "replace")}
            return e.code, parsed, dict(e.headers)

    def witness_call(self, body, **kw):
        return self.call("POST", "/v1/witness", body, **kw)

    def log_count(self):
        return len(self.storage.signing_log())


def payload_of(envelope):
    return json.loads(base64.b64decode(envelope["payload"]))


def payload_bytes(envelope):
    return base64.b64decode(envelope["payload"])


_FAKE = None


def fake_redact_bin():
    """A stand-in for tools/redact-copy with the same stdin/stdout contract, finding the one credential shape
    'sk-ant-' + 20 or more characters, so the screening path is exercised without Go."""
    global _FAKE
    if _FAKE is None:
        d = tempfile.mkdtemp(prefix="cw-redact-")
        p = pathlib.Path(d) / "redact-copy"
        p.write_text("#!/usr/bin/env python3\n"
                     "import json, re, sys\n"
                     "t = sys.stdin.buffer.read().decode('utf-8')\n"
                     "ms = [{'rule': 'anthropic-api-key', 'start': m.start(), 'end': m.end(), 'pass': 1}"
                     " for m in re.finditer(r'sk-ant-[A-Za-z0-9_\\-]{20,}', t)]\n"
                     "print(json.dumps({'text': t, 'matches': ms, 'passes': 1, 'rules': 'fake'}))\n")
        p.chmod(0o755)
        _FAKE = str(p)
    return _FAKE


_REAL = None


def real_redact_bin():
    """tools/redact-copy built with Go from the vendored tree (offline), or None when Go is not installed."""
    global _REAL
    if _REAL is None:
        go = shutil.which("go")
        if go is None:
            return None
        out = pathlib.Path(tempfile.mkdtemp(prefix="cw-redact-go-")) / "redact-copy"
        env = dict(os.environ, CGO_ENABLED="0", GOFLAGS="-mod=vendor")
        done = subprocess.run([go, "build", "-trimpath", "-o", str(out), "."], cwd=str(ROOT / "tools" / "redact-copy"),
                              capture_output=True, env=env, timeout=300, check=False)
        if done.returncode != 0:
            raise RuntimeError("go build of tools/redact-copy failed: " + done.stderr.decode("utf-8", "replace")[-400:])
        _REAL = str(out)
    return _REAL


def agent_block(seed_bytes, agent_key_id, witness_id, claim_obj, evidence, nonce, agent_time):
    """The request's agent block, signed the way SPEC §2.4 says: Ed25519 over canonical {witness_id, claim_id, evidence
    (object sha256s and requested URLs, sorted), nonce, agent_time}."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from claim_witness import jcs
    claim_id = sha(jcs.canonical(claim_obj))
    refs = sorted([e["sha256"] for e in evidence if e.get("kind") == "object"] + [e["url"] for e in evidence if e.get("kind") == "url"])
    msg = jcs.canonical({"witness_id": witness_id, "claim_id": claim_id, "evidence": refs, "nonce": nonce, "agent_time": agent_time})
    sig = Ed25519PrivateKey.from_private_bytes(seed_bytes).sign(msg)
    return {"agent_key_id": agent_key_id, "agent_sig": b64(sig), "nonce": nonce, "agent_time": agent_time}


def public_of(seed_bytes):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    return Ed25519PrivateKey.from_private_bytes(seed_bytes).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
