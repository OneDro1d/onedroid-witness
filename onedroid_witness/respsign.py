"""E2E-SIG3: the witness service signs what it answers and keeps its caller's signature (receipts and results, namespace onedroid-resp).

PORTED, not vendored byte for byte: Signer, StoreKeys, canonical and the receipt-caller rule are the ones in onedroid-audit
audit_server.py (main 465ae4b, file sha256 86471c67136626b843ae2d2ae4f3874849ee7bb080470d645905680cd9efaea9, E2E-SIG1 and E2E-K1), with
these changes only: the env names are WITNESS_*, the signed request line names the service "onedroid-witness" (a parameter of StoreKeys),
the audit job machinery is gone, and there is no file (bearer) key mode. The formats are the same: onedroid-receipt/1, onedroid-result/1,
signature = std base64 of the armored SSHSIG over the canonical JSON (sort_keys, separators (",", ":"), ensure_ascii False, UTF-8).

The private key is only ever read by ssh-keygen where it is mounted; nothing here copies, logs, serves or writes it, and no ssh-keygen
error text is kept. The per-model KeyStore (signing.py, namespace claims-snapshot) is not touched.
"""
import base64
import collections
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import tempfile
import threading
import time
import urllib.parse
import urllib.request

RESP_NAMESPACE = "onedroid-resp"
REQ_NAMESPACE = "onedroid-req"
SERVICE = "onedroid-witness"
RECEIPT_FORMAT, RESULT_FORMAT = "onedroid-receipt/1", "onedroid-result/1"
UNSIGNED = "no signing key configured"
SCOPE_WITNESS = "witness"
RECEIPT_FILE, RESULT_FILE, RESULT_SIG_FILE = "receipt.json", "result.json", "result.sig"
TERMINAL = ("done", "failed", "refused")
STORE_SCOPES = ("submit", "audit", "witness")
STORE_KID = re.compile(r"[A-Za-z0-9_-]{1,64}")
STORE_OWNER = re.compile(r"[^\s\x00-\x1f\x7f]{1,256}")
STORE_TIME = re.compile(r"[0-9]{1,12}")


class SigningError(Exception):
    pass


class KeyServiceUnavailable(Exception):
    pass


def canonical(obj):
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def utc_now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def _clean_env():
    return {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C"}


class Signer:
    """The service's Ed25519 key, used only through ssh-keygen: `-y` once at start to learn the public half (and refuse a key that is
    unreadable, passphrase-protected or not ed25519), `-Y sign -n onedroid-resp` per signature, the data on stdin."""

    TIMEOUT = 10

    def __init__(self, path):
        self.path = str(path)
        if shutil.which("ssh-keygen") is None:
            raise SystemExit("WITNESS_RESP_SIGNING_KEY: ssh-keygen (openssh-client) is not installed")
        try:
            done = subprocess.run(["ssh-keygen", "-y", "-P", "", "-f", self.path], capture_output=True, check=False,
                                  stdin=subprocess.DEVNULL, timeout=self.TIMEOUT, env=_clean_env())
        except (OSError, subprocess.SubprocessError):
            raise SystemExit("WITNESS_RESP_SIGNING_KEY: ssh-keygen could not read the key") from None
        parts = done.stdout.decode("utf-8", "replace").split() if done.returncode == 0 else []
        if len(parts) < 2:
            raise SystemExit("WITNESS_RESP_SIGNING_KEY: not a readable OpenSSH private key (unencrypted, at that path)")
        try:
            blob = base64.b64decode(parts[1], validate=True)
        except ValueError:
            blob = b""
        head = len(b"ssh-ed25519").to_bytes(4, "big") + b"ssh-ed25519"
        if parts[0] != "ssh-ed25519" or len(blob) != len(head) + 4 + 32 or not blob.startswith(head):
            raise SystemExit("WITNESS_RESP_SIGNING_KEY: the key is not ed25519")
        self.raw = blob[-32:]
        self.key_id = "sk_" + sha256_hex(self.raw)[:16]
        self.ssh = f"ssh-ed25519 {parts[1]}"

    def public(self):
        return {"key_id": self.key_id, "public_key": base64.b64encode(self.raw).decode("ascii"), "ssh": self.ssh}

    def sign(self, data):
        """The armored SSH signature (bytes) over data under the namespace onedroid-resp, or SigningError."""
        try:
            done = subprocess.run(["ssh-keygen", "-Y", "sign", "-n", RESP_NAMESPACE, "-f", self.path], input=data,
                                  capture_output=True, check=False, timeout=self.TIMEOUT, env=_clean_env())
        except (OSError, subprocess.SubprocessError):
            raise SigningError("ssh-keygen could not sign") from None
        if done.returncode != 0 or not done.stdout.startswith(b"-----BEGIN SSH SIGNATURE-----"):
            raise SigningError("ssh-keygen could not sign")
        return done.stdout


def load_signer(env):
    path = (env.get("WITNESS_RESP_SIGNING_KEY") or "").strip()
    return Signer(path) if path else None


class StoreKeys:
    """K1's store-mode verifier, ported (see the module doc). verify_request(method, path, body, headers) -> dict | None, or
    KeyServiceUnavailable. The key list is the store gateway's public keys; the signature is an armored SSH signature over the line
    `onedroid-req/1 <service> <METHOD> <path> sha256:<hex of body> <time>`, checked by `ssh-keygen -Y verify` against one allowed_signers
    line built from the listed key, in a private temp dir."""

    DEFAULT_URL = "http://store-gateway.evidence-dev.svc.cluster.local/stores/v1/public/keys"
    TTL, STALE, UNKNOWN_GAP, FAIL_GAP, WINDOW = 60, 300, 2, 2, 300
    FETCH_TIMEOUT, VERIFY_TIMEOUT, MAX_LIST, MAX_SIG = 5, 10, 1 << 20, 4096

    def __init__(self, url=None, clock=None, log=None, fetch=None, service=SERVICE):
        self.url, self.clock, self.log_fn, self.service = url or self.DEFAULT_URL, clock, log, service
        self.fetch = fetch or self._http_fetch
        self.lock = threading.Lock()
        self.keys, self.fetched_at, self.last_fail, self.last_unknown = {}, None, None, None
        self.reported = set()
        with self.lock:
            self._load(self._now())

    def _now(self):
        return float(self.clock()) if self.clock is not None else time.time()

    def _log(self, line):
        if self.log_fn is not None:
            self.log_fn(line)

    def _http_fetch(self):
        request = urllib.request.Request(self.url, headers={"accept": "application/json"})
        with urllib.request.urlopen(request, timeout=self.FETCH_TIMEOUT) as resp:
            data = resp.read(self.MAX_LIST + 1)
        if len(data) > self.MAX_LIST:
            raise ValueError("list too large")
        return data

    def _load(self, now):
        try:
            doc = json.loads(self.fetch())
            if not isinstance(doc, dict) or not isinstance(doc.get("keys"), list):
                raise ValueError("not a key list")
            keys = self._parse(doc["keys"])
        except Exception as exc:  # noqa: BLE001 - any failure is "the list is not there"
            self.last_fail = now
            if callable(getattr(exc, "close", None)):
                exc.close()
            self._log(f"store key list fetch failed: {type(exc).__name__}")
            return False
        self.keys, self.fetched_at, self.last_fail = keys, now, None
        return True

    def _ignore(self, kid, why):
        if kid not in self.reported:
            self.reported.add(kid)
            self._log(f"store key list: ignored key {kid} ({why})")

    def _parse(self, entries):
        out, seen, dupes = {}, set(), set()
        for e in entries:
            if not isinstance(e, dict) or not isinstance(e.get("key_id"), str) or not STORE_KID.fullmatch(e["key_id"]):
                self._ignore("-", "an entry without a usable key_id")
                continue
            kid = e["key_id"]
            if kid in seen:
                dupes.add(kid)
            seen.add(kid)
            if "state" in e and e["state"] != "active":
                continue
            owner, scopes, pub = e.get("owner"), e.get("scopes"), e.get("public_key")
            if not isinstance(owner, str) or not STORE_OWNER.fullmatch(owner):
                self._ignore(kid, "no usable owner")
                continue
            if not isinstance(scopes, list) or not all(isinstance(s, str) for s in scopes):
                self._ignore(kid, "no usable scopes list")
                continue
            try:
                raw = base64.b64decode(pub, validate=True) if isinstance(pub, str) else b""
            except ValueError:
                raw = b""
            if len(raw) != 32:
                self._ignore(kid, "no usable 32-byte public key")
                continue
            out[kid] = {"owner": owner, "scopes": [s for s in STORE_SCOPES if s in scopes], "raw": raw}
        for kid in dupes:
            if out.pop(kid, None) is not None:
                self._ignore(kid, "listed twice")
        return out

    def _entry(self, kid, now):
        with self.lock:
            can_try = self.last_fail is None or now - self.last_fail >= self.FAIL_GAP
            if can_try:
                if self.fetched_at is None or now - self.fetched_at > self.TTL:
                    self._load(now)
                elif kid not in self.keys and (self.last_unknown is None or now - self.last_unknown >= self.UNKNOWN_GAP):
                    self.last_unknown = now
                    self._load(now)
            if self.fetched_at is None or now - self.fetched_at > self.STALE:
                raise KeyServiceUnavailable("no good key list")
            return self.keys.get(kid)

    def verify_request(self, method, path, body, headers):
        kid, ts, sig = (headers.get(h) for h in ("X-Store-Key", "X-Store-Time", "X-Store-Signature"))
        if not (isinstance(kid, str) and isinstance(ts, str) and isinstance(sig, str)):
            return None
        if not STORE_KID.fullmatch(kid) or not STORE_TIME.fullmatch(ts) or not 0 < len(sig) <= 2 * self.MAX_SIG:
            return None
        try:
            armored = base64.b64decode(sig, validate=True)
        except ValueError:
            return None
        if len(armored) > self.MAX_SIG or not armored.startswith(b"-----BEGIN SSH SIGNATURE-----"):
            return None
        now = self._now()
        if abs(now - int(ts)) > self.WINDOW:
            return None
        entry = self._entry(kid, now)
        if entry is None:
            return None
        line = f"onedroid-req/1 {self.service} {method} {path} sha256:{sha256_hex(body)} {ts}"
        if not self._ssh_verify(kid, entry["raw"], armored, line.encode("utf-8")):
            return None
        return {"account": entry["owner"], "key_id": kid, "scopes": list(entry["scopes"]), "signed_line": line, "signature": sig,
                "signed_time": int(ts)}

    def _ssh_verify(self, kid, raw, armored, line):
        blob = b"".join(len(p).to_bytes(4, "big") + p for p in (b"ssh-ed25519", raw))
        signers = f'{kid} namespaces="{REQ_NAMESPACE}" ssh-ed25519 {base64.b64encode(blob).decode()}\n'
        tmp = tempfile.mkdtemp(prefix="witness-sig-")
        try:
            signers_path, sig_path = os.path.join(tmp, "allowed_signers"), os.path.join(tmp, "request.sig")
            with open(signers_path, "w", encoding="ascii") as f:
                f.write(signers)
            with open(sig_path, "wb") as f:
                f.write(armored)
            done = subprocess.run(["ssh-keygen", "-Y", "verify", "-f", signers_path, "-I", kid, "-n", REQ_NAMESPACE, "-s", sig_path],
                                  input=line, capture_output=True, timeout=self.VERIFY_TIMEOUT, check=False, env=_clean_env())
            return done.returncode == 0
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


def caller_record(account):
    """SIG1 R3 (store mode): who submitted, as the job folder keeps it. The signature is a proof of submission, not a secret; it is
    never logged."""
    if account is None:
        return None
    return {"key_id": account["key_id"], "owner": account["account"], "signed_line": account.get("signed_line"),
            "signature": account.get("signature"), "time": account.get("signed_time")}


def receipt_caller(caller):
    """SIG1 R4: the caller as the receipt holds it: the signature itself replaced by its sha256."""
    if caller is None or "signature" not in caller:
        return None if caller is None else dict(caller)
    out = {k: v for k, v in caller.items() if k != "signature"}
    sig = caller["signature"]
    out["signature_sha256"] = sha256_hex(sig.encode("utf-8")) if isinstance(sig, str) else None
    return out


def _write_bytes(path, data):
    tmp = path.with_name(f".{path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
    tmp.write_bytes(data)
    os.replace(tmp, path)


class Responder:
    """Receipts, results and the service key document for one JobStore. signer may be None (nothing is signed, and every document says
    why)."""

    def __init__(self, store, signer, version, private_mode=False, log=None):
        self.store, self.signer, self.version, self.private_mode = store, signer, version, private_mode
        self.log = log or (lambda line: print(line, flush=True))

    def _sign(self, obj):
        if self.signer is None:
            return None
        return base64.b64encode(self.signer.sign(canonical(obj))).decode("ascii")

    def keys_doc(self):
        return {"service": SERVICE, "namespace": RESP_NAMESPACE, "keys": [self.signer.public()] if self.signer is not None else []}

    def issue_receipt(self, jid, raw, account):
        """R4: the receipt for a job just adopted, signed (or unsigned with the reason), kept with the caller in <job>/receipt.json.
        Returns the fields the 202 body adds: receipt, signature (+ unsigned)."""
        caller = caller_record(account)
        receipt = {"format": RECEIPT_FORMAT, "service": SERVICE, "service_version": self.version, "job_id": jid, "received_at": utc_now(),
                   "request_sha256": sha256_hex(raw), "caller": receipt_caller(caller), "visibility": "private" if self.private_mode else "public"}
        try:
            signature = self._sign(receipt)
            why = UNSIGNED if self.signer is None else None
        except SigningError:
            self.log(f"job {jid} receipt could not be signed")
            signature, why = None, "the receipt could not be signed"
        record = {"caller": caller, "receipt": receipt, "receipt_signature": signature}
        d = self.store.dir(jid)
        _write_bytes(d / RECEIPT_FILE, (json.dumps(record, indent=1, ensure_ascii=False) + "\n").encode("utf-8"))
        out = {"receipt": receipt, "signature": signature}
        if signature is None:
            out["unsigned"] = why
        return out

    def finish(self, jid, status):
        """R5: a job that has ended (done, failed or refused) gets result.json (the canonical bytes that were signed) and result.sig.
        Called by the worker with the final status BEFORE it writes that status, so a job that reads as ended already has its result.
        A job with no receipt (from before SIG3) gets none."""
        d = self.store.dir(jid)
        if d is None or status.get("state") not in TERMINAL:
            return
        try:
            receipt = json.loads((d / RECEIPT_FILE).read_text(encoding="utf-8")).get("receipt")
        except (OSError, ValueError):
            return
        if not isinstance(receipt, dict):
            return
        outputs = {}
        if status.get("state") == "done" and status.get("answer_sha256"):
            outputs["answer.tar"] = status["answer_sha256"]
        result = {"format": RESULT_FORMAT, "service": SERVICE, "service_version": self.version, "job_id": jid,
                  "receipt_sha256": sha256_hex(canonical(receipt)), "state": status.get("state"),
                  "failure": status.get("reason") if status.get("state") != "done" else None,
                  "spend_usd": status.get("total_cost_usd"),
                  "models": {"run": list(status.get("models_run") or []), "skipped": list(status.get("models_skipped") or [])},
                  "outputs": outputs, "status": json.loads(json.dumps(status)), "finished_at": status.get("finished_at") or utc_now()}
        data = canonical(result)
        for name in (RESULT_FILE, RESULT_SIG_FILE):  # no result is served while the pair is being replaced
            try:
                (d / name).unlink()
            except OSError:
                pass
        try:
            armored = self.signer.sign(data) if self.signer is not None else None
        except SigningError:
            self.log(f"job {jid} result could not be signed")
            armored = None
        if armored is not None:
            _write_bytes(d / RESULT_SIG_FILE, armored)
        _write_bytes(d / RESULT_FILE, data)  # last: its presence says the result is complete

    def result_response(self, jid):
        """(status code, body) for GET /witness/<id>/result: {result, signature} (+ unsigned); 404 unknown id (or a job with no result
        ever); 409 until the job has ended."""
        d = self.store.dir(jid)
        status = self.store.status(jid) if d is not None else None
        if status is None:
            return 404, {"error": "unknown job id"}
        if status.get("state") not in TERMINAL:
            return 409, {"error": "no result yet", "state": status.get("state")}
        try:
            result = json.loads((d / RESULT_FILE).read_bytes())
        except (OSError, ValueError):
            if not (d / RECEIPT_FILE).exists():
                return 404, {"error": "no result was issued for this job (it predates signed responses)"}
            return 409, {"error": "no result yet", "state": status.get("state")}
        try:
            signature = base64.b64encode((d / RESULT_SIG_FILE).read_bytes()).decode("ascii")
        except OSError:
            signature = None
        out = {"result": result, "signature": signature}
        if signature is None:
            out["unsigned"] = UNSIGNED if self.signer is None else "the result could not be signed"
        return 200, out


Wiring = collections.namedtuple("Wiring", "responder verifier require_key")


def from_env(env, store, version, private_mode=False, fetch=None, log=None):
    """R1 and R3 from the environment: WITNESS_RESP_SIGNING_KEY, WITNESS_KEY_SOURCE ("store" or unset), WITNESS_STORE_KEYS_URL,
    WITNESS_REQUIRE_KEY ("1"). Anything unusable stops the server (SystemExit). `fetch` is for tests only."""
    log = log or (lambda line: print(line, flush=True))
    signer = load_signer(env)
    require = (env.get("WITNESS_REQUIRE_KEY") or "") == "1"
    source = env.get("WITNESS_KEY_SOURCE") or ""
    if source not in ("", "store"):
        raise SystemExit('WITNESS_KEY_SOURCE: "store" (evidence store keys) or unset')
    verifier = None
    if source == "store":
        if shutil.which("ssh-keygen") is None:
            raise SystemExit("WITNESS_KEY_SOURCE=store: ssh-keygen (openssh-client) is not installed")
        url = env.get("WITNESS_STORE_KEYS_URL") or StoreKeys.DEFAULT_URL
        parts = urllib.parse.urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.netloc:
            raise SystemExit("WITNESS_STORE_KEYS_URL: an http(s) URL")
        verifier = StoreKeys(url, log=log, fetch=fetch)
    elif require:
        raise SystemExit("WITNESS_REQUIRE_KEY=1 needs WITNESS_KEY_SOURCE=store")
    return Wiring(Responder(store, signer, version, private_mode=private_mode, log=log), verifier, require)
