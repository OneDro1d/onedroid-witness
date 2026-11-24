"""The HTTP API (SPEC §3), slice B1 routes, in the standard library's ThreadingHTTPServer (the onedroid_witness/server.py
style): one JSON answer per request, one log line per request with no bodies and no keys.

    POST /v1/witness              check one claim (JSON, or multipart: a part "request" plus one part per object, named by
                                  its sha256)
    GET  /v1/jobs/{id}            job status (the caller's own jobs only)
    POST /v1/agent-keys           register an agent's Ed25519 public key for the calling account
    POST /v1/observe              fetch a URL and sign an observation, with no claim (B2b)
    GET  /v1/observations/{id}    an observation's envelope and file names: public ones open, private ones to their account
    GET  /v1/observations/{id}/files/{name}   one file's bytes, same rule
    GET  /v1/methods              the method registry and the methods tarball's code_sha256
    GET  /.well-known/witness.json
    GET  /v1/key-lists/{seq}
    GET  /healthz

Auth (BD8) for the first three: `Authorization: Bearer <dev key>` (WITNESS_DEV_KEYS_FILE, each key mapped to an account; any
X-Witness-Account header is ignored), or the BFF's onedroid-req/1 signature (X-Store-Key, X-Store-Time, X-Store-Signature,
verified against the key list at WITNESS_CALLER_KEYS_URL) plus X-Witness-Account naming the account; POST /v1/observe the
same. GET /v1/observations authenticates when credentials are sent (to read the account's private ones). The other routes
are open.
"""
import email.parser
import email.policy
import hmac
import json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import __version__, jcs, reqauth
from .service import WitnessError

ACCOUNT = re.compile(r"^[A-Za-z0-9_.:@-]{1,128}$")
JOB_PATH = re.compile(r"^/v1/jobs/([A-Za-z0-9_-]{1,64})$")
KEYLIST_PATH = re.compile(r"^/v1/key-lists/([0-9]{1,9})$")
OBS_PATH = re.compile(r"^/v1/observations/([0-9a-f]{64})$")
OBS_FILE_PATH = re.compile(r"^/v1/observations/([0-9a-f]{64})/files/([A-Za-z0-9][A-Za-z0-9._-]{0,63})$")


class DevKeys:
    """Static dev API keys (BD8, dev only until B4): a JSON file, either {"<key>": "<account>"} or
    {"keys": [{"key": "<key>", "account": "<account>"}]}."""

    def __init__(self, mapping):
        self.mapping = {}
        for k, a in mapping.items():
            if isinstance(k, str) and len(k) >= 16 and isinstance(a, str) and ACCOUNT.match(a):
                self.mapping[k] = a

    @classmethod
    def from_file(cls, path):
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
        if isinstance(doc, dict) and isinstance(doc.get("keys"), list):
            doc = {e.get("key"): e.get("account") for e in doc["keys"] if isinstance(e, dict)}
        if not isinstance(doc, dict):
            raise SystemExit(f"{path}: not a dev key file")
        return cls(doc)

    def account(self, key):
        found = None
        for k, a in self.mapping.items():  # compare every key, in constant time each
            if hmac.compare_digest(k.encode("utf-8"), key.encode("utf-8")):
                found = a
        return found


class Auth:
    def __init__(self, dev_keys=None, caller_keys=None):
        self.dev_keys, self.caller_keys = dev_keys, caller_keys

    def account(self, method, path, body, headers):
        """The calling account, or WitnessError 401 (503 when the caller key list cannot be had)."""
        authz = headers.get("Authorization") or ""
        if authz:
            if not authz.startswith("Bearer ") or self.dev_keys is None:
                raise WitnessError(401, "unauthorized", "send Authorization: Bearer <api key>")
            acct = self.dev_keys.account(authz[len("Bearer "):].strip())
            if acct is None:
                raise WitnessError(401, "unauthorized", "unknown API key")
            return acct
        if headers.get("X-Store-Signature") and self.caller_keys is not None:
            try:
                who = self.caller_keys.verify_request(method, path, body, headers)
            except reqauth.KeyServiceUnavailable:
                raise WitnessError(503, "caller-keys-unavailable", "the caller key list cannot be read") from None
            if who is None:
                raise WitnessError(401, "unauthorized", "the onedroid-req/1 signature does not verify")
            acct = headers.get("X-Witness-Account") or ""
            if not ACCOUNT.match(acct):
                raise WitnessError(401, "unauthorized", "a signed BFF request names its account in X-Witness-Account")
            return acct
        raise WitnessError(401, "unauthorized", "send Authorization: Bearer <api key>, or a signed onedroid-req/1 request")


def parse_body(content_type, raw):
    """(request object, {sha256: bytes}) from a JSON or multipart body; WitnessError 400 otherwise."""
    ct = (content_type or "").split(";")[0].strip().lower()
    if ct == "multipart/form-data":
        msg = email.parser.BytesParser(policy=email.policy.HTTP).parsebytes(
            b"Content-Type: " + content_type.encode("latin-1") + b"\r\nMIME-Version: 1.0\r\n\r\n" + raw)
        if not msg.is_multipart():
            raise WitnessError(400, "malformed", "the multipart body does not parse")
        req, parts = None, {}
        for part in msg.iter_parts():
            name = part.get_param("name", header="content-disposition")
            data = part.get_payload(decode=True) or b""
            if name == "request":
                req = data
            elif isinstance(name, str) and re.match(r"^[0-9a-f]{64}$", name):
                parts[name] = data
            else:
                raise WitnessError(400, "malformed", "multipart parts are \"request\" and one per object, named by its sha256")
        if req is None:
            raise WitnessError(400, "malformed", "a multipart request has a part named \"request\" holding the JSON")
        return _json(req), parts
    if ct in ("application/json", ""):
        return _json(raw), {}
    raise WitnessError(400, "malformed", "send application/json or multipart/form-data")


def _json(raw):
    try:
        return jcs.loads_strict(raw)
    except jcs.CanonicalError as e:
        raise WitnessError(400, "malformed", f"the body is not JSON with integers only: {e}") from None


def make_handler(witness, auth):
    max_body = witness.cfg.max_body_bytes

    class Handler(BaseHTTPRequestHandler):
        server_version = f"claim-witness/{__version__}"
        sys_version = ""
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):
            print(f"{self.address_string()} {self.command} {self.path.split('?')[0]} {args[1] if len(args) > 1 else ''}", flush=True)

        def _send(self, code, obj, headers=None):
            body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def _send_bytes(self, code, data):
            self.send_response(code)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(data)

        def _maybe_account(self, path):
            if self.headers.get("Authorization") or self.headers.get("X-Store-Signature"):
                return auth.account("GET", path, b"", self.headers)
            return None

        def _error(self, e):
            self._send(e.status, e.body(), e.headers)

        def _read_body(self):
            try:
                n = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                raise WitnessError(400, "malformed", "Content-Length is not a number") from None
            if n < 0:
                raise WitnessError(400, "malformed", "Content-Length is negative")
            if n > max_body:
                self.close_connection = True
                raise WitnessError(413, "too-large", f"a request is at most {max_body} bytes")
            return self.rfile.read(n) if n else b""

        def do_GET(self):
            path = self.path.split("?", 1)[0]
            try:
                if path == "/healthz":
                    ok, out = witness.health()
                    return self._send(200 if ok else 503, out)
                if path == "/v1/methods":
                    return self._send(200, witness.methods_registry())
                if path == "/.well-known/witness.json":
                    return self._send(200, witness.well_known())
                m = KEYLIST_PATH.match(path)
                if m:
                    return self._send(200, witness.key_list(int(m.group(1))))
                if path.startswith("/v1/key-lists/"):
                    raise WitnessError(404, "not-found", "no such key list")
                m = OBS_PATH.match(path)
                if m:
                    return self._send(200, witness.observation_view(self._maybe_account(path), m.group(1)))
                m = OBS_FILE_PATH.match(path)
                if m:
                    return self._send_bytes(200, witness.observation_file(self._maybe_account(path), m.group(1), m.group(2)))
                if path.startswith("/v1/observations/"):
                    raise WitnessError(404, "not-found", "no such observation")
                m = JOB_PATH.match(path)
                if m or path.startswith("/v1/jobs/"):
                    acct = auth.account("GET", path, b"", self.headers)
                    if not m:
                        raise WitnessError(404, "not-found", "no such job")
                    return self._send(200, witness.job_view(acct, m.group(1)))
                raise WitnessError(404, "not-found", f"no route GET {path}")
            except WitnessError as e:
                self._error(e)

        def do_POST(self):
            path = self.path.split("?", 1)[0]
            try:
                if path not in ("/v1/witness", "/v1/agent-keys", "/v1/observe"):
                    self._read_body()
                    raise WitnessError(404, "not-found", f"no route POST {path}")
                raw = self._read_body()
                acct = auth.account("POST", path, raw, self.headers)
                if path == "/v1/agent-keys":
                    return self._send(200, witness.register_agent_key(acct, _json(raw)))
                if path == "/v1/observe":
                    status, out, headers = witness.observe(acct, _json(raw))
                    return self._send(status, out, headers)
                body, parts = parse_body(self.headers.get("Content-Type"), raw)
                status, out, headers = witness.submit(acct, body, parts, self.headers.get("Idempotency-Key"))
                self._send(status, out, headers)
            except WitnessError as e:
                self._error(e)

    return Handler


class Server(ThreadingHTTPServer):
    daemon_threads = True


def make_server(witness, auth, host="0.0.0.0", port=8080):
    return Server((host, port), make_handler(witness, auth))
