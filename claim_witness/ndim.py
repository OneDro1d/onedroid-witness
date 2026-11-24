"""n-dim objects through armarium (SPEC §7.5, DECISIONS BD4), behind one interface. armarium-service README, "SDK Data Mapping
Endpoints" (dev/ndim):

    POST   /chain/{name}/object                  body: a JSON object      -> {correlation_id, block}
    PUT    /chain/{name}/object/{id}?block=<tail> body: the new version  -> {correlation_id?, block}
    DELETE /chain/{name}/object/{id}?block=<tail>                         -> {correlation_id, deletion_marker_block, dek,
                                                                              residual, message}; 409 incomplete: retry
    GET    /chain/{name}/object/{id}                                      -> the object; 410 {"status": "deleted"}

Scope object:write / object:read on a token bound to the chain. armarium encrypts every version under its own data key and
splits it into 2048-byte ciphertext chunks itself. An object DELETE appends a DELETED marker: on a claimant chain created with
ARMARIUM_KMS (keyScheme akv1) the version's key is deleted (`dek: "deleted"`); on a legacy chain the key stays on the chain
under the shared key (`dek: "on-chain"`). In both cases the encrypted bytes stay on the chain (residual ciphertext-on-chain).

Settings: ARMARIUM_URL (https), ARMARIUM_TOKEN_FILE (read for each call, sent only as the bearer token, never logged),
ARMARIUM_CA_FILE (optional), ARMARIUM_CHAIN (the chain the witness writes to). With ARMARIUM_URL unset nothing is written.
chain_for() is the one place a per-owner claimant chain would be chosen later."""
import json
import os
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request

TOKEN = re.compile(r"[\x21-\x7e]{1,4096}")
CHAIN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
OBJ_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
ANSWER_MAX = 64 << 20
TIMEOUT_S = 30


class ArmariumError(Exception):
    """A call that did not do what was asked (HTTP status or transport); the message holds a code, never the token."""


class Gone(ArmariumError):
    """GET of an object whose last version is a DELETED marker (410)."""


class ArmariumClient:
    """The interface. Objects are JSON objects; ids and blocks as armarium answers them."""

    def create_object(self, chain, obj):
        """-> {"id", "block"}"""
        raise NotImplementedError

    def put_version(self, chain, obj_id, block, obj):
        """-> {"id", "block"}"""
        raise NotImplementedError

    def delete_object(self, chain, obj_id, block):
        """The DELETED marker (the tombstone of that version) -> {"id", "block", "dek", "residual"}"""
        raise NotImplementedError

    def get_object(self, chain, obj_id):
        """-> the object; Gone when deleted"""
        raise NotImplementedError


def chain_for(account, default_chain):
    """The chain a kept record of `account` is written to. Today one chain for every owner; armarium's recommended model is
    per-owner claimant chains under one claim-witness case, which would be chosen here."""
    return default_chain


def _read_token(path):
    try:
        with open(path, "rb") as f:
            tok = f.read(8192).decode("ascii").strip()
    except (OSError, UnicodeDecodeError):
        raise ArmariumError("ARMARIUM_TOKEN_FILE: cannot be read") from None
    if not TOKEN.fullmatch(tok):
        raise ArmariumError("ARMARIUM_TOKEN_FILE: not one token")
    return tok


class HttpArmarium(ArmariumClient):
    def __init__(self, url, token_file, ca_file=None):
        self.url, self.token_file, self.ca_file = url.rstrip("/"), token_file, ca_file
        ctx = ssl.create_default_context(cafile=ca_file) if ca_file else ssl.create_default_context()
        if ctx.verify_mode != ssl.CERT_REQUIRED or not ctx.check_hostname:
            raise ValueError("armarium's TLS context does not verify")
        self.ctx = ctx

    def _call(self, method, path, query=None, obj=None):
        token = _read_token(self.token_file)
        url = self.url + path + ("?" + urllib.parse.urlencode(query) if query else "")
        data = json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8") if obj is not None else None
        req = urllib.request.Request(url, data=data, method=method,
                                     headers={"Authorization": "Bearer " + token, "Content-Type": "application/json",
                                              "Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT_S, context=self.ctx) as r:
                status, raw = r.status, r.read(ANSWER_MAX)
        except urllib.error.HTTPError as e:
            try:
                status, raw = e.code, e.read(ANSWER_MAX)
            finally:
                e.close()
        except urllib.error.URLError as e:
            raise ArmariumError(f"unreachable ({type(e.reason).__name__})") from None
        except (OSError, ssl.SSLError) as e:
            raise ArmariumError(f"unreachable ({type(e).__name__})") from None
        try:
            answer = json.loads(raw) if raw else {}
        except ValueError:
            answer = None
        if status == 410:
            raise Gone("410 deleted")
        if status != 200:
            code = answer.get("error") if isinstance(answer, dict) and isinstance(answer.get("error"), str) else ""
            step = answer.get("step") if isinstance(answer, dict) and isinstance(answer.get("step"), str) else ""
            raise ArmariumError(f"http {status} {code[:40]} {step[:16]}".strip())
        if not isinstance(answer, dict):
            raise ArmariumError("bad answer: not a JSON object")
        return answer

    @staticmethod
    def _path(chain, obj_id=None):
        if not CHAIN.match(chain or ""):
            raise ArmariumError("bad chain name")
        p = f"/chain/{urllib.parse.quote(chain)}/object"
        if obj_id is not None:
            if not OBJ_ID.match(str(obj_id)):
                raise ArmariumError("bad object id")
            p += "/" + urllib.parse.quote(str(obj_id))
        return p

    @staticmethod
    def _block(a, *keys):
        for k in keys:
            v = a.get(k)
            if isinstance(v, int) and not isinstance(v, bool) and v >= 0:
                return v
        raise ArmariumError("bad answer: no block")

    def create_object(self, chain, obj):
        a = self._call("POST", self._path(chain), obj=obj)
        oid = a.get("correlation_id")
        if not isinstance(oid, str) or not OBJ_ID.match(oid):
            raise ArmariumError("bad answer: no correlation_id")
        return {"id": oid, "block": self._block(a, "block")}

    def put_version(self, chain, obj_id, block, obj):
        a = self._call("PUT", self._path(chain, obj_id), {"block": int(block)}, obj)
        return {"id": obj_id, "block": self._block(a, "block")}

    def delete_object(self, chain, obj_id, block):
        a = self._call("DELETE", self._path(chain, obj_id), {"block": int(block)})
        dek = a.get("dek") if a.get("dek") in ("deleted", "on-chain") else "unknown"
        residual = [x for x in a.get("residual") or [] if isinstance(x, str) and re.match(r"^[a-z-]{1,40}$", x)]
        return {"id": obj_id, "block": self._block(a, "deletion_marker_block", "block"), "dek": dek, "residual": residual}

    def get_object(self, chain, obj_id):
        return self._call("GET", self._path(chain, obj_id))


def from_env(env):
    """(client, chain), or (None, None) when ARMARIUM_URL is unset. ValueError on a bad setting."""
    url = (env.get("ARMARIUM_URL") or "").strip()
    if not url:
        return None, None
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https" or not parts.hostname:
        raise ValueError("ARMARIUM_URL: an https:// URL (the token is never sent in clear)")
    token_file = (env.get("ARMARIUM_TOKEN_FILE") or "").strip()
    if not token_file:
        raise ValueError("ARMARIUM_TOKEN_FILE is required with ARMARIUM_URL")
    if not os.path.exists(token_file):
        return None, None  # an optional Secret volume not created yet: nothing is written, the records say not-configured
    chain = (env.get("ARMARIUM_CHAIN") or "").strip()
    if not CHAIN.match(chain):
        raise ValueError("ARMARIUM_CHAIN: the chain name the witness writes to")
    ca_file = (env.get("ARMARIUM_CA_FILE") or "").strip() or None
    if ca_file and not os.path.exists(ca_file):
        ca_file = None  # an optional ConfigMap volume not created: the system's trust
    try:
        client = HttpArmarium(url, token_file, ca_file)
    except (OSError, ssl.SSLError):
        raise ValueError("ARMARIUM_CA_FILE: not a readable PEM CA certificate") from None
    return client, chain
