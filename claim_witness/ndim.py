"""n-dim objects through armarium's REAL object service (SPEC §7.5, DECISIONS BD4, B3W), behind one interface.

One CLAIMANT chain per owner under one claim-witness case (armarium PR #78, README of armarium-objects and its round-trip
scripts). The token is bound to the case, so it covers every claimant created under it:

    POST   /chain/{case}/claimant {from:{id,address}, to:{id,address}, ruleSet}  -> 201 {"id": <cid>, "level": "claimant", ...}
                                  the FIRST create waits for a disk and a node pod: up to 6 minutes
    POST   /chain/{cid}/object                              body: a JSON object  -> {correlation_id, block}
    PUT    /chain/{cid}/object/{id}?block=<tail>            body: the new version -> {new_correlation_id, new_block, original_id}
    GET    /chain/{cid}/object/{version id}                                       -> the version; 410 {"status": "deleted"}
    DELETE /chain/{cid}/object/{version id}?block=<its tail>                      -> 200 {dek, residual, message}; 409
                                  {"status": "incomplete"}: retry the same DELETE
    no token 401; a chain outside the token's case 403.

The key is PER VERSION: deleting a record with N versions is N DELETEs, each with its own id and tail block. armarium encrypts
every version under its own data key (wrapped by the claimant chain's key) and splits it into 2048-byte chunks itself. On a
claimant chain a DELETE destroys that version's key (`dek: "deleted"`); the encrypted bytes stay on the chain (`residual:
["ciphertext-on-chain"]`). We never write our own tombstone version.

Settings: ARMARIUM_URL (https), ARMARIUM_TOKEN_FILE (read for each call, sent only as the bearer token, never logged),
ARMARIUM_CA_FILE (optional), ARMARIUM_CASE (the 32-hex case the owners' chains are created under). With ARMARIUM_URL unset
nothing is written.

The claimant of an owner is created in the BACKGROUND (records.ndim_sync_all, the sealer's n-dim thread), never in a request:
ensure_chain() stores the chain durably (storage table ndim_chains, migration 005) and retries a failed create with backoff.
The row is keyed by owner_tag = HMAC(key, account), so the table never holds an account. from/to/ruleSet are derived from the
same key (owner_params) and carry no account either."""
import hashlib
import hmac
import json
import os
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request

TOKEN = re.compile(r"[\x21-\x7e]{1,4096}")
CHAIN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")  # a claimant id is 32 hex and may start with a digit
CASE = re.compile(r"^[0-9a-f]{32}$")
OBJ_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
ANSWER_MAX = 64 << 20
TIMEOUT_S = 30
CLAIMANT_TIMEOUT_S = 420  # the first create of a claimant waits for a disk and a node pod (armarium: up to 6 minutes)
BACKOFF_BASE_S = 30
BACKOFF_MAX_S = 3600
MAX_ATTEMPTS = 12  # transient failures of one step before it is "failed" (a configuration error fails at once)


class ArmariumError(Exception):
    """A call that did not do what was asked (HTTP status or transport); the message holds a code, never the token."""


class ArmariumConfigError(ArmariumError):
    """401 or 403: the token is missing, expired, or not bound to this case. Retrying cannot help; the operator fixes the Secret."""


class Gone(ArmariumError):
    """GET of a version whose key was deleted (410)."""


class ArmariumClient:
    """The interface. Objects are JSON objects; ids and blocks as armarium answers them."""

    def create_claimant(self, case, body):
        """-> {"id"}: a claimant chain under `case`; body is {from, to, ruleSet} (owner_params)"""
        raise NotImplementedError

    def create_object(self, chain, obj):
        """-> {"id", "block"}"""
        raise NotImplementedError

    def put_version(self, chain, obj_id, block, obj):
        """A new version after the version `obj_id` whose tail block is `block` -> {"id": the NEW version's id, "block": its
        block, "original_id"}"""
        raise NotImplementedError

    def delete_object(self, chain, obj_id, block):
        """Delete one version's key -> {"id", "dek": "deleted" | "on-chain" | "unknown", "residual": [...]}"""
        raise NotImplementedError

    def get_object(self, chain, obj_id):
        """-> the version's object; Gone when its key was deleted"""
        raise NotImplementedError


def owner_params(key, account):
    """{"tag", "body"} for one owner. tag = HMAC(key, account): the storage key, the account never stored with the chain. body is
    the claimant request: ids, addresses and ruleSet each an HMAC of the account under `key` with its own label, so armarium
    sees stable per-owner values that name no account and cannot be tied to the tag or to each other."""
    acct = account.encode("utf-8")

    def h(label, n):
        return hmac.new(key, label + b"\x00" + acct, hashlib.sha256).hexdigest()[:n]

    return {"tag": hmac.new(key, b"owner-tag\x00" + acct, hashlib.sha256).hexdigest(),
            "body": {"from": {"id": h(b"from-id", 32), "address": "0x" + h(b"from-address", 40)},
                     "to": {"id": h(b"to-id", 32), "address": "0x" + h(b"to-address", 40)},
                     "ruleSet": h(b"rule-set", 32)}}


def chain_for(storage, key, account):
    """The claimant id of this owner's chain, or None while it is not created (a request never creates it)."""
    row = storage.get_ndim_chain(owner_params(key, account)["tag"])
    return row["claimant_id"] if row and row["state"] == "ready" else None


def _backoff(attempts):
    return min(BACKOFF_MAX_S, BACKOFF_BASE_S * 2 ** max(0, attempts - 1))


def ensure_chain(storage, client, case, key, account, now):
    """One step of an owner's chain: create the row, and create the claimant unless it exists, is failed, or is backing off.
    Blocks for as long as the create takes (up to CLAIMANT_TIMEOUT_S): call it from the background only. -> the row."""
    from .storage import Conflict
    p = owner_params(key, account)
    row = storage.get_ndim_chain(p["tag"])
    if row is None:
        try:
            storage.put_ndim_chain({"owner_tag": p["tag"], "case_id": case, "claimant_id": None, "state": "pending", "attempts": 0,
                                    "next_try_at": 0, "last_error": None, "created_at": int(now), "updated_at": int(now)})
        except Conflict:
            pass
        row = storage.get_ndim_chain(p["tag"])
    if row["state"] != "pending" or row["next_try_at"] > now:
        return row
    attempts = row["attempts"] + 1
    try:
        got = client.create_claimant(case, p["body"])
    except ArmariumConfigError as e:
        storage.update_ndim_chain(p["tag"], state="failed", attempts=attempts, last_error=str(e)[:200], updated_at=int(now))
    except ArmariumError as e:
        if attempts >= MAX_ATTEMPTS:
            storage.update_ndim_chain(p["tag"], state="failed", attempts=attempts, last_error=f"gave up: {str(e)[:150]}",
                                      updated_at=int(now))
        else:
            storage.update_ndim_chain(p["tag"], attempts=attempts, next_try_at=int(now) + _backoff(attempts),
                                      last_error=str(e)[:200], updated_at=int(now))
    else:
        storage.update_ndim_chain(p["tag"], state="ready", claimant_id=got["id"], attempts=attempts, next_try_at=0,
                                  last_error=None, updated_at=int(now))
    return storage.get_ndim_chain(p["tag"])


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

    def _call(self, method, path, query=None, obj=None, timeout=TIMEOUT_S):
        token = _read_token(self.token_file)
        url = self.url + path + ("?" + urllib.parse.urlencode(query) if query else "")
        data = json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8") if obj is not None else None
        req = urllib.request.Request(url, data=data, method=method,
                                     headers={"Authorization": "Bearer " + token, "Content-Type": "application/json",
                                              "Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=self.ctx) as r:
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
        if status in (401, 403):
            raise ArmariumConfigError(f"configuration: armarium refused the token (http {status}); the token is missing, "
                                      "expired or not bound to this case")
        if status not in (200, 201):
            def word(k):
                return answer.get(k)[:40] if isinstance(answer, dict) and isinstance(answer.get(k), str) else ""
            raise ArmariumError(f"http {status} {word('error')} {word('status')} {word('step')}".replace("  ", " ").strip())
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
    def _block(a, key):
        v = a.get(key)
        if isinstance(v, int) and not isinstance(v, bool) and v >= 0:
            return v
        raise ArmariumError("bad answer: no block")

    @staticmethod
    def _id(a, key):
        v = a.get(key)
        if not isinstance(v, str) or not OBJ_ID.match(v):
            raise ArmariumError(f"bad answer: no {key}")
        return v

    def create_claimant(self, case, body):
        if not CASE.match(case or ""):
            raise ArmariumError("bad case")
        a = self._call("POST", f"/chain/{case}/claimant", obj=body, timeout=CLAIMANT_TIMEOUT_S)
        cid = a.get("id")
        if not isinstance(cid, str) or not CHAIN.match(cid):
            raise ArmariumError("bad answer: no claimant id")
        return {"id": cid}

    def create_object(self, chain, obj):
        a = self._call("POST", self._path(chain), obj=obj)
        return {"id": self._id(a, "correlation_id"), "block": self._block(a, "block")}

    def put_version(self, chain, obj_id, block, obj):
        a = self._call("PUT", self._path(chain, obj_id), {"block": int(block)}, obj)
        return {"id": self._id(a, "new_correlation_id"), "block": self._block(a, "new_block"),
                "original_id": self._id(a, "original_id")}

    def delete_object(self, chain, obj_id, block):
        a = self._call("DELETE", self._path(chain, obj_id), {"block": int(block)})
        dek = a.get("dek") if a.get("dek") in ("deleted", "on-chain") else "unknown"
        residual = [x for x in a.get("residual") or [] if isinstance(x, str) and re.match(r"^[a-z-]{1,40}$", x)]
        return {"id": obj_id, "dek": dek, "residual": residual}

    def get_object(self, chain, obj_id):
        return self._call("GET", self._path(chain, obj_id))


def from_env(env):
    """(client, case), or (None, None) when ARMARIUM_URL is unset or its token file is not mounted. ValueError on a bad setting."""
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
    case = (env.get("ARMARIUM_CASE") or "").strip()
    if not CASE.match(case):
        raise ValueError("ARMARIUM_CASE: the 32-hex case the owners' claimant chains are created under")
    ca_file = (env.get("ARMARIUM_CA_FILE") or "").strip() or None
    if ca_file and not os.path.exists(ca_file):
        ca_file = None  # an optional ConfigMap volume not created: the system's trust
    try:
        client = HttpArmarium(url, token_file, ca_file)
    except (OSError, ssl.SSLError):
        raise ValueError("ARMARIUM_CA_FILE: not a readable PEM CA certificate") from None
    return client, case
