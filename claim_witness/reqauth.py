"""Caller authentication (SPEC §3, BD8).

onedroid-req/1: the caller signs the line `onedroid-req/1 <service> <METHOD> <path> sha256:<hex of body> <unix time>` as an
SSH signature (SSHSIG, namespace onedroid-req) with an Ed25519 key from a published key list, and sends the headers
X-Store-Key (key id), X-Store-Time and X-Store-Signature (standard base64 of the armored signature). The time must be within
300 s. This is the scheme onedroid_witness/respsign.py (StoreKeys, CallerKeys) verifies with ssh-keygen; here it is ported to
Python with `cryptography`, so the witness needs no ssh-keygen. The key list is fetched from a URL (WITNESS_CALLER_KEYS_URL),
in the audit service's shape {"service", "keys": [{key_id, public_key (std base64 of 32 bytes), state?}]}, cached 60 s,
refetched for an unknown key at most every 2 s, and refused when older than 300 s.
"""
import base64
import hashlib
import json
import re
import threading
import time
import urllib.request

from . import crypto

REQ_NAMESPACE = "onedroid-req"
MAGIC = b"SSHSIG"
KID = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
TS = re.compile(r"^[0-9]{1,12}$")
ACCOUNT = re.compile(r"^[A-Za-z0-9_.:@-]{1,128}$")


class KeyServiceUnavailable(Exception):
    pass


def _s(b):
    return len(b).to_bytes(4, "big") + b


def _read(buf, i):
    n = int.from_bytes(buf[i:i + 4], "big")
    if i + 4 + n > len(buf):
        raise ValueError("truncated")
    return buf[i + 4:i + 4 + n], i + 4 + n


def _signed_data(namespace, hash_alg, message):
    h = hashlib.new(hash_alg, message).digest()
    return MAGIC + _s(namespace.encode()) + _s(b"") + _s(hash_alg.encode()) + _s(h)


def sshsig_sign(seed, namespace, message, hash_alg="sha512"):
    """An armored SSHSIG (as `ssh-keygen -Y sign -n <namespace>` makes) over message with an Ed25519 seed."""
    pub = crypto.ed25519_public(seed)
    sig = crypto.ed25519_sign(seed, _signed_data(namespace, hash_alg, message))
    blob = (MAGIC + (1).to_bytes(4, "big") + _s(_s(b"ssh-ed25519") + _s(pub)) + _s(namespace.encode()) + _s(b"") +
            _s(hash_alg.encode()) + _s(_s(b"ssh-ed25519") + _s(sig)))
    b64 = base64.b64encode(blob).decode()
    lines = [b64[i:i + 70] for i in range(0, len(b64), 70)]
    return ("-----BEGIN SSH SIGNATURE-----\n" + "\n".join(lines) + "\n-----END SSH SIGNATURE-----\n").encode()


def sshsig_verify(public, armored, namespace, message):
    try:
        text = armored.decode("ascii").strip()
        if not (text.startswith("-----BEGIN SSH SIGNATURE-----") and text.endswith("-----END SSH SIGNATURE-----")):
            return False
        body = "".join(text.splitlines()[1:-1])
        blob = base64.b64decode(body, validate=True)
        if blob[:6] != MAGIC or int.from_bytes(blob[6:10], "big") != 1:
            return False
        i = 10
        pk, i = _read(blob, i)
        ns, i = _read(blob, i)
        _reserved, i = _read(blob, i)
        alg, i = _read(blob, i)
        sigblob, i = _read(blob, i)
        kt, j = _read(pk, 0)
        raw_pub, _ = _read(pk, j)
        st, j = _read(sigblob, 0)
        sig, _ = _read(sigblob, j)
        if kt != b"ssh-ed25519" or st != b"ssh-ed25519" or raw_pub != public or ns != namespace.encode():
            return False
        if alg not in (b"sha256", b"sha512"):
            return False
        return crypto.ed25519_verify(public, sig, _signed_data(namespace, alg.decode(), message))
    except (ValueError, UnicodeDecodeError, IndexError):
        return False


class CallerKeys:
    TTL, STALE, UNKNOWN_GAP, FAIL_GAP, WINDOW = 60, 300, 2, 2, 300
    FETCH_TIMEOUT, MAX_LIST, MAX_SIG = 5, 1 << 20, 4096

    def __init__(self, url, service="claim-witness", fetch=None, clock=None, log=None):
        self.url, self.service, self.clock = url, service, clock or time.time
        self.fetch = fetch or self._http_fetch
        self.log = log or (lambda line: None)
        self.lock = threading.Lock()
        self.keys, self.fetched_at, self.last_fail, self.last_unknown = {}, None, None, None
        with self.lock:
            self._load(self.clock())

    def _http_fetch(self):
        req = urllib.request.Request(self.url, headers={"accept": "application/json"})
        with urllib.request.urlopen(req, timeout=self.FETCH_TIMEOUT) as resp:
            data = resp.read(self.MAX_LIST + 1)
        if len(data) > self.MAX_LIST:
            raise ValueError("list too large")
        return data

    def _load(self, now):
        try:
            doc = json.loads(self.fetch())
            keys = {}
            for e in doc["keys"]:
                kid = e.get("key_id")
                if not isinstance(kid, str) or not KID.match(kid) or e.get("state", "active") != "active":
                    continue
                raw = base64.b64decode(e.get("public_key") or "", validate=True)
                if len(raw) == 32:
                    keys[kid] = {"raw": raw, "owner": doc.get("service") or "caller"}
        except Exception as exc:  # noqa: BLE001 - any failure is "the list is not there"
            self.last_fail = now
            self.log(f"caller key list fetch failed: {type(exc).__name__}")
            return False
        self.keys, self.fetched_at, self.last_fail = keys, now, None
        return True

    def _entry(self, kid, now):
        with self.lock:
            if self.last_fail is None or now - self.last_fail >= self.FAIL_GAP:
                if self.fetched_at is None or now - self.fetched_at > self.TTL:
                    self._load(now)
                elif kid not in self.keys and (self.last_unknown is None or now - self.last_unknown >= self.UNKNOWN_GAP):
                    self.last_unknown = now
                    self._load(now)
            if self.fetched_at is None or now - self.fetched_at > self.STALE:
                raise KeyServiceUnavailable("no good caller key list")
            return self.keys.get(kid)

    def verify_request(self, method, path, body, headers):
        """{"key_id", "owner"} for a good onedroid-req/1 signature, else None (KeyServiceUnavailable with no key list)."""
        kid, ts, sig = (headers.get(h) for h in ("X-Store-Key", "X-Store-Time", "X-Store-Signature"))
        if not (isinstance(kid, str) and isinstance(ts, str) and isinstance(sig, str)):
            return None
        if not KID.match(kid) or not TS.match(ts) or not 0 < len(sig) <= 2 * self.MAX_SIG:
            return None
        try:
            armored = base64.b64decode(sig, validate=True)
        except ValueError:
            return None
        now = self.clock()
        if abs(now - int(ts)) > self.WINDOW:
            return None
        entry = self._entry(kid, now)
        if entry is None:
            return None
        line = f"onedroid-req/1 {self.service} {method} {path} sha256:{hashlib.sha256(body).hexdigest()} {ts}"
        if not sshsig_verify(entry["raw"], armored, REQ_NAMESPACE, line.encode("utf-8")):
            return None
        return {"key_id": kid, "owner": entry["owner"]}
