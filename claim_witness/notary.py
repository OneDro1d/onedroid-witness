"""The armarium notary behind one interface (SPEC §2.5, §7.2): NotaryClient.seal(over_hex) -> the notary result object.

HttpNotary is the onedroid-audit client (onedroid-audit/notary.py, SITE-21) with this witness's settings:

    POST {WITNESS_NOTARY_URL}/notary/v1/seals   Authorization: Bearer <token from WITNESS_NOTARY_TOKEN_FILE>
         {"profile": "hash/1", "key": "<H(signed batch header) hex>",
          "payload": "<std base64 of {"label":"claim-witness/batch/1","over":"sha256:<hex>"}>"}
         200 every chain landed; 202 not yet (the same request repeated resumes it); 409 key_conflict

    result: {"status": "landed" | "failed" | "off", "profile", "over", "key",
             "anchors": [{chain, state, tx_hash, block, block_time, explorer_url, final}], "reason": null | "<code>: <text>"}

`final: false` on a landed chain (base-sepolia answers it at write time) means the transaction is written but not yet final on
that chain: status stays "landed" (a transaction exists), all_final() is false, and the sealer keeps the batch pending and asks
again, with the same key and the same bytes, on each tick until no anchor says false.

The key is the hash itself, so a repeat (a retry after a 202 or a later sealer tick) is the same request and armarium answers
the same transactions. A 202, 429, 5xx or no answer is repeated with the same bytes, at most MAX_ATTEMPTS times inside
WITNESS_NOTARY_TIMEOUT_S (60 s); a 409, any other 4xx, a 200 that is not every chain landed, or a certificate that does not
verify ends it at once. Own model key (C2): own_from_env builds the client for own batches, the same request with profile
WITNESS_NOTARY_OWN_PROFILE (hash/1-own; never hash/1) and WITNESS_NOTARY_OWN_TOKEN_FILE (required: never the public token). TLS is always verified (WITNESS_NOTARY_CA_FILE, else the system's trust). The token is read from its
file for each seal, sent only in the Authorization header, and never logged or returned; no free text from the notary is kept.
"""
import base64
import json
import math
import os
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

PROFILE = "hash/1"
OWN_PROFILE = "hash/1-own"  # own model key (C2): armarium's profile anchoring on lab-qbft only; WITNESS_NOTARY_OWN_PROFILE
OWN_CHAIN = "lab-qbft"  # the one chain an own batch may be anchored on
LABEL = "claim-witness/batch/1"  # hash/1's optional label: ^[A-Za-z0-9][A-Za-z0-9.:/_-]{0,63}$
SEALS_PATH = "/notary/v1/seals"
DEFAULT_TIMEOUT_S = 60.0
MAX_ATTEMPTS = 10
RETRY_S = 3.0
HTTP_TIMEOUT_S = 30.0
TOKEN = re.compile(r"[\x21-\x7e]{1,4096}")
HEX64 = re.compile(r"[0-9a-f]{64}")
TX_HASH = re.compile(r"0x[0-9a-fA-F]{64}")
IDENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
BLOCK_TIME = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]{8,20}(Z|[+-][0-9]{2}:[0-9]{2})")
EXPLORER = re.compile(r"https://[A-Za-z0-9.-]{1,253}(:[0-9]{1,5})?/[A-Za-z0-9/._~%?=&#:-]{0,300}")
IDENT_PROFILE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,63}")
ANSWER_MAX = 1 << 20
REASON_MAX = 400


class NotaryClient:
    """The interface: seal "sha256:<over_hex>" under the client's `profile` (hash/1, or for own batches the own profile) and
    return the result object; never raises for an answer."""

    profile = PROFILE

    def seal(self, over_hex):
        raise NotImplementedError


def off_result():
    return {"status": "off", "profile": None, "over": None, "key": None, "anchors": [], "reason": None}


class _Stop(Exception):
    pass


def read_token(path):
    try:
        with open(path, "rb") as fh:
            raw = fh.read(8192)
    except OSError:
        raise ValueError("WITNESS_NOTARY_TOKEN_FILE: cannot be read") from None
    try:
        token = raw.decode("ascii").strip()
    except UnicodeDecodeError:
        token = ""
    if not TOKEN.fullmatch(token):
        raise ValueError("WITNESS_NOTARY_TOKEN_FILE: not one token (printable ASCII, no spaces)")
    return token


def tls_context(ca_file):
    ctx = ssl.create_default_context(cafile=ca_file) if ca_file else ssl.create_default_context()
    if ctx.verify_mode != ssl.CERT_REQUIRED or not ctx.check_hostname:
        raise ValueError("the notary's TLS context does not verify")
    return ctx


def settings(env):
    """None (off) when WITNESS_NOTARY_TOKEN_FILE is unset; else {url, token_file, ca_file, timeout_s}. ValueError on a bad
    value: an https URL, a token file holding one token, a loadable CA file, a timeout above 0."""
    token_file = (env.get("WITNESS_NOTARY_TOKEN_FILE") or "").strip()
    if not token_file or not os.path.exists(token_file):
        return None  # unset, or an optional Secret volume not created yet: the notary is off
    url = (env.get("WITNESS_NOTARY_URL") or "").strip().rstrip("/")
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https" or not parts.hostname:
        raise ValueError("WITNESS_NOTARY_URL: an https:// URL (the token is never sent in clear)")
    read_token(token_file)
    ca_file = (env.get("WITNESS_NOTARY_CA_FILE") or "").strip() or None
    if ca_file and not os.path.exists(ca_file):
        ca_file = None  # an optional ConfigMap volume not created: the system's trust
    if ca_file:
        try:
            tls_context(ca_file)
        except (OSError, ssl.SSLError, ValueError):
            raise ValueError("WITNESS_NOTARY_CA_FILE: not a readable PEM CA certificate") from None
    raw = (env.get("WITNESS_NOTARY_TIMEOUT_S") or "").strip()
    timeout = DEFAULT_TIMEOUT_S
    if raw:
        try:
            timeout = float(raw)
        except ValueError:
            raise ValueError("WITNESS_NOTARY_TIMEOUT_S: not a number") from None
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("WITNESS_NOTARY_TIMEOUT_S: a number of seconds above 0")
    return {"url": url, "token_file": token_file, "ca_file": ca_file, "timeout_s": timeout}


def from_env(env):
    cfg = settings(env)
    return HttpNotary(cfg) if cfg else None


def own_settings(env):
    """Own model key (C2): the settings of the notary client for own batches, or None (own batches close unanchored).
    WITNESS_NOTARY_OWN_PROFILE: unset means hash/1-own; empty or "off" means no own profile; hash/1 (the public profile) is
    refused, so an own batch can never be sent with it. WITNESS_NOTARY_OWN_TOKEN_FILE: the token for it, required: unset,
    empty or not mounted means no own notary (DESIGN C2: own batches unanchored), never the public token. The URL, CA and
    timeout are the notary's."""
    raw = env.get("WITNESS_NOTARY_OWN_PROFILE")
    profile = OWN_PROFILE if raw is None else raw.strip()
    if profile in ("", "off"):
        return None
    if profile == PROFILE:
        raise ValueError("WITNESS_NOTARY_OWN_PROFILE: hash/1 anchors on a public chain; own batches never use it")
    if not IDENT_PROFILE.fullmatch(profile):
        raise ValueError("WITNESS_NOTARY_OWN_PROFILE: a profile name like hash/1-own")
    own_token = (env.get("WITNESS_NOTARY_OWN_TOKEN_FILE") or "").strip()
    if not own_token or not os.path.exists(own_token):
        return None
    cfg = settings(dict(env, WITNESS_NOTARY_TOKEN_FILE=own_token))
    if cfg is None:
        return None
    return dict(cfg, profile=profile)


def own_from_env(env):
    cfg = own_settings(env)
    return HttpNotary(cfg) if cfg else None


def all_final(result):
    """True when `result` landed and no anchor says final:false (an anchor without the field is not held back)."""
    if not isinstance(result, dict) or result.get("status") != "landed":
        return False
    anchors = result.get("anchors") or []
    return bool(anchors) and all(a.get("final") is not False for a in anchors)


def _anchor(e):
    e = e if isinstance(e, dict) else {}
    ref = e.get("ref") if isinstance(e.get("ref"), dict) else {}

    def ident(v):
        return v if isinstance(v, str) and IDENT.fullmatch(v) else None

    tx, block, url, bt = ref.get("tx_hash"), ref.get("block"), e.get("explorer_url"), e.get("block_time")
    return {"chain": ident(e.get("chain")), "state": ident(e.get("state")),
            "tx_hash": tx if isinstance(tx, str) and TX_HASH.fullmatch(tx) else None,
            "block": block if isinstance(block, int) and not isinstance(block, bool) and block >= 0 else None,
            "block_time": bt if isinstance(bt, str) and BLOCK_TIME.fullmatch(bt) else None,
            "explorer_url": url if isinstance(url, str) and EXPLORER.fullmatch(url) else None,
            "final": e.get("final") if isinstance(e.get("final"), bool) else None}


def _code(value):
    return value if isinstance(value, str) and IDENT.fullmatch(value) else "-"


def _states(anchors):
    return ", ".join(f"{a['chain']} {a['state']}" for a in anchors) or "no chain"


class HttpNotary(NotaryClient):
    def __init__(self, cfg, sleep=time.sleep, clock=time.monotonic):
        self.cfg, self.sleep, self.clock = cfg, sleep, clock
        self.profile = cfg.get("profile") or PROFILE

    def _clean(self, text, token):
        text = " ".join(str(text).split())
        if token:
            text = text.replace(token, "[token]")
        return text[:REASON_MAX]

    def seal(self, over_hex):
        if not isinstance(over_hex, str) or not HEX64.fullmatch(over_hex):
            raise ValueError("over is 64 lower-case hex")
        over, key = "sha256:" + over_hex, over_hex
        out = {"status": "failed", "profile": self.profile, "over": over, "key": key, "anchors": [], "reason": None}
        token = None
        try:
            token = read_token(self.cfg["token_file"])
        except ValueError as e:
            out["reason"] = f"token: {e}"
            return out
        payload = json.dumps({"label": LABEL, "over": over}, separators=(",", ":")).encode("ascii")
        body = json.dumps({"profile": self.profile, "key": key, "payload": base64.b64encode(payload).decode("ascii")},
                          separators=(",", ":")).encode("ascii")
        headers = {"Authorization": "Bearer " + token, "Content-Type": "application/json", "Accept": "application/json"}
        timeout = float(self.cfg.get("timeout_s") or DEFAULT_TIMEOUT_S)
        pause = min(RETRY_S, timeout / MAX_ATTEMPTS)
        end = self.clock() + timeout
        last, attempts = "nothing answered", 0
        try:
            try:
                ctx = tls_context(self.cfg.get("ca_file"))
            except (OSError, ssl.SSLError, ValueError):
                raise _Stop("tls: WITNESS_NOTARY_CA_FILE no longer loads") from None
            while True:
                attempts += 1
                status, data = self._post(body, headers, ctx, max(0.5, min(HTTP_TIMEOUT_S, end - self.clock())))
                if status is None:
                    last = data
                else:
                    answer = self._json(data)
                    anchors = [_anchor(e) for e in answer.get("anchors")] if isinstance(answer.get("anchors"), list) else []
                    if status == 200:
                        return self._landed(out, answer, anchors, key, token)
                    out["anchors"] = anchors
                    if status == 202:
                        last = f"202 ({_states(anchors)})"
                    elif status == 409:
                        raise _Stop("key_conflict: the key was already used for another payload; a repeat never lands")
                    elif status == 429 or status >= 500:
                        last = f"{status} {_code(answer.get('error'))}"
                    else:
                        raise _Stop(f"http_{status}: {_code(answer.get('error'))}")
                if attempts >= MAX_ATTEMPTS or self.clock() + pause >= end:
                    out["reason"] = self._clean(f"not_landed: {attempts} attempt(s) in {timeout:g} s; the last: {last}", token)
                    return out
                self.sleep(pause)
        except _Stop as e:
            out["reason"] = self._clean(str(e), token)
            return out
        except Exception as e:  # noqa: BLE001 - a notary failure never fails the sealer
            out["reason"] = self._clean(f"error: {type(e).__name__}", token)
            return out

    def _post(self, body, headers, ctx, timeout):
        req = urllib.request.Request(self.cfg["url"] + SEALS_PATH, data=body, method="POST", headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                return resp.status, resp.read(ANSWER_MAX)
        except urllib.error.HTTPError as e:
            try:
                return e.code, e.read(ANSWER_MAX)
            finally:
                e.close()
        except urllib.error.URLError as e:
            if isinstance(e.reason, ssl.SSLError):
                raise _Stop(f"tls: the notary's certificate did not verify ({type(e.reason).__name__})") from None
            return None, f"unreachable ({type(e.reason).__name__})"
        except ssl.SSLError as e:
            raise _Stop(f"tls: the notary's certificate did not verify ({type(e).__name__})") from None
        except (OSError, TimeoutError) as e:
            return None, f"unreachable ({type(e).__name__})"

    @staticmethod
    def _json(data):
        try:
            value = json.loads(data)
        except ValueError:
            return {}
        return value if isinstance(value, dict) else {}

    def _landed(self, out, answer, anchors, key, token):
        out["anchors"] = anchors
        if answer.get("key") != key or answer.get("profile") != self.profile:
            out["reason"] = "bad_answer: the 200 is not for this key and profile"
        elif not anchors:
            out["reason"] = "bad_answer: the 200 names no chain"
        elif not all(a["chain"] and a["state"] == "landed" and a["tx_hash"] and a["block"] is not None for a in anchors):
            out["reason"] = self._clean(f"bad_answer: the 200 is not every chain landed with a transaction ({_states(anchors)})",
                                        token)
        else:
            out["status"] = "landed"
        return out
