"""The signer sidecar (ARCHITECTURE §2 and TB4, SPEC §7.1 and §7.4): the only process holding the witness key.

- It listens on a Unix socket whose path comes from WITNESS_SIGNER_SOCKET only; it has no network listener.
- A request is one JSON line {"op": "sign", "predicateType", "payload"} (or {"op": "info"}); the answer is one JSON line.
- It signs only claim, observation and batch-header payloads that pass their schema (schemas.py), with this witness's id,
  its own key id and the current key list's sequence number, and a time within 300 s of its clock.
- Every signature is appended to the signing log (seq, payload id, predicateType, time) before the answer goes back.
- Key lists are signed only by the operator command (`python -m claim_witness signer keylist init|rotate`), run inside the
  container, with the outgoing and the incoming key; they are logged too.
"""
import argparse
import base64
import calendar
import json
import os
import socketserver
import stat
import sys
import threading
import time

from . import crypto, dsse, ids, jcs, schemas
from .schemas import BATCH_TYPE, CLAIM_TYPE, KEYLIST_TYPE, OBSERVATION_TYPE
from .storage import TIERS

BATCH_PAYLOAD_TYPE = "application/vnd.onedroid.witness.batch-header+json"
MAX_REQUEST = 8 << 20
TIME_SKEW = 300


class Refused(Exception):
    pass


class SignerUnavailable(Exception):
    pass


def iso(t):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(int(t)))


def parse_iso(s):
    return calendar.timegm(time.strptime(s, "%Y-%m-%dT%H:%M:%SZ"))


def read_seed(path):
    """A 32-byte Ed25519 seed from a file: standard base64 of 32 bytes (or of 64 bytes seed||public), or the raw bytes."""
    with open(path, "rb") as f:
        data = f.read()
    try:
        raw = base64.b64decode(data.strip(), validate=True)
    except ValueError:
        raw = data
    if len(raw) == 64:
        raw = raw[:32]
    if len(raw) != 32:
        raise SystemExit(f"{path}: not an Ed25519 seed (32 bytes, base64 or raw)")
    return raw


# --------------------------------------------------------------------------------------------------------------------- key lists


def _keylist_envelope(storage, predicate, signers, now):
    stmt = {"_type": dsse.STATEMENT_TYPE, "subject": [{"name": "key-list", "digest": {"sha256": ids.sha256_hex(jcs.canonical(predicate))}}],
            "predicateType": KEYLIST_TYPE, "predicate": predicate}
    raw = jcs.canonical(stmt)
    env = dsse.sign(raw, signers)
    storage.put_key_list(predicate["seq"], env, ids.sha256_hex(raw), now)
    storage.append_signing_log(ids.record_id(raw), KEYLIST_TYPE, now, leaf=ids.leaf_hash(raw))
    return env


def _predicate_of(env):
    return json.loads(dsse.payload_bytes(env))["predicate"]


def keylist_init(storage, seed, key_id, witness_id, clock=time.time, batch_interval_s=3600):
    """Key list 1, signed by its one key. Refused (SystemExit) when a key list exists."""
    if storage.latest_key_list() is not None:
        raise SystemExit("a key list exists already: use `keylist rotate`")
    now = int(clock())
    pred = {"witness": witness_id, "seq": 1,
            "keys": [{"key_id": key_id, "alg": "ed25519", "public": base64.b64encode(crypto.ed25519_public(seed)).decode(),
                      "valid_from": iso(now), "valid_to": None, "revoked_at": None, "revoke_reason": None}],
            "sealers": [], "batch_interval_s": int(batch_interval_s)}
    return _keylist_envelope(storage, pred, [(key_id, seed)], now)


def keylist_rotate(storage, out_seed, out_key_id, in_seed, in_key_id, witness_id, clock=time.time, revoke_reason=None):
    """Key list n+1: the outgoing key ends (valid_to now; revoked_at now with a reason when revoking), the incoming key
    starts. Signed by both (SPEC §7.4)."""
    latest = storage.latest_key_list()
    if latest is None:
        raise SystemExit("no key list yet: use `keylist init`")
    prev = _predicate_of(latest["envelope"])
    if prev["witness"] != witness_id:
        raise SystemExit(f"the current key list is for {prev['witness']}, not {witness_id}")
    keys = [dict(k) for k in prev["keys"]]
    by_id = {k["key_id"]: k for k in keys}
    out = by_id.get(out_key_id)
    out_pub = base64.b64encode(crypto.ed25519_public(out_seed)).decode()
    if out is None or out["public"] != out_pub or out.get("revoked_at") or out.get("valid_to"):
        raise SystemExit(f"{out_key_id}: not the current key of this list, or the key file does not hold it")
    if in_key_id in by_id:
        raise SystemExit(f"{in_key_id}: already in the key list")
    now = int(clock())
    out["valid_to"] = iso(now)
    if revoke_reason:
        out["revoked_at"], out["revoke_reason"] = iso(now), str(revoke_reason)
    keys.append({"key_id": in_key_id, "alg": "ed25519", "public": base64.b64encode(crypto.ed25519_public(in_seed)).decode(),
                 "valid_from": iso(now), "valid_to": None, "revoked_at": None, "revoke_reason": None})
    pred = dict(prev, seq=prev["seq"] + 1, keys=keys)
    return _keylist_envelope(storage, pred, [(out_key_id, out_seed), (in_key_id, in_seed)], now)


# --------------------------------------------------------------------------------------------------------------------- the core


class SignerCore:
    def __init__(self, seed, key_id, witness_id, storage, clock=time.time):
        self.seed, self.key_id, self.witness_id, self.storage, self.clock = seed, key_id, witness_id, storage, clock
        self.public = crypto.ed25519_public(seed)
        self.lock = threading.Lock()
        self.seq = self._current_seq()

    def _current_seq(self):
        latest = self.storage.latest_key_list()
        if latest is None:
            raise SystemExit("no key list: run `python -m claim_witness signer keylist init` first")
        pred = _predicate_of(latest["envelope"])
        k = {x["key_id"]: x for x in pred["keys"]}.get(self.key_id)
        if pred["witness"] != self.witness_id or k is None or k["public"] != base64.b64encode(self.public).decode() \
                or k.get("valid_to") or k.get("revoked_at"):
            raise SystemExit(f"key {self.key_id} is not the current key of {self.witness_id}'s key list {pred['seq']}")
        return pred["seq"]

    def info(self):
        return {"witness_id": self.witness_id, "key_id": self.key_id, "key_list_seq": self.seq,
                "public": base64.b64encode(self.public).decode()}

    def sign(self, predicate_type, payload, tier="public"):
        """Sign and append to the signing log under `tier` (own model key, C2): "own" for what is signed while serving an
        own-key request, else "public". A batch header's `anchoring` must be its tier (absent = public)."""
        if tier not in TIERS:
            raise Refused(f"tier: one of {list(TIERS)}")
        if predicate_type == BATCH_TYPE and isinstance(payload, dict) and payload.get("anchoring", "public") != tier:
            raise Refused(f"a batch header with anchoring {payload.get('anchoring', 'public')!r} is signed in tier "
                          f"{payload.get('anchoring', 'public')!r} only, not {tier!r}")
        with self.lock:
            try:
                self.seq = self._current_seq()
            except SystemExit as e:
                raise Refused(str(e)) from None
            witness = {"id": self.witness_id, "key_id": self.key_id, "key_list_seq": self.seq}
            try:
                schemas.check(predicate_type, payload, witness)
            except schemas.SchemaError as e:
                raise Refused(str(e)) from None
            now = int(self.clock())
            if predicate_type in (CLAIM_TYPE, OBSERVATION_TYPE):
                p = payload["predicate"]
                t = p.get("witnessed_at") if predicate_type == CLAIM_TYPE else p.get("fetched_at")
                if abs(parse_iso(t) - now) > TIME_SKEW:
                    raise Refused(f"the payload's time {t} is more than {TIME_SKEW} s from the signer's clock")
            raw = jcs.canonical(payload)
            pid = ids.record_id(raw)
            if predicate_type == BATCH_TYPE:
                sig = crypto.ed25519_sign(self.seed, dsse.pae(BATCH_PAYLOAD_TYPE, raw))
                seq = self.storage.append_signing_log(pid, predicate_type, now, leaf=ids.leaf_hash(raw), tier=tier)
                return {"keyid": self.key_id, "sig": base64.b64encode(sig).decode(), "payload_id": pid, "log_seq": seq,
                        "payloadType": BATCH_PAYLOAD_TYPE, "tier": tier}
            env = dsse.sign(raw, [(self.key_id, self.seed)])
            seq = self.storage.append_signing_log(pid, predicate_type, now, leaf=ids.leaf_hash(raw), tier=tier)
            return {"envelope": env, "payload_id": pid, "log_seq": seq, "tier": tier}

    def handle(self, req):
        """One request object to one answer object (the socket protocol)."""
        if not isinstance(req, dict):
            return {"error": "bad-request", "detail": "a JSON object"}
        op = req.get("op", "sign")
        if op == "info":
            return self.info()
        if op != "sign":
            return {"error": "bad-request", "detail": f"unknown op {op!r}"}
        try:
            return self.sign(req.get("predicateType"), req.get("payload"), req.get("tier", "public"))
        except Refused as e:
            return {"error": "refused", "detail": str(e)}


class LocalSignerClient:
    """The client interface over an in-process core (tests); answers pass through JSON as they would over the socket."""

    def __init__(self, core):
        self.core = core

    def _call(self, req):
        out = json.loads(json.dumps(self.core.handle(json.loads(json.dumps(req)))))
        if out.get("error") == "refused":
            raise Refused(out.get("detail"))
        if "error" in out:
            raise SignerUnavailable(out.get("detail"))
        return out

    def info(self):
        return self._call({"op": "info"})

    def sign(self, predicate_type, payload, tier="public"):
        req = {"op": "sign", "predicateType": predicate_type, "payload": payload}
        if tier != "public":
            req["tier"] = tier
        out = self._call(req)
        if out.get("tier", "public") != tier:  # a signer that does not know tiers logged the row as public: never pass it off
            raise SignerUnavailable(f"the signer logged tier {out.get('tier', 'public')!r}, not {tier!r}")
        return out


class SocketSignerClient(LocalSignerClient):
    TIMEOUT = 10

    def __init__(self, path):
        self.path = path

    def _call(self, req):
        import socket
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                s.settimeout(self.TIMEOUT)
                s.connect(self.path)
                s.sendall(json.dumps(req).encode("utf-8") + b"\n")
                buf = b""
                while not buf.endswith(b"\n"):
                    chunk = s.recv(65536)
                    if not chunk:
                        break
                    buf += chunk
        except OSError as e:
            raise SignerUnavailable(f"the signer socket does not answer: {type(e).__name__}") from None
        try:
            out = json.loads(buf)
        except ValueError:
            raise SignerUnavailable("the signer's answer is not JSON") from None
        if out.get("error") == "refused":
            raise Refused(out.get("detail"))
        if "error" in out:
            raise SignerUnavailable(out.get("detail"))
        return out


# --------------------------------------------------------------------------------------------------------------------- the socket


class _Handler(socketserver.StreamRequestHandler):
    def handle(self):
        line = self.rfile.readline(MAX_REQUEST + 1)
        if len(line) > MAX_REQUEST:
            out = {"error": "bad-request", "detail": "request too large"}
        else:
            try:
                out = self.server.core.handle(json.loads(line))
            except ValueError:
                out = {"error": "bad-request", "detail": "not JSON"}
        self.wfile.write(json.dumps(out).encode("utf-8") + b"\n")


class _Server(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True


def make_socket_server(path, core):
    if os.path.exists(path):
        if not stat.S_ISSOCK(os.stat(path).st_mode):
            raise SystemExit(f"{path} exists and is not a socket")
        os.unlink(path)
    old = os.umask(0o117)
    try:
        srv = _Server(path, _Handler)
    finally:
        os.umask(old)
    os.chmod(path, 0o660)
    srv.core = core
    return srv


def socket_path_from_env(env):
    path = (env.get("WITNESS_SIGNER_SOCKET") or "").strip()
    if not path:
        raise SystemExit("WITNESS_SIGNER_SOCKET: the signer's Unix socket path is required")
    if not path.startswith("/"):
        raise SystemExit("WITNESS_SIGNER_SOCKET: an absolute filesystem path (the signer has no network listener)")
    return path


# --------------------------------------------------------------------------------------------------------------------- CLI


def main(argv, env=None):
    from . import storage as storage_mod
    env = dict(os.environ) if env is None else env
    ap = argparse.ArgumentParser(prog="claim_witness signer")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("serve", help="serve the Unix socket (env: WITNESS_SIGNER_SOCKET, WITNESS_SIGNING_KEY_FILE, WITNESS_KEY_ID, WITNESS_ID)")
    kl = sub.add_parser("keylist", help="operator commands: sign a new key list")
    ks = kl.add_subparsers(dest="kcmd", required=True)
    i = ks.add_parser("init")
    i.add_argument("--key-file", required=True)
    i.add_argument("--key-id", required=True)
    i.add_argument("--batch-interval-s", type=int, default=3600)
    r = ks.add_parser("rotate")
    r.add_argument("--outgoing-key-file", required=True)
    r.add_argument("--outgoing-key-id", required=True)
    r.add_argument("--incoming-key-file", required=True)
    r.add_argument("--incoming-key-id", required=True)
    r.add_argument("--revoke", metavar="REASON", help="also revoke the outgoing key, with this reason")
    ks.add_parser("show")
    a = ap.parse_args(argv)
    witness_id = env.get("WITNESS_ID") or "witness:onedroid"
    st = storage_mod.from_env(env)

    def say(env_):
        pred = _predicate_of(env_)
        signers = ", ".join(s["keyid"] for s in env_["signatures"])
        print(f"key list seq {pred['seq']} of {pred['witness']} signed by {signers}; "
              f"sha256 {ids.sha256_hex(dsse.payload_bytes(env_))}", flush=True)

    if a.cmd == "keylist":
        if a.kcmd == "init":
            say(keylist_init(st, read_seed(a.key_file), a.key_id, witness_id, batch_interval_s=a.batch_interval_s))
        elif a.kcmd == "rotate":
            say(keylist_rotate(st, read_seed(a.outgoing_key_file), a.outgoing_key_id, read_seed(a.incoming_key_file),
                               a.incoming_key_id, witness_id, revoke_reason=a.revoke))
        else:
            latest = st.latest_key_list()
            if latest is None:
                print("no key list", flush=True)
                return 1
            print(json.dumps(latest["envelope"]), flush=True)
        return 0
    path = socket_path_from_env(env)
    key_file = (env.get("WITNESS_SIGNING_KEY_FILE") or "").strip()
    key_id = (env.get("WITNESS_KEY_ID") or "").strip()
    if not key_file or not key_id:
        raise SystemExit("WITNESS_SIGNING_KEY_FILE and WITNESS_KEY_ID are required")
    seed = read_seed(key_file)
    if env.get("WITNESS_SIGNER_BOOTSTRAP") == "1" and st.latest_key_list() is None:
        say(keylist_init(st, seed, key_id, witness_id, batch_interval_s=int(env.get("WITNESS_BATCH_INTERVAL_S") or 3600)))
    core = SignerCore(seed, key_id, witness_id, st)
    srv = make_socket_server(path, core)
    print(f"signer: {witness_id} key {key_id}, key list {core.seq}, on {path}", flush=True)
    try:
        srv.serve_forever()
    finally:
        srv.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
