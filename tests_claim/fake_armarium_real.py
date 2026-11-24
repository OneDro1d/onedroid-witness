"""Fakes that mimic armarium's REAL answers as the loom-armarium session reported them (24 Nov 2026, ARMARIUM.md; armarium PR #78
README and scripts/objects-roundtrip.sh), as local HTTPS servers. Differences from the B3 fakes in fake_seal.py, each one a fact
of the real service:

object service
- one claimant chain per owner: POST /chain/<case>/claimant {from, to, ruleSet} answers 201 {"id": <32 hex>, "level":
  "claimant"}; the id can start with a digit; the first create is slow (`claimant_delay_s`); a second create of the same body
  is a new claimant (no idempotency is assumed);
- POST /chain/<cid>/object answers 200 {"correlation_id", "block"};
- PUT /chain/<cid>/object/<id>?block=<tail> answers 200 {"new_correlation_id", "new_block", "original_id"} (names differ from POST);
- every version has its own id, block and key: GET /chain/<cid>/object/<version id> reads that version;
- DELETE /chain/<cid>/object/<version id>?block=<its tail> answers 200 {"dek": "deleted", "residual": ["ciphertext-on-chain"],
  "message": ...} (no block field); the same version then reads 410 {"status": "deleted"}; earlier versions still read 200;
  `incomplete_once` makes the first DELETE of a version answer 409 {"status": "incomplete"} (retry the same DELETE);
- no token 401; a chain outside the token's case 403 (also a chain this fake never created under the case);
notary
- POST /notary/v1/seals answers 200 with every chain landed and `final` per chain: lab-qbft final true, base-sepolia final false
  until `finalize()` is called (the same request then answers final true), the key and profile echoed; the payload must be the
  base64 of a JSON object {"over": "sha256:<hex>", "label"?: ...} and nothing else."""
import base64
import hashlib
import http.server
import json
import pathlib
import re
import ssl
import tempfile
import threading
import time
import urllib.parse

from tests_claim.fake_seal import _Server


class HttpsFake:
    """As fake_seal.HttpsFake, plus `public` paths that need no token (the notary's verify route)."""

    TOKEN = "fake-armarium-token-0123456789"
    public = ()

    def __init__(self, tls):
        ca, cert, key = tls
        self.ca_file, self.requests = ca, []
        outer = self

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _do(self):
                n = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(n) if n else b""
                u = urllib.parse.urlsplit(self.path)
                outer.requests.append({"method": self.command, "path": u.path, "query": u.query,
                                       "auth": self.headers.get("Authorization"), "body": body})
                if u.path not in outer.public and self.headers.get("Authorization") != "Bearer " + outer.TOKEN:
                    status, obj = 401, {"error": "unauthorized"}
                else:
                    status, obj = outer.handle(self.command, u.path, urllib.parse.parse_qs(u.query), body)
                data = json.dumps(obj).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_GET = do_POST = do_PUT = do_DELETE = _do

        self.server = _Server(("127.0.0.1", 0), H)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        self.server.socket = ctx.wrap_socket(self.server.socket, server_side=True)
        self.url = f"https://127.0.0.1:{self.server.server_address[1]}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.token_file = str(pathlib.Path(tempfile.mkdtemp(prefix="cw-tok-")) / "token")
        pathlib.Path(self.token_file).write_text(self.TOKEN + "\n")

    def close(self):
        self.server.shutdown()
        self.server.server_close()


CASE = "1e59334fee73fc758f793ce01c3cdd00"
HEX32 = re.compile(r"^[0-9a-f]{32}$")
ADDR = re.compile(r"^0x[0-9a-f]{40}$")


class RealObjects(HttpsFake):
    def __init__(self, tls, first_claimant_id_with_digit=True):
        self.claimants, self.versions, self.block, self.n = {}, {}, 100, 0
        self.claimant_delay_s, self.claimant_status, self.object_status = 0.0, None, None
        self.incomplete_once, self._incomplete_done = False, set()
        self.digit_ids = first_claimant_id_with_digit
        self.lock = threading.Lock()
        super().__init__(tls)

    def next_id(self, label):
        self.n += 1
        raw = hashlib.sha256(f"{label}|{self.n}".encode()).hexdigest()[:32]
        return ("7" + raw[1:]) if self.digit_ids else ("a" + raw[1:])

    def next_block(self):
        self.block += 1
        return self.block

    def calls(self, method=None, kind=None):
        """Recorded requests, optionally of one method and one route kind (claimant, object)."""
        out = []
        for r in self.requests:
            if method and r["method"] != method:
                continue
            if kind == "claimant" and not r["path"].endswith("/claimant"):
                continue
            if kind == "object" and "/object" not in r["path"]:
                continue
            out.append(r)
        return out

    def handle(self, method, path, q, body):
        parts = path.strip("/").split("/")
        if len(parts) < 3 or parts[0] != "chain":
            return 404, {"error": "not_found"}
        chain = parts[1]
        if parts[2] == "claimant" and method == "POST" and len(parts) == 3:
            if chain != CASE:
                return 403, {"error": "outside_bind"}
            if self.claimant_status:
                return self.claimant_status, {"error": "fake_failure"}
            doc = json.loads(body)
            ok = (set(doc) == {"from", "to", "ruleSet"} and HEX32.match(doc["ruleSet"])
                  and all(set(doc[k]) == {"id", "address"} and HEX32.match(doc[k]["id"]) and ADDR.match(doc[k]["address"])
                          for k in ("from", "to")))
            if not ok:
                return 422, {"error": "bad_claimant"}
            if self.claimant_delay_s:
                time.sleep(self.claimant_delay_s)
            with self.lock:
                cid = self.next_id("claimant")
                self.claimants[cid] = doc
                self.versions[cid] = {}
            return 201, {"id": cid, "level": "claimant", "keyScheme": "akv1"}
        if parts[2] != "object" or chain not in self.claimants:
            return 403, {"error": "outside_bind"}
        if self.object_status:
            return self.object_status, {"error": "fake_failure"}
        vs = self.versions[chain]
        if method == "POST" and len(parts) == 3:
            with self.lock:
                oid = self.next_id("object")
                blk = self.next_block()
                vs[oid] = {"doc": json.loads(body), "block": blk, "deleted": False, "original": oid}
            return 200, {"correlation_id": oid, "block": blk}
        if len(parts) != 4 or parts[3] not in vs:
            return 404, {"error": "not_found"}
        v = vs[parts[3]]
        if method == "GET":
            if v["deleted"]:
                return 410, {"status": "deleted"}
            return 200, v["doc"]
        if "block" not in q or int(q["block"][0]) != v["block"]:
            return 400, {"error": "block_must_be_the_tail_of_this_version"}
        if method == "PUT":
            if v["deleted"]:
                return 410, {"status": "deleted"}
            with self.lock:
                nid, blk = self.next_id("version"), self.next_block()
                vs[nid] = {"doc": json.loads(body), "block": blk, "deleted": False, "original": v["original"]}
            return 200, {"new_correlation_id": nid, "new_block": blk, "original_id": v["original"]}
        if method == "DELETE":
            if self.incomplete_once and parts[3] not in self._incomplete_done:
                self._incomplete_done.add(parts[3])
                return 409, {"status": "incomplete"}
            v["deleted"] = True
            return 200, {"dek": "deleted", "residual": ["ciphertext-on-chain"],
                         "message": "the key for this version is deleted; the encrypted bytes stay on the chain; this is not erasure"}
        return 405, {"error": "method"}


class RealNotary(HttpsFake):
    public = ("/notary/v1/verify",)

    def __init__(self, tls):
        self.base_final, self.status_override = False, None
        super().__init__(tls)

    def finalize(self):
        self.base_final = True

    def handle(self, method, path, q, body):
        if method == "POST" and path == "/notary/v1/verify":
            req = json.loads(body)
            ok = (set(req) == {"over", "chain", "tx_hash"} and re.fullmatch(r"sha256:[0-9a-f]{64}", req["over"])
                  and req["chain"] in ("lab-qbft", "base-sepolia"))
            return (200, {"verdict": "VERIFIED", "chain": req["chain"]}) if ok else (422, {"verdict": "REFUSED"})
        if method != "POST" or path != "/notary/v1/seals":
            return 404, {"error": "not_found"}
        req = json.loads(body)
        if set(req) != {"profile", "key", "payload"} or req["profile"] != "hash/1":
            return 400, {"error": "bad_request"}
        payload = json.loads(base64.b64decode(req["payload"], validate=True))
        over_ok = isinstance(payload.get("over"), str) and re.fullmatch(r"sha256:[0-9a-f]{64}", payload["over"])
        label_ok = "label" not in payload or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.:/_-]{0,63}", str(payload["label"]))
        if not over_ok or not label_ok or set(payload) - {"over", "label"}:
            return 422, {"error": "payload_rule"}
        anchors = []
        for chain, final, blk in (("lab-qbft", True, 66059), ("base-sepolia", self.base_final, 63163025)):
            tx = "0x" + hashlib.sha256((chain + req["key"]).encode()).hexdigest()
            anchors.append({"chain": chain, "state": "landed", "final": final,
                            "ref": {"chain": chain, "correlation_id": "c-" + chain, "block": blk, "tx_hash": tx},
                            "signer": "0x" + "1" * 40, "block_time": "2026-11-24T21:07:00Z"})
        return self.status_override or 200, {"profile": req["profile"], "key": req["key"], "anchors": anchors}
