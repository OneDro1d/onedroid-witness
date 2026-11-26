"""Fakes for slice B3: the armarium notary and armarium's n-dim objects, in memory (the NotaryClient and ArmariumClient
interfaces), and the notary as a local HTTPS server (a throwaway CA and a 127.0.0.1 certificate made with `cryptography`). The
HTTPS fakes of armarium's REAL answers, object service included, are in fake_armarium_real.py (B3W). Nothing here talks to a
real armarium."""
import base64
import datetime
import hashlib
import http.server
import json
import pathlib
import ssl
import tempfile
import threading
import time
import urllib.parse


def _iso(t):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(int(t)))


class FakeNotary:
    """NotaryClient: seal(over_hex) -> the notary result object (onedroid-audit notary.py shape). `fail` makes the next seals
    fail; `delay_s` sets block_time that many seconds after the clock."""

    def __init__(self, clock=time.time, chain="base-sepolia", delay_s=60, final=True, profile="hash/1", chains=None):
        self.clock, self.chain, self.delay_s, self.final = clock, chain, delay_s, final
        self.profile = profile  # own key: the own-tier client is a notary with profile hash/1-own (lab-qbft only)
        self.chains = list(chains) if chains else [chain]
        self.calls, self.fail = [], False

    def seal(self, over_hex):
        self.calls.append(over_hex)
        if self.fail:
            return {"status": "failed", "profile": self.profile, "over": "sha256:" + over_hex, "key": over_hex, "anchors": [],
                    "reason": "not_landed: fake"}
        anchors = []
        for c in self.chains:
            tx = "0x" + hashlib.sha256(b"tx|" + c.encode() + b"|" + over_hex.encode()).hexdigest() if c != self.chains[0] else \
                "0x" + hashlib.sha256(b"tx|" + over_hex.encode()).hexdigest()
            anchors.append({"chain": c, "state": "landed", "tx_hash": tx, "block": 1000 + len(self.calls),
                            "block_time": _iso(self.clock() + self.delay_s), "explorer_url": None, "final": self.final})
        return {"status": "landed", "profile": self.profile, "over": "sha256:" + over_hex, "key": over_hex,
                "anchors": anchors, "reason": None}


class FakeArmarium:
    """ArmariumClient in memory, with the REAL interface of B3W: create_claimant (one chain per owner, a digit-first id), objects
    keyed by (chain, version id) holding {doc, block, deleted}; put_version answers the new version's id and block (and
    original_id); delete_object answers {id, dek, residual} (no block). `dek` is what an object delete reports ("deleted" for a
    claimant chain with its own key, "on-chain" for a legacy chain). `fail` makes every call raise a transient ArmariumError."""

    def __init__(self, dek="deleted"):
        self.objects, self.claimants, self.block, self.dek, self.calls, self.fail = {}, {}, 100, dek, [], False

    def _next(self):
        self.block += 1
        return self.block

    def _check(self, op):
        self.calls.append(op)
        if self.fail:
            from claim_witness.ndim import ArmariumError
            raise ArmariumError("fake-failure")

    def create_claimant(self, case, body):
        self._check(("claimant", case))
        cid = "7" + hashlib.sha256(json.dumps(body, sort_keys=True).encode() + str(len(self.claimants)).encode()).hexdigest()[:31]
        self.claimants[cid] = body
        return {"id": cid}

    def create_object(self, chain, obj):
        self._check(("create", chain))
        oid = hashlib.sha256(json.dumps(obj, sort_keys=True).encode() + str(self.block).encode()).hexdigest()[:32]
        blk = self._next()
        self.objects[(chain, oid)] = {"doc": json.loads(json.dumps(obj)), "block": blk, "deleted": False, "original": oid}
        return {"id": oid, "block": blk}

    def put_version(self, chain, obj_id, block, obj):
        self._check(("put", chain, obj_id))
        old = self.objects[(chain, obj_id)]
        nid, blk = hashlib.sha256(obj_id.encode() + str(self.block).encode()).hexdigest()[:32], self._next()
        self.objects[(chain, nid)] = {"doc": json.loads(json.dumps(obj)), "block": blk, "deleted": False, "original": old["original"]}
        return {"id": nid, "block": blk, "original_id": old["original"]}

    def delete_object(self, chain, obj_id, block):
        self._check(("delete", chain, obj_id))
        self.objects[(chain, obj_id)]["deleted"] = True
        residual = ["ciphertext-on-chain"] + (["legacy-shared-kek"] if self.dek == "on-chain" else [])
        return {"id": obj_id, "dek": self.dek, "residual": residual}

    def get_object(self, chain, obj_id):
        from claim_witness.ndim import Gone
        v = self.objects[(chain, obj_id)]
        if v["deleted"]:
            raise Gone(obj_id)
        return v["doc"]

    def all_text(self):
        return json.dumps({f"{c}/{o}": v["doc"] for (c, o), v in self.objects.items()})


# --------------------------------------------------------------------------------------------------------------------- TLS


def make_tls(tmp=None):
    """(ca_file, cert_file, key_file) for a throwaway CA and a server certificate for 127.0.0.1 and localhost."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    import ipaddress
    d = pathlib.Path(tmp or tempfile.mkdtemp(prefix="cw-tls-"))
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "claim-witness test CA")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=5))
          .not_valid_after(now + datetime.timedelta(days=1))
          .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
          .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True, content_commitment=False,
                                       key_encipherment=False, data_encipherment=False, key_agreement=False,
                                       encipher_only=False, decipher_only=False), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
          .sign(ca_key, hashes.SHA256()))
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")]))
            .issuer_name(ca_name).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"),
                                                        x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256()))
    (d / "ca.pem").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    (d / "cert.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (d / "key.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                  serialization.NoEncryption()))
    return str(d / "ca.pem"), str(d / "cert.pem"), str(d / "key.pem")


class _Server(http.server.ThreadingHTTPServer):
    daemon_threads = True


class HttpsFake:
    """A local HTTPS server; handle(method, path, query, headers, body) -> (status, obj) is the route logic."""

    TOKEN = "fake-armarium-token-0123456789"

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
                if self.headers.get("Authorization") != "Bearer " + outer.TOKEN:
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


class HttpsNotary(HttpsFake):
    """POST /notary/v1/seals {profile, key, payload}: 200 with every chain landed (or `answer_status` to force another)."""

    def __init__(self, tls, block_time="2026-11-24T12:00:00Z", chain="base-sepolia"):
        self.answer_status, self.block_time, self.chain = 200, block_time, chain
        super().__init__(tls)

    def handle(self, method, path, q, body):
        if method != "POST" or path != "/notary/v1/seals":
            return 404, {"error": "not_found"}
        req = json.loads(body)
        payload = json.loads(base64.b64decode(req["payload"]))
        if set(req) != {"profile", "key", "payload"} or "over" not in payload or set(payload) - {"over", "label"}:
            return 422, {"error": "payload_rule"}
        if self.answer_status == 409:
            return 409, {"error": "key_conflict", "message": "x", "anchors": []}
        tx = "0x" + hashlib.sha256(req["key"].encode()).hexdigest()
        return self.answer_status, {"profile": req["profile"], "key": req["key"], "anchors": [
            {"chain": self.chain, "state": "landed" if self.answer_status == 200 else "in_doubt",
             "ref": {"chain": self.chain, "correlation_id": "c1", "block": 4242, "tx_hash": tx},
             "signer": "0x" + "1" * 40, "block_time": self.block_time, "final": False}]}
