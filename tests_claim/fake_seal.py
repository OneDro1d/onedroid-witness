"""Fakes for slice B3: the armarium notary and armarium's n-dim object routes, in memory (the NotaryClient and ArmariumClient
interfaces) and as local HTTPS servers speaking the real routes (so the real HTTP clients are tested without a network: a
throwaway CA and a 127.0.0.1 certificate made with `cryptography`). Nothing here talks to a real armarium."""
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

    def __init__(self, clock=time.time, chain="base-sepolia", delay_s=60):
        self.clock, self.chain, self.delay_s = clock, chain, delay_s
        self.calls, self.fail = [], False

    def seal(self, over_hex):
        self.calls.append(over_hex)
        if self.fail:
            return {"status": "failed", "profile": "hash/1", "over": "sha256:" + over_hex, "key": over_hex, "anchors": [],
                    "reason": "not_landed: fake"}
        tx = "0x" + hashlib.sha256(b"tx|" + over_hex.encode()).hexdigest()
        return {"status": "landed", "profile": "hash/1", "over": "sha256:" + over_hex, "key": over_hex,
                "anchors": [{"chain": self.chain, "state": "landed", "tx_hash": tx, "block": 1000 + len(self.calls),
                             "block_time": _iso(self.clock() + self.delay_s), "explorer_url": None, "final": False}],
                "reason": None}


class FakeArmarium:
    """ArmariumClient in memory: each object a list of versions (dicts); a delete appends a DELETED marker. `dek` is what an
    object delete reports ("deleted" for a claimant chain with its own key, "on-chain" for a legacy chain)."""

    def __init__(self, dek="deleted"):
        self.objects, self.block, self.dek, self.calls, self.fail = {}, 100, dek, [], False

    def _next(self):
        self.block += 1
        return self.block

    def _check(self, op):
        self.calls.append(op)
        if self.fail:
            from claim_witness.ndim import ArmariumError
            raise ArmariumError("fake-failure")

    def create_object(self, chain, obj):
        self._check(("create", chain))
        oid = hashlib.sha256(json.dumps(obj, sort_keys=True).encode() + str(self.block).encode()).hexdigest()[:32]
        self.objects[(chain, oid)] = [json.loads(json.dumps(obj))]
        return {"id": oid, "block": self._next()}

    def put_version(self, chain, obj_id, block, obj):
        self._check(("put", chain, obj_id))
        self.objects[(chain, obj_id)].append(json.loads(json.dumps(obj)))
        return {"id": obj_id, "block": self._next()}

    def delete_object(self, chain, obj_id, block):
        self._check(("delete", chain, obj_id))
        self.objects[(chain, obj_id)].append("DELETED")
        residual = ["ciphertext-on-chain"] + (["legacy-shared-kek"] if self.dek == "on-chain" else [])
        return {"id": obj_id, "block": self._next(), "dek": self.dek, "residual": residual}

    def get_object(self, chain, obj_id):
        from claim_witness.ndim import Gone
        v = self.objects[(chain, obj_id)]
        if v[-1] == "DELETED":
            raise Gone(obj_id)
        return v[-1]

    def all_text(self):
        return json.dumps({f"{c}/{o}": v for (c, o), v in self.objects.items()})


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


class HttpsArmarium(HttpsFake):
    """armarium's SDK object routes (cmd/armarium-service/README.md): POST /chain/{name}/object, GET/PUT/DELETE
    /chain/{name}/object/{id}?block=."""

    def __init__(self, tls, dek="deleted"):
        self.mem, self.dek = FakeArmarium(dek), dek
        super().__init__(tls)

    def handle(self, method, path, q, body):
        parts = path.strip("/").split("/")
        if len(parts) < 3 or parts[0] != "chain" or parts[2] != "object":
            return 404, {"error": "not_found"}
        chain = parts[1]
        if method == "POST" and len(parts) == 3:
            out = self.mem.create_object(chain, json.loads(body))
            return 200, {"correlation_id": out["id"], "block": out["block"]}
        oid = parts[3] if len(parts) == 4 else None
        if oid is None or (chain, oid) not in self.mem.objects:
            return 404, {"error": "not_found"}
        if method in ("PUT", "DELETE") and "block" not in q:
            return 400, {"error": "block_required"}
        if method == "PUT":
            out = self.mem.put_version(chain, oid, int(q["block"][0]), json.loads(body))
            return 200, {"correlation_id": oid, "block": out["block"]}
        if method == "DELETE":
            out = self.mem.delete_object(chain, oid, int(q["block"][0]))
            return 200, {"correlation_id": oid, "deletion_marker_block": out["block"], "dek": out["dek"],
                         "residual": out["residual"],
                         "message": "the key for this version is deleted; the encrypted bytes stay on the chain; this is not erasure"}
        if method == "GET":
            v = self.mem.objects[(chain, oid)][-1]
            if v == "DELETED":
                return 410, {"status": "deleted"}
            return 200, v
        return 405, {"error": "method"}


class HttpsNotary(HttpsFake):
    """POST /notary/v1/seals {profile, key, payload}: 200 with every chain landed (or `answer_status` to force another)."""

    def __init__(self, tls, block_time="2026-11-24T12:00:00Z"):
        self.answer_status, self.block_time = 200, block_time
        super().__init__(tls)

    def handle(self, method, path, q, body):
        if method != "POST" or path != "/notary/v1/seals":
            return 404, {"error": "not_found"}
        req = json.loads(body)
        payload = json.loads(base64.b64decode(req["payload"]))
        if set(req) != {"profile", "key", "payload"} or set(payload) != {"over"}:
            return 422, {"error": "payload_rule"}
        if self.answer_status == 409:
            return 409, {"error": "key_conflict", "message": "x", "anchors": []}
        tx = "0x" + hashlib.sha256(req["key"].encode()).hexdigest()
        return self.answer_status, {"profile": req["profile"], "key": req["key"], "anchors": [
            {"chain": "base-sepolia", "state": "landed" if self.answer_status == 200 else "in_doubt",
             "ref": {"chain": "base-sepolia", "correlation_id": "c1", "block": 4242, "tx_hash": tx},
             "signer": "0x" + "1" * 40, "block_time": self.block_time, "final": False}]}
