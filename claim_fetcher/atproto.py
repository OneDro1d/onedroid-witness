"""AT Protocol proof checking for `capture: post` (slice B5a), standard library only, verify-only.

What is checked (https://atproto.com/specs/repository, /specs/did, /specs/handle, /specs/cryptography):
- the post URL: https://bsky.app/profile/<handle or DID>/post/<record key>, nothing else;
- the CAR v1 file a PDS answers to com.atproto.sync.getRecord: every block's sha2-256 digest must equal its CID's;
- the commit (the CAR's one root): DAG-CBOR {did, version, data, rev, prev, sig}; its `did` must be the repository's
  DID; `sig` is a 64-byte ECDSA signature (r||s, low-S) over sha256(DAG-CBOR of the commit without `sig`), checked
  against the DID document's `#atproto` key (Multikey: secp256k1 or P-256, compressed);
- the Merkle search tree path from the commit's `data` to the key `app.bsky.feed.post/<rkey>`, every node present in
  the CAR, and the record block it names, whose `$type` must be the collection.

DAG-CBOR here is the strict subset AT Protocol uses: integers, byte and text strings, arrays, maps with text keys in
canonical order (length first, then bytes), CID links (tag 42), true, false and null; floats, other tags and
indefinite lengths are refused. The elliptic-curve arithmetic is plain affine Weierstrass math with Python integers
(pow(x, -1, p) for inverses): verification uses only public values, so constant time does not matter.
"""
import base64
import hashlib
import json
import re
import urllib.parse

POST_HOST = "bsky.app"
POST_COLLECTION = "app.bsky.feed.post"
PLC_DIRECTORY = "https://plc.directory"
MAX_DID_DOC = 64 * 1024
RKEY_RE = re.compile(r"^[A-Za-z0-9._:~-]{1,512}$")
PLC_RE = re.compile(r"^did:plc:[a-z2-7]{24}$")
WEB_RE = re.compile(r"^did:web:([a-z0-9.-]+)$")
LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
CODEC_DAG_CBOR, CODEC_RAW, MH_SHA256 = 0x71, 0x55, 0x12


class ProofError(ValueError):
    """Bytes that are not what AT Protocol says they must be (a CAR, a block, DAG-CBOR)."""


# names ----------------------------------------------------------------------------------------------------------------

def normalize_handle(handle):
    """A handle (a DNS name of at least two labels whose last label does not start with a digit) in lower case, else
    ValueError."""
    if not isinstance(handle, str):
        raise ValueError("handle: a string")
    h = handle.lower()
    if not 3 <= len(h) <= 253 or not h.isascii():
        raise ValueError("handle: 3 to 253 ASCII characters")
    labels = h.split(".")
    if len(labels) < 2 or not all(LABEL_RE.match(lab) for lab in labels) or labels[-1][0].isdigit():
        raise ValueError(f"handle: not a valid handle: {handle[:80]!r}")
    return h


def valid_did(did):
    return isinstance(did, str) and (bool(PLC_RE.match(did)) or _web_host(did) is not None)


def _web_host(did):
    m = WEB_RE.match(did) if isinstance(did, str) else None
    if not m:
        return None
    try:
        return normalize_handle(m.group(1))
    except ValueError:
        return None


def did_doc_url(did):
    """Where a DID's document is read: plc.directory for did:plc, the domain's /.well-known/did.json for did:web
    (a bare domain only: no port, no path). ValueError for anything else."""
    if isinstance(did, str) and PLC_RE.match(did):
        return f"{PLC_DIRECTORY}/{did}"
    host = _web_host(did)
    if host:
        return f"https://{host}/.well-known/did.json"
    raise ValueError(f"not a supported DID: {str(did)[:80]!r}")


def parse_post_url(url):
    """(actor, rkey) of https://bsky.app/profile/<handle or DID>/post/<rkey>: the actor is a lower-cased handle or a
    DID. ValueError for every other URL (other hosts, http, ports, credentials, queries, fragments, other paths)."""
    if not isinstance(url, str) or len(url) > 2048:
        raise ValueError("not a Bluesky post URL")
    try:
        u = urllib.parse.urlsplit(url)
        port = u.port
    except ValueError:
        raise ValueError("not a Bluesky post URL") from None
    if (u.scheme != "https" or (u.hostname or "") != POST_HOST or u.netloc.lower() != POST_HOST or port is not None
            or u.query or u.fragment or "@" in u.netloc):
        raise ValueError("not a Bluesky post URL (https://bsky.app/profile/<handle or DID>/post/<rkey>)")
    parts = u.path.split("/")
    if len(parts) != 5 or parts[0] != "" or parts[1] != "profile" or parts[3] != "post":
        raise ValueError("not a Bluesky post URL (https://bsky.app/profile/<handle or DID>/post/<rkey>)")
    actor, rkey = parts[2], parts[4]
    if not RKEY_RE.match(rkey) or rkey in (".", ".."):
        raise ValueError("not a valid record key")
    if actor.startswith("did:"):
        if not valid_did(actor):
            raise ValueError("not a supported DID")
        return actor, rkey
    return normalize_handle(actor), rkey


# varints, base32, base58 ----------------------------------------------------------------------------------------------

def varint_encode(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def varint_decode(data, off):
    n = shift = 0
    for i in range(10):
        if off + i >= len(data):
            raise ProofError("truncated varint")
        b = data[off + i]
        n |= (b & 0x7F) << shift
        shift += 7
        if not b & 0x80:
            return n, off + i + 1
    raise ProofError("varint too long")


B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58encode(data):
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = B58[r] + out
    return "1" * (len(data) - len(data.lstrip(b"\x00"))) + out


def b58decode(text):
    n = 0
    for c in text:
        i = B58.find(c)
        if i < 0:
            raise ValueError("not base58btc")
        n = n * 58 + i
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\x00" * (len(text) - len(text.lstrip("1"))) + body


# CIDs -----------------------------------------------------------------------------------------------------------------

class CID:
    """A CIDv1 with a sha2-256 multihash. Equal and hashable by its bytes; str() is the base32 multibase form."""
    __slots__ = ("raw", "codec", "digest")

    def __init__(self, raw):
        raw = bytes(raw)
        version, off = varint_decode(raw, 0)
        if version != 1:
            raise ProofError("only CIDv1 is supported")
        codec, off = varint_decode(raw, off)
        mh, off = varint_decode(raw, off)
        size, off = varint_decode(raw, off)
        if mh != MH_SHA256 or size != 32 or len(raw) != off + 32:
            raise ProofError("only sha2-256 CIDs are supported")
        self.raw, self.codec, self.digest = raw, codec, raw[off:]

    @classmethod
    def read(cls, data, off):
        """(CID, offset after it) from inside a CAR."""
        start = off
        for _ in range(4):
            _, off = varint_decode(data, off)
        if off + 32 > len(data):
            raise ProofError("truncated CID")
        return cls(data[start:off + 32]), off + 32

    @classmethod
    def parse_str(cls, text):
        if not isinstance(text, str) or not text.startswith("b"):
            raise ProofError("only base32 CIDs are supported")
        body = text[1:].upper()
        try:
            raw = base64.b32decode(body + "=" * (-len(body) % 8))
        except ValueError:
            raise ProofError("not base32") from None
        return cls(raw)

    def __str__(self):
        return "b" + base64.b32encode(self.raw).decode().lower().rstrip("=")

    def __repr__(self):
        return f"CID({self})"

    def __eq__(self, other):
        return isinstance(other, CID) and other.raw == self.raw

    def __hash__(self):
        return hash(self.raw)


def cid_for(data, codec=CODEC_DAG_CBOR):
    return CID(b"\x01" + varint_encode(codec) + bytes([MH_SHA256, 32]) + hashlib.sha256(data).digest())


# DAG-CBOR -------------------------------------------------------------------------------------------------------------

def _head(major, n):
    if n < 24:
        return bytes([major << 5 | n])
    for ai, size in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if n < 1 << (8 * size):
            return bytes([major << 5 | ai]) + n.to_bytes(size, "big")
    raise ValueError("integer too large for CBOR")


def _key_order(k):
    b = k.encode("utf-8")
    return (len(b), b)


def cbor_encode(obj):
    if obj is None:
        return b"\xf6"
    if obj is True:
        return b"\xf5"
    if obj is False:
        return b"\xf4"
    if isinstance(obj, int):
        return _head(0, obj) if obj >= 0 else _head(1, -1 - obj)
    if isinstance(obj, (bytes, bytearray)):
        return _head(2, len(obj)) + bytes(obj)
    if isinstance(obj, str):
        b = obj.encode("utf-8")
        return _head(3, len(b)) + b
    if isinstance(obj, CID):
        link = b"\x00" + obj.raw
        return b"\xd8\x2a" + _head(2, len(link)) + link
    if isinstance(obj, (list, tuple)):
        return _head(4, len(obj)) + b"".join(cbor_encode(x) for x in obj)
    if isinstance(obj, dict):
        if not all(isinstance(k, str) for k in obj):
            raise ValueError("DAG-CBOR map keys are strings")
        keys = sorted(obj, key=_key_order)
        return _head(5, len(obj)) + b"".join(cbor_encode(k) + cbor_encode(obj[k]) for k in keys)
    raise ValueError(f"cannot encode {type(obj).__name__} as DAG-CBOR")


def _decode(data, off, depth):
    if depth > 64:
        raise ProofError("nested too deep")
    if off >= len(data):
        raise ProofError("truncated CBOR")
    ib = data[off]
    major, ai = ib >> 5, ib & 0x1F
    off += 1
    if major == 7:
        if ai == 20:
            return False, off
        if ai == 21:
            return True, off
        if ai == 22:
            return None, off
        raise ProofError("floats and other simple values are not DAG-CBOR here")
    if ai < 24:
        n = ai
    elif ai <= 27:
        size = 1 << (ai - 24)
        if off + size > len(data):
            raise ProofError("truncated CBOR")
        n = int.from_bytes(data[off:off + size], "big")
        off += size
    else:
        raise ProofError("indefinite or reserved length")
    if major == 0:
        return n, off
    if major == 1:
        return -1 - n, off
    if major in (2, 3):
        if off + n > len(data):
            raise ProofError("truncated string")
        raw = data[off:off + n]
        off += n
        if major == 2:
            return bytes(raw), off
        try:
            return raw.decode("utf-8"), off
        except UnicodeDecodeError:
            raise ProofError("text is not UTF-8") from None
    if major == 4:
        out = []
        for _ in range(n):
            v, off = _decode(data, off, depth + 1)
            out.append(v)
        return out, off
    if major == 5:
        out = {}
        for _ in range(n):
            k, off = _decode(data, off, depth + 1)
            if not isinstance(k, str) or k in out:
                raise ProofError("map keys must be distinct strings")
            v, off = _decode(data, off, depth + 1)
            out[k] = v
        return out, off
    if major == 6:
        if n != 42:
            raise ProofError("only tag 42 (CID) is allowed")
        v, off = _decode(data, off, depth + 1)
        if not isinstance(v, bytes) or not v.startswith(b"\x00"):
            raise ProofError("a CID link is bytes with a 0x00 prefix")
        return CID(v[1:]), off
    raise ProofError("bad CBOR")


def cbor_decode(data):
    value, off = _decode(bytes(data), 0, 0)
    if off != len(data):
        raise ProofError("trailing bytes after CBOR")
    return value


# CAR v1 ---------------------------------------------------------------------------------------------------------------

def read_car(data):
    """(roots, {CID: block bytes}); ProofError unless every block hashes to its CID."""
    data = bytes(data)
    hlen, off = varint_decode(data, 0)
    if off + hlen > len(data):
        raise ProofError("truncated CAR header")
    header = cbor_decode(data[off:off + hlen])
    off += hlen
    if not isinstance(header, dict) or header.get("version") != 1 or not isinstance(header.get("roots"), list):
        raise ProofError("not a CAR v1 header")
    roots = header["roots"]
    if not all(isinstance(r, CID) for r in roots):
        raise ProofError("CAR roots must be CIDs")
    blocks = {}
    while off < len(data):
        blen, off = varint_decode(data, off)
        end = off + blen
        if end > len(data) or blen == 0:
            raise ProofError("truncated CAR block")
        cid, boff = CID.read(data, off)
        if boff > end:
            raise ProofError("bad CAR block")
        block = data[boff:end]
        if hashlib.sha256(block).digest() != cid.digest:
            raise ProofError(f"block {cid} does not hash to its CID")
        blocks[cid] = block
        off = end
    return roots, blocks


def build_car(roots, blocks):
    """A CAR v1 file from roots and [(CID, bytes)] (tests and fixtures)."""
    header = cbor_encode({"roots": list(roots), "version": 1})
    out = bytearray(varint_encode(len(header)) + header)
    for cid, data in blocks:
        out += varint_encode(len(cid.raw) + len(data)) + cid.raw + data
    return bytes(out)


# curves and ECDSA -----------------------------------------------------------------------------------------------------

class Curve:
    __slots__ = ("name", "p", "a", "b", "n", "gx", "gy")

    def __init__(self, name, p, a, b, n, gx, gy):
        self.name, self.p, self.a, self.b, self.n, self.gx, self.gy = name, p, a, b, n, gx, gy


CURVES = {
    "secp256k1": Curve("secp256k1", 2**256 - 2**32 - 977, 0, 7,
                       0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
                       0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
                       0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8),
    "p256": Curve("p256", 2**256 - 2**224 + 2**192 + 2**96 - 1, -3,
                  0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
                  0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
                  0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
                  0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5),
}
MULTICODEC = {"secp256k1": b"\xe7\x01", "p256": b"\x80\x24"}  # secp256k1-pub 0xe7, p256-pub 0x1200 (varints)


def _on_curve(c, pt):
    x, y = pt
    return 0 <= x < c.p and 0 <= y < c.p and (y * y - (x * x * x + c.a * x + c.b)) % c.p == 0


def _add(c, p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    (x1, y1), (x2, y2) = p1, p2
    if x1 == x2:
        if (y1 + y2) % c.p == 0:
            return None
        lam = (3 * x1 * x1 + c.a) * pow(2 * y1, -1, c.p) % c.p
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, c.p) % c.p
    x3 = (lam * lam - x1 - x2) % c.p
    return x3, (lam * (x1 - x3) - y1) % c.p


def point_mul(c, k, pt):
    out = None
    while k:
        if k & 1:
            out = _add(c, out, pt)
        pt = _add(c, pt, pt)
        k >>= 1
    return out


def decompress(c, data):
    if len(data) != 33 or data[0] not in (2, 3):
        raise ValueError("a compressed public key is 33 bytes starting 02 or 03")
    x = int.from_bytes(data[1:], "big")
    if x >= c.p:
        raise ValueError("not on the curve")
    y = pow((x * x * x + c.a * x + c.b) % c.p, (c.p + 1) // 4, c.p)  # both primes are 3 mod 4
    if (y * y - (x * x * x + c.a * x + c.b)) % c.p:
        raise ValueError("not on the curve")
    if y & 1 != data[0] & 1:
        y = c.p - y
    return x, y


def compress(pt):
    x, y = pt
    return bytes([2 | (y & 1)]) + x.to_bytes(32, "big")


def parse_multikey(text):
    """(curve name, public point) of a did:key-style Multikey ('z' + base58btc(multicodec + compressed key)).
    ValueError for anything but a secp256k1 or P-256 key on its curve."""
    if not isinstance(text, str) or not text.startswith("z") or len(text) > 128:
        raise ValueError("publicKeyMultibase: base58btc ('z') expected")
    raw = b58decode(text[1:])
    for name, prefix in MULTICODEC.items():
        if raw.startswith(prefix):
            return name, decompress(CURVES[name], raw[len(prefix):])
    raise ValueError("publicKeyMultibase: not a secp256k1 or P-256 key")


def encode_multikey(curve_name, pt):
    return "z" + b58encode(MULTICODEC[curve_name] + compress(pt))


def ecdsa_verify(curve_name, pub, msg_hash, sig):
    """ECDSA over a 32-byte hash with a 64-byte r||s signature; high-S signatures are refused (AT Protocol)."""
    c = CURVES[curve_name]
    if len(sig) != 64 or len(msg_hash) != 32 or pub is None or not _on_curve(c, pub):
        return False
    r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
    if not (1 <= r < c.n and 1 <= s <= c.n // 2):
        return False
    z = int.from_bytes(msg_hash, "big")
    w = pow(s, -1, c.n)
    pt = _add(c, point_mul(c, z * w % c.n, (c.gx, c.gy)), point_mul(c, r * w % c.n, pub))
    return pt is not None and pt[0] % c.n == r


# DID documents --------------------------------------------------------------------------------------------------------

def did_doc_info(data, did):
    """{key: the #atproto publicKeyMultibase or None, pds: the AtprotoPersonalDataServer endpoint or None, handles:
    the at:// names in alsoKnownAs, lower-cased, in order}. ValueError when it is not this DID's JSON document."""
    if len(data) > MAX_DID_DOC:
        raise ValueError("DID document too large")
    try:
        doc = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise ValueError("DID document is not JSON") from None
    if not isinstance(doc, dict) or doc.get("id") != did:
        raise ValueError("the document is not this DID's")
    handles = []
    for aka in doc.get("alsoKnownAs") or []:
        if isinstance(aka, str) and aka.startswith("at://"):
            try:
                h = normalize_handle(aka[5:])
            except ValueError:
                continue
            if h not in handles:
                handles.append(h)
    key = None
    for vm in doc.get("verificationMethod") or []:
        if isinstance(vm, dict) and vm.get("id") in (f"{did}#atproto", "#atproto") \
                and isinstance(vm.get("publicKeyMultibase"), str):
            key = vm["publicKeyMultibase"]
            break
    pds = None
    for svc in doc.get("service") or []:
        if isinstance(svc, dict) and str(svc.get("id", "")).endswith("#atproto_pds") \
                and svc.get("type") == "AtprotoPersonalDataServer" and isinstance(svc.get("serviceEndpoint"), str):
            pds = svc["serviceEndpoint"]
            break
    return {"key": key, "pds": pds, "handles": handles}


# the proof ------------------------------------------------------------------------------------------------------------

def _mst_find(blocks, root, key):
    """The value CID for key in the MST rooted at root, None when the tree proves it absent; ProofError when a node on
    the path is missing or malformed."""
    cid = root
    for _ in range(128):
        if cid not in blocks:
            raise ProofError("proof-incomplete")
        node = cbor_decode(blocks[cid])
        if not isinstance(node, dict) or not isinstance(node.get("e"), list):
            raise ProofError("bad MST node")
        nxt, prev = node.get("l"), b""
        for e in node["e"]:
            if not isinstance(e, dict) or not isinstance(e.get("k"), bytes) or not isinstance(e.get("p"), int) \
                    or not isinstance(e.get("v"), CID) or e["p"] > len(prev):
                raise ProofError("bad MST entry")
            k = prev[:e["p"]] + e["k"]
            if k <= prev and prev:
                raise ProofError("MST keys out of order")
            prev = k
            if k == key:
                return e["v"]
            if k > key:
                break
            nxt = e.get("t")
        if nxt is None:
            return None
        if not isinstance(nxt, CID):
            raise ProofError("bad MST link")
        cid = nxt
    raise ProofError("MST too deep")


def verify_record(car, did, collection, rkey, key_multibase):
    """{signature: verified | failed | not-available, reason, commit_cid, record_cid, rev, record} for the record
    collection/rkey of did, from a getRecord CAR and the DID document's key."""
    out = {"signature": "failed", "reason": None, "commit_cid": None, "record_cid": None, "rev": None, "record": None}
    if key_multibase is None:
        return dict(out, signature="not-available", reason="no-key")
    try:
        curve, pub = parse_multikey(key_multibase)
    except ValueError:
        return dict(out, signature="not-available", reason="unsupported-key")
    try:
        roots, blocks = read_car(car)
    except ProofError:
        return dict(out, reason="bad-car")
    if len(roots) != 1 or roots[0] not in blocks:
        return dict(out, reason="proof-incomplete")
    try:
        commit = cbor_decode(blocks[roots[0]])
    except ProofError:
        return dict(out, reason="bad-commit")
    out["commit_cid"] = str(roots[0])
    if (not isinstance(commit, dict) or not isinstance(commit.get("sig"), bytes) or not isinstance(commit.get("data"), CID)
            or commit.get("version") not in (2, 3) or not isinstance(commit.get("did"), str)):
        return dict(out, reason="bad-commit")
    out["rev"] = commit.get("rev") if isinstance(commit.get("rev"), str) else None
    if commit["did"] != did:
        return dict(out, reason="commit-did-mismatch")
    unsigned = {k: v for k, v in commit.items() if k != "sig"}
    if not ecdsa_verify(curve, pub, hashlib.sha256(cbor_encode(unsigned)).digest(), commit["sig"]):
        return dict(out, reason="bad-signature")
    try:
        value = _mst_find(blocks, commit["data"], f"{collection}/{rkey}".encode())
    except ProofError as e:
        return dict(out, reason="proof-incomplete" if str(e) == "proof-incomplete" else "bad-mst")
    if value is None:
        return dict(out, reason="record-not-in-proof")
    if value not in blocks:
        return dict(out, reason="proof-incomplete")
    try:
        record = cbor_decode(blocks[value])
    except ProofError:
        return dict(out, reason="bad-record")
    if not isinstance(record, dict) or record.get("$type") != collection:
        return dict(out, reason="wrong-type")
    return dict(out, signature="verified", reason=None, record_cid=str(value), record=record,
                key_type=curve)
