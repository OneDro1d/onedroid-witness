"""Test-only helpers for the AT Protocol tests: a deterministic ECDSA signer over the fetcher's own curve arithmetic
(the fetcher itself only verifies), and a builder for small signed repositories exported as a CAR, the shape
com.atproto.sync.getRecord answers with (commit block first as the root, then the MST node(s), then the record)."""
import hashlib
import json
import pathlib

from claim_fetcher import atproto

FIX = pathlib.Path(__file__).resolve().parent / "fixtures" / "bsky"
REAL_DID = "did:plc:z72i7hdynmk6r22z27h6tvur"
REAL_RKEY = "3n2opitxdyc2j"
REAL_URL = f"https://bsky.app/profile/bsky.app/post/{REAL_RKEY}"
REAL_RECORD_CID = "bafyreihjpuz225u5djer7b6oqj5aszoqcblsjogyzlkr2ipw65cz3sk45m"
OTHER_DID = "did:plc:ewvi7nxzyoun6zhxrhs64oiz"  # atproto.com
PDS = "https://puffball.us-east.host.bsky.network"
OTHER_PDS = "https://enoki.us-east.host.bsky.network"


def fixture(name):
    return (FIX / name).read_bytes()


def real_car():
    return fixture(f"post-{REAL_RKEY}.car")


def real_doc():
    return fixture(f"did-plc-{REAL_DID.split(':')[2]}.json")


def other_doc():
    return fixture(f"did-plc-{OTHER_DID.split(':')[2]}.json")


def real_key():
    return json.loads(real_doc())["verificationMethod"][0]["publicKeyMultibase"]


def dns_txt():
    data = json.loads(fixture("dns-txt.json"))
    return {k: v for k, v in data.items() if not k.startswith("_comment")}


def sign(curve_name, priv, msg_hash, high_s=False):
    """64-byte r||s over a 32-byte hash, low-S unless high_s (k derived from the key and the hash: test use only)."""
    c = atproto.CURVES[curve_name]
    k = int.from_bytes(hashlib.sha256(priv.to_bytes(32, "big") + msg_hash).digest(), "big") % c.n or 1
    x, _ = atproto.point_mul(c, k, (c.gx, c.gy))
    r = x % c.n
    z = int.from_bytes(msg_hash, "big")
    s = pow(k, -1, c.n) * (z + r * priv) % c.n
    if s > c.n // 2:
        s = c.n - s
    if high_s:
        s = c.n - s
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def multikey(curve_name, priv):
    c = atproto.CURVES[curve_name]
    pub = atproto.point_mul(c, priv, (c.gx, c.gy))
    return atproto.encode_multikey(curve_name, pub)


def make_repo(did, records, curve_name="secp256k1", priv=0x1234567890ABCDEF, high_s=False, tamper_sig=False,
              commit_did=None):
    """(car bytes, commit CID, {key: record CID}) for a one-node MST holding `records` {"collection/rkey": obj}."""
    blocks = []
    entries, prev_key = [], b""
    rec_cids = {}
    for key in sorted(records):
        data = atproto.cbor_encode(records[key])
        cid = atproto.cid_for(data)
        blocks.append((cid, data))
        rec_cids[key] = cid
        kb = key.encode()
        p = 0
        while p < min(len(kb), len(prev_key)) and kb[p] == prev_key[p]:
            p += 1
        entries.append({"k": kb[p:], "p": p, "t": None, "v": cid})
        prev_key = kb
    node = atproto.cbor_encode({"e": entries, "l": None})
    node_cid = atproto.cid_for(node)
    blocks.insert(0, (node_cid, node))
    unsigned = {"did": commit_did or did, "version": 3, "data": node_cid, "rev": "3n2zzzzzzzz22", "prev": None}
    sig = sign(curve_name, priv, hashlib.sha256(atproto.cbor_encode(unsigned)).digest(), high_s=high_s)
    if tamper_sig:
        sig = bytes([sig[0] ^ 1]) + sig[1:]
    commit = atproto.cbor_encode(dict(unsigned, sig=sig))
    commit_cid = atproto.cid_for(commit)
    blocks.insert(0, (commit_cid, commit))
    return atproto.build_car([commit_cid], blocks), commit_cid, rec_cids


def did_doc(did, key_multibase, handles, pds="https://pds.example.com", key_type="Multikey"):
    return json.dumps({"id": did, "alsoKnownAs": [f"at://{h}" for h in handles],
                       "verificationMethod": [{"id": f"{did}#atproto", "type": key_type, "controller": did,
                                               "publicKeyMultibase": key_multibase}],
                       "service": [{"id": "#atproto_pds", "type": "AtprotoPersonalDataServer",
                                    "serviceEndpoint": pds}]}).encode()


def post_record(text="hello", created="2026-11-20T10:00:00.000Z"):
    return {"$type": "app.bsky.feed.post", "createdAt": created, "langs": ["en"], "text": text}
