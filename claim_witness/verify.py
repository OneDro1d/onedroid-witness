#!/usr/bin/env python3
"""witness-verify (SPEC §6): steps 1 (key list), 2 (signature), 3 (ids and commitments), 4 (the seal, B3), 5 (key validity:
at the anchor time when sealed, else at the payload's own time), 6 (bundle files and the re-run of a pure-Python method from
the tarball pinned by code_sha256) and 7 (the agent's signature).

B3, step 4 (`seal`): the leaf H(0x00 || payload) and its path must give the batch root (RFC 9162 §2.1.3.2); the batch header
must be signed by a key of the key list (PAE over the canonical header without `sig`), name that root and this witness; the
notary's `over` must be "sha256:" + H(canonical signed header) with every anchor landed. The anchor transaction is read only
when --rpc URL is given (`seal-chain`, BD21; the only network use here): for each base-sepolia anchor the transaction and its
block are read, and PASS needs the transaction to exist, be to 0x0, carry the JSON datablock with mode "hash" and payload.over
equal to the seal's over, sit in the anchor's block, in a block whose timestamp is the anchor's block_time (to the second); the
sender must be a sealer of the key list (or of --sealer ADDRESS, repeatable) at the block time, and with neither the PASS line
says the sender was not checked. An unreachable or erroring RPC is a FAIL, never a PASS. lab-qbft and any other chain are a
SKIP naming it as the operator's own chain. Without --rpc, `SKIP seal-chain` (no network). Key validity is then judged
at the anchor time (the earliest landed block_time; with --rpc the chain's own timestamp of the earliest base-sepolia anchor
that passed): a key revoked at or before it fails; FLAG seal-delay when the anchor
came more than interval_s + 15 minutes after the payload's time. A pending seal is SKIP ("time not proven").
Own model key: a batch header with `anchoring: own` prints `INFO anchoring: own chain only (...)`; its missing base-sepolia
anchor is never a FAIL, but a base-sepolia anchor on it is `FAIL seal`, as is an `anchoring` other than public or own. A header
without the field is public.

B2b: an observation envelope (predicateType observation/v1) is verified too: signature, payload canonical, observation id,
manifest digest (a public observation's subject is H(canonical manifest)), key validity at fetched_at, every file given with
--evidence against the manifest, and text.canonical.txt recomputed from rendered.html with the tarball's canon/1.

Observation re-run (VR-13): a record whose evidence is an observation or a URL (page.live, match.text, post.by-author) is re-run
from the observation folders of the bundle, observations/<id>/ (envelope.json, seal.json, files/<name>; or --observation DIR).
Each observation the record names is verified as above first, and only then are its files given to the method from the tarball,
in the shape the server gives it. An observation that fails its own checks makes method-rerun FAIL; one the bundle lacks, or a
fetch that left none, is a SKIP naming it. match.screenshot is never re-run by this verifier: "re-run skipped (needs image)".

match.image-text (NS-11): the model's transcription of the image is not re-run (`SKIP transcription-rerun`); rule R1 is, from
the tarball, over the transcription a private record's disclosed body keeps (judgment.transcription): `transcription-sha256`
(the text is the sha256 the record names), `transcription-prompt` (the record's prompt_sha256 is the tarball's PROMPT), then
`method-rerun` (finding, reason, outcome, detail, statement, limits and the missing tokens as the record has them).

One module, Python 3.10+ standard library only, importing nothing from its own package, so it can be copied and run alone:

    python3 -m claim_witness.verify --envelope answer.json --keys keys.json [--disclosure d.json] [--agent-key a.json]
                                    [--methods witness-methods-1.0.0.tar.gz] [--evidence FILE ...] [--record-id HEX]
                                    [--observation DIR ...]
    ... [--rpc https://sepolia.base.org] [--sealer 0xADDRESS ...]   # read the base-sepolia anchor transaction (any form above)
    python3 -m claim_witness.verify --bundle DIR [--disclosure FILE]
                                                      # envelope.json, keys.json, agent_key.json,
                                                      # witness-methods-*.tar.gz, evidence/<sha256>,
                                                      # observations/<id>/{envelope.json, seal.json, files/<name>}
                                                      # The witness never puts the private disclosure in a bundle (BD17):
                                                      # the owner or a token holder passes it with --disclosure FILE (from
                                                      # GET /v1/records/{id}). A disclosure.json you put in DIR yourself
                                                      # is picked up too.
    --trust KEYS.json uses a key list you trust instead of the bundled one.

Ed25519 uses the `cryptography` package when it can be imported, otherwise the pure-Python RFC 8032 code below (BD10);
WITNESS_VERIFY_PURE=1 forces the pure code. Every check prints PASS, FAIL or SKIP with its name; exit 0 means every
applicable check passed, 1 that one failed, 2 a usage error.
"""
import argparse
import base64
import hashlib
import importlib.util
import io
import json
import os
import pathlib
import re
import sys
import tarfile
import tempfile

PAYLOAD_TYPE = "application/vnd.in-toto+json"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
CLAIM_TYPE = "https://onedroid.ai/witness/claim/v1"
OBSERVATION_TYPE = "https://onedroid.ai/witness/observation/v1"
NEEDS_IMAGE = ("match.screenshot",)
IMAGE_TEXT = ("match.image-text",)  # NS-11: R1 re-runs over the transcription the record's body keeps
RECORD_METHODS = ("record.valid", "record.disclose")  # B5b: their evidence names records, given with --record or a bundle
KEYLIST_TYPE = "https://onedroid.ai/witness/key-list/v1"
BATCH_PAYLOAD_TYPE = "application/vnd.onedroid.witness.batch-header+json"
MAX_INT = 2 ** 53 - 1
SEAL_GRACE_S = 900
ANCHOR_SKEW_S = 300  # the signer's own clock tolerance: an anchor further before the payload's time is inconsistent

# ---------------------------------------------------------------------------------------------------------------------
# RFC 8032 Ed25519, pure Python (the reference code of RFC 8032 §6, restated)

_P = 2 ** 255 - 19
_Q = 2 ** 252 + 27742317777372353535851937790883648493


def _inv(x):
    return pow(x, _P - 2, _P)


_D = -121665 * _inv(121666) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _add(P, Q):
    A, B = (P[1] - P[0]) * (Q[1] - Q[0]) % _P, (P[1] + P[0]) * (Q[1] + Q[0]) % _P
    C, D = 2 * P[3] * Q[3] * _D % _P, 2 * P[2] * Q[2] % _P
    E, F, G, H = B - A, D - C, D + C, B + A
    return (E * F % _P, G * H % _P, F * G % _P, E * H % _P)


def _mul(s, P):
    Q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            Q = _add(Q, P)
        P = _add(P, P)
        s >>= 1
    return Q


def _equal(P, Q):
    return (P[0] * Q[2] - Q[0] * P[2]) % _P == 0 and (P[1] * Q[2] - Q[1] * P[2]) % _P == 0


def _recover_x(y, sign):
    if y >= _P:
        return None
    x2 = (y * y - 1) * _inv(_D * y * y + 1) % _P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


_GY = 4 * _inv(5) % _P
_GX = _recover_x(_GY, 0)
_G = (_GX, _GY, 1, _GX * _GY % _P)


def _compress(P):
    zi = _inv(P[2])
    x, y = P[0] * zi % _P, P[1] * zi % _P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _decompress(s):
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    return None if x is None else (x, y, 1, x * y % _P)


def _h(data):
    return int.from_bytes(hashlib.sha512(data).digest(), "little") % _Q


def _expand(seed):
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def ed25519_public_pure(seed):
    return _compress(_mul(_expand(seed)[0], _G))


def ed25519_sign_pure(seed, msg):
    a, prefix = _expand(seed)
    A = _compress(_mul(a, _G))
    r = _h(prefix + msg)
    Rs = _compress(_mul(r, _G))
    s = (r + _h(Rs + A + msg) * a) % _Q
    return Rs + int.to_bytes(s, 32, "little")


def ed25519_verify_pure(public, sig, msg):
    if len(public) != 32 or len(sig) != 64:
        return False
    A = _decompress(public)
    R = _decompress(sig[:32])
    if A is None or R is None:
        return False
    s = int.from_bytes(sig[32:], "little")
    if s >= _Q:
        return False
    return _equal(_mul(s, _G), _add(R, _mul(_h(sig[:32] + public + msg), A)))


def _backend():
    if os.environ.get("WITNESS_VERIFY_PURE") == "1":
        return None
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        return Ed25519PublicKey
    except ImportError:
        return None


def ed25519_verify(public, sig, msg):
    backend = _backend()
    if backend is None:
        return ed25519_verify_pure(public, sig, msg)
    try:
        backend.from_public_bytes(public).verify(sig, msg)
        return True
    except Exception:  # noqa: BLE001 - InvalidSignature or a malformed key
        return False


# ---------------------------------------------------------------------------------------------------------------------
# RFC 8785 with integers only (BD9), ids and commitments (SPEC §2.0, §2.6): restated from claim_witness.jcs and .ids, which
# the vectors check against this module


def canonical(v):
    if v is None:
        return b"null"
    if v is True:
        return b"true"
    if v is False:
        return b"false"
    if isinstance(v, int):
        if not -MAX_INT <= v <= MAX_INT:
            raise ValueError("integer outside the I-JSON range")
        return str(v).encode()
    if isinstance(v, float):
        raise ValueError("floats are not allowed")
    if isinstance(v, str):
        return json.dumps(v, ensure_ascii=False).encode("utf-8")
    if isinstance(v, list):
        return b"[" + b",".join(canonical(x) for x in v) + b"]"
    if isinstance(v, dict):
        keys = sorted(v, key=lambda k: k.encode("utf-16-be", "surrogatepass"))
        return b"{" + b",".join(canonical(k) + b":" + canonical(v[k]) for k in keys) + b"}"
    raise ValueError(f"{type(v).__name__} is not JSON")


def _no_float(s):
    raise ValueError("floats are not allowed")


def _pairs(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise ValueError("duplicate key")
        d[k] = v
    return d


def loads_strict(data):
    return json.loads(data.decode("utf-8") if isinstance(data, bytes) else data, parse_float=_no_float,
                      object_pairs_hook=_pairs)


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def claim_id(claim):
    return sha256_hex(canonical(claim))


def claim_commitment(salt, claim):
    return sha256_hex(b"witness-commit/1|claim|" + salt + canonical(claim))


def body_commitment(salt, body):
    return sha256_hex(b"witness-commit/1|body|" + salt + canonical(body))


def b64url_decode(s):
    s = s.strip()
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def pae(payload_type, payload):
    t = payload_type.encode("utf-8")
    return b"DSSEv1 %d %s %d %s" % (len(t), t, len(payload), payload)


OUTCOME = {("positive", True): "SUPPORTED", ("positive", False): "NOT_SUPPORTED",
           ("negative", True): "NOT_SUPPORTED", ("negative", False): "SUPPORTED"}


def outcome_for(finding_class, assertion):
    return OUTCOME.get((finding_class, bool(assertion)), "CANNOT_WITNESS")


def agent_message(witness_id, claim, evidence, nonce, agent_time):
    refs = sorted([e["sha256"] for e in evidence if e.get("kind") == "object"] + [e["url"] for e in evidence if e.get("kind") == "url"]
                  + [e["id"] for e in evidence if e.get("kind") in ("observation", "record")])
    return canonical({"witness_id": witness_id, "claim_id": claim_id(claim), "evidence": refs, "nonce": nonce, "agent_time": agent_time})


# ---------------------------------------------------------------------------------------------------------------------


# ---------------------------------------------------------------------------------------------------------------------
# step 4: the seal (RFC 9162 §2.1.3.2, restated from claim_witness.merkle)


def merkle_root_from_path(leaf_hex, index, size, path_hex):
    """The root a leaf and its inclusion path give in a tree of `size` leaves, or None when they cannot fit."""
    try:
        r = bytes.fromhex(leaf_hex)
        hashes = [bytes.fromhex(x) for x in path_hex]
    except (TypeError, ValueError):
        return None
    if not (isinstance(index, int) and isinstance(size, int)) or isinstance(index, bool) or not 0 <= index < size or len(r) != 32:
        return None
    fn, sn = index, size - 1
    for x in hashes:
        if len(x) != 32 or sn == 0:
            return None
        if fn & 1 or fn == sn:
            r = hashlib.sha256(b"\x01" + x + r).digest()
            if not fn & 1:
                while fn and not fn & 1:
                    fn >>= 1
                    sn >>= 1
        else:
            r = hashlib.sha256(b"\x01" + r + x).digest()
        fn >>= 1
        sn >>= 1
    return r.hex() if sn == 0 else None


def _utc(value):
    """An RFC 3339 time as YYYY-MM-DDTHH:MM:SSZ (UTC, seconds), or None."""
    import datetime
    if not isinstance(value, str):
        return None
    try:
        t = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if t.tzinfo is None:
        return None
    return t.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _secs(t):
    import calendar
    import time as _t
    return calendar.timegm(_t.strptime(t, "%Y-%m-%dT%H:%M:%SZ"))


# step 4, the anchor transaction (BD21): read only when --rpc is given. Measured on Base Sepolia: a seal is one transaction to
# 0x0 whose input is the UTF-8 JSON datablock {"correlationId", "previousChunkBlockId", "chunkData", "mode": "hash",
# "payload": {"label", "over": "sha256:<hex>"}}.

CHAIN = "base-sepolia"
CHAIN_TIMEOUT_S = 20
# own model key (C2): a batch header with anchoring "own" was sealed on OneDroid's own chain (lab-qbft) only
OWN_INFO = ("INFO anchoring: own chain only (a check paid with the user's own model key is not anchored on a public chain)")
ZERO_ADDRESS = "0x" + "0" * 40
_ADDRESS = re.compile(r"^0x[0-9a-fA-F]{40}$")


class ChainError(Exception):
    """The RPC could not be reached or did not answer a result."""


def _origin(rpc):
    """scheme://host:port of the RPC URL: what a failure names (a path or userinfo may carry an API key)."""
    import urllib.parse
    u = urllib.parse.urlsplit(rpc)
    return f"{u.scheme}://{u.hostname}" + (f":{u.port}" if u.port else "")


def _rpc_call(rpc, method, params, timeout=CHAIN_TIMEOUT_S):
    import urllib.error
    import urllib.request
    where = f"RPC {_origin(rpc)}"
    if not rpc.lower().startswith(("http://", "https://")):
        raise ChainError(f"{where} is not an http(s) URL")
    req = urllib.request.Request(rpc, data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(),
                                 headers={"content-type": "application/json", "user-agent": "witness-verify"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            doc = json.loads(resp.read(8_000_000))
    except (OSError, ValueError) as e:  # URLError, HTTPError, timeouts and refused connections are OSError
        raise ChainError(f"{where} could not be read for {method}: {type(e).__name__}") from None
    if not isinstance(doc, dict):
        raise ChainError(f"{where} answered {method} with something that is not a JSON-RPC response")
    if "error" in doc:
        raise ChainError(f"{where} answered {method} with an error")
    if "result" not in doc:
        raise ChainError(f"{where} answered {method} without a result")
    return doc["result"]


def _hex_int(v):
    if not isinstance(v, str) or not re.fullmatch(r"0x[0-9a-fA-F]+", v):
        raise ValueError("not a hex quantity")
    return int(v, 16)


def _sealers_for(kl, flag_addresses):
    """The base-sepolia sealer entries the sender is judged against, or None when none is named. `--sealer ADDRESS` (the
    verifier's own trust) replaces the key list's `sealers`; otherwise the key list's entries for base-sepolia."""
    if flag_addresses:
        return [{"chain": CHAIN, "address": a, "valid_from": "", "valid_to": None} for a in flag_addresses]
    listed = [s for s in ((kl or {}).get("sealers") or []) if isinstance(s, dict) and s.get("chain") == CHAIN and s.get("address")]
    return listed or None


def check_anchor_tx(rpc, anchor, over, sealers=None, timeout=CHAIN_TIMEOUT_S):
    """Read one base-sepolia anchor transaction. (True, what was proven) or (False, the reason by name). PASS only when the
    transaction exists, is to 0x0, carries a hash-mode datablock whose payload.over is `over`, sits in the anchor's block, and
    that block's timestamp is the anchor's block_time (to the second). `sealers` (entries with address, valid_from, valid_to)
    names who may have sent it at the block time; None says the sender was not checked."""
    import time as _t
    tx_hash, what = anchor.get("tx_hash"), f"{anchor.get('chain')} tx {anchor.get('tx_hash')}"
    try:
        tx = _rpc_call(rpc, "eth_getTransactionByHash", [tx_hash], timeout)
        if not isinstance(tx, dict):
            return False, f"{what}: transaction not found on {_origin(rpc)}"
        if str(tx.get("to") or "").lower() != ZERO_ADDRESS:
            return False, f"{what}: not to 0x0 (to {tx.get('to')})"
        try:
            block = _hex_int(tx.get("blockNumber"))
        except ValueError:
            return False, f"{what}: not found in a block (still pending)"
        try:
            data = json.loads(bytes.fromhex(str(tx.get("input"))[2:]).decode("utf-8"))
            carried = data["payload"]["over"]
            is_hash = data["mode"] == "hash" and isinstance(carried, str)
        except (ValueError, KeyError, TypeError, AttributeError):
            is_hash = False
        if not is_hash:
            return False, f"{what}: the input is not a hash-mode datablock with a payload.over"
        if carried != over:
            return False, f"{what}: different over (the transaction carries {carried}, the seal's is {over})"
        if block != anchor.get("block"):
            return False, f"{what}: block mismatch (the transaction is in block {block}, the anchor says {anchor.get('block')})"
        blk = _rpc_call(rpc, "eth_getBlockByNumber", [hex(block), False], timeout)
        if not isinstance(blk, dict) or blk.get("hash") != tx.get("blockHash") or _hex_int(blk.get("number")) != block:
            return False, f"{what}: block mismatch (block {block} on {_origin(rpc)} is not the transaction's block)"
        stamp = _t.strftime("%Y-%m-%dT%H:%M:%SZ", _t.gmtime(_hex_int(blk.get("timestamp"))))
        if stamp != _utc(anchor.get("block_time")):
            return False, f"{what}: time mismatch (the block's timestamp is {stamp}, the anchor says {anchor.get('block_time')})"
    except ChainError as e:
        return False, f"{what}: {e}"
    except (ValueError, TypeError):
        return False, f"{what}: {_origin(rpc)} answered something unreadable"
    sender = str(tx.get("from") or "")
    if sealers is None:
        who = "the sender was not checked against a sealer list (the key list names none for base-sepolia and no --sealer was given)"
    elif any(str(s.get("address", "")).lower() == sender.lower() and (s.get("valid_from") or "") <= stamp
             and (s.get("valid_to") is None or stamp <= s["valid_to"]) for s in sealers):
        who = f"the sender is a listed sealer at {stamp}"
    else:
        return False, f"{what}: the sender {sender} is not a sealer for {anchor.get('chain')} at {stamp}"
    return True, f"{what} in block {block}, sent by {sender}; over {over} matches, to 0x0, block time {stamp}; {who}"


def check_chain(r, rpc, landed, over, sealers):
    """Step 4's seal-chain over the landed anchors: every base-sepolia anchor is read through `rpc`; any other chain (lab-qbft is
    the operator's own) is a SKIP, never claimed as checked. Returns the earliest block time of the base-sepolia anchors that
    passed (equal to their block_time to the second), or None."""
    passed = []
    for a in landed:
        if a.get("chain") != CHAIN:
            r.skip("seal-chain", f"{a.get('chain')} is the operator's own chain, not claimed as checked by this RPC "
                                 f"(tx {a.get('tx_hash')})")
            continue
        ok, text = check_anchor_tx(rpc, a, over, sealers)
        if ok:
            r.ok("seal-chain", text)
            passed.append(_utc(a.get("block_time")))
        else:
            r.fail("seal-chain", text)
    return min(passed) if passed else None


def check_seal(r, seal, raw, keys, kl, skip_text):
    """Step 4. Returns (failed, anchor): failed is True when the seal fails for a structural reason (path, header key or
    signature, witness, over, notary result, block time); anchor is the earliest landed block_time (UTC string) when one can be
    read from an anchored seal, else None. The header's key revoked at or before the anchor time, or the batch closing outside
    its validity, is key validity, not the seal: it is its own `key-validity` FAIL here, and the record's key is judged in step 5."""
    if not isinstance(seal, dict) or "batch_header" not in seal:
        r.skip("seal", skip_text)
        return False, None
    errs, key_errs, anchor = [], [], None
    try:
        hdr = seal["batch_header"]
        # own model key (C2): the signed header says how the batch is anchored; a header without the field is public
        anchoring = hdr.get("anchoring", "public") if isinstance(hdr, dict) else "public"
        if anchoring == "own":
            r.line(OWN_INFO)
            public = sorted({f"{a.get('chain')} (tx {a.get('tx_hash')})" for a in (seal.get("notary") or {}).get("anchors") or []
                             if isinstance(a, dict) and a.get("chain") == CHAIN})
            if public:
                errs.append(f"the batch header says anchoring: own (OneDroid's own chain only) but the seal carries a {CHAIN} "
                            f"anchor: {', '.join(public)}")
        elif anchoring != "public":
            errs.append(f"the batch header's anchoring is {anchoring!r}, not public or own")
        leaf = sha256_hex(b"\x00" + raw)
        root = merkle_root_from_path(leaf, seal["leaf_index"], hdr["size"], seal["path"])
        if root is None or root != hdr["root"]:
            errs.append("the leaf and its path do not give the batch root")
        unsigned = {k: v for k, v in hdr.items() if k != "sig"}
        entry = (keys or {}).get(hdr.get("key_id"))
        if entry is None:
            errs.append(f"the batch header's key {hdr.get('key_id')!r} is not in the key list")
        elif not ed25519_verify(base64.b64decode(entry["public"]), base64.b64decode(hdr["sig"], validate=True),
                                pae(BATCH_PAYLOAD_TYPE, canonical(unsigned))):
            errs.append("the batch header's signature does not verify")
        if kl is not None and hdr.get("witness") != kl.get("witness"):
            errs.append(f"the batch header names {hdr.get('witness')!r}, the key list {kl.get('witness')!r}")
        anchored = seal.get("state") == "anchored"
        if anchored:
            notary = seal.get("notary") or {}
            if notary.get("over") != "sha256:" + sha256_hex(canonical(hdr)):
                errs.append("the notary's over is not sha256 of the canonical signed batch header")
            landed = [a for a in notary.get("anchors") or [] if isinstance(a, dict) and a.get("state") == "landed" and a.get("tx_hash")]
            if notary.get("status") != "landed" or not landed:
                errs.append("the notary result is not landed on a chain")
            times = sorted(t for t in (_utc(a.get("block_time")) for a in landed) if t)
            if landed and not times:
                errs.append("no landed anchor carries a block_time")
            anchor = times[0] if times else None
            if anchor and entry is not None:
                if entry.get("revoked_at") and entry["revoked_at"] <= anchor:
                    key_errs.append(f"the batch header's key {hdr.get('key_id')} was revoked at {entry['revoked_at']} "
                                    f"({entry.get('revoke_reason')}), before the anchor time {anchor}")
                closed = hdr.get("closed_at", "")
                if not (entry.get("valid_from", "") <= closed and (entry.get("valid_to") is None or closed <= entry["valid_to"])):
                    key_errs.append(f"the batch closed at {closed}, outside its header key's validity "
                                    f"{entry.get('valid_from')}..{entry.get('valid_to')}")
    except (KeyError, TypeError, ValueError, AttributeError) as e:
        errs.append(f"unreadable seal: {type(e).__name__}")
    if errs:
        r.fail("seal", "; ".join(errs))
        if key_errs:
            r.fail("key-validity", "; ".join(key_errs))
        return True, anchor
    if not anchored:
        r.skip("seal", f"batched (leaf {seal['leaf_index']} of {hdr['size']}: the path and the header verify) but not anchored: "
                       "the time is not proven")
        return False, None
    chains = ", ".join(sorted({a.get("chain") or "?" for a in landed}))
    r.ok("seal", f"leaf {seal['leaf_index']} of batch {hdr['batch_id'][:16]}... (size {hdr['size']}) gives its root; header "
                 f"signed by {hdr['key_id']}; notary over matches; anchored on {chains} at {anchor}")
    rpc = getattr(r, "rpc", None)
    if not rpc:
        r.skip("seal-chain", "the anchor transaction itself was not read: give --rpc URL (a Base Sepolia JSON-RPC endpoint, "
                             "e.g. https://sepolia.base.org) to read it here, or check it with armarium's POST /notary/v1/verify "
                             "{over, chain, tx_hash}")
    else:
        chain_time = check_chain(r, rpc, landed, notary["over"], _sealers_for(kl, getattr(r, "sealer_flags", ())))
        if chain_time:  # the chain's own block time, equal to the anchor's block_time to the second
            anchor = chain_time
    if key_errs:
        r.fail("key-validity", "; ".join(key_errs))
    return False, anchor


def key_validity(r, entry, kid, at, anchor, interval_s=None, what="payload"):
    """Step 5. Sealed (anchor given): a key revoked at or before the anchor time fails; otherwise `at` must lie in the key's
    validity. Unsealed: a revoked key fails, because the payload cannot prove it was signed before the revocation."""
    if anchor is None:
        if entry.get("revoked_at"):
            r.fail("key-validity", f"key {kid} was revoked at {entry['revoked_at']} ({entry.get('revoke_reason')}); an unsealed "
                                   f"{what} cannot prove it was signed before that")
            return
        ok = entry.get("valid_from", "") <= at and (entry.get("valid_to") is None or at <= entry["valid_to"])
        r.check("key-validity", ok, f"{at} is outside the key's validity {entry.get('valid_from')}..{entry.get('valid_to')}",
                f"{kid} valid at the {what}'s own time {at} (not proven until sealed)")
        return
    try:
        early = _secs(anchor) + ANCHOR_SKEW_S < _secs(at)
    except ValueError:
        early = True
    if early:
        r.fail("key-validity", f"anchored at {anchor}, before the {what}'s own time {at}: the times are not consistent")
        return
    if entry.get("revoked_at") and entry["revoked_at"] <= anchor:
        r.fail("key-validity", f"key {kid} was revoked at {entry['revoked_at']} ({entry.get('revoke_reason')}), before the "
                               f"anchor time {anchor}")
        return
    ok = entry.get("valid_from", "") <= at and (entry.get("valid_to") is None or at <= entry["valid_to"])
    if r.check("key-validity", ok, f"{at} is outside the key's validity {entry.get('valid_from')}..{entry.get('valid_to')}",
               f"{kid} valid at {at}, anchored at {anchor} before any revocation"):
        try:
            if interval_s is not None and _secs(anchor) - _secs(at) > int(interval_s) + SEAL_GRACE_S:
                r.line(f"FLAG seal-delay: anchored {_secs(anchor) - _secs(at)} s after {at}, more than interval_s "
                       f"{interval_s} + {SEAL_GRACE_S} s")
        except ValueError:
            pass


class Report:
    def __init__(self, out):
        self.out, self.failed, self.nfail = out, False, 0
        self.rpc, self.sealer_flags = None, ()  # --rpc URL and --sealer ADDRESS: the anchor transaction is read only with an RPC

    def line(self, text):
        print(text, file=self.out)

    def ok(self, name, note=""):
        self.line(f"PASS {name}" + (f": {note}" if note else ""))

    def fail(self, name, why):
        self.failed = True
        self.nfail += 1
        self.line(f"FAIL {name}: {why}")
        return False

    def skip(self, name, why):
        self.line(f"SKIP {name}: {why}")

    def check(self, name, cond, why, note=""):
        if cond:
            self.ok(name, note)
            return True
        return self.fail(name, why)


def _read_json(path):
    return json.loads(pathlib.Path(path).read_text(encoding="utf-8"))


def _envelope_payload(env):
    return base64.b64decode(env["payload"], validate=True)


def _verify_sig(env, keyid, public):
    for s in env.get("signatures") or []:
        if s.get("keyid") == keyid:
            try:
                sig = base64.b64decode(s["sig"], validate=True)
            except ValueError:
                return False
            return ed25519_verify(public, sig, pae(env["payloadType"], _envelope_payload(env)))
    return False


def check_key_list(r, env, trusted):
    """(key list predicate, {key_id: entry}) or (None, None)."""
    try:
        st = loads_strict(_envelope_payload(env))
        kl = st["predicate"]
        if st.get("_type") != STATEMENT_TYPE or st.get("predicateType") != KEYLIST_TYPE:
            raise ValueError("not a key-list statement")
        if st["subject"][0]["digest"]["sha256"] != sha256_hex(canonical(kl)):
            raise ValueError("the subject digest is not the key list's fingerprint")
        keys = {k["key_id"]: k for k in kl["keys"]}
        for k in keys.values():
            if k.get("alg") != "ed25519" or len(base64.b64decode(k["public"], validate=True)) != 32:
                raise ValueError(f"key {k.get('key_id')}: not a 32-byte ed25519 public key")
    except (KeyError, IndexError, TypeError, ValueError) as e:
        r.fail("key-list", f"unreadable: {e}")
        return None, None
    signers = set()
    for s in env.get("signatures") or []:
        kid = s.get("keyid")
        if kid not in keys or not _verify_sig(env, kid, base64.b64decode(keys[kid]["public"])):
            r.fail("key-list", f"signature by {kid!r} does not verify with a key in the list")
            return None, None
        signers.add(kid)
    need = 1 if kl.get("seq") == 1 else 2
    if len(signers) < need:
        r.fail("key-list", f"seq {kl.get('seq')} needs {need} signatures (outgoing and incoming key), has {len(signers)}")
        return None, None
    r.ok("key-list", f"{'trusted list' if trusted else 'bundled list'} seq {kl.get('seq')} of {kl.get('witness')}, "
                     f"signed by {', '.join(sorted(signers))}")
    return kl, keys


def _safe_extract(data, dest):
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
        for m in tf.getmembers():
            parts = pathlib.PurePosixPath(m.name).parts
            if m.name.startswith("/") or ".." in parts or not (m.isfile() or m.isdir()) or not parts or parts[0] != "witness_methods":
                raise ValueError(f"unsafe or unexpected tar member {m.name!r}")
        for m in tf.getmembers():
            target = pathlib.Path(dest, *pathlib.PurePosixPath(m.name).parts)
            if m.isdir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(tf.extractfile(m).read())


def _load_methods(tar_bytes):
    d = tempfile.mkdtemp(prefix="witness-methods-")
    _safe_extract(tar_bytes, d)
    pkg = pathlib.Path(d) / "witness_methods"
    name = "witness_methods_" + sha256_hex(tar_bytes)[:16]
    spec = importlib.util.spec_from_file_location(name, pkg / "__init__.py", submodule_search_locations=[str(pkg)])
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def _record_of(doc):
    """(record id, {envelope, seal}) from a JSON document holding a record's envelope (an answer, a record view, a bundle's
    envelope.json with its seal.json beside it), or None."""
    try:
        env = doc["envelope"] if "envelope" in doc else doc
        return sha256_hex(_envelope_payload(env)), {"envelope": env, "seal": doc.get("seal") if "envelope" in doc else None}
    except (KeyError, TypeError, ValueError, AttributeError):
        return None


def _observation_of(folder, expect_name):
    """(id, {envelope, seal, disclosure, files: [bytes], expect_id}) from an observation folder (a bundle's observations/<id>/:
    envelope.json, seal.json, disclosure.json, files/<name>), or None when it holds no readable envelope. A bundle's folder is
    named by the id it claims, and the id is then expected (a folder holding another observation fails its record-id check);
    for --observation DIR the id is the payload's hash."""
    try:
        env = _read_json(folder / "envelope.json")
        oid = sha256_hex(_envelope_payload(env))
    except (OSError, KeyError, TypeError, ValueError, AttributeError):
        return None
    one = {"envelope": env, "seal": None, "disclosure": None, "files": [], "expect_id": folder.name if expect_name else None}
    for key, name in (("seal", "seal.json"), ("disclosure", "disclosure.json")):
        if (folder / name).is_file():
            one[key] = _read_json(folder / name)
    if (folder / "files").is_dir():
        one["files"] = [p.read_bytes() for p in sorted((folder / "files").iterdir()) if p.is_file()]
    return (folder.name if expect_name else oid), one


def _compare(r, lib, method, claim, view, res):
    outcome = outcome_for(lib.finding_class(method["id"], res.finding), claim["assertion"])
    statement = lib.render_statement(method["id"], claim["assertion"], res.vars)
    diffs = []
    for name, got, want in (("finding", res.finding, view["finding"]), ("reason", res.reason, view["reason"]),
                            ("outcome", outcome, view["outcome"]), ("detail", res.detail, view["detail"]),
                            ("statement", statement, view.get("statement", statement)), ("limits", lib.get(method["id"]).limits,
                                                                                         view["limits"])):
        if got != want:
            diffs.append(f"{name}: re-run gives {got!r}, record has {want!r}")
    r.check("method-rerun", not diffs, "; ".join(diffs), f"{method['id']} {lib.get(method['id']).version} re-ran to "
                                                         f"{res.finding or res.reason}")


def rerun_record_method(r, view, files, tar_bytes, records):
    """B5b: record.valid and record.disclose re-run from the tarball over the record they name (its envelope and seal, given
    with --record or in a bundle's records/<id>/) and the object they carry (the key list, or the disclosure), pure over those
    inputs. A record's seal is the one the check saw: a seal that has moved on (pending, then anchored) gives another answer."""
    method, claim, evidence = view["method"], view["claim"], view["evidence"]
    by_sha = {sha256_hex(b): b for b in files}
    wanted = {e["sha256"] for e in evidence if e.get("kind") == "object"}
    if files:
        extra = sorted(set(by_sha) - wanted)
        r.check("bundle-files", not extra, f"file(s) {', '.join(x[:12] for x in extra)} match no evidence fingerprint in the record",
                f"{len(by_sha)} file(s) match their fingerprints")
    if tar_bytes is None:
        r.skip("method-rerun", f"no methods tarball given (--methods); the record names methods tarball sha256 {method['code_sha256']}")
        return
    if not r.check("methods-tarball", sha256_hex(tar_bytes) == method["code_sha256"],
                   f"tarball sha256 {sha256_hex(tar_bytes)[:16]}... is not the record's code_sha256 {method['code_sha256'][:16]}..."):
        return
    ref = next((e for e in evidence if e.get("kind") == "record"), None)
    if ref is None or ref["id"] not in (records or {}):
        r.skip("method-rerun", "the checked record is not given (--record FILE, or a bundle's records/<id>/envelope.json)")
        return
    missing = sorted(wanted - set(by_sha))
    if missing:
        r.skip("method-rerun", f"evidence bytes not given for {', '.join(m[:12] for m in missing)}")
        return
    try:
        lib = _load_methods(tar_bytes)
    except Exception as e:  # noqa: BLE001
        r.fail("method-rerun", f"the tarball does not load: {type(e).__name__}: {e}")
        return
    m = lib.get(method["id"])
    if m is None or m.version != method["version"]:
        r.fail("method-rerun", f"the tarball has {method['id']} {m.version if m else None}, the record names {method['version']}")
        return
    ev = {e["slot"]: dict(e, data=by_sha[e["sha256"]]) for e in evidence if e.get("kind") == "object"}
    got = records[ref["id"]]
    ev[ref["slot"]] = {"slot": ref["slot"], "kind": "record", "id": ref["id"], "envelope": got["envelope"], "seal": got["seal"],
                       "ed25519_verify": ed25519_verify}
    _compare(r, lib, method, claim, view, lib.run(method["id"], claim["params"], ev))


NOT_READ_BY_METHODS = ("capture.wacz", "screenshot.png")  # no pure method reads these two, so a bundle may leave them out


def _observation_for_rerun(r, oid, observations, keys, kl, tar_bytes):
    """One observation of the bundle, verified as any observation is (signature, id, manifest, files against the manifest,
    text.canonical.txt, seal) and only then offered to a method: ("ok", evidence) | ("skip", why) | ("fail", why)."""
    got = (observations or {}).get(oid)
    if got is None:
        return "skip", f"observation {oid} is not in the bundle (observations/{oid}/)"
    try:
        env = got["envelope"]
        raw = _envelope_payload(env)
        st = loads_strict(raw)
        st["predicate"]
    except (KeyError, TypeError, ValueError) as e:
        r.fail("payload", f"observation {oid}: unreadable envelope payload: {e}")
        return "fail", f"observation {oid} has an unreadable envelope"
    if st.get("predicateType") != OBSERVATION_TYPE:
        r.fail("payload", f"observation {oid}: predicateType {st.get('predicateType')!r} is not {OBSERVATION_TYPE}")
        return "fail", f"observation {oid} is not an observation statement"
    if env.get("payloadType") != PAYLOAD_TYPE:
        r.fail("signature", f"payloadType {env.get('payloadType')!r} is not {PAYLOAD_TYPE}")
    ok, manifest, named = run_observation_checks(r, env, keys, st, raw, list(got["files"]), tar_bytes, got.get("expect_id"),
                                                 got.get("disclosure"), got.get("seal"), kl)
    if not ok or env.get("payloadType") != PAYLOAD_TYPE:
        return "fail", f"observation {oid} failed its own checks (above): its files are not handed to the method"
    if manifest is None:
        return "skip", (f"observation {oid} is private: its manifest needs observations/{oid}/disclosure.json "
                        "(--observation DIR with a disclosure.json)")
    missing = sorted(f["name"] for f in manifest.get("files") or [] if f["name"] not in named and f["name"] not in NOT_READ_BY_METHODS)
    if missing:
        return "skip", f"observation {oid} lacks file(s) its manifest lists: {', '.join(missing)}"
    return "ok", {"slot": None, "kind": "observation", "id": oid, "manifest": manifest, "files": named}


def rerun_observed(r, view, files, tar_bytes, observations, keys, kl):
    """Step 6 for a pure method whose evidence holds observations (page.live, match.text, post.by-author): each observation the
    evidence names (an `observation` item's id, a `url` item's `observations`) is read from the bundle's observations/<id>/,
    verified, and given to the method exactly as the server gives it: an observation evidence item
    {slot, kind, id, manifest, files}, and for page.live {slot, kind: url, url, attempts: [{observation}, ...]} in the
    order the record lists them. A fetch that failed left no observation, so it is a SKIP, never a FAIL."""
    method, claim, evidence = view["method"], view["claim"], view["evidence"]
    by_sha = {sha256_hex(b): b for b in files}
    wanted = {e["sha256"] for e in evidence if e.get("kind") == "object"}
    if files:
        extra = sorted(set(by_sha) - wanted)
        r.check("bundle-files", not extra, f"file(s) {', '.join(x[:12] for x in extra)} match no evidence fingerprint in the record",
                f"{len(by_sha)} file(s) match their fingerprints")
    if tar_bytes is None:
        r.skip("method-rerun", f"no methods tarball given (--methods); the record names methods tarball sha256 {method['code_sha256']}")
        return
    if not r.check("methods-tarball", sha256_hex(tar_bytes) == method["code_sha256"],
                   f"tarball sha256 {sha256_hex(tar_bytes)[:16]}... is not the record's code_sha256 {method['code_sha256'][:16]}..."):
        return
    missing = sorted(wanted - set(by_sha))
    if missing:
        r.skip("method-rerun", f"evidence bytes not given for {', '.join(m[:12] for m in missing)}")
        return
    ids = {}
    for e in evidence:
        if e.get("kind") == "observation":
            ids[e["slot"]] = [e["id"]]
        elif e.get("kind") == "url":
            ids[e["slot"]] = list(e.get("observations") or [])
            if not ids[e["slot"]]:
                r.skip("method-rerun", f"the url evidence {e.get('url')!r} left no observation (its fetch failed): nothing to re-run")
                return
    got, problems, skips = {}, [], []
    for slot, oids in ids.items():
        for oid in oids:
            state, val = _observation_for_rerun(r, oid, observations, keys, kl, tar_bytes)
            if state == "ok":
                got[oid] = dict(val, slot=slot)
            elif state == "fail":
                problems.append(val)
            else:
                skips.append(val)
    if problems:
        r.fail("method-rerun", "; ".join(problems))
        return
    if skips:
        r.skip("method-rerun", "; ".join(skips))
        return
    try:
        lib = _load_methods(tar_bytes)
    except Exception as e:  # noqa: BLE001
        r.fail("method-rerun", f"the tarball does not load: {type(e).__name__}: {e}")
        return
    m = lib.get(method["id"])
    if m is None or not m.mechanical:
        r.skip("method-rerun", f"{method['id']} is not a pure-Python method in this tarball")
        return
    if m.version != method["version"]:
        r.fail("method-rerun", f"the tarball has {method['id']} {m.version}, the record names {method['version']}")
        return
    ev = {}
    for e in evidence:
        if e.get("kind") == "object":
            ev[e["slot"]] = dict(e, data=by_sha[e["sha256"]])
        elif e.get("kind") == "observation":
            ev[e["slot"]] = got[e["id"]]
        elif e.get("kind") == "url":
            seen = [got[o] for o in ids[e["slot"]]]
            if method["id"] == "page.live":
                ev[e["slot"]] = {"slot": e["slot"], "kind": "url", "url": e["url"], "attempts": [{"observation": o} for o in seen]}
            else:
                ev[e["slot"]] = seen[0]
    res = lib.run(method["id"], claim["params"], ev)
    if method["id"] == "page.live" and res.reason == "undecided" and "confirm_after_s" not in res.detail \
            and len(ids.get("page") or []) < 2:
        r.skip("method-rerun", "the first look said gone and its confirming fetch left no observation: the confirmation cannot be re-run")
        return
    _compare(r, lib, method, claim, view, res)


def rerun_image_text(r, view, files, tar_bytes):
    """Step 6 for match.image-text (NS-11): the model's reading of the image is not re-run (it needs the model); rule R1 is,
    from the tarball, over the transcription the record keeps in its body (judgment.transcription), and must give the record's
    finding, reason, outcome, detail, statement and limits and the judgment's missing tokens. The transcription must be its
    recorded sha256 and the prompt the tarball's. The image bytes, when given, are fingerprinted against the record."""
    method, claim, evidence = view["method"], view["claim"], view["evidence"]
    by_sha = {sha256_hex(b): b for b in files}
    wanted = {e["sha256"] for e in evidence if e.get("kind") == "object"}
    if files:
        extra = sorted(set(by_sha) - wanted)
        r.check("bundle-files", not extra, f"file(s) {', '.join(x[:12] for x in extra)} match no evidence fingerprint in the record",
                f"{len(by_sha)} file(s) match their fingerprints")
    if tar_bytes is None:
        r.skip("method-rerun", f"no methods tarball given (--methods); the record names methods tarball sha256 {method['code_sha256']}")
        return
    if not r.check("methods-tarball", sha256_hex(tar_bytes) == method["code_sha256"],
                   f"tarball sha256 {sha256_hex(tar_bytes)[:16]}... is not the record's code_sha256 {method['code_sha256'][:16]}..."):
        return
    try:
        lib = _load_methods(tar_bytes)
    except Exception as e:  # noqa: BLE001
        r.fail("method-rerun", f"the tarball does not load: {type(e).__name__}: {e}")
        return
    m = lib.get(method["id"])
    mod = getattr(lib, "match_image_text", None)
    if m is None or mod is None:
        r.skip("method-rerun", f"{method['id']} is not a pure-Python method in this tarball")
        return
    if m.version != method["version"]:
        r.fail("method-rerun", f"the tarball has {method['id']} {m.version}, the record names {method['version']}")
        return
    j = view.get("judgment")
    if not isinstance(j, dict) or "transcription" not in j:
        r.fail("method-rerun", "the record carries no transcription (judgment.transcription): R1 cannot be re-run")
        return
    text = j["transcription"]
    if text is None:
        r.check("transcription-sha256", j.get("transcription_sha256") is None,
                "the record names a transcription sha256 but no transcription", "no transcription (every model failed)")
    else:
        r.check("transcription-sha256", isinstance(text, str) and sha256_hex(text.encode("utf-8")) == j.get("transcription_sha256"),
                "the recorded transcription is not the sha256 the record names", j.get("transcription_sha256") or "")
    r.check("transcription-prompt", j.get("prompt_sha256") == mod.PROMPT_SHA256,
            f"the record's prompt_sha256 {str(j.get('prompt_sha256'))[:16]}... is not this tarball's prompt {mod.PROMPT_SHA256[:16]}...",
            mod.PROMPT_SHA256)
    r.skip("transcription-rerun", "the model's reading of the image is not re-run offline (it needs the model); R1 is re-run "
                                  "over the recorded transcription")
    img = next((e for e in evidence if e.get("kind") == "object" and e.get("slot") == "image"), None)
    if img is None:
        r.fail("method-rerun", "the record has no image evidence")
        return
    tr = None if text is None else {"text": text, "truncated": bool(j.get("truncated"))}
    ev = {"image": dict(img, data=by_sha.get(img["sha256"]), transcription=tr)}
    res = lib.run(method["id"], claim["params"], ev)
    outcome = outcome_for(lib.finding_class(method["id"], res.finding), claim["assertion"])
    statement = lib.render_statement(method["id"], claim["assertion"], res.vars)
    diffs = []
    checks = [("finding", res.finding, view["finding"]), ("reason", res.reason, view["reason"]),
              ("outcome", outcome, view["outcome"]), ("detail", res.detail, view["detail"]),
              ("statement", statement, view.get("statement", statement)), ("limits", m.limits, view["limits"])]
    if text is not None:
        rule = mod.r1(claim["params"]["text"], text)
        checks += [("missing_tokens", rule["missing_tokens"], j.get("missing_tokens")),
                   ("missing_number_tokens", rule["missing_number_tokens"], j.get("missing_number_tokens"))]
    for name, got, want in checks:
        if got != want:
            diffs.append(f"{name}: re-run gives {got!r}, record has {want!r}")
    r.check("method-rerun", not diffs, "; ".join(diffs),
            f"{method['id']} {m.version} re-ran R1 over the recorded transcription to {res.finding or res.reason}")
def rerun(r, view, files, tar_bytes, records=None, observations=None, keys=None, kl=None):
    """Step 6: files are fingerprinted; the method re-runs from the tarball and must give the record's finding."""
    method, claim, evidence = view["method"], view["claim"], view["evidence"]
    if method["id"] in RECORD_METHODS:
        rerun_record_method(r, view, files, tar_bytes, records)
        return
    if method["id"] in NEEDS_IMAGE:
        r.skip("method-rerun", "re-run skipped (needs image)")
        return
    if method["id"] in IMAGE_TEXT:
        rerun_image_text(r, view, files, tar_bytes)
        return
    if any(e.get("kind") != "object" for e in evidence):
        rerun_observed(r, view, files, tar_bytes, observations, keys, kl)
        return
    by_sha = {sha256_hex(b): b for b in files}
    wanted = {e["sha256"] for e in evidence if e.get("kind") == "object"}
    if files:
        extra = sorted(set(by_sha) - wanted)
        r.check("bundle-files", not extra, f"file(s) {', '.join(x[:12] for x in extra)} match no evidence fingerprint in the record",
                f"{len(by_sha)} file(s) match their fingerprints")
    if tar_bytes is None:
        r.skip("method-rerun", f"no methods tarball given (--methods); the record names methods tarball sha256 {method['code_sha256']}")
        return
    if not r.check("methods-tarball", sha256_hex(tar_bytes) == method["code_sha256"],
                   f"tarball sha256 {sha256_hex(tar_bytes)[:16]}... is not the record's code_sha256 {method['code_sha256'][:16]}..."):
        return
    missing = sorted(wanted - set(by_sha))
    if missing:
        r.skip("method-rerun", f"evidence bytes not given for {', '.join(m[:12] for m in missing)}")
        return
    try:
        lib = _load_methods(tar_bytes)
    except Exception as e:  # noqa: BLE001
        r.fail("method-rerun", f"the tarball does not load: {type(e).__name__}: {e}")
        return
    m = lib.get(method["id"])
    if m is None or not m.mechanical:
        r.skip("method-rerun", f"{method['id']} is not a pure-Python method in this tarball")
        return
    if m.version != method["version"]:
        r.fail("method-rerun", f"the tarball has {method['id']} {m.version}, the record names {method['version']}")
        return
    ev = {e["slot"]: dict(e, data=by_sha[e["sha256"]]) for e in evidence if e.get("kind") == "object"}
    res = lib.run(method["id"], claim["params"], ev)
    outcome = outcome_for(lib.finding_class(method["id"], res.finding), claim["assertion"])
    statement = lib.render_statement(method["id"], claim["assertion"], res.vars)
    diffs = []
    for name, got, want in (("finding", res.finding, view["finding"]), ("reason", res.reason, view["reason"]),
                            ("outcome", outcome, view["outcome"]), ("detail", res.detail, view["detail"]),
                            ("statement", statement, view.get("statement", statement)), ("limits", m.limits, view["limits"])):
        if got != want:
            diffs.append(f"{name}: re-run gives {got!r}, record has {want!r}")
    r.check("method-rerun", not diffs, "; ".join(diffs), f"{method['id']} {m.version} re-ran to {res.finding or res.reason}")


def _key_validity(r, entry, kid, at):
    if entry.get("revoked_at"):
        r.fail("key-validity", f"key {kid} was revoked at {entry['revoked_at']} ({entry.get('revoke_reason')}); an unsealed "
                               "payload cannot prove it was signed before that")
    else:
        ok = entry.get("valid_from", "") <= at and (entry.get("valid_to") is None or at <= entry["valid_to"])
        r.check("key-validity", ok, f"{at} is outside the key's validity {entry.get('valid_from')}..{entry.get('valid_to')}",
                f"{kid} valid at the payload's own time {at} (not proven until sealed)")


def run_observation_checks(r, env, keys, st, raw, files, tar_bytes, expect_id, disclosure=None, seal=None, kl=None):
    """An observation envelope: id, manifest digest, key validity at fetched_at, files, text.canonical.txt. Returns (ok,
    manifest, named): ok is False when any check of this observation failed; manifest is the manifest (the public predicate,
    or a private observation's disclosed body) or None; named is {file name: bytes} for the given files that match it."""
    failed_before = r.nfail
    oid = sha256_hex(raw)
    r.line(f"observation id: {oid}")
    sig = (env.get("signatures") or [{}])[0]
    kid = sig.get("keyid")
    entry = keys.get(kid) if keys else None
    if entry is None:
        r.fail("signature", f"key {kid!r} is not in the key list")
    else:
        r.check("signature", _verify_sig(env, kid, base64.b64decode(entry["public"])), f"does not verify with {kid}", f"by {kid}")
    try:
        canon_ok = canonical(st) == raw
    except ValueError:
        canon_ok = False
    r.check("payload-canonical", canon_ok, "the payload is not RFC 8785 canonical JSON with integers only")
    r.check("record-id", expect_id is None or expect_id == oid, f"recomputed {oid}, expected {expect_id}",
            oid if expect_id is None else "matches the expected id")
    pred = st["predicate"]
    subject = st.get("subject", [{}])[0].get("digest", {}).get("sha256")
    manifest = None
    if pred.get("visibility") == "public":
        if r.check("manifest-digest", subject == sha256_hex(canonical(pred)), "the subject digest is not H(canonical manifest)"):
            manifest = pred
    elif disclosure is not None:
        try:
            salt, body = b64url_decode(disclosure["salt"]), disclosure["body"]
            if r.check("body-commitment", subject == pred.get("body_commitment") == body_commitment(salt, body),
                       "the body commitment does not match the disclosure"):
                manifest = body
        except (KeyError, TypeError, ValueError) as e:
            r.fail("body-commitment", f"unreadable disclosure: {e}")
    else:
        r.skip("manifest-digest", "private observation and no disclosure given (--disclosure)")
    seal_failed, anchor = check_seal(r, seal, raw, keys, kl, "pending: this observation is signed by its key; its time is not proven")
    if entry is not None and (anchor or not seal_failed):
        key_validity(r, entry, kid, pred.get("fetched_at", ""), anchor,
                     (seal or {}).get("batch_header", {}).get("interval_s"), "observation")
    if manifest is None:
        return r.nfail == failed_before, None, {}
    listed ={f["name"]: f["sha256"] for f in manifest.get("files") or []}
    by_sha = {sha256_hex(b): b for b in files}
    if files:
        stray = sorted(x[:12] for x in set(by_sha) - set(listed.values()))
        r.check("observation-files", not stray, f"file(s) {', '.join(stray)} match no fingerprint in the manifest",
                f"{len(by_sha)} file(s) match the manifest")
    else:
        r.skip("observation-files", "no files given (--evidence)")
    named = {n: by_sha[h] for n, h in listed.items() if h in by_sha}
    if tar_bytes is None or "rendered.html" not in named or "text.canonical.txt" not in listed:
        r.skip("text-canonical", "needs rendered.html (--evidence) and the methods tarball (--methods)")
        return r.nfail == failed_before, manifest, named
    try:
        lib = _load_methods(tar_bytes)
        text = lib.canon.canon1(named["rendered.html"], "text/html", layer="rendered").encode("utf-8")
    except Exception as e:  # noqa: BLE001
        r.fail("text-canonical", f"canon/1 from the tarball did not run: {type(e).__name__}")
        return False, manifest, named
    r.check("text-canonical", sha256_hex(text) == listed["text.canonical.txt"],
            "canon/1 of rendered.html is not the manifest's text.canonical.txt", "canon/1 of rendered.html is text.canonical.txt")
    return r.nfail == failed_before, manifest, named


def run_checks(r, env, keys_env, trusted=False, disclosure=None, agent_key=None, files=(), tar_bytes=None, expect_id=None,
               seal=None, records=None, observations=None):
    r.line("ed25519: " + ("cryptography" if _backend() is not None else "pure-python"))
    kl, keys = check_key_list(r, keys_env, trusted) if keys_env is not None else (None, None)
    if keys_env is None:
        r.fail("key-list", "no key list given (--keys, --trust or a bundle's keys.json)")
    try:
        raw = _envelope_payload(env)
        st = loads_strict(raw)
        pred = st["predicate"]
    except (KeyError, TypeError, ValueError) as e:
        r.fail("payload", f"unreadable envelope payload: {e}")
        return
    if st.get("predicateType") == OBSERVATION_TYPE:
        if env.get("payloadType") != PAYLOAD_TYPE:
            r.fail("signature", f"payloadType {env.get('payloadType')!r} is not {PAYLOAD_TYPE}")
        run_observation_checks(r, env, keys, st, raw, list(files), tar_bytes, expect_id, disclosure, seal, kl)
        return
    rid = sha256_hex(raw)
    r.line(f"record id: {rid}")
    # step 2
    sig = (env.get("signatures") or [{}])[0]
    kid = sig.get("keyid")
    entry = keys.get(kid) if keys else None
    if env.get("payloadType") != PAYLOAD_TYPE:
        r.fail("signature", f"payloadType {env.get('payloadType')!r} is not {PAYLOAD_TYPE}")
    elif entry is None:
        r.fail("signature", f"key {kid!r} is not in the key list")
    else:
        r.check("signature", _verify_sig(env, kid, base64.b64decode(entry["public"])), f"does not verify with {kid}",
                f"by {kid}")
    if kl is not None and pred.get("witness", {}).get("id") != kl.get("witness"):
        r.fail("key-list", f"the list is for {kl.get('witness')!r}, the record names {pred.get('witness', {}).get('id')!r}")
    # step 3
    try:
        canon_ok = canonical(st) == raw
    except ValueError:
        canon_ok = False
    r.check("payload-canonical", canon_ok, "the payload is not RFC 8785 canonical JSON with integers only")
    r.check("record-id", expect_id is None or expect_id == rid, f"recomputed {rid}, expected {expect_id}",
            rid if expect_id is None else "matches the expected id")
    subject = st.get("subject", [{}])[0].get("digest", {}).get("sha256")
    view = None
    if pred.get("visibility") == "public":
        r.check("claim-id", subject == claim_id(pred["claim"]), "the subject digest is not H(canonical claim)")
        view = pred
    elif disclosure is None:
        r.skip("claim-id", "private record and no disclosure given (--disclosure)")
    else:
        try:
            salt = b64url_decode(disclosure["salt"])
            body = disclosure["body"]
            r.check("claim-commitment", subject == claim_commitment(salt, body["claim"]), "the claim commitment does not match the disclosure")
            if r.check("body-commitment", pred.get("body_commitment") == body_commitment(salt, body),
                       "the body commitment does not match the disclosure"):
                view = body
        except (KeyError, TypeError, ValueError) as e:
            r.fail("claim-commitment", f"unreadable disclosure: {e}")
    # step 4
    seal_failed, anchor = check_seal(r, seal, raw, keys, kl, "pending: this record is signed by its key; its time is not proven")
    # step 5: at the anchor time when sealed (also when the seal failed but an anchor time can be read), else at the record's own time
    if entry is not None and (anchor or not seal_failed):
        key_validity(r, entry, kid, pred.get("witnessed_at", ""), anchor,
                     (seal or {}).get("batch_header", {}).get("interval_s"), "record")
    # step 6
    if view is not None:
        rerun(r, dict(view, method=pred["method"], finding=pred["finding"], outcome=pred["outcome"], reason=pred["reason"],
                      detail=pred["detail"], limits=pred["limits"]), list(files), tar_bytes, records, observations, keys, kl)
    elif files or tar_bytes:
        r.skip("method-rerun", "private record and no disclosure given")
    # step 7
    sub = (view or {}).get("submitter") or {}
    if "agent_sig" not in sub:
        r.skip("agent-signature", "no agent signature in the record" if view is not None else "private record and no disclosure")
    elif agent_key is None:
        r.skip("agent-signature", "no agent key given (--agent-key)")
    elif agent_key.get("agent_key_id") != sub.get("agent_key_id"):
        r.fail("agent-signature", f"the agent key given is {agent_key.get('agent_key_id')!r}, the record names {sub.get('agent_key_id')!r}")
    else:
        try:
            msg = agent_message(pred["witness"]["id"], view["claim"], view["evidence"], sub["nonce"], sub["agent_time"])
            ok = ed25519_verify(base64.b64decode(agent_key["public_key"]), base64.b64decode(sub["agent_sig"]), msg)
        except (KeyError, TypeError, ValueError):
            ok = False
        r.check("agent-signature", ok, "does not verify with the agent key", sub["agent_key_id"])


def main(argv=None, out=None):
    out = out or sys.stdout
    ap = argparse.ArgumentParser(prog="witness-verify", description=__doc__.split("\n\n")[0])
    ap.add_argument("--bundle")
    ap.add_argument("--envelope")
    ap.add_argument("--keys")
    ap.add_argument("--trust")
    ap.add_argument("--disclosure", help="a private record's disclosure {salt, body} (the owner or a token holder reads it from "
                                         "GET /v1/records/{id}); a bundle never carries it; also taken from DIR/disclosure.json")
    ap.add_argument("--agent-key")
    ap.add_argument("--methods")
    ap.add_argument("--evidence", action="append", default=[],
                    help="an evidence file, or a folder whose files are all read (like a bundle's evidence/); repeatable")
    ap.add_argument("--record-id")
    ap.add_argument("--record", action="append", default=[],
                    help="a record record.valid or record.disclose names: its envelope (an answer or a record view, with its seal)")
    ap.add_argument("--observation", action="append", default=[],
                    help="a folder holding an observation the record relied on: envelope.json, files/<name>, optionally seal.json and "
                         "disclosure.json (a bundle's observations/<id>/); repeatable")
    ap.add_argument("--seal", help="the seal JSON (GET /v1/records/{id}/seal); a whole answer's own seal is used otherwise")
    ap.add_argument("--rpc", help="a Base Sepolia JSON-RPC URL (e.g. https://sepolia.base.org): reads each base-sepolia anchor "
                                  "transaction of the seal (the only network use of this verifier)")
    ap.add_argument("--sealer", action="append", default=[],
                    help="an address that may have sent the anchor transaction (0x + 40 hex); repeatable; replaces the key "
                         "list's sealers. With neither, the sender is reported, not checked")
    try:
        a = ap.parse_args(argv)
    except SystemExit as e:  # --help is 0, a usage error 2: argparse's own code
        return e.code if isinstance(e.code, int) else 2
    if a.rpc is not None and not a.rpc.lower().startswith(("http://", "https://")):
        print("witness-verify: --rpc must be an http(s) URL", file=sys.stderr)
        return 2
    for s in a.sealer:
        if not _ADDRESS.match(s):
            print(f"witness-verify: --sealer {s!r} is not an address (0x and 40 hex digits)", file=sys.stderr)
            return 2
    try:  # an evidence path is a file, or a folder whose files are all read (sorted, like a bundle's evidence/)
        files, tar_bytes = [], None
        for p in map(pathlib.Path, a.evidence):
            files += [q.read_bytes() for q in sorted(p.iterdir()) if q.is_file()] if p.is_dir() else [p.read_bytes()]
    except OSError as e:
        print(f"witness-verify: cannot read input: {e}", file=sys.stderr)
        return 2
    env_path, keys_path, disc_path, agent_path, tar_path = a.envelope, a.keys, a.disclosure, a.agent_key, a.methods
    seal_path = a.seal
    if a.bundle:
        b = pathlib.Path(a.bundle)
        pick = lambda cur, name: cur or (str(b / name) if (b / name).is_file() else None)
        env_path, keys_path = pick(env_path, "envelope.json"), pick(keys_path, "keys.json")
        disc_path, agent_path = pick(disc_path, "disclosure.json"), pick(agent_path, "agent_key.json")
        seal_path = pick(seal_path, "seal.json")
        tars = sorted(b.glob("witness-methods-*.tar.gz"))
        tar_path = tar_path or (str(tars[0]) if tars else None)
        if (b / "evidence").is_dir():
            files += [p.read_bytes() for p in sorted((b / "evidence").iterdir()) if p.is_file()]
        if (b / "records").is_dir():
            for d in sorted(p for p in (b / "records").iterdir() if p.is_dir()):
                if (d / "envelope.json").is_file():
                    one = {"envelope": _read_json(d / "envelope.json")}
                    if (d / "seal.json").is_file():
                        one["seal"] = _read_json(d / "seal.json")
                    a.record.append(one)
        if (b / "observations").is_dir():
            bundled = {str(p) for p in sorted((b / "observations").iterdir()) if p.is_dir() and (p / "envelope.json").is_file()}
            a.observation += sorted(bundled)
    else:
        bundled = set()
    if not env_path:
        print("witness-verify: give --envelope or --bundle", file=sys.stderr)
        return 2
    try:
        env = _read_json(env_path)
        disclosure = _read_json(disc_path) if disc_path else None
        seal = _read_json(seal_path) if seal_path else None
        if isinstance(env, dict) and "envelope" in env:  # a whole POST /v1/witness or /v1/observe answer, or a record view
            disclosure = disclosure or env.get("disclosure")
            seal = seal if seal is not None else env.get("seal")
            env = env["envelope"]
        trusted = bool(a.trust)
        keys_env = _read_json(a.trust or keys_path) if (a.trust or keys_path) else None
        agent_key = _read_json(agent_path) if agent_path else None
        records = {}
        for x in a.record:
            got = _record_of(x if isinstance(x, dict) else _read_json(x))
            if got is not None:
                records[got[0]] = got[1]
        tar_bytes = pathlib.Path(tar_path).read_bytes() if tar_path else None
        observations = {}
        for folder in a.observation:
            got = _observation_of(pathlib.Path(folder), expect_name=folder in bundled)
            if got is not None:
                observations[got[0]] = got[1]
    except (OSError, ValueError) as e:
        print(f"witness-verify: cannot read input: {e}", file=sys.stderr)
        return 2
    r = Report(out)
    r.rpc, r.sealer_flags = a.rpc, tuple(a.sealer)
    run_checks(r, env, keys_env, trusted, disclosure, agent_key, files, tar_bytes, a.record_id, seal, records, observations)
    r.line("RESULT: " + ("FAIL" if r.failed else "PASS"))
    return 1 if r.failed else 0


if __name__ == "__main__":
    sys.exit(main())
