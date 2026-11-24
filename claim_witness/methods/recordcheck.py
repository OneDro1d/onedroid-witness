"""Shared pure helpers of record.valid and record.disclose (B5b, SPEC §4, §9).

Standard library only and no package imports: it ships in the methods tarball, so witness-verify re-runs both methods from the
tarball a record's code_sha256 names. The checks restate claim_witness/verify.py's steps 1, 2, 4 and 5 (key list, signature, seal,
key validity at the anchor time) and its canonical JSON, merkle path and commitments (test vectors check both sides). The one
thing it does not carry is Ed25519: the caller passes `ed25519_verify(public, sig, msg) -> bool` inside the record evidence
(the witness passes claim_witness.crypto's, witness-verify passes its own, pure Python under WITNESS_VERIFY_PURE=1).
"""
import base64
import binascii
import calendar
import datetime
import hashlib
import json
import time

PAYLOAD_TYPE = "application/vnd.in-toto+json"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
CLAIM_TYPE = "https://onedroid.ai/witness/claim/v1"
KEYLIST_TYPE = "https://onedroid.ai/witness/key-list/v1"
BATCH_PAYLOAD_TYPE = "application/vnd.onedroid.witness.batch-header+json"
MAX_INT = 2 ** 53 - 1
ANCHOR_SKEW_S = 300
CHECKS = ("key-list", "signature", "key-list-witness", "record-id", "seal", "key-validity")


def canonical(v):
    """RFC 8785 with integers only."""
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
    return json.loads(data.decode("utf-8") if isinstance(data, bytes) else data, parse_float=_no_float, object_pairs_hook=_pairs)


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def pae(payload_type, payload):
    t = payload_type.encode("utf-8")
    return b"DSSEv1 %d %s %d %s" % (len(t), t, len(payload), payload)


def b64url_decode(s):
    s = s.strip()
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def claim_commitment(salt, claim):
    return sha256_hex(b"witness-commit/1|claim|" + salt + canonical(claim))


def body_commitment(salt, body):
    return sha256_hex(b"witness-commit/1|body|" + salt + canonical(body))


def merkle_root_from_path(leaf_hex, index, size, path_hex):
    """RFC 9162 §2.1.3.2: the root a leaf and its inclusion path give in a tree of `size` leaves, or None."""
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


def utc(value):
    """An RFC 3339 time as YYYY-MM-DDTHH:MM:SSZ (UTC, seconds), or None."""
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
    return calendar.timegm(time.strptime(t, "%Y-%m-%dT%H:%M:%SZ"))


def landed_anchors(seal):
    notary = seal.get("notary") if isinstance(seal, dict) else None
    notary = notary if isinstance(notary, dict) else {}
    return [a for a in notary.get("anchors") or [] if isinstance(a, dict) and a.get("state") == "landed" and a.get("tx_hash")]


def anchor_time(seal):
    """The earliest landed block_time of an anchored seal (UTC string), else None (pending, absent, or not landed)."""
    if not isinstance(seal, dict) or seal.get("state") != "anchored":
        return None
    notary = seal.get("notary") if isinstance(seal.get("notary"), dict) else {}
    if notary.get("status") != "landed":
        return None
    times = sorted(t for t in (utc(a.get("block_time")) for a in landed_anchors(seal)) if t)
    return times[0] if times else None


# ---------------------------------------------------------------------------------------------------------------- record.valid


def _sig_ok(env, keyid, public_b64, ed25519_verify):
    for s in env.get("signatures") or []:
        if isinstance(s, dict) and s.get("keyid") == keyid:
            try:
                sig = base64.b64decode(s["sig"], validate=True)
                payload = base64.b64decode(env["payload"], validate=True)
                return bool(ed25519_verify(base64.b64decode(public_b64, validate=True), sig, pae(env["payloadType"], payload)))
            except (KeyError, TypeError, ValueError, binascii.Error):
                return False
    return False


def _key_list(kl_raw, ed25519_verify):
    """(keys {key_id: entry}, predicate, None) for a key list that verifies; (None, None, "unreadable") when the bytes are not a
    key-list envelope at all; (None, None, "invalid") when it is one that does not verify (digest, key shapes, signatures)."""
    try:
        env = json.loads(kl_raw.decode("utf-8"))
        st = loads_strict(base64.b64decode(env["payload"], validate=True))
        kl = st["predicate"]
        if not isinstance(kl, dict) or st.get("predicateType") != KEYLIST_TYPE or not isinstance(env.get("signatures"), list):
            return None, None, "unreadable"
        listed = kl["keys"]
        if not isinstance(listed, list):
            return None, None, "unreadable"
    except (KeyError, TypeError, ValueError, binascii.Error, AttributeError, UnicodeDecodeError):
        return None, None, "unreadable"
    try:
        if st.get("_type") != STATEMENT_TYPE or st["subject"][0]["digest"]["sha256"] != sha256_hex(canonical(kl)):
            return None, None, "invalid"
        keys = {k["key_id"]: k for k in listed}
        for k in keys.values():
            if k.get("alg") != "ed25519" or len(base64.b64decode(k["public"], validate=True)) != 32:
                return None, None, "invalid"
        signers = set()
        for s in env["signatures"]:
            kid = s.get("keyid")
            if kid not in keys or not _sig_ok(env, kid, keys[kid]["public"], ed25519_verify):
                return None, None, "invalid"
            signers.add(kid)
        if len(signers) < (1 if kl.get("seq") == 1 else 2):
            return None, None, "invalid"
    except (KeyError, IndexError, TypeError, ValueError, binascii.Error, AttributeError):
        return None, None, "invalid"
    return keys, kl, None


def _seal_errors(seal, raw, keys, kl, ed25519_verify):
    """(errors, anchor time or None, anchored?, header key entry): verify.check_seal's checks for a seal that has a batch."""
    errs, anchor, entry = [], None, None
    hdr = seal["batch_header"]
    leaf = sha256_hex(b"\x00" + raw)
    root = merkle_root_from_path(leaf, seal["leaf_index"], hdr["size"], seal["path"])
    if root is None or root != hdr["root"]:
        errs.append("path")
    unsigned = {k: v for k, v in hdr.items() if k != "sig"}
    entry = keys.get(hdr.get("key_id"))
    if entry is None:
        errs.append("header-key")
    elif not ed25519_verify(base64.b64decode(entry["public"]), base64.b64decode(hdr["sig"], validate=True),
                          pae(BATCH_PAYLOAD_TYPE, canonical(unsigned))):
        errs.append("header-sig")
    if hdr.get("witness") != kl.get("witness"):
        errs.append("header-witness")
    anchored = seal.get("state") == "anchored"
    if anchored:
        notary = seal.get("notary") if isinstance(seal.get("notary"), dict) else {}
        if notary.get("over") != "sha256:" + sha256_hex(canonical(hdr)):
            errs.append("over")
        landed = landed_anchors(seal)
        if notary.get("status") != "landed" or not landed:
            errs.append("not-landed")
        times = sorted(t for t in (utc(a.get("block_time")) for a in landed) if t)
        if landed and not times:
            errs.append("block-time")
        anchor = times[0] if times else None
        if anchor and entry is not None:
            if entry.get("revoked_at") and entry["revoked_at"] <= anchor:
                errs.append("header-key-revoked")
            closed = hdr.get("closed_at", "")
            if not (entry.get("valid_from", "") <= closed and (entry.get("valid_to") is None or closed <= entry["valid_to"])):
                errs.append("header-key-validity")
    return errs, anchor, anchored


def assess_valid(env, seal, kl_raw, record_id, ed25519_verify):
    """record.valid: (verdict, failed, anchor). verdict is "valid" (signature, key validity and seal verify, the seal anchored),
    "invalid" (failed lists the failing checks, in CHECKS order), "pending" (nothing failed but the seal is not anchored: the time
    and the key's validity at the anchor are not proven) or "unreadable" (the record or the key list is not a readable
    envelope: no verdict about the record)."""
    failed = set()
    keys, kl, kl_state = _key_list(kl_raw, ed25519_verify)
    if kl_state == "unreadable":
        return "unreadable", [], None
    try:
        raw = base64.b64decode(env["payload"], validate=True)
        st = loads_strict(raw)
        pred = st["predicate"]
        if st.get("predicateType") != CLAIM_TYPE or not isinstance(pred, dict) or not isinstance(env.get("signatures"), list):
            return "unreadable", [], None
    except (KeyError, TypeError, ValueError, binascii.Error, AttributeError):
        return "unreadable", [], None
    if kl_state == "invalid":
        return "invalid", ["key-list"], None
    sig = env["signatures"][0] if env["signatures"] and isinstance(env["signatures"][0], dict) else {}
    kid = sig.get("keyid")
    entry = keys.get(kid)
    if env.get("payloadType") != PAYLOAD_TYPE or entry is None or not _sig_ok(env, kid, entry["public"], ed25519_verify):
        failed.add("signature")
    witness = pred.get("witness") if isinstance(pred.get("witness"), dict) else {}
    if witness.get("id") != kl.get("witness"):
        failed.add("key-list-witness")
    if sha256_hex(raw) != record_id:
        failed.add("record-id")
    anchor, anchored = None, False
    if isinstance(seal, dict) and "batch_header" in seal:
        try:
            errs, anchor, anchored = _seal_errors(seal, raw, keys, kl, ed25519_verify)
        except (KeyError, TypeError, ValueError, AttributeError):
            errs = ["unreadable"]
        if errs:
            failed.add("seal")
            anchor, anchored = None, False
    at = pred.get("witnessed_at", "")
    if entry is not None and "seal" not in failed:
        if anchored and anchor:
            try:
                early = _secs(anchor) + ANCHOR_SKEW_S < _secs(at)
            except ValueError:
                early = True
            valid = entry.get("valid_from", "") <= at and (entry.get("valid_to") is None or at <= entry["valid_to"])
            if early or (entry.get("revoked_at") and entry["revoked_at"] <= anchor) or not valid:
                failed.add("key-validity")
        else:
            valid = entry.get("valid_from", "") <= at and (entry.get("valid_to") is None or at <= entry["valid_to"])
            if entry.get("revoked_at") or not valid:
                failed.add("key-validity")
    if failed:
        return "invalid", [c for c in CHECKS if c in failed], None
    if not anchored or not anchor:
        return "pending", [], None
    return "valid", [], anchor


# -------------------------------------------------------------------------------------------------------------- record.disclose


def assess_disclose(env, seal, disclosure_raw, record_id):
    """record.disclose: (verdict, body-or-disclosure, anchor time). verdict: "disclosed" (both commitments of the private
    record's envelope match the disclosure and its seal is anchored), "mismatch" (not JSON, not {salt, body}, or a commitment
    differs), "not-private" (the envelope is a public record), "not-anchored", or "unreadable" (the envelope)."""
    try:
        raw = base64.b64decode(env["payload"], validate=True)
        st = loads_strict(raw)
        pred = st["predicate"]
        if st.get("predicateType") != CLAIM_TYPE or not isinstance(pred, dict) or sha256_hex(raw) != record_id:
            return "unreadable", None, None
        subject = st["subject"][0]["digest"]["sha256"]
    except (KeyError, IndexError, TypeError, ValueError, binascii.Error, AttributeError):
        return "unreadable", None, None
    if pred.get("visibility") != "private":
        return "not-private", None, None
    try:
        d = loads_strict(disclosure_raw)
        if not isinstance(d, dict) or set(d) != {"salt", "body"} or not isinstance(d["body"], dict):
            return "mismatch", None, None
        salt = b64url_decode(d["salt"])
        ok = (len(salt) == 16 and subject == claim_commitment(salt, d["body"]["claim"])
              and pred.get("body_commitment") == body_commitment(salt, d["body"]))
    except (KeyError, TypeError, ValueError, binascii.Error, UnicodeDecodeError, AttributeError):
        return "mismatch", None, None
    if not ok:
        return "mismatch", None, None
    at = anchor_time(seal)
    if at is None:
        return "not-anchored", d, None
    return "disclosed", d, at
