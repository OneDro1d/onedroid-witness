"""DSSE envelopes (SPEC §2.5): payloadType application/vnd.in-toto+json, payload = standard base64 of the canonical
Statement, signatures [{keyid, sig}] with sig = standard base64 of Ed25519 over PAE(payloadType, payload)."""
import base64

from . import crypto

PAYLOAD_TYPE = "application/vnd.in-toto+json"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"


def pae(payload_type, payload):
    t = payload_type.encode("utf-8")
    return b"DSSEv1 %d %s %d %s" % (len(t), t, len(payload), payload)


def sign(payload_bytes, signers, payload_type=PAYLOAD_TYPE):
    """An envelope over payload_bytes, signed by each (keyid, seed) in signers."""
    msg = pae(payload_type, payload_bytes)
    return {"payloadType": payload_type, "payload": base64.b64encode(payload_bytes).decode("ascii"),
            "signatures": [{"keyid": kid, "sig": base64.b64encode(crypto.ed25519_sign(seed, msg)).decode("ascii")}
                           for kid, seed in signers]}


def payload_bytes(envelope):
    return base64.b64decode(envelope["payload"], validate=True)


def verify(envelope, keys, keyid=None):
    """True when the signature by `keyid` (or, without one, every signature whose keyid is in keys, at least one) verifies
    with keys[keyid] (raw 32-byte public keys)."""
    try:
        msg = pae(envelope["payloadType"], payload_bytes(envelope))
        sigs = envelope["signatures"]
        checked = 0
        for s in sigs:
            kid = s.get("keyid")
            if keyid is not None and kid != keyid:
                continue
            if kid not in keys:
                if keyid is not None:
                    return False
                continue
            if not crypto.ed25519_verify(keys[kid], base64.b64decode(s["sig"], validate=True), msg):
                return False
            checked += 1
        return checked > 0
    except (KeyError, TypeError, ValueError):
        return False
