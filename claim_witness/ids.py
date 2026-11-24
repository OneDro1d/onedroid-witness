"""Ids and commitments (SPEC §2.0, §2.6), built exactly as written. H = sha256, fingerprints are lowercase hex."""
import base64
import hashlib

from .jcs import canonical


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def object_id(data):
    """An object's id: the sha256 of its bytes."""
    return sha256_hex(data)


def claim_id(claim):
    """H(canonical claim object): the `claim` field of the record exactly."""
    return sha256_hex(canonical(claim))


def record_id(payload_bytes):
    """A record or observation id: H(canonical payload bytes), the leaf input without the 0x00 prefix."""
    return sha256_hex(payload_bytes)


def leaf_hash(payload_bytes):
    """The Merkle leaf (RFC 9162): H(0x00 || payload)."""
    return sha256_hex(b"\x00" + payload_bytes)


def claim_commitment(salt, claim):
    """H("witness-commit/1|claim|" || salt || canonical(claim))."""
    return sha256_hex(b"witness-commit/1|claim|" + bytes(salt) + canonical(claim))


def body_commitment(salt, body):
    """H("witness-commit/1|body|" || salt || canonical(body))."""
    return sha256_hex(b"witness-commit/1|body|" + bytes(salt) + canonical(body))


def b64url(data):
    """base64url without padding (the salt's form in a disclosure and a private link)."""
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64url_decode(s):
    s = s.strip()
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
