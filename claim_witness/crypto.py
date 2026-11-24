"""Ed25519 (the `cryptography` package, or the vendored pure-Python RFC 8032 code in verify.py when it is absent) and
AES-256-GCM with HKDF-SHA256 (BD1 custody: job answers are stored encrypted under a key derived from the master key)."""
import hashlib
import hmac
import os

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    HAVE_CRYPTOGRAPHY = True
except ImportError:  # pragma: no cover - the image always has it
    HAVE_CRYPTOGRAPHY = False

from . import verify as _pure


def ed25519_public(seed):
    if HAVE_CRYPTOGRAPHY:
        return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(serialization.Encoding.Raw,
                                                                                    serialization.PublicFormat.Raw)
    return _pure.ed25519_public_pure(seed)


def ed25519_sign(seed, msg):
    if HAVE_CRYPTOGRAPHY:
        return Ed25519PrivateKey.from_private_bytes(seed).sign(msg)
    return _pure.ed25519_sign_pure(seed, msg)


def ed25519_verify(public, sig, msg):
    if len(public) != 32 or len(sig) != 64:
        return False
    if HAVE_CRYPTOGRAPHY:
        try:
            Ed25519PublicKey.from_public_bytes(public).verify(sig, msg)
            return True
        except (InvalidSignature, ValueError):
            return False
    return _pure.ed25519_verify_pure(public, sig, msg)


def hkdf_sha256(key, info, length=32, salt=b""):
    prk = hmac.new(salt or b"\x00" * 32, key, hashlib.sha256).digest()
    out, block, i = b"", b"", 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([i]), hashlib.sha256).digest()
        out += block
        i += 1
    return out[:length]


def seal_box(master_key, context, plaintext):
    """AES-256-GCM under HKDF(master_key, "claim-witness/job/1|" + context): nonce || ciphertext."""
    if not HAVE_CRYPTOGRAPHY:
        raise RuntimeError("AES-GCM needs the cryptography package")
    key = hkdf_sha256(master_key, b"claim-witness/job/1|" + context.encode())
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, context.encode())


def open_box(master_key, context, blob):
    key = hkdf_sha256(master_key, b"claim-witness/job/1|" + context.encode())
    blob = bytes(blob)
    return AESGCM(key).decrypt(blob[:12], blob[12:], context.encode())
