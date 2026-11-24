#!/usr/bin/env python3
"""witness-verify (SPEC §6): steps 1 (key list), 2 (signature), 3 (ids and commitments), 4 (the seal, B3), 5 (key validity:
at the anchor time when sealed, else at the payload's own time), 6 (bundle files and the re-run of a pure-Python method from
the tarball pinned by code_sha256) and 7 (the agent's signature).

B3, step 4 (`seal`): the leaf H(0x00 || payload) and its path must give the batch root (RFC 9162 §2.1.3.2); the batch header
must be signed by a key of the key list (PAE over the canonical header without `sig`), name that root and this witness; the
notary's `over` must be "sha256:" + H(canonical signed header) with every anchor landed. The anchor transaction itself is not
read here (SKIP seal-chain: check it with armarium's POST /notary/v1/verify or an RPC you trust). Key validity is then judged
at the anchor time (the earliest landed block_time): a key revoked at or before it fails; FLAG seal-delay when the anchor
came more than interval_s + 15 minutes after the payload's time. A pending seal is SKIP ("time not proven").

B2b: an observation envelope (predicateType observation/v1) is verified too: signature, payload canonical, observation id,
manifest digest (a public observation's subject is H(canonical manifest)), key validity at fetched_at, every file given with
--evidence against the manifest, and text.canonical.txt recomputed from rendered.html with the tarball's canon/1. A record
whose evidence is an observation or a URL is not re-run here (the observations come in the bundle with S3), and
match.screenshot is never re-run by this verifier: "re-run skipped (needs image)".

One module, Python 3.10+ standard library only, importing nothing from its own package, so it can be copied and run alone:

    python3 -m claim_witness.verify --envelope answer.json --keys keys.json [--disclosure d.json] [--agent-key a.json]
                                    [--methods witness-methods-1.0.0.tar.gz] [--evidence FILE ...] [--record-id HEX]
    python3 -m claim_witness.verify --bundle DIR      # envelope.json, keys.json, disclosure.json, agent_key.json,
                                                      # witness-methods-*.tar.gz, evidence/<sha256>
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


def check_seal(r, seal, raw, keys, kl, skip_text):
    """Step 4. Returns the anchor time (UTC string) when the seal verifies and is anchored, "failed" when it fails, else None."""
    if not isinstance(seal, dict) or "batch_header" not in seal:
        r.skip("seal", skip_text)
        return None
    errs, anchor = [], None
    try:
        hdr = seal["batch_header"]
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
                    errs.append(f"the header's key was revoked at {entry['revoked_at']}, before the anchor time {anchor}")
                closed = hdr.get("closed_at", "")
                if not (entry.get("valid_from", "") <= closed and (entry.get("valid_to") is None or closed <= entry["valid_to"])):
                    errs.append(f"the batch closed at {closed}, outside its key's validity")
    except (KeyError, TypeError, ValueError, AttributeError) as e:
        errs.append(f"unreadable seal: {type(e).__name__}")
    if errs:
        r.fail("seal", "; ".join(errs))
        return "failed"
    if not anchored:
        r.skip("seal", f"batched (leaf {seal['leaf_index']} of {hdr['size']}: the path and the header verify) but not anchored: "
                       "the time is not proven")
        return None
    chains = ", ".join(sorted({a.get("chain") or "?" for a in landed}))
    r.ok("seal", f"leaf {seal['leaf_index']} of batch {hdr['batch_id'][:16]}... (size {hdr['size']}) gives its root; header "
                 f"signed by {hdr['key_id']}; notary over matches; anchored on {chains} at {anchor}")
    r.skip("seal-chain", "the anchor transaction itself was not read: check it with armarium's POST /notary/v1/verify "
                         "{over, chain, tx_hash} or an RPC you trust")
    return anchor


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
        self.out, self.failed = out, False

    def line(self, text):
        print(text, file=self.out)

    def ok(self, name, note=""):
        self.line(f"PASS {name}" + (f": {note}" if note else ""))

    def fail(self, name, why):
        self.failed = True
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
        r.skip("method-rerun", "no methods tarball given (--methods)")
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


def rerun(r, view, files, tar_bytes, records=None):
    """Step 6: files are fingerprinted; the method re-runs from the tarball and must give the record's finding."""
    method, claim, evidence = view["method"], view["claim"], view["evidence"]
    if method["id"] in RECORD_METHODS:
        rerun_record_method(r, view, files, tar_bytes, records)
        return
    if method["id"] in NEEDS_IMAGE:
        r.skip("method-rerun", "re-run skipped (needs image)")
        return
    if any(e.get("kind") != "object" for e in evidence):
        r.skip("method-rerun", "the evidence is an observation: its re-run needs the observation files (the bundle, S3)")
        return
    by_sha = {sha256_hex(b): b for b in files}
    wanted = {e["sha256"] for e in evidence if e.get("kind") == "object"}
    if files:
        extra = sorted(set(by_sha) - wanted)
        r.check("bundle-files", not extra, f"file(s) {', '.join(x[:12] for x in extra)} match no evidence fingerprint in the record",
                f"{len(by_sha)} file(s) match their fingerprints")
    if tar_bytes is None:
        r.skip("method-rerun", "no methods tarball given (--methods)")
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
    """An observation envelope: id, manifest digest, key validity at fetched_at, files, text.canonical.txt."""
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
    anchor = check_seal(r, seal, raw, keys, kl, "pending: this observation is signed by its key; its time is not proven")
    if entry is not None and anchor != "failed":
        key_validity(r, entry, kid, pred.get("fetched_at", ""), anchor,
                     (seal or {}).get("batch_header", {}).get("interval_s"), "observation")
    if manifest is None:
        return
    listed = {f["name"]: f["sha256"] for f in manifest.get("files") or []}
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
        return
    try:
        lib = _load_methods(tar_bytes)
        text = lib.canon.canon1(named["rendered.html"], "text/html", layer="rendered").encode("utf-8")
    except Exception as e:  # noqa: BLE001
        r.fail("text-canonical", f"canon/1 from the tarball did not run: {type(e).__name__}")
        return
    r.check("text-canonical", sha256_hex(text) == listed["text.canonical.txt"],
            "canon/1 of rendered.html is not the manifest's text.canonical.txt", "canon/1 of rendered.html is text.canonical.txt")


def run_checks(r, env, keys_env, trusted=False, disclosure=None, agent_key=None, files=(), tar_bytes=None, expect_id=None,
               seal=None, records=None):
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
    anchor = check_seal(r, seal, raw, keys, kl, "pending: this record is signed by its key; its time is not proven")
    # step 5: at the anchor time when sealed, else at the record's own time
    if entry is not None and anchor != "failed":
        key_validity(r, entry, kid, pred.get("witnessed_at", ""), anchor,
                     (seal or {}).get("batch_header", {}).get("interval_s"), "record")
    # step 6
    if view is not None:
        rerun(r, dict(view, method=pred["method"], finding=pred["finding"], outcome=pred["outcome"], reason=pred["reason"],
                      detail=pred["detail"], limits=pred["limits"]), list(files), tar_bytes, records)
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
    ap.add_argument("--disclosure")
    ap.add_argument("--agent-key")
    ap.add_argument("--methods")
    ap.add_argument("--evidence", action="append", default=[])
    ap.add_argument("--record-id")
    ap.add_argument("--record", action="append", default=[],
                    help="a record record.valid or record.disclose names: its envelope (an answer or a record view, with its seal)")
    ap.add_argument("--seal", help="the seal JSON (GET /v1/records/{id}/seal); a whole answer's own seal is used otherwise")
    try:
        a = ap.parse_args(argv)
    except SystemExit:
        return 2
    files, tar_bytes = [pathlib.Path(p).read_bytes() for p in a.evidence], None
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
    except (OSError, ValueError) as e:
        print(f"witness-verify: cannot read input: {e}", file=sys.stderr)
        return 2
    r = Report(out)
    run_checks(r, env, keys_env, trusted, disclosure, agent_key, files, tar_bytes, a.record_id, seal, records)
    r.line("RESULT: " + ("FAIL" if r.failed else "PASS"))
    return 1 if r.failed else 0


if __name__ == "__main__":
    sys.exit(main())
