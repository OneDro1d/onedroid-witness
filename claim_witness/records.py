"""Kept records (SPEC §2.6 as changed by DECISIONS BD1, §3, §7.5; BD4): keep, the private store and its reads, share tokens,
owner search, owner delete, evidence delete, takedown, the bundle, and each kept record's n-dim object.

Custody (BD1). Each kept record has its own random 32-byte data key, stored only wrapped by the master key (AES-256-GCM under
HKDF(master, "claim-witness/kek/1"), the record id as associated data). Under the data key the witness stores a private
record's disclosure {salt, body} and, with kept evidence, a random evidence key; each kept evidence file is AES-256-GCM under
the evidence key, its media type and name inside the ciphertext. The evidence key is returned once at keep time: with it the
holder can read the evidence ciphertext wherever it sits (an n-dim object with NDIM_STORE_EVIDENCE) without this witness.

Owner search is plaintext and server-side: the witness opens the owner's own bodies. Its index rows are keyed tokens,
HMAC(HKDF(master, "claim-witness/owner-index/1"), account || NUL || word), never words, and only the owner's account can
match them. Share tokens are capabilities for one record: "wst_" + 32 random bytes (base64url), stored as their sha256 only.

Owner delete (private records): the wrapped data key, the encrypted body and salt, the kept evidence and its key, the
index rows, the share tokens, the stored job answers and the account's private observations the record relied on are
deleted; the envelope (commitments only), the signing-log row, the batch leaf and the seal stay, so the record still proves
that something was witnessed at that time. Each version of the n-dim object is DELETEd at armarium (B3W: its key per version;
we write no tombstone version). Wording rule (Michal, armarium item 3):
answers state what the witness deleted and what stays; where n-dim holds bytes they say "the key is deleted; the encrypted
bytes stay on the chain" only when armarium reported that the key was deleted."""
import base64
import binascii
import hashlib
import hmac
import io
import json
import os
import re
import tarfile
import threading
import time
import unicodedata

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import archived, crypto, dsse, ids, jcs, methods, ndim, tarball
from .schemas import CLAIM_TYPE
from .service import WitnessError, iso

DAY = 86400
HEX64 = re.compile(r"^[0-9a-f]{64}$")
KEEP_KEYS = {"envelope", "disclosure", "keep_evidence_days", "evidence"}
SHARE_KEYS = {"days", "evidence"}
DEFAULT_SHARE_DAYS = 30
MAX_SHARE_DAYS = 365
MAX_EVIDENCE_DAYS = 3650
RECORD_KIND = "claim-witness/record/1"
EVIDENCE_KIND = "claim-witness/evidence/1"
KEY_DELETED = "the key is deleted; the encrypted bytes stay on the chain"


def _box(key, aad, data):
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, data, aad)


def _open(key, aad, blob):
    blob = bytes(blob)
    return AESGCM(key).decrypt(blob[:12], blob[12:], aad)


def _norm(text):
    return " ".join(unicodedata.normalize("NFKC", text).casefold().split())


def _words(text):
    return sorted(set(re.findall(r"\w+", _norm(text))))


def _strings(v):
    if isinstance(v, str):
        yield v
    elif isinstance(v, dict):
        for k, x in v.items():
            yield from _strings(k)
            yield from _strings(x)
    elif isinstance(v, list):
        for x in v:
            yield from _strings(x)


def searchable(body):
    """The text owner search reads in a private body: the statement, the claim (statement and params), the label, and each
    evidence item's name and URL."""
    claim = body.get("claim") or {}
    parts = [body.get("statement"), claim.get("statement"), body.get("label")]
    parts += list(_strings(claim.get("params") or {}))
    for e in body.get("evidence") or []:
        parts += [e.get("name"), e.get("url")]
    return "\n".join(p for p in parts if isinstance(p, str))


class Records:
    def __init__(self, witness):
        self.w = witness
        mk = witness.cfg.master_key
        self.kek = crypto.hkdf_sha256(mk, b"claim-witness/kek/1")
        self.index_key = crypto.hkdf_sha256(mk, b"claim-witness/owner-index/1")
        self.ndim_key = crypto.hkdf_sha256(mk, b"claim-witness/ndim-owner/1")  # owner_tag and the claimant request values
        self._ndim_lock = threading.RLock()  # one ndim_sync at a time (the n-dim thread and an owner's delete)
        self._chain_lock = threading.Lock()  # one claimant create at a time (it can take minutes)

    @property
    def st(self):
        return self.w.storage

    def now(self):
        return self.w.now()

    # ------------------------------------------------------------------------------------------------------- keys

    def _data_key(self, row):
        if row.get("wrapped_key") is None:
            return None
        return _open(self.kek, b"record-key|" + row["record_id"].encode(), row["wrapped_key"])

    def _disclosure(self, row):
        dk = self._data_key(row)
        if dk is None or row.get("body_box") is None:
            return None
        return json.loads(_open(dk, b"body|" + row["record_id"].encode(), row["body_box"]))

    def _evidence_key(self, row):
        dk = self._data_key(row)
        if dk is None or row.get("evidence_key_box") is None:
            return None
        if row.get("evidence_expires_at") is not None and row["evidence_expires_at"] <= self.now():
            return None
        return _open(dk, b"evidence-key|" + row["record_id"].encode(), row["evidence_key_box"])

    def _evidence_files(self, row):
        """{sha256: {media_type, name, data}} of the kept evidence still held (none once deleted or expired)."""
        ek = self._evidence_key(row)
        if ek is None:
            return {}
        out = {}
        for e in self.st.get_kept_evidence(row["record_id"]):
            doc = json.loads(_open(ek, f"evidence|{row['record_id']}|{e['sha256']}".encode(), e["box"]))
            out[e["sha256"]] = {"media_type": doc["media_type"], "name": doc["name"], "data": base64.b64decode(doc["content_b64"])}
        return out

    def _token(self, account, word):
        return hmac.new(self.index_key, account.encode("utf-8") + b"\x00" + word.encode("utf-8"), hashlib.sha256).hexdigest()

    # ------------------------------------------------------------------------------------------------------- access

    def _row(self, rid):
        row = self.st.get_kept(rid) if isinstance(rid, str) and HEX64.match(rid) else None
        if row is None:
            raise WitnessError(404, "not-found", "no kept record with this id (GET /v1/records/{id}/seal serves the seal of "
                                                 "any record this witness signed)")
        return row

    def _owned(self, account, rid):
        row = self._row(rid)
        if not hmac.compare_digest(row["account"], account or ""):
            raise WitnessError(403, "not-owner", "only the account that kept this record may do this")
        return row

    def _share(self, token, rid):
        if not isinstance(token, str) or not 8 <= len(token) <= 200:
            raise WitnessError(403, "share-token-invalid", "the share token is not valid for this record")
        s = self.st.get_share(hashlib.sha256(token.encode("utf-8")).hexdigest())
        if s is None or s["record_id"] != rid or s["revoked_at"] is not None or s["expires_at"] <= self.now():
            raise WitnessError(403, "share-token-invalid", "the share token is not valid for this record (revoked, expired or "
                                                           "for another record)")
        return s

    def _reader(self, account, row, token):
        """(owner?, share row or None) for this reader."""
        owner = account is not None and hmac.compare_digest(row["account"], account)
        share = self._share(token, row["record_id"]) if token else None
        if row["taken_down_at"] is not None and not owner:
            raise WitnessError(410, "taken-down", "this record was taken down; its seal is still served at "
                                                  f"/v1/records/{row['record_id']}/seal")
        return owner, share

    def _link(self, rid, token=None):
        return f"{self.w.cfg.link_base.rstrip('/')}/r/{rid}" + (f"?token={token}" if token else "")

    # ------------------------------------------------------------------------------------------------------- keep

    def keep(self, account, rid, body, parts=None):
        parts = parts or {}
        if not isinstance(rid, str) or not HEX64.match(rid):
            raise WitnessError(404, "not-found", "a record id is 64 lowercase hex")
        if not isinstance(body, dict):
            raise WitnessError(400, "malformed", "the request is a JSON object")
        extra = set(body) - KEEP_KEYS
        if extra:
            raise WitnessError(422, "invalid-request", f"unknown field(s): {', '.join(sorted(extra))} (a keep request has no "
                                                       "visibility: the record's own visibility is signed)")
        env = body.get("envelope")
        if not isinstance(env, dict) or not isinstance(env.get("payload"), str) or not isinstance(env.get("signatures"), list):
            raise WitnessError(422, "invalid-request", "envelope: the record's DSSE envelope is required")
        try:
            raw = base64.b64decode(env["payload"], validate=True)
            stmt = jcs.loads_strict(raw)
            pred = stmt["predicate"]
        except (KeyError, TypeError, ValueError, binascii.Error, jcs.CanonicalError):
            raise WitnessError(422, "invalid-envelope", "the envelope's payload is not a canonical statement") from None
        if ids.record_id(raw) != rid:
            raise WitnessError(422, "record-mismatch", "the id in the path is not H(the envelope's payload)")
        if stmt.get("predicateType") != CLAIM_TYPE or env.get("payloadType") != dsse.PAYLOAD_TYPE or not isinstance(pred, dict):
            raise WitnessError(422, "not-a-record", "only claim records (predicateType claim/v1) are kept")
        if not self.w._own_signature_ok(env) or not self.st.log_has(rid):
            raise WitnessError(422, "not-witnessed-here", "this envelope is not a record this witness signed")
        vis = pred.get("visibility")
        if vis == "public":
            if "disclosure" in body:
                raise WitnessError(422, "invalid-request", "a public record has no disclosure")
            view, disclosure = pred, None
        else:
            disclosure = body.get("disclosure")
            if disclosure is None:
                raise WitnessError(422, "disclosure-required", "a private record is kept with its disclosure {salt, body}")
            view = self._check_disclosure(stmt, disclosure)
        owner = (view.get("submitter") or {}).get("account")
        if not isinstance(owner, str) or not hmac.compare_digest(owner, account):
            raise WitnessError(403, "not-owner", "a record is kept by the account that made it")
        existing = self.st.get_kept(rid)
        if existing is not None:
            if existing["deleted_at"] is not None:
                raise WitnessError(410, "deleted", "the owner deleted this record's private data; it cannot be kept again")
            return self._keep_answer(existing, already=True)
        days, files = self._evidence_request(body, parts, view)
        now = self.now()
        dk = os.urandom(32)
        rb = rid.encode()
        arm = self.w.cfg.armarium is not None
        # the owner's claimant chain is created in the background (ndim_sync_all), never in this request
        nd = {"chain": None, "record": {"state": "pending" if arm else "not-configured"}, "evidence": None}
        row = {"record_id": rid, "account": account, "visibility": vis, "method": pred["method"]["id"], "outcome": pred["outcome"],
               "witnessed_at": pred["witnessed_at"], "envelope": env, "wrapped_key": _box(self.kek, b"record-key|" + rb, dk),
               "body_box": None, "evidence_key_box": None, "evidence_expires_at": None, "evidence_deleted_at": None,
               "kept_at": now, "deleted_at": None, "taken_down_at": None, "takedown_by": None, "ndim": nd}
        if disclosure is not None:
            row["body_box"] = _box(dk, b"body|" + rb, jcs.canonical(disclosure))
        ek, ev_rows = None, []
        if files:
            ek = os.urandom(32)
            row["evidence_key_box"] = _box(dk, b"evidence-key|" + rb, ek)
            row["evidence_expires_at"] = now + days * DAY
            for sha, f in sorted(files.items()):
                doc = jcs.canonical({"media_type": f["media_type"], "name": f["name"], "content_b64": base64.b64encode(f["data"]).decode()})
                ev_rows.append({"sha256": sha, "box": _box(ek, f"evidence|{rid}|{sha}".encode(), doc)})
            if self.w.cfg.ndim_store_evidence:
                nd["evidence"] = {"state": "pending" if arm else "not-configured"}
        try:
            self.st.put_kept(row)
        except Exception as e:  # a concurrent keep of the same record
            from .storage import Conflict
            if isinstance(e, Conflict):
                return self._keep_answer(self.st.get_kept(rid), already=True)
            raise
        if ev_rows:
            self.st.put_kept_evidence(rid, ev_rows)
        if disclosure is not None:
            self.st.put_index(rid, account, [self._token(account, w) for w in _words(searchable(view))])
        else:  # B7: a public record's text goes to the public full-text index; a private one's never does
            self.w.search.index(rid, view)
        for r in view.get("relied_on") or []:
            if isinstance(r, dict) and isinstance(r.get("id"), str) and self.st.get_observation(r["id"]) is not None:
                self.st.set_observation_kept(r["id"], True)  # kept as long as the record (SPEC §8 retention)
        out = self._keep_answer(self.st.get_kept(rid), already=False)
        if ek is not None:
            out["evidence_key"] = ids.b64url(ek)
        return out

    def _check_disclosure(self, stmt, d):
        try:
            if not isinstance(d, dict) or set(d) != {"salt", "body"} or not isinstance(d["body"], dict):
                raise ValueError("shape")
            salt = ids.b64url_decode(d["salt"])
            ok = (len(salt) == 16 and stmt["subject"][0]["digest"]["sha256"] == ids.claim_commitment(salt, d["body"]["claim"])
                  and stmt["predicate"]["body_commitment"] == ids.body_commitment(salt, d["body"]))
        except (KeyError, IndexError, TypeError, ValueError, binascii.Error, jcs.CanonicalError):
            ok = False
        if not ok:
            raise WitnessError(422, "disclosure-mismatch", "the disclosure does not match the record's claim and body commitments")
        return d["body"]

    def _evidence_request(self, body, parts, view):
        days = body.get("keep_evidence_days", 0)
        if not isinstance(days, int) or isinstance(days, bool) or not 0 <= days <= MAX_EVIDENCE_DAYS:
            raise WitnessError(422, "invalid-request", f"keep_evidence_days: an integer from 0 to {MAX_EVIDENCE_DAYS}")
        items = body.get("evidence")
        if items is not None and not isinstance(items, list):
            raise WitnessError(422, "invalid-request", "evidence: a list of {sha256, content_b64}")
        given = list(items or [])
        if days == 0 and (given or parts):
            raise WitnessError(422, "invalid-request", "evidence is kept with keep_evidence_days > 0")
        if days > 0 and not (given or parts):
            raise WitnessError(422, "evidence-required", "keep_evidence_days > 0 needs the evidence bytes")
        record_objects = {e["sha256"]: e for e in view.get("evidence") or [] if isinstance(e, dict) and e.get("kind") == "object"}
        raw = {}
        for e in given:
            if not isinstance(e, dict) or set(e) != {"sha256", "content_b64"} or not isinstance(e["content_b64"], str):
                raise WitnessError(422, "invalid-request", "an evidence item is {sha256, content_b64}")
            try:
                raw[e["sha256"]] = base64.b64decode(e["content_b64"], validate=True)
            except (binascii.Error, ValueError):
                raise WitnessError(400, "malformed", "evidence content_b64 is standard base64") from None
        raw.update(parts)
        files = {}
        for sha, data in raw.items():
            if sha not in record_objects:
                raise WitnessError(422, "evidence-not-in-record", "kept evidence must be one of the record's object evidence items")
            if len(data) > self.w.cfg.max_object_bytes:
                raise WitnessError(413, "too-large", f"an evidence object is at most {self.w.cfg.max_object_bytes} bytes")
            if hashlib.sha256(data).hexdigest() != sha:
                raise WitnessError(400, "hash-mismatch", "the evidence bytes do not hash to their sha256")
            files[sha] = {"media_type": record_objects[sha]["media_type"], "name": record_objects[sha]["name"], "data": data}
        return days, files

    def _keep_answer(self, row, already):
        out = {"record_id": row["record_id"], "visibility": row["visibility"], "link": self._link(row["record_id"]),
               "kept_at": iso(row["kept_at"]), "already_kept": bool(already), "seal": self.w.sealer.seal_view(row["record_id"]),
               "ndim": self.ndim_view(row)}
        if row.get("evidence_expires_at") is not None:
            out["evidence"] = {"expires_at": iso(row["evidence_expires_at"])}
        return out

    # ------------------------------------------------------------------------------------------------------- reads

    def view(self, account, rid, token=None):
        row = self._row(rid)
        owner, share = self._reader(account, row, token)
        out = {"record_id": rid, "visibility": row["visibility"], "envelope": row["envelope"],
               "seal": self.w.sealer.seal_view(rid), "kept_at": iso(row["kept_at"]),
               "deleted_at": iso(row["deleted_at"]) if row["deleted_at"] is not None else None,
               "taken_down_at": iso(row["taken_down_at"]) if row["taken_down_at"] is not None else None,
               "ndim": self.ndim_view(row), "link": self._link(rid),
               # own model key (C1): "own" when the record was signed while serving an own-key check (its seal is anchored on
               # OneDroid's own chain only), from the signing log's tier; every other record is "public"
               "anchoring": self.st.log_tier(rid) or "public"}
        reader = row["visibility"] == "public" or owner or share is not None
        if reader:
            files = self._evidence_files(row)
            out["evidence"] = {"files": sorted(files),
                               "expires_at": iso(row["evidence_expires_at"]) if row["evidence_expires_at"] and files else None,
                               "deleted_at": iso(row["evidence_deleted_at"]) if row["evidence_deleted_at"] else None}
        if row["visibility"] == "private" and (owner or share is not None) and row["deleted_at"] is None:
            d = self._disclosure(row)
            if d is not None:
                out["disclosure"] = d
        return out

    def evidence_file(self, account, rid, sha, token=None):
        row = self._row(rid)
        owner, share = self._reader(account, row, token)
        may = row["visibility"] == "public" or owner or (share is not None and share["evidence"])
        f = self._evidence_files(row).get(sha) if may else None
        if f is None:
            raise WitnessError(404, "not-found", "no kept evidence file this reader may see")
        return f["data"]

    # ------------------------------------------------------------------------------------------------------- shares

    def share_create(self, account, rid, body):
        row = self._owned(account, rid)
        if row["visibility"] != "private":
            raise WitnessError(422, "public-record", "a public record is read without a token")
        if row["deleted_at"] is not None:
            raise WitnessError(410, "deleted", "the owner deleted this record's private data")
        body = body if body is not None else {}
        if not isinstance(body, dict) or set(body) - SHARE_KEYS:
            raise WitnessError(422, "invalid-request", "a share is {days?: 1-365, evidence?: true|false}")
        days, evidence = body.get("days", DEFAULT_SHARE_DAYS), body.get("evidence", False)
        if not isinstance(days, int) or isinstance(days, bool) or not 1 <= days <= MAX_SHARE_DAYS:
            raise WitnessError(422, "invalid-request", f"days: an integer from 1 to {MAX_SHARE_DAYS}")
        if not isinstance(evidence, bool):
            raise WitnessError(422, "invalid-request", "evidence: true or false")
        token = "wst_" + ids.b64url(os.urandom(32))
        th = hashlib.sha256(token.encode()).hexdigest()
        now = self.now()
        srow = {"token_id": "tok_" + th[:16], "token_hash": th, "record_id": rid, "account": account, "evidence": evidence,
                "created_at": now, "expires_at": now + days * DAY, "revoked_at": None}
        self.st.put_share(srow)
        return {"token_id": srow["token_id"], "token": token, "link": self._link(rid, token), "expires_at": iso(srow["expires_at"]),
                "evidence": evidence}

    def share_list(self, account, rid):
        self._owned(account, rid)
        return {"shares": [{"token_id": s["token_id"], "created_at": iso(s["created_at"]), "expires_at": iso(s["expires_at"]),
                            "revoked_at": iso(s["revoked_at"]) if s["revoked_at"] is not None else None,
                            "evidence": bool(s["evidence"])} for s in self.st.shares_of(rid)]}

    def share_revoke(self, account, rid, token_id):
        self._owned(account, rid)
        s = next((x for x in self.st.shares_of(rid) if x["token_id"] == token_id), None)
        if s is None:
            raise WitnessError(404, "not-found", "no such share token for this record")
        if s["revoked_at"] is None:
            self.st.update_share(token_id, revoked_at=self.now())
            s["revoked_at"] = self.now()
        return {"token_id": token_id, "revoked_at": iso(s["revoked_at"])}

    # ------------------------------------------------------------------------------------------------------- search

    def search(self, account, q=None, method=None, outcome=None, since=None):
        """The owner's own kept private records, newest kept first; q matches the plaintext body (all its words, then the
        phrase), opened server-side. Never another account's, never public search."""
        if q is not None and (not isinstance(q, str) or len(q) > 500):
            raise WitnessError(422, "invalid-request", "q: at most 500 characters")
        since_t = None
        if since:
            try:
                from .service import parse_iso
                since_t = parse_iso(since)
            except ValueError:
                raise WitnessError(422, "invalid-request", "since: like 2026-11-24T10:41:07Z") from None
        rows = [r for r in self.st.kept_list(account=account, visibility="private") if r["deleted_at"] is None]
        rows = [r for r in rows if (method is None or r["method"] == method) and (outcome is None or r["outcome"] == outcome)]
        if since_t is not None:
            from .service import parse_iso
            rows = [r for r in rows if parse_iso(r["witnessed_at"]) >= since_t]
        words = _words(q) if q else []
        if q and not words:
            return {"records": []}
        if words:
            hits = self.st.find_index(account, [self._token(account, w) for w in words])
            rows = [r for r in rows if r["record_id"] in hits]
        out = []
        for r in sorted(rows, key=lambda r: (-r["kept_at"], r["record_id"])):
            d = self._disclosure(r)
            if d is None:
                continue
            if q and _norm(q) not in _norm(searchable(d["body"])):
                continue
            out.append({"record_id": r["record_id"], "method": r["method"], "outcome": r["outcome"],
                        "witnessed_at": r["witnessed_at"], "kept_at": iso(r["kept_at"]), "statement": d["body"].get("statement"),
                        "label": d["body"].get("label")})
        return {"records": out}

    # ------------------------------------------------------------------------------------------------------- delete

    def delete(self, account, rid):
        row = self._owned(account, rid)
        if row["visibility"] != "private":
            raise WitnessError(422, "use-takedown", "a public record's content is public: take it down "
                                                    f"(POST /v1/records/{rid}/takedown) or delete its kept evidence")
        if row["deleted_at"] is not None:
            return self._delete_answer(row, None, already=True)
        d = self._disclosure(row)
        had_evidence = row["evidence_key_box"] is not None
        n_ev = self.st.delete_kept_evidence(rid)
        n_idx = self.st.delete_index(rid)
        n_sh = self.st.delete_shares(rid)
        n_jobs = self.st.delete_jobs_for_record(rid)
        n_obs, gone_obs = 0, []
        for r in ((d or {}).get("body") or {}).get("relied_on") or []:
            o = self.st.get_observation(r.get("id")) if isinstance(r, dict) else None
            if o is not None and o["visibility"] == "private" and o["account"] == account:
                self.st.delete_observation(o["id"])
                gone_obs.append(o["id"])
                n_obs += 1
        self.w.graph.record_deleted(rid, gone_obs)  # B7: its edges, and the private observations' nodes and edges
        now = self.now()
        self.st.update_kept(rid, wrapped_key=None, body_box=None, evidence_key_box=None, deleted_at=now,
                            evidence_deleted_at=now if had_evidence and row["evidence_deleted_at"] is None else row["evidence_deleted_at"])
        self.ndim_sync(rid)
        counts = {"evidence": n_ev, "index": n_idx, "shares": n_sh, "jobs": n_jobs, "observations": n_obs}
        return self._delete_answer(self.st.get_kept(rid), counts, already=False)

    def _delete_answer(self, row, counts, already):
        rid = row["record_id"]
        out = {"record_id": rid, "deleted_at": iso(row["deleted_at"]), "already_deleted": bool(already)}
        if counts is not None:
            out["deleted"] = [
                "the record's data key (it was stored only wrapped by the master key)",
                "the encrypted private body and its salt",
                f"{counts['evidence']} kept evidence file(s) and the evidence key",
                f"{counts['index']} owner search index row(s)",
                f"{counts['shares']} share token(s)",
                f"{counts['jobs']} stored job answer(s)",
                f"{counts['observations']} private observation(s) this record relied on, with their files"]
        else:
            out["deleted"] = ["see the first delete answer; nothing more was held"]
        out["kept"] = [
            "the signed envelope (commitments only) and its seal, still served at /v1/records/{id} and /v1/records/{id}/seal"
            .replace("{id}", rid),
            "the signing-log row and the batch leaf",
            "the attempt tag (an HMAC of the claim, kept 30 days after the check)",
            "any copy a reader already took through the API or a share link, and the disclosure the owner holds"]
        out["ndim"] = self.ndim_view(row)
        return out

    def delete_evidence(self, account, rid):
        row = self._owned(account, rid)
        if row["deleted_at"] is not None:
            raise WitnessError(410, "deleted", "the owner deleted this record's private data")
        n = self.st.delete_kept_evidence(rid)
        now = self.now()
        if row["evidence_key_box"] is not None or n:
            self.st.update_kept(rid, evidence_key_box=None, evidence_deleted_at=now)
        self.ndim_sync(rid)
        row = self.st.get_kept(rid)
        return {"record_id": rid, "evidence_deleted_at": iso(row["evidence_deleted_at"]) if row["evidence_deleted_at"] else None,
                "deleted": [f"{n} kept evidence file(s) and the record's evidence key"],
                "kept": ["the record, its envelope and its seal", "the evidence_key returned at keep time, wherever its holder keeps it"],
                "ndim": self.ndim_view(row)}

    def takedown(self, account, rid, body):
        row = self._row(rid)
        owner = hmac.compare_digest(row["account"], account)
        operator = account in (self.w.cfg.operator_accounts or ())
        if not (owner or operator):
            raise WitnessError(403, "not-owner", "a takedown is made by the record's owner or an operator")
        body = body if body is not None else {}
        if not isinstance(body, dict) or set(body) - {"reason"} or not isinstance(body.get("reason", ""), str) \
                or len(body.get("reason", "")) > 500:
            raise WitnessError(422, "invalid-request", "a takedown is {reason?: text}; the reason is not stored")
        if row["taken_down_at"] is None:
            self.st.update_kept(rid, taken_down_at=self.now(), takedown_by="owner" if owner else "operator")
            self.w.search.remove(rid)  # B7: the indexed text goes with the page (graph reads the kept row's taken_down_at)
            row = self.st.get_kept(rid)
        return {"record_id": rid, "taken_down_at": iso(row["taken_down_at"]), "by": row["takedown_by"],
                "note": "the public page and the bundle are hidden; the signed record and its seal stay valid wherever someone holds them"}

    # ------------------------------------------------------------------------------------------------------- bundle

    def bundle(self, account, rid, token=None):
        """A tar for witness-verify --bundle: envelope.json, seal.json, keys.json (the key list in force now) and
        keys-seal.json, agent_key.json (public records only), evidence/<sha256> (kept evidence this reader may see),
        observations/<id>/{envelope.json, seal.json, files/<name>} for the observations relied on that this reader may see,
        and the methods tarball. Never a disclosure.json, for any reader (BD17, README_CLAIM decision 154): a private body
        travels only through a deliberate share link, and the owner or token holder gives the disclosure from
        GET /v1/records/{id} to witness-verify with --disclosure FILE."""
        row = self._row(rid)
        owner, share = self._reader(account, row, token)
        st = self.st
        files = {"envelope.json": json.dumps(row["envelope"], indent=1).encode(),
                 "seal.json": json.dumps(self.w.sealer.seal_view(rid), indent=1).encode()}
        latest = st.latest_key_list()
        if latest is not None:
            files["keys.json"] = json.dumps(latest["envelope"], indent=1).encode()
            files["keys-seal.json"] = json.dumps(self.w.sealer.seal_view(ids.record_id(dsse.payload_bytes(latest["envelope"]))),
                                                 indent=1).encode()
        reader_private = row["visibility"] == "private" and (owner or share is not None) and row["deleted_at"] is None
        view = None
        if row["visibility"] == "public":
            view = json.loads(dsse.payload_bytes(row["envelope"]))["predicate"]
            sub = view.get("submitter") or {}
            ak = st.get_agent_key(sub["agent_key_id"]) if sub.get("agent_key_id") else None
            if ak is not None:
                files["agent_key.json"] = json.dumps({"agent_key_id": ak["agent_key_id"], "agent": ak["agent"],
                                                      "public_key": ak["public_key"]}, indent=1).encode()
        elif reader_private:
            d = self._disclosure(row)
            if d is not None:
                view = d["body"]  # BD17: read only to pick the observations and records this reader may see; never written out
        if row["visibility"] == "public" or owner or (share is not None and share["evidence"]):
            for sha, f in self._evidence_files(row).items():
                files[f"evidence/{sha}"] = f["data"]
        for r in (view or {}).get("relied_on") or []:
            o = st.get_observation(r.get("id")) if isinstance(r, dict) else None
            if o is None or not (o["visibility"] == "public" or (reader_private and o["account"] == row["account"])):
                continue
            base = f"observations/{o['id']}/"
            files[base + "envelope.json"] = json.dumps(o["envelope"], indent=1).encode()
            files[base + "seal.json"] = json.dumps(self.w.sealer.seal_view(o["id"]), indent=1).encode()
            for name, data in st.get_observation_files(o["id"]).items():
                if o["visibility"] == "private":
                    data = crypto.open_box(self.w.cfg.master_key, f"observation/{o['id']}/{name}", data)
                files[base + "files/" + name] = data
        # B5b: the record a record.valid or record.disclose names: its envelope (commitments only if private) and its seal as now
        for r in (view or {}).get("evidence") or []:
            if isinstance(r, dict) and r.get("kind") == "record" and isinstance(r.get("id"), str):
                o = st.get_kept(r["id"])
                if o is not None and (o["taken_down_at"] is None or o["account"] == row["account"]):
                    files[f"records/{o['record_id']}/envelope.json"] = json.dumps(o["envelope"], indent=1).encode()
                    files[f"records/{o['record_id']}/seal.json"] = json.dumps(self.w.sealer.seal_view(o["record_id"]), indent=1).encode()
        files.update(self._methods_files(row))
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tf:
            for name in sorted(files):
                ti = tarfile.TarInfo(name)
                ti.size, ti.mtime, ti.mode = len(files[name]), int(row["kept_at"]), 0o644
                tf.addfile(ti, io.BytesIO(files[name]))
        return buf.getvalue()

    @staticmethod
    def _methods_files(row):
        """The methods tarball the RECORD names (decision 161), as {file name: bytes}. witness-verify refuses any tarball whose
        sha256 is not the record's method.code_sha256, so today's build is carried only when it is the record's: the current
        build for a record signed by it, an archived one (claim_witness/methods_archive/) for an older record, named by its own
        library version. A method whose code_sha256 is not a methods tarball (match.screenshot: the image digest) keeps the
        current tarball, as before. A sha256 nobody can supply gives no tarball, never a wrong one: witness-verify then says
        SKIP method-rerun, and witness-methods-missing.txt names the sha256."""
        method = json.loads(dsse.payload_bytes(row["envelope"])).get("predicate", {}).get("method")
        method = method if isinstance(method, dict) else {}
        sha = method.get("code_sha256")
        if sha == tarball.methods_code_sha256():
            return {tarball.tarball_name(): tarball.build_methods_tarball()}
        got = archived.get(sha)
        if got is not None:
            return {archived.tarball_name(got[0]): got[1]}
        known = methods.get(method.get("id")) if isinstance(method.get("id"), str) else None
        if known is not None and not known.pure:
            return {tarball.tarball_name(): tarball.build_methods_tarball()}
        note = (f"The record names methods tarball sha256 {sha} ({method.get('id')} {method.get('version')}). This witness has no\n"
                f"copy of it, so the bundle carries no methods tarball: witness-verify skips the method re-run and does not\n"
                f"check a tarball. It never carries a different tarball, which would fail methods-tarball.\n")
        return {"witness-methods-missing.txt": note.encode()}

    # ------------------------------------------------------------------------------------------------------- retention

    def purge(self, now):
        """Kept evidence past its keep_evidence_days: its files and its key are deleted (the record stays)."""
        for r in self.st.kept_list():
            if r["evidence_key_box"] is not None and r["evidence_expires_at"] is not None and r["evidence_expires_at"] <= now:
                self.st.delete_kept_evidence(r["record_id"])
                self.st.update_kept(r["record_id"], evidence_key_box=None, evidence_deleted_at=now)

    # ------------------------------------------------------------------------------------------------------- n-dim

    def _owner_chain_row(self, account):
        return self.st.get_ndim_chain(ndim.owner_params(self.ndim_key, account)["tag"])

    def ndim_view(self, row):
        n = row["ndim"] or {}
        rec = n.get("record") or {"state": "not-configured"}
        chain = n.get("chain")
        state, error = rec["state"], n.get("error")
        if self.w.cfg.armarium is not None and state in ("pending", "written") and not chain:
            c = self._owner_chain_row(row["account"])
            if c is not None and c["last_error"] and not error:
                error = c["last_error"]
            if c is not None and c["state"] == "failed":
                n = dict(n, failed=True)
        if n.get("failed"):
            state = "failed"
        notes = {
            "not-configured": "n-dim is not configured on this witness (ARMARIUM_URL unset): nothing was written to a chain",
            "pending": "not written yet: the sealer writes the envelope as an n-dim object, on the owner's own chain, once the "
                       "record's batch is closed",
            "written": f"the envelope is an n-dim object on chain {chain}"
                       + (" (a private envelope holds commitments only)" if row["visibility"] == "private" else ""),
            "deleted": self._deleted_note(rec, chain),
            "not-written": "the record was deleted before its envelope was written: nothing was written to a chain",
            "failed": "writing to n-dim stopped and is not retried until the witness restarts: " + (error or "see last_error")
                      + ("; no key was deleted" if rec["state"] == "written" and row["deleted_at"] is not None else ""),
        }
        out = {"state": state, "chain": chain, "note": notes.get(state, state)}
        if rec.get("object_id"):
            out["object_id"] = rec["object_id"]
        for k in ("dek", "residual"):
            if rec.get(k) is not None:
                out[k] = rec[k]
        if error:
            out["last_error"] = error
        ev = n.get("evidence")
        if ev:
            e = {"state": "failed" if n.get("failed") and ev["state"] in ("pending", "written") else ev["state"]}
            for k in ("object_id", "dek", "residual"):
                if ev.get(k) is not None:
                    e[k] = ev[k]
            if e["state"] == "written":
                e["note"] = (f"the kept evidence is an n-dim object on chain {chain}, encrypted under the evidence key before "
                             "armarium encrypts it again")
            elif e["state"] == "deleted":
                e["note"] = self._deleted_note(ev, chain).replace("the envelope", "the kept evidence")
            elif e["state"] == "not-written":
                e["note"] = "the kept evidence was never written to a chain"
            else:
                e["note"] = notes.get(e["state"], e["state"]).replace("the envelope", "the kept evidence")
            out["evidence"] = e
        return out

    @staticmethod
    def _deleted_note(obj, chain):
        """The wording rule: "the key is deleted; the encrypted bytes stay on the chain" only when armarium said dek deleted."""
        if obj.get("dek") == "deleted":
            return KEY_DELETED
        return ("armarium keeps a version's key on the chain under its shared key (a legacy chain), or did not say it deleted "
                f"the key, so the key was not deleted; the encrypted bytes stay on the chain {chain}")

    @staticmethod
    def _gone(r):
        return r["deleted_at"] is not None or r["evidence_deleted_at"] is not None

    def _ndim_due(self, r, now):
        """Does this kept record have n-dim work now (not failed, not backing off)?"""
        n = r["ndim"] or {}
        if n.get("failed") or n.get("next_try_at", 0) > now:
            return False
        rec, ev = (n.get("record") or {}).get("state"), (n.get("evidence") or {}).get("state")
        return (rec == "pending" or (r["deleted_at"] is not None and rec == "written") or ev == "pending"
                or (self._gone(r) and ev == "written"))

    def _needs_chain(self, r):
        n = r["ndim"] or {}
        if n.get("chain"):
            return False
        rec, ev = (n.get("record") or {}).get("state"), (n.get("evidence") or {}).get("state")
        return ((rec == "pending" and r["deleted_at"] is None and self.st.get_seal(r["record_id"]) is not None)
                or (ev == "pending" and not self._gone(r)))

    def ndim_sync_all(self):
        """The n-dim thread's step: make each owner's claimant chain (one create at a time; it can take minutes), then bring each
        record's objects one step on. Never called from a request."""
        arm, case = self.w.cfg.armarium, self.w.cfg.ndim_case
        if arm is None:
            return
        now = self.now()
        due = [r for r in self.st.kept_list() if self._ndim_due(r, now)]
        seen = set()
        for r in due:
            if r["account"] in seen or not self._needs_chain(r):
                continue
            seen.add(r["account"])
            with self._chain_lock:
                ndim.ensure_chain(self.st, arm, case, self.ndim_key, r["account"], self.now())
        for r in due:
            self.ndim_sync(r["record_id"])

    def ndim_rearm(self):
        """At sealer start: what failed (a configuration error, or too many failures) is tried again, once: the operator has
        had the chance to fix the Secret and restart the pod."""
        for c in self.st.ndim_chains():
            if c["state"] == "failed":
                self.st.update_ndim_chain(c["owner_tag"], state="pending", attempts=0, next_try_at=0, last_error=None)
        for r in self.st.kept_list():
            n = r["ndim"] or {}
            if n.get("failed"):
                n = json.loads(json.dumps(n))
                for k in ("failed", "attempts", "next_try_at", "error"):
                    n.pop(k, None)
                self.st.update_kept(r["record_id"], ndim=n)

    def _delete_versions(self, arm, chain, obj):
        """DELETE each version of an n-dim object that still has its key (every version has its own); stops at the first
        failure, keeping the progress. True when every version is deleted, with obj's dek and residual."""
        for v in obj["versions"]:
            if v.get("dek") is None:
                r = arm.delete_object(chain, v["id"], v["block"])
                v.update(dek=r["dek"], residual=list(r["residual"]))
        deks = {v["dek"] for v in obj["versions"]}
        obj.update(state="deleted", dek="deleted" if deks == {"deleted"} else sorted(deks - {"deleted"})[0],
                   residual=sorted({x for v in obj["versions"] for x in v["residual"]}))

    @staticmethod
    def _written(obj, r):
        obj.update(state="written", object_id=r["id"], block=r["block"], versions=[{"id": r["id"], "block": r["block"]}])

    def ndim_sync(self, rid):
        """One step of each object's life: record pending -> written (after its batch closed, on the owner's chain) -> deleted
        (after an owner delete: every version DELETEd); evidence pending -> written -> deleted (after an evidence or owner
        delete). A record deleted before it was written is "not-written". Never makes a chain: it waits for ndim_sync_all.
        A transient failure keeps the progress and backs off; a configuration error (401/403) or MAX_ATTEMPTS failures in a row
        make the record "failed" with the reason, until the sealer restarts."""
        arm = self.w.cfg.armarium
        if arm is None:
            return
        with self._ndim_lock:
            row = self.st.get_kept(rid)
            if row is None:
                return
            n = json.loads(json.dumps(row["ndim"]))
            now = self.now()
            if n.get("failed") or n.get("next_try_at", 0) > now:
                return
            rec, ev = n["record"], n.get("evidence")
            gone = self._gone(row)
            n.pop("error", None)
            try:
                if not n.get("chain") and self._needs_chain(row):
                    cid = ndim.chain_for(self.st, self.ndim_key, row["account"])
                    if cid is None:
                        self.st.update_kept(rid, ndim=n)
                        return  # the n-dim thread creates it
                    n["chain"] = cid
                chain = n.get("chain")
                if rec["state"] == "pending" and row["deleted_at"] is not None:
                    rec["state"] = "not-written"
                if rec["state"] == "pending" and chain and self.st.get_seal(rid) is not None:
                    self._written(rec, arm.create_object(chain, {"kind": RECORD_KIND, "record_id": rid, "envelope": row["envelope"],
                                                                 "seal": self.w.sealer.seal_view(rid)}))
                if row["deleted_at"] is not None and rec["state"] == "written":
                    self._delete_versions(arm, chain, rec)
                if ev:
                    if ev["state"] == "pending" and gone:
                        ev["state"] = "not-written"
                    elif ev["state"] == "pending" and chain:
                        files = self._evidence_files(row)
                        ek = self._evidence_key(row)
                        if files and ek is not None:
                            doc = jcs.canonical({"files": [{"sha256": s, "media_type": f["media_type"], "name": f["name"],
                                                            "content_b64": base64.b64encode(f["data"]).decode()}
                                                           for s, f in sorted(files.items())]})
                            box = _box(ek, f"evidence-object|{rid}".encode(), doc)
                            self._written(ev, arm.create_object(chain, {"kind": EVIDENCE_KIND, "record_id": rid,
                                                                        "box_b64": base64.b64encode(box).decode()}))
                    if ev["state"] == "written" and gone:
                        self._delete_versions(arm, chain, ev)
                n.pop("attempts", None)
                n.pop("next_try_at", None)
            except ndim.ArmariumConfigError as e:
                n.update(error=str(e)[:200], failed=True)
            except ndim.ArmariumError as e:
                attempts = n.get("attempts", 0) + 1
                n.update(error=str(e)[:200], attempts=attempts)
                if attempts >= ndim.MAX_ATTEMPTS:
                    n["failed"] = True
                else:
                    n["next_try_at"] = int(now) + ndim._backoff(attempts)
            self.st.update_kept(rid, ndim=n)
