"""The witness service (SPEC §2.4, §3, §7.3; DECISIONS BD1, BD3, BD8), slice B1: one claim in, one signed record out.

POST /v1/witness runs these steps, in this order, and refuses before anything is signed:
  1. parse and validate the request: claim (VR-1), options, label, evidence slots (§2.2), the object bytes (VR-4, 413);
  2. an Idempotency-Key the account used within 24 h returns that first answer (409 when the request differs);
  3. public screening of the signed fields (VR-21): media first, then personal data and credentials (503 without the helper);
  4. the agent block (VR-22): a registered key of this account, the Ed25519 signature, agent_time within 300 s, a nonce not
     seen in 24 h (consumed here);
  5. the object-only idempotency rule (§3): a mechanical method over object evidence only, the same claim id, evidence,
     method version, visibility, agent key and account within 24 h returns the existing record;
  6. a job runs the method, renders the template, builds the record (public, or the §2.6 private allow-list with a fresh salt),
     counts the attempt (§7.3), has the signer sign it and stores the answer encrypted (BD1). The caller gets 200 within
     `wait` s, else 202 {job_id}.
"""
import base64
import binascii
import calendar
import hashlib
import hmac
import json
import os
import re
import sys
import threading
import time
import unicodedata
import uuid

from . import attempts, crypto, ids, jcs, methods, record, screen, signer as signer_mod, tarball
from .schemas import CLAIM_TYPE
from .storage import Conflict

DAY = 86400
JOB_TTL = DAY
NONCE_WINDOW = DAY
IDEM_WINDOW = DAY
ATTEMPT_WINDOW = attempts.WINDOW_DAYS * DAY
AGENT_SKEW = 300
HEX64 = re.compile(r"^[0-9a-f]{64}$")
ISO = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
NONCE = re.compile(r"^[A-Za-z0-9_.:-]{8,128}$")
IDEM_KEY = re.compile(r"^[\x21-\x7e]{1,128}$")
MEDIA_TYPE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,126}/[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,126}(\s*;[\x20-\x7e]{0,200})?$")
REQUEST_KEYS = {"claim", "label", "evidence", "agent", "options"}
CLAIM_KEYS = {"method", "method_major", "params", "assertion", "statement"}
OBJECT_KEYS = {"slot", "kind", "sha256", "media_type", "name", "content_b64"}
AGENT_KEYS = {"agent_key_id", "agent_sig", "nonce", "agent_time"}
OPTION_KEYS = {"keep", "visibility", "keep_evidence_days", "allow_provider", "accept_untrusted", "panel", "wait", "models"}
KINDS = ("object", "url", "observation", "record")
RUNTIME = f"python{sys.version_info[0]}.{sys.version_info[1]}"


class WitnessError(Exception):
    """An answer that is not a record: status, an error code and a readable detail."""

    def __init__(self, status, error, detail="", headers=None):
        super().__init__(f"{status} {error}: {detail}")
        self.status, self.error, self.detail, self.headers = status, error, detail, dict(headers or {})

    def body(self):
        return {"error": self.error, "detail": self.detail}


class Config:
    def __init__(self, witness_id, attempt_key, master_key, redact_bin=None, clock=time.time, max_object_bytes=20 << 20,
                 max_body_bytes=25 << 20, default_wait=10, max_wait=60, rate_per_minute=60, workers=8, trust_list=None):
        if not attempt_key or len(attempt_key) < 32:
            raise ValueError("attempt_key: at least 32 bytes")
        if not master_key or len(master_key) < 32:
            raise ValueError("master_key: at least 32 bytes")
        self.witness_id, self.attempt_key, self.master_key = witness_id, bytes(attempt_key), bytes(master_key)
        self.redact_bin, self.clock = redact_bin, clock
        self.max_object_bytes, self.max_body_bytes = int(max_object_bytes), int(max_body_bytes)
        self.default_wait, self.max_wait, self.rate_per_minute = int(default_wait), int(max_wait), int(rate_per_minute)
        self.workers = int(workers)
        self.trust_list = list(trust_list) if trust_list is not None else [witness_id]


def iso(t):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(int(t)))


def parse_iso(s):
    return calendar.timegm(time.strptime(s, "%Y-%m-%dT%H:%M:%SZ"))


def _text_ok(s, max_len):
    return (isinstance(s, str) and 0 < len(s) <= max_len and unicodedata.normalize("NFC", s) == s
            and not any(unicodedata.category(c) == "Cc" for c in s))


class Prepared:
    """A validated request: everything the job needs."""
    __slots__ = ("account", "claim", "method", "label", "evidence", "objects", "options", "agent", "agent_row", "request_sha256",
                 "auto_fp", "idem_key")


class RateLimit:
    def __init__(self, per_minute):
        self.per_minute, self.lock, self.hits = per_minute, threading.Lock(), {}

    def check(self, account):
        now = time.monotonic()
        with self.lock:
            q = [t for t in self.hits.get(account, []) if now - t < 60]
            if len(q) >= self.per_minute:
                self.hits[account] = q
                raise WitnessError(429, "rate-limited", f"at most {self.per_minute} checks a minute per account",
                                   {"Retry-After": str(max(1, int(60 - (now - q[0])) + 1))})
            q.append(now)
            self.hits[account] = q


class Witness:
    def __init__(self, storage, signer, config):
        self.storage, self.signer, self.cfg = storage, signer, config
        self.screener = screen.Screener(config.redact_bin)
        self.rate = RateLimit(config.rate_per_minute)
        self.attempt_lock = threading.Lock()
        self.events = {}
        self.events_lock = threading.Lock()
        self.slots = threading.BoundedSemaphore(config.workers)
        self.last_purge = None

    def now(self):
        return int(self.cfg.clock())

    # ------------------------------------------------------------------------------------------------------- read routes

    def health(self):
        try:
            info = self.signer.info()
            return True, {"ok": True, "service": "claim-witness", "witness_id": self.cfg.witness_id, "key_id": info["key_id"],
                          "key_list_seq": info["key_list_seq"]}
        except (signer_mod.SignerUnavailable, signer_mod.Refused, OSError, KeyError) as e:
            return False, {"ok": False, "service": "claim-witness", "detail": f"signer: {type(e).__name__}"}

    def methods_registry(self):
        code = tarball.methods_code_sha256()
        out = []
        for m in methods.METHODS.values():
            out.append({"id": m.id, "major": m.major, "version": m.version, "code_sha256": code, "runtime": RUNTIME,
                        "mechanical": m.mechanical, "determinism": m.determinism, "params_schema": m.params_schema,
                        "slots": {k: list(v) for k, v in m.slots.items()},
                        "templates": {"true": m.templates[True], "false": m.templates[False]},
                        "findings": dict(m.findings), "limits": m.limits})
        return {"library": {"version": tarball.library_version(), "tarball": tarball.tarball_name(), "code_sha256": code,
                            "runtime": RUNTIME, "canonicaliser": "canon/1"},
                "methods": out, "models": []}

    def well_known(self):
        latest = self.storage.latest_key_list()
        if latest is None:
            raise WitnessError(503, "no-key-list", "the witness has no key list yet")
        pred = json.loads(base64.b64decode(latest["envelope"]["payload"]))["predicate"]
        return {"witness_id": self.cfg.witness_id, "key_list_seq": latest["seq"], "key_list": latest["envelope"],
                "key_list_sha256": latest["sha256"], "batch_interval_s": pred.get("batch_interval_s"),
                "sealers": pred.get("sealers", []), "trust_list": list(self.cfg.trust_list), "seal": "none (S3)"}

    def key_list(self, seq):
        env = self.storage.get_key_list(seq)
        if env is None:
            raise WitnessError(404, "not-found", f"no key list {seq}")
        return env

    # ------------------------------------------------------------------------------------------------------- agent keys

    def register_agent_key(self, account, body):
        if not isinstance(body, dict) or set(body) != {"public_key"} or not isinstance(body["public_key"], str):
            raise WitnessError(400, "invalid-request", "send {\"public_key\": standard base64 of the raw 32-byte Ed25519 key}")
        try:
            pub = base64.b64decode(body["public_key"], validate=True)
        except (binascii.Error, ValueError):
            pub = b""
        if len(pub) != 32:
            raise WitnessError(400, "invalid-public-key", "public_key: standard base64 of the raw 32-byte Ed25519 key")
        tag = account.encode("utf-8") + b"|" + pub
        row = {"agent_key_id": "ak_" + hashlib.sha256(b"claim-witness/agent-key/1|" + tag).hexdigest()[:32],
               "account": account, "agent": "agt_" + hashlib.sha256(b"claim-witness/agent/1|" + tag).hexdigest()[:24],
               "public_key": base64.b64encode(pub).decode("ascii"), "created_at": self.now()}
        self.storage.add_agent_key(row)
        got = self.storage.get_agent_key(row["agent_key_id"])
        return {"agent_key_id": got["agent_key_id"], "agent": got["agent"]}

    # ------------------------------------------------------------------------------------------------------- jobs

    def purge(self):
        now = self.now()
        self.storage.purge(jobs_before=now - JOB_TTL, nonces_before=now - NONCE_WINDOW, attempts_before=now - ATTEMPT_WINDOW)
        self.last_purge = now

    def _maybe_purge(self):
        if self.last_purge is None or self.now() - self.last_purge >= 60:
            self.purge()

    def _answer_of(self, job):
        return json.loads(crypto.open_box(self.cfg.master_key, job["id"], job["answer"]))

    def job_view(self, account, job_id):
        job = self.storage.get_job(job_id) if isinstance(job_id, str) and len(job_id) <= 64 else None
        if job is None or job["account"] != account or job["created_at"] < self.now() - JOB_TTL:
            raise WitnessError(404, "not-found", "no such job")
        out = {"job_id": job["id"], "state": job["state"]}
        if job["state"] == "done":
            out["answer"] = self._answer_of(job)
        elif job["state"] == "failed":
            out["http_status"] = job["http_status"]
            out["error"] = job["error"]
        return out

    def _finished(self, job):
        """(status, body) of a finished job as POST /v1/witness answers it."""
        if job["state"] == "done":
            return 200, self._answer_of(job)
        return job["http_status"] or 500, job["error"] or {"error": "failed", "detail": ""}

    # ------------------------------------------------------------------------------------------------------- POST /v1/witness

    def submit(self, account, body, parts=None, idem_key=None):
        """(status, body, headers) for one POST /v1/witness."""
        if not isinstance(body, dict):
            raise WitnessError(400, "malformed", "the request is a JSON object")
        self._maybe_purge()
        self.rate.check(account)
        now = self.now()
        if idem_key is not None and not IDEM_KEY.match(idem_key):
            raise WitnessError(400, "invalid-idempotency-key", "Idempotency-Key: 1 to 128 printable ASCII characters")
        req_sha = self._request_sha256(body)
        if idem_key is not None:
            job = self.storage.find_job_by_idem(account, idem_key, since=now - IDEM_WINDOW)
            if job is not None:
                if job["request_sha256"] != req_sha:
                    raise WitnessError(409, "idempotency-conflict", "this Idempotency-Key was used with a different request")
                return self._respond(job["id"], self._wait_of(body))
        p = self.prepare(account, body, parts or {})
        p.request_sha256, p.idem_key = req_sha, idem_key
        if p.options["visibility"] == "public":
            self._screen(p, statement=None)
        if p.agent is not None:
            self._check_agent(p, now)
        if p.auto_fp is not None:
            prev = self.storage.find_job_by_auto(account, p.auto_fp, since=now - IDEM_WINDOW)
            if prev is not None:
                if idem_key is not None:
                    jid = self._new_job(p, now, state="done", answer=prev["answer"], answer_ctx=prev["id"])
                    return self._respond(jid, 0)
                return 200, self._answer_of(prev), {}
        jid = self._new_job(p, now)
        ev = threading.Event()
        with self.events_lock:
            self.events[jid] = ev
        threading.Thread(target=self._run_job, args=(jid, p), daemon=True, name=f"job-{jid[:8]}").start()
        return self._respond(jid, p.options["wait"])

    def _wait_of(self, body):
        w = (body.get("options") or {}).get("wait", self.cfg.default_wait) if isinstance(body.get("options"), dict) else 0
        return min(w, self.cfg.max_wait) if isinstance(w, int) and not isinstance(w, bool) and w >= 0 else self.cfg.default_wait

    def _respond(self, jid, wait):
        with self.events_lock:
            ev = self.events.get(jid)
        if ev is not None and wait > 0:
            ev.wait(wait)
        job = self.storage.get_job(jid)
        if job is not None and job["state"] in ("done", "failed"):
            status, out = self._finished(job)
            return status, out, {}
        return 202, {"job_id": jid, "state": job["state"] if job else "queued"}, {"Location": f"/v1/jobs/{jid}"}

    def _new_job(self, p, now, state="queued", answer=None, answer_ctx=None):
        jid = uuid.uuid4().hex
        if answer is not None and answer_ctx != jid:
            answer = crypto.seal_box(self.cfg.master_key, jid, crypto.open_box(self.cfg.master_key, answer_ctx, answer))
        try:
            self.storage.create_job({"id": jid, "account": p.account, "state": state, "created_at": now, "idem_key": p.idem_key,
                                     "request_sha256": p.request_sha256, "auto_fp": p.auto_fp,
                                     "http_status": 200 if state == "done" else None, "answer": answer, "error": None})
        except Conflict:  # a uuid4 collision
            raise WitnessError(500, "internal", "job id collision") from None
        return jid

    def _run_job(self, jid, p):
        try:
            with self.slots:
                self.storage.update_job(jid, state="running")
                try:
                    answer = self._witness(p)
                except WitnessError as e:
                    self.storage.update_job(jid, state="failed", http_status=e.status, error=e.body())
                    return
                except (signer_mod.SignerUnavailable, signer_mod.Refused) as e:
                    self.storage.update_job(jid, state="failed", http_status=503,
                                            error={"error": "signer-unavailable", "detail": type(e).__name__})
                    return
                except Exception as e:  # noqa: BLE001 - a job never dies silently
                    self.storage.update_job(jid, state="failed", http_status=500,
                                            error={"error": "internal", "detail": type(e).__name__})
                    return
                blob = crypto.seal_box(self.cfg.master_key, jid, json.dumps(answer, ensure_ascii=False).encode("utf-8"))
                self.storage.update_job(jid, state="done", http_status=200, answer=blob)
        finally:
            with self.events_lock:
                ev = self.events.pop(jid, None)
            if ev is not None:
                ev.set()

    # ------------------------------------------------------------------------------------------------------- the check

    def _witness(self, p):
        m = p.method
        ev = {e["slot"]: dict(e, data=p.objects[e["sha256"]]) for e in p.evidence}
        res = methods.run(m.id, p.claim["params"], ev)
        statement = m.render(p.claim["assertion"], res.vars)
        public = p.options["visibility"] == "public"
        if public:
            self._screen(p, statement=statement)
        info = self.signer.info()
        now = self.now()
        submitter = {"account": p.account}
        if p.agent is not None:
            submitter.update(agent=p.agent_row["agent"], agent_key_id=p.agent["agent_key_id"], agent_sig=p.agent["agent_sig"],
                             nonce=p.agent["nonce"], agent_time=p.agent["agent_time"])
        options_used = {"accept_untrusted": p.options["accept_untrusted"], "allow_provider": p.options["allow_provider"],
                        "panel": p.options["panel"]}
        tag = attempts.attempt_tag(self.cfg.attempt_key, p.claim, [e["sha256"] for e in p.evidence], [], m.id, p.account)
        with self.attempt_lock:
            prior = self.storage.count_attempts(tag, since=now - ATTEMPT_WINDOW)
            pred = record.public_predicate(
                p.claim, statement, [{k: e[k] for k in ("slot", "kind", "sha256", "media_type", "name")} for e in p.evidence],
                {"id": m.id, "version": m.version, "code_sha256": tarball.methods_code_sha256(), "runtime": RUNTIME},
                res.finding, res.reason, res.detail, m.limits, attempts.attempt_field(prior), submitter, options_used, iso(now),
                {"id": self.cfg.witness_id, "key_id": info["key_id"], "key_list_seq": info["key_list_seq"]})
            stmt, disclosure = record.build(pred, p.options["visibility"], label=p.label)
            out = self.signer.sign(CLAIM_TYPE, stmt)
            self.storage.add_attempt(tag, pred["outcome"], now)
        env = out["envelope"]
        answer = {"record_id": ids.record_id(base64.b64decode(env["payload"])), "envelope": env, "seal": {"state": "pending"}}
        if disclosure is not None:
            answer["disclosure"] = disclosure
        if res.failing_tests:
            answer["failing_tests"] = res.failing_tests
        return answer

    # ------------------------------------------------------------------------------------------------------- validation

    def _request_sha256(self, body):
        def strip(v):
            if isinstance(v, dict):
                return {k: strip(x) for k, x in v.items() if k != "content_b64"}
            if isinstance(v, list):
                return [strip(x) for x in v]
            return v
        try:
            return hashlib.sha256(jcs.canonical(strip(body))).hexdigest()
        except jcs.CanonicalError as e:
            raise WitnessError(400, "malformed", f"the request is not canonicalisable JSON: {e}") from None

    def prepare(self, account, body, parts):
        p = Prepared()
        p.account = account
        extra = set(body) - REQUEST_KEYS
        if extra:
            raise WitnessError(422, "invalid-request", f"unknown request field(s): {', '.join(sorted(extra))}")
        for k in ("claim", "evidence"):
            if k not in body:
                raise WitnessError(422, "invalid-request", f"{k} is required")
        p.options = self._options(body.get("options"))
        p.label = self._label(body.get("label"))
        p.claim, p.method = self._claim(body["claim"])
        p.evidence = self._evidence(p.method, body["evidence"])
        p.objects = self._objects(body["evidence"], parts)
        p.agent = self._agent_block(body.get("agent"))
        p.agent_row = None
        p.auto_fp = None
        if p.method.mechanical and all(e["kind"] == "object" for e in p.evidence):
            p.auto_fp = hashlib.sha256(jcs.canonical({
                "account": account, "claim_id": ids.claim_id(p.claim), "method": p.method.id, "version": p.method.version,
                "evidence": sorted([e["slot"], e["sha256"], e["media_type"], e["name"]] for e in p.evidence),
                "visibility": p.options["visibility"], "label": p.label,
                "agent_key_id": p.agent["agent_key_id"] if p.agent else None})).hexdigest()
        return p

    def _options(self, o):
        if o is None:
            o = {}
        if not isinstance(o, dict):
            raise WitnessError(422, "invalid-options", "options: an object")
        extra = set(o) - OPTION_KEYS
        if extra:
            raise WitnessError(422, "invalid-options", f"unknown option(s): {', '.join(sorted(extra))}")
        out = {"keep": o.get("keep", False), "visibility": o.get("visibility", "private"),
               "keep_evidence_days": o.get("keep_evidence_days", 0), "allow_provider": o.get("allow_provider", False),
               "accept_untrusted": o.get("accept_untrusted", False), "panel": o.get("panel", 1),
               "wait": o.get("wait", self.cfg.default_wait), "models": o.get("models")}
        for k in ("keep", "allow_provider", "accept_untrusted"):
            if not isinstance(out[k], bool):
                raise WitnessError(422, "invalid-options", f"options.{k}: true or false")
        if out["visibility"] not in ("public", "private"):
            raise WitnessError(422, "invalid-options", "options.visibility: public or private")
        for k, lo, hi in (("keep_evidence_days", 0, 3650), ("panel", 1, 3), ("wait", 0, None)):
            v = out[k]
            if not isinstance(v, int) or isinstance(v, bool) or v < lo or (hi is not None and v > hi):
                raise WitnessError(422, "invalid-options", f"options.{k}: an integer from {lo}" + (f" to {hi}" if hi else ""))
        out["wait"] = min(out["wait"], self.cfg.max_wait)  # a longer wait is served as the longest the witness holds a request
        mo = out["models"]
        if mo is not None:
            if not isinstance(mo, dict) or not set(mo) <= {"count", "require"} or "count" not in mo:
                raise WitnessError(422, "invalid-options", "options.models: {count: 1|2|3, require?: n <= count}")
            c, r = mo["count"], mo.get("require", mo["count"])
            if not all(isinstance(x, int) and not isinstance(x, bool) for x in (c, r)) or not (1 <= c <= 3 and 1 <= r <= c):
                raise WitnessError(422, "invalid-options", "options.models: {count: 1|2|3, require?: n <= count}")
        if out["keep"] or out["keep_evidence_days"]:
            raise WitnessError(422, "keep-not-served", "keeping a record comes with slice S3; send keep: false")
        return out

    def _label(self, label):
        if label is None:
            return None
        if not isinstance(label, str) or len(label) > 200:
            raise WitnessError(422, "invalid-label", "label: a string of at most 200 characters")
        return label

    def _claim(self, c):
        if not isinstance(c, dict):
            raise WitnessError(422, "invalid-claim", "claim: an object")
        if set(c) != CLAIM_KEYS:
            missing, extra = CLAIM_KEYS - set(c), set(c) - CLAIM_KEYS
            raise WitnessError(422, "invalid-claim", "claim: exactly {method, method_major, params, assertion, statement}"
                               + (f"; missing {', '.join(sorted(missing))}" if missing else "")
                               + (f"; unknown {', '.join(sorted(extra))}" if extra else ""))
        if not isinstance(c["method"], str) or not isinstance(c["method_major"], int) or isinstance(c["method_major"], bool):
            raise WitnessError(422, "invalid-claim", "claim.method: a string, claim.method_major: an integer")
        m = methods.get(c["method"])
        if m is None or m.major != c["method_major"]:
            raise WitnessError(422, "unknown-method", f"no method {c['method']!r} major {c['method_major']} (GET /v1/methods)")
        if not isinstance(c["assertion"], bool):
            raise WitnessError(422, "invalid-claim", "claim.assertion: true or false")
        if not isinstance(c["params"], dict):
            raise WitnessError(422, "invalid-params", "claim.params: an object")
        try:
            m.check_params(c["params"])
        except methods.ParamsError as e:
            raise WitnessError(422, "invalid-params", str(e)) from None
        if m.mechanical:
            if c["statement"] is not None:
                raise WitnessError(422, "statement-not-allowed",
                                   f"{m.id} is a mechanical method: statement must be null (the record's statement is its template)")
        elif not _text_ok(c["statement"], 4000):
            raise WitnessError(422, "invalid-claim", "claim.statement: 1 to 4,000 characters of NFC text")
        try:
            jcs.canonical(c)
        except jcs.CanonicalError as e:
            raise WitnessError(422, "invalid-claim", f"claim: {e}") from None
        return dict(c), m

    def _evidence(self, m, items):
        if not isinstance(items, list):
            raise WitnessError(422, "wrong-evidence-slots", "evidence: a list")
        seen = {}
        for e in items:
            if not isinstance(e, dict) or not isinstance(e.get("slot"), str) or e.get("kind") not in KINDS:
                raise WitnessError(422, "invalid-evidence", "an evidence item is {slot, kind: object|url|observation|record, ...}")
            slot = e["slot"]
            if slot not in m.slots or e["kind"] not in m.slots[slot] or slot in seen:
                raise WitnessError(422, "wrong-evidence-slots", f"{m.id} takes exactly the slots "
                                   + ", ".join(f"{s} ({'|'.join(k)})" for s, k in m.slots.items()))
            seen[slot] = e
        if set(seen) != set(m.slots):
            raise WitnessError(422, "wrong-evidence-slots", f"{m.id} takes exactly the slots "
                               + ", ".join(f"{s} ({'|'.join(k)})" for s, k in m.slots.items()))
        out = []
        for e in items:
            extra = set(e) - OBJECT_KEYS
            if extra:
                raise WitnessError(422, "invalid-evidence", f"evidence {e['slot']}: unknown field(s) {', '.join(sorted(extra))}")
            if not isinstance(e.get("sha256"), str) or not HEX64.match(e["sha256"]):
                raise WitnessError(422, "invalid-evidence", f"evidence {e['slot']}: sha256 is 64 lowercase hex")
            if not isinstance(e.get("media_type"), str) or not MEDIA_TYPE.match(e["media_type"]):
                raise WitnessError(422, "invalid-evidence", f"evidence {e['slot']}: media_type like text/plain")
            if not _text_ok(e.get("name"), 255):
                raise WitnessError(422, "invalid-evidence", f"evidence {e['slot']}: name, 1 to 255 characters of NFC text")
            out.append({"slot": e["slot"], "kind": "object", "sha256": e["sha256"], "media_type": e["media_type"], "name": e["name"]})
        return out

    def _objects(self, items, parts):
        objects = {}
        for e in items:
            data = None
            if e.get("content_b64") is not None:
                if not isinstance(e["content_b64"], str):
                    raise WitnessError(400, "malformed", f"evidence {e['slot']}: content_b64 is standard base64")
                if len(e["content_b64"]) > (self.cfg.max_object_bytes + 2) // 3 * 4 + 4:
                    raise WitnessError(413, "too-large", f"an evidence object is at most {self.cfg.max_object_bytes} bytes")
                try:
                    data = base64.b64decode(e["content_b64"], validate=True)
                except (binascii.Error, ValueError):
                    raise WitnessError(400, "malformed", f"evidence {e['slot']}: content_b64 is standard base64") from None
            elif e["sha256"] in parts:
                data = parts[e["sha256"]]
            if data is None:
                raise WitnessError(400, "missing-object", f"evidence {e['slot']}: send the bytes inline (content_b64) or as a "
                                                          f"multipart part named {e['sha256']}")
            if len(data) > self.cfg.max_object_bytes:
                raise WitnessError(413, "too-large", f"an evidence object is at most {self.cfg.max_object_bytes} bytes")
            if hashlib.sha256(data).hexdigest() != e["sha256"]:
                raise WitnessError(400, "hash-mismatch", f"evidence {e['slot']}: the bytes do not hash to the given sha256")
            objects[e["sha256"]] = data
        return objects

    def _agent_block(self, a):
        if a is None:
            return None
        if not isinstance(a, dict) or set(a) != AGENT_KEYS or not all(isinstance(a[k], str) for k in AGENT_KEYS):
            raise WitnessError(400, "invalid-agent", "agent: {agent_key_id, agent_sig, nonce, agent_time}, all strings")
        if not NONCE.match(a["nonce"]):
            raise WitnessError(400, "invalid-agent", "agent.nonce: 8 to 128 of A-Z a-z 0-9 _ . : -")
        if not ISO.match(a["agent_time"]):
            raise WitnessError(400, "invalid-agent", "agent.agent_time: like 2026-11-24T10:41:07Z")
        try:
            sig = base64.b64decode(a["agent_sig"], validate=True)
        except (binascii.Error, ValueError):
            sig = b""
        if len(sig) != 64:
            raise WitnessError(400, "invalid-agent", "agent.agent_sig: standard base64 of a 64-byte Ed25519 signature")
        return dict(a)

    def agent_message(self, p):
        refs = sorted(e["sha256"] for e in p.evidence)
        return jcs.canonical({"witness_id": self.cfg.witness_id, "claim_id": ids.claim_id(p.claim), "evidence": refs,
                              "nonce": p.agent["nonce"], "agent_time": p.agent["agent_time"]})

    def _check_agent(self, p, now):
        row = self.storage.get_agent_key(p.agent["agent_key_id"])
        if row is None or not hmac.compare_digest(row["account"], p.account):
            raise WitnessError(403, "agent-key-not-yours", "the agent key is not registered for this account")
        try:
            t = parse_iso(p.agent["agent_time"])
        except ValueError:
            raise WitnessError(400, "invalid-agent", "agent.agent_time is not a time") from None
        if abs(now - t) > AGENT_SKEW:
            raise WitnessError(401, "stale-agent-time", f"agent_time is more than {AGENT_SKEW} s from the witness's clock")
        pub = base64.b64decode(row["public_key"])
        if not crypto.ed25519_verify(pub, base64.b64decode(p.agent["agent_sig"]), self.agent_message(p)):
            raise WitnessError(401, "bad-agent-signature", "agent_sig does not verify with the registered key")
        if not self.storage.use_nonce(p.agent["agent_key_id"], p.agent["nonce"], at=now, window=NONCE_WINDOW):
            raise WitnessError(401, "nonce-reused", "this nonce was used in the last 24 h")
        p.agent_row = row

    def _screen(self, p, statement):
        ev = [dict(e, data=p.objects[e["sha256"]]) for e in p.evidence]
        try:
            self.screener.screen_public(p.claim, statement, ev)
        except screen.ScreenRefused as e:
            raise WitnessError(422, e.code, e.detail) from None
        except screen.ScreenUnavailable as e:
            raise WitnessError(503, "screening-unavailable", f"a public claim cannot be screened now ({e}); nothing was signed") from None


def read_key_file(path, what):
    """A 32-byte key from a file: standard base64 of 32 or more bytes, or the raw bytes."""
    with open(path, "rb") as f:
        data = f.read()
    try:
        raw = base64.b64decode(data.strip(), validate=True)
    except (binascii.Error, ValueError):
        raw = data
    if len(raw) < 32:
        raise SystemExit(f"{what}: {path} holds fewer than 32 bytes")
    return raw


def random_key():
    return os.urandom(32)
