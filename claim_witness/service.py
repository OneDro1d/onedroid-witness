"""The witness service (SPEC §2.3, §2.4, §3, §7.3; DECISIONS BD1, BD3, BD8), slices B1 and B2b: one claim in, one signed
record out; observations of web pages through the fetcher (B2b).

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

B2b: `url` evidence is observed in the job (a fresh capture through the fetcher, signed as an observation, or with max_age
one of the reader's visible observations reused); `observation` evidence is loaded by id or checked from its envelope under
the Evidence-trust rule (§4); page.live confirms a not-live answer with a second fetch after confirm_delay_s. Every fetch
failure is a signed CANNOT_WITNESS with the fetcher's reason. POST /v1/observe signs an observation with no claim.
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

import urllib.parse

from . import (attempts, crypto, dsse, ids, jcs, judge as judge_mod, methods, observation, ocr, record, screen,
               signer as signer_mod, tarball)
from .fetcher import FetchFailed
from .methods import judge_supports, page_live
from .methods.result import Result
from .schemas import CLAIM_TYPE, KEYLIST_TYPE, OBSERVATION_TYPE
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
URL_ITEM_KEYS = {"slot", "kind", "url", "capture", "max_age"}
OBS_ITEM_KEYS = {"slot", "kind", "id", "envelope", "key_list", "files"}
OBSERVE_KEYS = {"url", "capture", "visibility", "max_age", "wait"}
FILE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
MAX_AGE = 30 * DAY
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
                 max_body_bytes=25 << 20, default_wait=10, max_wait=60, rate_per_minute=60, workers=8, trust_list=None,
                 judge=None, price=None, judge_output_ttl=DAY,
                 fetcher=None, resolvers=None, confirm_delay_s=60, sleep=time.sleep, free_observations_per_day=50,
                 observation_price=None, image_digest=None, tesseract_bin=None, host_fetches_per_minute=6, observation_ttl=DAY,
                 notary=None, armarium=None, ndim_chain=None, ndim_store_evidence=False, batch_interval_s=3600,
                 batch_max_leaves=100000, sealer_poll_s=30, link_base="https://evidence.onedroid.ai", operator_accounts=None):
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
        self.judge = judge  # a judge.Judge (the model backend), or None: judge.supports then answers 503
        self.price = judge_mod.price_list(price)  # BD3, reported with every answer; the BFF holds the credits
        self.judge_output_ttl = int(judge_output_ttl)
        self.fetcher, self.resolvers = fetcher, list(resolvers or [])
        self.confirm_delay_s, self.sleep = int(confirm_delay_s), sleep
        # One observation price: WITNESS_OBSERVATION_PRICE when set, else the price list's `observation` (BD3: 5). The
        # price list that /v1/price and /v1/methods publish carries the same number.
        if observation_price is not None:
            self.price["observation"] = int(observation_price)
        self.free_observations_per_day, self.observation_price = int(free_observations_per_day), self.price["observation"]
        self.image_digest, self.tesseract_bin = ocr.parse_digest(image_digest), tesseract_bin
        self.host_fetches_per_minute, self.observation_ttl = int(host_fetches_per_minute), int(observation_ttl)
        # B3: the sealer (SPEC §7.2), the notary (a notary.NotaryClient, or None: batches close but never anchor), n-dim (an
        # ndim.ArmariumClient and its chain, or None: nothing is written), and the kept-record settings
        if int(batch_interval_s) < 1 or int(batch_max_leaves) < 1:
            raise ValueError("batch_interval_s and batch_max_leaves: integers >= 1")
        self.notary, self.armarium, self.ndim_chain = notary, armarium, ndim_chain
        if armarium is not None and not ndim_chain:
            raise ValueError("ndim_chain: the chain to write to is required with an armarium client")
        self.ndim_store_evidence = bool(ndim_store_evidence)
        self.batch_interval_s, self.batch_max_leaves = int(batch_interval_s), int(batch_max_leaves)
        self.sealer_poll_s, self.link_base = float(sealer_poll_s), str(link_base)
        self.operator_accounts = list(operator_accounts or [])


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
                 "auto_fp", "idem_key", "models", "given_files", "given_rows")


class HostLimit:
    """At most n fetches a minute per target host (SPEC §8); a job over the limit waits for a slot."""

    def __init__(self, per_minute):
        self.per_minute, self.lock, self.hits = per_minute, threading.Lock(), {}

    def wait(self, host):
        while True:
            with self.lock:
                now = time.monotonic()
                q = [t for t in self.hits.get(host, []) if now - t < 60]
                if len(q) < self.per_minute:
                    q.append(now)
                    self.hits[host] = q
                    return
                delay = 60 - (now - q[0]) + 0.01
            time.sleep(delay)


class Ctx:
    """What one check used: the observations it rests on and how many were fresh or reused (for the price)."""

    def __init__(self):
        self.fresh, self.paid, self.reused, self.relied_on = 0, 0, 0, []

    def rely(self, oid, signer, trusted):
        if all(r["id"] != oid for r in self.relied_on):
            self.relied_on.append({"id": oid, "kind": "observation", "signer": signer, "trusted": bool(trusted)})


class Untrusted(Exception):
    def __init__(self, reason, vars_=None):
        super().__init__(reason)
        self.reason, self.vars = reason, dict(vars_ or {})


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
        self.host_limit = HostLimit(config.host_fetches_per_minute)
        self.lookup_key = hmac.new(config.master_key, b"claim-witness/observation-lookup/1", hashlib.sha256).digest()
        from .records import Records  # B3; imported here: records.py imports WitnessError from this module
        from .sealer import Sealer
        self.records = Records(self)
        self.sealer = Sealer(self)

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
            entry = {"id": m.id, "major": m.major, "version": m.version, "code_sha256": self._code_of(m)[0],
                     "runtime": self._code_of(m)[1], "mechanical": m.mechanical, "pure": m.pure, "determinism": m.determinism,
                     "params_schema": m.params_schema, "slots": {k: list(v) for k, v in m.slots.items()},
                     "slot_counts": {k: list(v) for k, v in m.slot_counts.items()},
                     "templates": {"true": m.templates[True], "false": m.templates[False]},
                     "findings": dict(m.findings), "limits": m.limits}
            if m.thresholds:
                entry["thresholds"] = dict(m.thresholds)
            if m.id == "judge.supports":
                entry.update(prompt_sha256=judge_supports.prompt_sha256(), max_input_tokens=judge_supports.MAX_INPUT_TOKENS,
                             served=self.cfg.judge is not None)
            out.append(entry)
        return {"library": {"version": tarball.library_version(), "tarball": tarball.tarball_name(), "code_sha256": code,
                            "runtime": RUNTIME, "canonicaliser": "canon/1"},
                "methods": out, "models": self._public_models(), "price": dict(self.cfg.price),
                "observations": {"free_per_day": self.cfg.free_observations_per_day, "price": self.cfg.observation_price}}

    def _public_models(self):
        return judge_mod.public_models(self.cfg.judge.models, self.cfg.price) if self.cfg.judge is not None else []

    def price_view(self):
        """GET /v1/price (BD3): the provisional price list in credits, the model list with each run's price, and the free
        fresh observations a day."""
        return dict(self.cfg.price, models=self._public_models(), free_observations_per_day=self.cfg.free_observations_per_day,
                    note="Prices are provisional (DECISIONS BD3). The witness reports a price with each answer; the BFF holds "
                         "and settles the credits.")

    def _ocr(self):
        return ocr.Ocr(self.cfg.tesseract_bin)

    def _code_of(self, m):
        """(code_sha256, runtime): the methods tarball for pure methods, the image digest for match.screenshot (§9.4)."""
        if m.pure:
            return tarball.methods_code_sha256(), RUNTIME
        ver = self._ocr().version() if self.cfg.tesseract_bin else None
        return self.cfg.image_digest, f"{RUNTIME}+tesseract-{ver or 'unknown'}"

    def well_known(self):
        latest = self.storage.latest_key_list()
        if latest is None:
            raise WitnessError(503, "no-key-list", "the witness has no key list yet")
        pred = json.loads(base64.b64decode(latest["envelope"]["payload"]))["predicate"]
        return {"witness_id": self.cfg.witness_id, "key_list_seq": latest["seq"], "key_list": latest["envelope"],
                "key_list_sha256": latest["sha256"], "batch_interval_s": self.cfg.batch_interval_s,
                "sealers": pred.get("sealers", []), "trust_list": list(self.cfg.trust_list),
                "seal": {"profile": "hash/1", "notary": self.cfg.notary is not None, "batch_max_leaves": self.cfg.batch_max_leaves,
                         "leaf": "H(0x00 || payload)", "tree": "RFC 9162 section 2.1",
                         "over": "sha256:H(canonical signed batch header)"},
                "ndim": {"configured": self.cfg.armarium is not None, "store_evidence": self.cfg.ndim_store_evidence}}

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
        self.storage.purge(jobs_before=now - JOB_TTL, nonces_before=now - NONCE_WINDOW, attempts_before=now - ATTEMPT_WINDOW,
                           outputs_expired_at=now, observations_before=now - self.cfg.observation_ttl)
        self.records.purge(now)
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
        self._resolve_ids(p)
        if p.options["visibility"] == "public":
            self._screen(p, statement=None)
        self._require_services(p)
        if p.agent is not None:
            self._check_agent(p, now)
        if p.auto_fp is not None:
            prev = self.storage.find_job_by_auto(account, p.auto_fp, since=now - IDEM_WINDOW)
            if prev is not None:
                if idem_key is not None:
                    jid = self._new_job(p, now, state="done", answer=prev["answer"], answer_ctx=prev["id"],
                                        record_id=prev.get("record_id"))
                    return self._respond(jid, 0)
                return 200, self._answer_of(prev), {}
        jid = self._new_job(p, now)
        ev = threading.Event()
        with self.events_lock:
            self.events[jid] = ev
        threading.Thread(target=self._run_job, args=(jid, lambda: self._witness(p)), daemon=True, name=f"job-{jid[:8]}").start()
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

    def _new_job(self, p, now, state="queued", answer=None, answer_ctx=None, record_id=None):
        jid = uuid.uuid4().hex
        if answer is not None and answer_ctx != jid:
            answer = crypto.seal_box(self.cfg.master_key, jid, crypto.open_box(self.cfg.master_key, answer_ctx, answer))
        try:
            self.storage.create_job({"id": jid, "account": p.account, "state": state, "created_at": now, "idem_key": p.idem_key,
                                     "request_sha256": p.request_sha256, "auto_fp": p.auto_fp,
                                     "http_status": 200 if state == "done" else None, "answer": answer, "error": None,
                                     "record_id": record_id})
        except Conflict:  # a uuid4 collision
            raise WitnessError(500, "internal", "job id collision") from None
        return jid

    def _run_job(self, jid, work):
        try:
            with self.slots:
                self.storage.update_job(jid, state="running")
                try:
                    answer = work()
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
                self.storage.update_job(jid, state="done", http_status=200, answer=blob, record_id=answer.get("record_id"))
        finally:
            with self.events_lock:
                ev = self.events.pop(jid, None)
            if ev is not None:
                ev.set()

    # ------------------------------------------------------------------------------------------------------- the check

    def _witness(self, p):
        m = p.method
        ctx = Ctx()
        judgment, model_runs, raw_outputs = None, [], []
        if m.mechanical:
            res, rec_evidence = self._evaluate(p, ctx)
        else:  # judge.supports (§5): the model calls happen here, before the attempt lock and the signer
            res, rec_evidence, judgment, model_runs, raw_outputs = self._judge(p, ctx)
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
        if m.mechanical:
            options_used = {"accept_untrusted": p.options["accept_untrusted"], "allow_provider": p.options["allow_provider"],
                            "panel": p.options["panel"]}
        else:  # BD2 replaces §5.6's panel: the record says how many models ran and how many had to agree
            options_used = {"accept_untrusted": p.options["accept_untrusted"], "allow_provider": p.options["allow_provider"],
                            "models": dict(p.models)}
        objs = [e["sha256"] for e in p.evidence if e["kind"] == "object"] + [e["id"] for e in p.evidence if e["kind"] == "observation"]
        urls = [e["url"] for e in p.evidence if e["kind"] == "url"]
        tag = attempts.attempt_tag(self.cfg.attempt_key, p.claim, objs, urls, m.id, p.account)
        code, runtime = self._code_of(m)
        with self.attempt_lock:
            prior = self.storage.count_attempts(tag, since=now - ATTEMPT_WINDOW)
            pred = record.public_predicate(
                p.claim, statement, rec_evidence, {"id": m.id, "version": m.version, "code_sha256": code, "runtime": runtime},
                res.finding, res.reason, res.detail, m.limits, attempts.attempt_field(prior), submitter, options_used, iso(now),
                {"id": self.cfg.witness_id, "key_id": info["key_id"], "key_list_seq": info["key_list_seq"]}, judgment=judgment,
                relied_on=ctx.relied_on)
            stmt, disclosure = record.build(pred, p.options["visibility"], label=p.label)
            out = self.signer.sign(CLAIM_TYPE, stmt)
            self.storage.add_attempt(tag, pred["outcome"], now)
        env = out["envelope"]
        rid = ids.record_id(base64.b64decode(env["payload"]))
        if public:  # §5.8: raw outputs of a public record are kept 24 h; a private record's are discarded (BD1)
            for spec, text, provider, served in raw_outputs:
                if text is not None:
                    self.storage.add_judge_output({"record_id": rid, "model": spec.id, "provider": provider, "served_model": served,
                                                   "raw": text, "created_at": now, "expires_at": now + self.cfg.judge_output_ttl})
        observed = any(e["kind"] != "object" for e in p.evidence)
        answer = {"record_id": rid, "envelope": env, "seal": {"state": "pending"},
                  "price": self._price(p.account, ctx, check=not m.mechanical or not observed, model_runs=model_runs,
                                       observations=observed)}
        if disclosure is not None:
            answer["disclosure"] = disclosure
        if res.failing_tests:
            answer["failing_tests"] = res.failing_tests
        return answer

    def _price(self, account, ctx, check=False, model_runs=(), observations=True):
        """The one `price` object of an answer (BD3, never signed): {credits, lines} with a `check` line (1) for a mechanical
        check over objects and for every judge.supports claim, a `model-run` line per model run made (B6), and an
        `observation` line per paid fresh observation (B2b: the first 50 fresh a day are free, reuse is free). When the
        evidence includes a url or an observation it also carries fresh_observations, reused_observations and free_left_today.
        credits is the sum of the lines."""
        pl = self.cfg.price
        lines = judge_mod.price_of(list(model_runs), pl)["lines"]
        if not check:
            lines = lines[1:]
        lines += [{"item": "observation", "credits": self.cfg.observation_price} for _ in range(ctx.paid)]
        out = {"credits": sum(x["credits"] for x in lines), "lines": lines}
        if observations:
            used = self.storage.fresh_count(account, self.now() // DAY)
            out.update(fresh_observations=ctx.fresh, reused_observations=ctx.reused,
                       free_left_today=max(0, self.cfg.free_observations_per_day - used))
        return out

    # ------------------------------------------------------------------------------------------------------- judge.supports

    def _judge(self, p, ctx):
        """judge.supports over objects and observations (SPEC §2.2, §5.2): an object's visible text is its canon/1 text, an
        observation's is its text.canonical.txt, with the hidden nodes from its hidden-nodes.json (item_from_observation).
        Observation evidence goes through the Evidence-trust rule first (§4): an observation that cannot be trusted or read
        gives no finding, and no model is called. Returns (Result, record evidence, judgment, model runs, raw outputs)."""
        rec, entries = [], []
        for e in p.evidence:
            if e["kind"] == "object":
                rec.append({k: e[k] for k in ("slot", "kind", "sha256", "media_type", "name")})
            else:
                rec.append({"slot": e["slot"], "kind": "observation", "id": e["id"]})
        statement, assertion = p.claim["statement"], p.claim["assertion"]
        count, require = p.models["count"], p.models["require"]
        try:
            for e in p.evidence:
                if e["kind"] == "observation":
                    entries.append(self._given_observation(p, e, ctx))
                else:
                    entries.append((p.objects[e["sha256"]], e["media_type"]))
        except Untrusted as u:
            j = self.cfg.judge.no_run(statement, u.reason, len(p.evidence), count, require)
        else:
            j = self.cfg.judge.run(statement, assertion, entries, count, require)
        res = methods.Result(j["finding"], j["detail"], j["vars"], reason=j["reason"])
        return res, rec, j["judgment"], j["model_runs"], j["raw"]

    # ------------------------------------------------------------------------------------------------------- evidence (B2b)

    def _evaluate(self, p, ctx):
        """(Result, the record's evidence list): every slot resolved, then the method run (or a no-finding answer for
        evidence that cannot be trusted or read)."""
        m = p.method
        ev, rec = {}, []
        sub = next((e for e in p.evidence if e["kind"] == "object"), None)
        base_vars = {"sha": sub["sha256"]} if sub else {}
        try:
            for e in p.evidence:
                if e["kind"] == "observation":
                    ev[e["slot"]] = self._given_observation(p, e, ctx)
                    rec.append({"slot": e["slot"], "kind": "observation", "id": e["id"]})
        except Untrusted as u:
            rec = []
            for e in p.evidence:
                if e["kind"] == "object":
                    rec.append({k: e[k] for k in ("slot", "kind", "sha256", "media_type", "name")})
                elif e["kind"] == "observation":
                    rec.append({"slot": e["slot"], "kind": "observation", "id": e["id"]})
                else:
                    rec.append({"slot": e["slot"], "kind": "url", "url": e["url"], "capture": e["capture"], "observations": []})
            vars_ = dict(base_vars, **{k: v for k, v in u.vars.items() if isinstance(v, str)})
            vars_.setdefault("url", "an observation that could not be used")
            vars_.setdefault("fetched_at", "an unknown time")
            return Result(None, {}, vars_, reason=u.reason), rec
        for e in p.evidence:
            if e["kind"] == "object":
                ev[e["slot"]] = dict(e, data=p.objects[e["sha256"]])
                rec.append({k: e[k] for k in ("slot", "kind", "sha256", "media_type", "name")})
            elif e["kind"] == "url":
                if m.id == "page.live":
                    ev[e["slot"]] = self._page_live_attempts(p, e, ctx)
                    obs_ids = [a["observation"]["id"] for a in ev[e["slot"]]["attempts"] if "observation" in a]
                else:
                    a = self._attempt(p, e, ctx, allow_reuse=True)
                    ev[e["slot"]] = a["observation"] if "observation" in a else {"slot": e["slot"], "kind": "url", "url": e["url"],
                                                                                  "failure": a["failure"]}
                    obs_ids = [a["observation"]["id"]] if "observation" in a else []
                rec.append({"slot": e["slot"], "kind": "url", "url": e["url"], "capture": e["capture"], "observations": obs_ids})
        rec.sort(key=lambda r: [x["slot"] for x in p.evidence].index(r["slot"]))
        if m.id == "match.screenshot":
            img = ev["submitted"]
            img["ocr_text"] = self._ocr().text(img["data"])
        return methods.run(m.id, p.claim["params"], ev), rec

    def _lookup_tag(self, visibility, account, url, capture):
        msg = jcs.canonical({"visibility": visibility, "account": account if visibility == "private" else None, "url": url,
                             "capture": capture})
        return hmac.new(self.lookup_key, msg, hashlib.sha256).hexdigest()

    def _box_ctx(self, oid, name):
        return f"observation/{oid}/{name}"

    def _observation_evidence(self, row, files_stored):
        """An observation as method evidence, from its stored row and files (private ones opened)."""
        if row["visibility"] == "private":
            body = json.loads(crypto.open_box(self.cfg.master_key, self._box_ctx(row["id"], "body"), row["body_box"]))
            files = {n: crypto.open_box(self.cfg.master_key, self._box_ctx(row["id"], n), b) for n, b in files_stored.items()}
        else:
            body = json.loads(base64.b64decode(row["envelope"]["payload"]))["predicate"]
            files = files_stored
        return {"slot": "page", "kind": "observation", "id": row["id"], "manifest": body, "files": files}

    def _fresh(self, account, visibility, url, capture, ctx):
        """Fetch, build, sign and store one observation: (method evidence, envelope, disclosure). FetchFailed passes through."""
        try:
            host = urllib.parse.urlsplit(url).hostname or ""
        except ValueError:
            host = ""
        self.host_limit.wait(host.lower())
        cap = self.cfg.fetcher.capture(url, capture)
        pred, files = observation.from_capture(cap.manifest, cap.files, visibility)
        stmt, disclosure = observation.statement(pred)
        out = self.signer.sign(OBSERVATION_TYPE, stmt)
        env, oid = out["envelope"], out["payload_id"]
        now = self.now()
        row = {"id": oid, "account": account, "visibility": visibility, "lookup_tag": self._lookup_tag(visibility, account, url, capture),
               "fetched_at": parse_iso(pred["fetched_at"]), "created_at": now, "envelope": env, "body_box": None,
               "signer": env["signatures"][0]["keyid"]}
        stored = files
        if visibility == "private":
            row["body_box"] = crypto.seal_box(self.cfg.master_key, self._box_ctx(oid, "body"),
                                              json.dumps(disclosure["body"], ensure_ascii=False).encode("utf-8"))
            stored = {n: crypto.seal_box(self.cfg.master_key, self._box_ctx(oid, n), b) for n, b in files.items()}
        try:
            self.storage.put_observation(row, stored)
        except Conflict:
            pass  # the very same signed payload again (same capture in the same second): one observation, stored once
        n = self.storage.bump_fresh(account, now // DAY)
        ctx.fresh += 1
        if n > self.cfg.free_observations_per_day:
            ctx.paid += 1
        ctx.rely(oid, row["signer"], True)
        return {"slot": "page", "kind": "observation", "id": oid, "manifest": disclosure["body"] if disclosure else pred,
                "files": files}, env, disclosure

    def _reuse(self, account, visibility, url, capture, max_age, ctx):
        """A visible observation of url no older than max_age (public ones; for a private request also the account's own
        private ones), or None."""
        if max_age <= 0:
            return None
        tags = [self._lookup_tag("public", None, url, capture)]
        if visibility == "private":
            tags.append(self._lookup_tag("private", account, url, capture))
        row = self.storage.find_observation(tags, since=self.now() - max_age)
        if row is None or (row["visibility"] == "private" and row["account"] != account):
            return None
        files = self.storage.get_observation_files(row["id"])
        if not files or not self._own_signature_ok(row["envelope"]):
            return None
        ctx.reused += 1
        ctx.rely(row["id"], row["signer"], True)
        return row, self._observation_evidence(row, files)

    def _attempt(self, p, e, ctx, allow_reuse):
        """One look at a url evidence item: {"observation": evidence} or {"failure": {...}} (page_live.py's attempt shape)."""
        vis = p.options["visibility"]
        if allow_reuse:
            got = self._reuse(p.account, vis, e["url"], e["capture"], e["max_age"], ctx)
            if got is not None:
                return {"observation": got[1]}
        try:
            obs, _, _ = self._fresh(p.account, vis, e["url"], e["capture"], ctx)
            return {"observation": obs}
        except FetchFailed as f:
            part = f.partial or {}
            at = part.get("fetched_at") if isinstance(part.get("fetched_at"), str) and ISO.match(part["fetched_at"]) else iso(self.now())
            fail = {"reason": f.reason, "code": f.code, "nxdomain": f.nxdomain, "partial": {k: part[k] for k in ("redirects", "robots") if k in part},
                    "at": at, "dns": []}
            if f.nxdomain and not part.get("redirects"):
                try:
                    host = urllib.parse.urlsplit(e["url"]).hostname or ""
                except ValueError:
                    host = ""
                fail["dns"] = [r.query(host) for r in self.cfg.resolvers] if host else []
            return {"failure": fail}

    def _page_live_attempts(self, p, e, ctx):
        """page.live: the first look, and when it says gone (404/410 on the exact URL, or NXDOMAIN from two resolvers) a second
        fetch at least confirm_delay_s after the first; the job sleeps meanwhile (the caller has a 202 by then)."""
        first = self._attempt(p, e, ctx, allow_reuse=True)
        out = [first]
        if page_live.assess(first)[0] == "gone":
            t0 = parse_iso(page_live._at(first))
            wait = t0 + self.cfg.confirm_delay_s - self.now()
            if wait > 0:
                self.cfg.sleep(wait)
            out.append(self._attempt(p, e, ctx, allow_reuse=False))
        return {"slot": e["slot"], "kind": "url", "url": e["url"], "attempts": out, "confirm_min_s": self.cfg.confirm_delay_s}

    # ------------------------------------------------------------------------------------------------------- evidence trust

    def _own_keys(self):
        """{key_id: entry} over every key list this witness has signed, the latest entry for each key."""
        out = {}
        latest = self.storage.latest_key_list()
        if latest is None:
            return out
        for seq in range(1, latest["seq"] + 1):
            env = self.storage.get_key_list(seq)
            if env is None:
                continue
            for k in json.loads(base64.b64decode(env["payload"]))["predicate"]["keys"]:
                out[k["key_id"]] = k
        return out

    @staticmethod
    def _sig_ok(env, public_b64):
        try:
            sig = base64.b64decode(env["signatures"][0]["sig"], validate=True)
            payload = base64.b64decode(env["payload"], validate=True)
            return crypto.ed25519_verify(base64.b64decode(public_b64), sig, dsse.pae(env["payloadType"], payload))
        except (KeyError, IndexError, TypeError, ValueError, binascii.Error):
            return False

    def _own_signature_ok(self, env):
        try:
            key = self._own_keys().get(env["signatures"][0]["keyid"])
        except (KeyError, IndexError, TypeError):
            return False
        return key is not None and not key.get("revoked_at") and self._sig_ok(env, key["public"])

    def _foreign_key(self, key_list, keyid):
        """The public key for keyid from a key list another witness signed, when the list verifies (its signatures by keys in
        it, its subject digest) and names a witness other than this one; else None."""
        try:
            st = jcs.loads_strict(base64.b64decode(key_list["payload"], validate=True))
            kl = st["predicate"]
            if st.get("predicateType") != KEYLIST_TYPE or st["subject"][0]["digest"]["sha256"] != ids.sha256_hex(jcs.canonical(kl)):
                return None
            if kl.get("witness") == self.cfg.witness_id:
                return None  # this witness's keys come from its own lists only
            keys = {k["key_id"]: k for k in kl["keys"]}
            sigs = key_list.get("signatures") or []
            if not sigs or not all(s.get("keyid") in keys and self._sig_ok({"payloadType": key_list["payloadType"], "payload": key_list["payload"],
                                                                         "signatures": [s]}, keys[s["keyid"]]["public"]) for s in sigs):
                return None
            k = keys.get(keyid)
            return None if k is None or k.get("revoked_at") else k["public"]
        except (KeyError, IndexError, TypeError, ValueError, binascii.Error, jcs.CanonicalError):
            return None

    def _given_observation(self, p, e, ctx):
        """Observation evidence by id (this witness's store) or by envelope (checked under the Evidence-trust rule)."""
        if "envelope" not in e:
            row = p.given_rows[_index_of(p, e)]
            files = self.storage.get_observation_files(row["id"])
            if not self._own_signature_ok(row["envelope"]):
                ctx.rely(row["id"], row["signer"], False)
                raise Untrusted("evidence-untrusted")
            ctx.rely(row["id"], row["signer"], True)
            if not files:
                raise Untrusted("unreadable")
            return self._observation_evidence(row, files)
        env = e["envelope"]
        keyid = (env.get("signatures") or [{}])[0].get("keyid") if isinstance(env.get("signatures"), list) else None
        signer = keyid if isinstance(keyid, str) else "unknown"
        try:
            raw = base64.b64decode(env["payload"], validate=True)
            stmt = jcs.loads_strict(raw)
            pred = stmt["predicate"]
        except (KeyError, TypeError, ValueError, binascii.Error, jcs.CanonicalError):
            ctx.rely(e["id"], signer, False)
            raise Untrusted("evidence-untrusted") from None
        vars_ = {"url": pred.get("requested_url"), "fetched_at": pred.get("fetched_at")} if isinstance(pred, dict) else {}
        if ids.record_id(raw) != e["id"] or stmt.get("predicateType") != OBSERVATION_TYPE or env.get("payloadType") != dsse.PAYLOAD_TYPE:
            ctx.rely(e["id"], signer, False)
            raise Untrusted("evidence-untrusted", vars_)
        own = self._own_keys().get(signer)
        if own is not None:
            trusted = not own.get("revoked_at") and self._sig_ok(env, own["public"])
            if not trusted:
                ctx.rely(e["id"], signer, False)
                raise Untrusted("evidence-untrusted", vars_)
        else:
            public = self._foreign_key(e["key_list"], signer) if isinstance(e.get("key_list"), dict) else None
            if public is None or not self._sig_ok(env, public):
                ctx.rely(e["id"], signer, False)
                raise Untrusted("evidence-untrusted", vars_)
            trusted = False
        if pred.get("visibility") != "public":
            row = self.storage.get_observation(e["id"]) if own is not None else None
            if row is None or row["account"] != p.account or p.options["visibility"] != "private":
                ctx.rely(e["id"], signer, trusted)
                raise Untrusted("unreadable")
            files = self.storage.get_observation_files(row["id"])
            ctx.rely(e["id"], signer, True)
            if not files:
                raise Untrusted("unreadable")
            return self._observation_evidence(row, files)
        if stmt["subject"][0]["digest"]["sha256"] != observation.manifest_digest(pred):
            ctx.rely(e["id"], signer, False)
            raise Untrusted("evidence-untrusted", vars_)
        given = p.given_files.get(_index_of(p, e))
        if given is not None and not observation.files_match(pred, given):
            ctx.rely(e["id"], signer, False)
            raise Untrusted("evidence-untrusted", vars_)
        if not trusted and not p.options["accept_untrusted"]:
            ctx.rely(e["id"], signer, False)
            raise Untrusted("evidence-untrusted", vars_)
        ctx.rely(e["id"], signer, trusted)
        files = self.storage.get_observation_files(e["id"]) if own is not None else {}
        if files and self.storage.get_observation(e["id"])["visibility"] == "public":
            pass
        elif given is not None:
            files = given
        else:
            raise Untrusted("unreadable", vars_)
        return {"slot": e["slot"], "kind": "observation", "id": e["id"], "manifest": pred, "files": files}

    def _resolve_ids(self, p):
        """Observation evidence by id must name an observation the reader may see: a public one, or for a private claim one of
        the account's own private ones (VR-20). Checked before anything runs."""
        p.given_rows = {}
        for i, e in enumerate(p.evidence):
            if e["kind"] == "observation" and "envelope" not in e:
                row = self.storage.get_observation(e["id"])
                visible = row is not None and (row["visibility"] == "public" or (
                    row["account"] == p.account and p.options["visibility"] == "private"))
                if not visible:
                    raise WitnessError(422, "observation-not-found", f"evidence {e['slot']}: no observation {e['id'][:12]}... "
                                                                     "this account may use (kept 24 h unless a kept record uses it)")
                p.given_rows[i] = row

    def _require_services(self, p):
        if any(e["kind"] == "url" for e in p.evidence) and self.cfg.fetcher is None:
            raise WitnessError(503, "fetcher-not-configured", "url evidence needs the fetcher (FETCHER_URL); nothing was signed")
        if p.method.id == "match.screenshot":
            if not self.cfg.image_digest or not self.cfg.tesseract_bin or not self._ocr().available():
                raise WitnessError(503, "ocr-unavailable", "match.screenshot needs Tesseract and WITNESS_IMAGE_DIGEST; nothing was signed")

    # ------------------------------------------------------------------------------------------------------- POST /v1/observe

    def observe(self, account, body, idem_key=None):
        """(status, body, headers) for POST /v1/observe {url, capture?, visibility?, max_age?, wait?}: a signed observation
        with no claim. A failed fetch is 422 with the reason as the error; nothing is signed then."""
        if not isinstance(body, dict):
            raise WitnessError(400, "malformed", "the request is a JSON object")
        self._maybe_purge()
        self.rate.check(account)
        extra = set(body) - OBSERVE_KEYS
        if extra:
            raise WitnessError(422, "invalid-request", f"unknown field(s): {', '.join(sorted(extra))}")
        url = body.get("url")
        try:
            methods.check_url(url)
        except methods.ParamsError as e:
            raise WitnessError(422, "invalid-request", str(e)) from None
        capture = body.get("capture", "page")
        if capture != "page":
            raise WitnessError(422, "capture-not-served", "capture: page (post captures come with post.by-author)")
        vis = body.get("visibility", "private")
        if vis not in ("public", "private"):
            raise WitnessError(422, "invalid-request", "visibility: public or private")
        max_age, wait = body.get("max_age", 0), body.get("wait", self.cfg.default_wait)
        for k, v in (("max_age", max_age), ("wait", wait)):
            if not isinstance(v, int) or isinstance(v, bool) or v < 0:
                raise WitnessError(422, "invalid-request", f"{k}: an integer >= 0")
        if max_age > MAX_AGE:
            raise WitnessError(422, "invalid-request", f"max_age: at most {MAX_AGE} s")
        if vis == "public":
            try:
                self.screener.screen_public({"params": {"url": url}, "statement": None}, None, [])
            except screen.ScreenRefused as e:
                raise WitnessError(422, e.code, e.detail) from None
            except screen.ScreenUnavailable as e:
                raise WitnessError(503, "screening-unavailable", f"a public observation cannot be screened now ({e})") from None
        if self.cfg.fetcher is None:
            raise WitnessError(503, "fetcher-not-configured", "POST /v1/observe needs the fetcher (FETCHER_URL)")
        p = Prepared()
        p.account, p.idem_key, p.auto_fp = account, None, None
        p.request_sha256 = self._request_sha256(dict(body, _route="observe"))
        jid = self._new_job(p, self.now())
        ev = threading.Event()
        with self.events_lock:
            self.events[jid] = ev
        work = lambda: self._observe_job(account, url, capture, vis, max_age)  # noqa: E731
        threading.Thread(target=self._run_job, args=(jid, work), daemon=True, name=f"obs-{jid[:8]}").start()
        return self._respond(jid, min(wait, self.cfg.max_wait))

    def _observe_job(self, account, url, capture, vis, max_age):
        ctx = Ctx()
        got = self._reuse(account, vis, url, capture, max_age, ctx)
        if got is not None:
            row = got[0]
            out = {"observation_id": row["id"], "envelope": row["envelope"], "reused": True}
        else:
            try:
                obs, env, disclosure = self._fresh(account, vis, url, capture, ctx)
            except FetchFailed as f:
                raise WitnessError(422, f.reason, f"the fetch failed ({f.code}); nothing was signed") from None
            out = {"observation_id": obs["id"], "envelope": env, "reused": False}
            if disclosure is not None:
                out["disclosure"] = disclosure
        out["seal"] = {"state": "pending"}
        out["price"] = self._price(account, ctx)
        return out

    def observation_view(self, account, obs_id):
        """GET /v1/observations/{id}: a public one for anyone, a private one for its account only (with its body)."""
        row = self.storage.get_observation(obs_id) if isinstance(obs_id, str) and HEX64.match(obs_id) else None
        if row is None or (row["visibility"] == "private" and row["account"] != account):
            raise WitnessError(404, "not-found", "no such observation (files are kept 24 h unless a kept record uses them)")
        files = self.storage.get_observation_files(obs_id)
        out = {"observation_id": obs_id, "visibility": row["visibility"], "envelope": row["envelope"], "files": sorted(files),
               "seal": {"state": "pending"}}
        if row["visibility"] == "private":
            out["body"] = self._observation_evidence(row, {})["manifest"]
        return out

    def observation_file(self, account, obs_id, name):
        row = self.storage.get_observation(obs_id) if isinstance(obs_id, str) and HEX64.match(obs_id) else None
        if row is None or (row["visibility"] == "private" and row["account"] != account):
            raise WitnessError(404, "not-found", "no such observation")
        files = self.storage.get_observation_files(obs_id)
        if name not in files:
            raise WitnessError(404, "not-found", "no such file")
        if row["visibility"] == "private":
            return crypto.open_box(self.cfg.master_key, self._box_ctx(obs_id, name), files[name])
        return files[name]

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
        p.given_files = {}
        p.evidence = self._evidence(p.method, body["evidence"], p)
        p.objects = self._objects([e for e in body["evidence"] if e.get("kind") == "object"], parts)
        if p.method.id == "page.live" and any(e["kind"] == "url" and e["url"] != p.claim["params"]["url"] for e in p.evidence):
            raise WitnessError(422, "wrong-evidence-slots", "page.live: the page slot's url is the claim's params.url")
        p.agent = self._agent_block(body.get("agent"))
        p.agent_row = None
        p.auto_fp = None
        p.models = None
        if not p.method.mechanical:
            p.models = self._judge_checks(p, body.get("options") or {})
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
            raise WitnessError(422, "keep-not-served", "send keep: false and keep the record after the check with POST "
                                                       "/v1/records/{id}/keep (envelope, disclosure for a private record, "
                                                       "keep_evidence_days and the evidence bytes)")
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

    def _judge_checks(self, p, raw_options):
        """judge.supports before anything runs: a configured backend (else 503), the model setup (BD2; the legacy `panel: n`
        means {count: n, require: n}), no more models than configured, and a private claim only with allow_provider (§5.7)."""
        judge = self.cfg.judge
        if judge is None:
            raise WitnessError(503, "judge-not-configured", "this witness has no model backend; nothing was signed")
        if "models" in raw_options:
            models = judge_mod.models_option(p.options["models"])
            if "panel" in raw_options and raw_options["panel"] != models["count"]:
                raise WitnessError(422, "invalid-options", "options.panel and options.models.count disagree; send models only")
        else:
            models = {"count": p.options["panel"], "require": p.options["panel"]}
        if models["count"] > len(judge.models):
            raise WitnessError(422, "invalid-options", f"options.models.count: this witness has {len(judge.models)} model(s)")
        if p.options["visibility"] == "private" and not p.options["allow_provider"]:
            raise WitnessError(422, "provider-not-allowed", "a private judge.supports claim is read by a model provider: send "
                                                            "options.allow_provider: true to allow it, or make the claim public")
        return models

    def _slots_text(self, m):
        def n(s):
            lo, hi = m.slot_counts[s]
            return f"{lo}" if lo == hi else f"{lo}-{hi}"
        return f"{m.id} takes exactly the slots " + ", ".join(f"{s} ({'|'.join(k)}, {n(s)})" for s, k in m.slots.items())

    def _evidence(self, m, items, p=None):
        if not isinstance(items, list):
            raise WitnessError(422, "wrong-evidence-slots", "evidence: a list")
        counts = {}
        for e in items:
            if not isinstance(e, dict) or not isinstance(e.get("slot"), str) or e.get("kind") not in KINDS:
                raise WitnessError(422, "invalid-evidence", "an evidence item is {slot, kind: object|url|observation|record, ...}")
            slot = e["slot"]
            if slot not in m.slots or e["kind"] not in m.slots[slot]:
                raise WitnessError(422, "wrong-evidence-slots", self._slots_text(m))
            counts[slot] = counts.get(slot, 0) + 1
        for slot, (lo, hi) in m.slot_counts.items():
            if not lo <= counts.get(slot, 0) <= hi:
                raise WitnessError(422, "wrong-evidence-slots", self._slots_text(m))
        out = []  # a kind outside the slot's kinds is refused above: judge.supports takes object and observation only (§2.2)
        for e in items:
            if e["kind"] == "url":
                out.append(self._url_item(e))
                continue
            if e["kind"] == "observation":
                out.append(self._obs_item(e, p, len(out)))
                continue
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

    def _url_item(self, e):
        extra = set(e) - URL_ITEM_KEYS
        if extra:
            raise WitnessError(422, "invalid-evidence", f"evidence {e['slot']}: unknown field(s) {', '.join(sorted(extra))}")
        try:
            methods.check_url(e.get("url"))
        except methods.ParamsError as x:
            raise WitnessError(422, "invalid-evidence", f"evidence {e['slot']}: {x}") from None
        capture = e.get("capture", "page")
        if capture == "post":
            raise WitnessError(422, "capture-not-served", f"evidence {e['slot']}: post captures come with post.by-author")
        if capture != "page":
            raise WitnessError(422, "invalid-evidence", f"evidence {e['slot']}: capture is page or post")
        max_age = e.get("max_age", 0)
        if not isinstance(max_age, int) or isinstance(max_age, bool) or not 0 <= max_age <= MAX_AGE:
            raise WitnessError(422, "invalid-evidence", f"evidence {e['slot']}: max_age, seconds from 0 to {MAX_AGE}")
        return {"slot": e["slot"], "kind": "url", "url": e["url"], "capture": capture, "max_age": max_age}

    def _obs_item(self, e, p, idx=None):
        extra = set(e) - OBS_ITEM_KEYS
        if extra:
            raise WitnessError(422, "invalid-evidence", f"evidence {e['slot']}: unknown field(s) {', '.join(sorted(extra))}")
        if not isinstance(e.get("id"), str) or not HEX64.match(e["id"]):
            raise WitnessError(422, "invalid-evidence", f"evidence {e['slot']}: id is the observation id, 64 lowercase hex")
        out = {"slot": e["slot"], "kind": "observation", "id": e["id"]}
        if "envelope" in e:
            env = e["envelope"]
            if not isinstance(env, dict) or not isinstance(env.get("payload"), str) or not isinstance(env.get("signatures"), list):
                raise WitnessError(422, "invalid-evidence", f"evidence {e['slot']}: envelope is a DSSE envelope")
            out["envelope"] = env
        elif "key_list" in e or "files" in e:
            raise WitnessError(422, "invalid-evidence", f"evidence {e['slot']}: key_list and files go with an envelope")
        if "key_list" in e:
            if not isinstance(e["key_list"], dict):
                raise WitnessError(422, "invalid-evidence", f"evidence {e['slot']}: key_list is the signer's key-list envelope")
            out["key_list"] = e["key_list"]
        if "files" in e:
            f = e["files"]
            if not isinstance(f, dict) or not all(isinstance(k, str) and FILE_NAME.match(k) and isinstance(v, str) for k, v in f.items()):
                raise WitnessError(422, "invalid-evidence", f"evidence {e['slot']}: files is {{name: standard base64}}")
            try:
                files = {k: base64.b64decode(v, validate=True) for k, v in f.items()}
            except (binascii.Error, ValueError):
                raise WitnessError(400, "malformed", f"evidence {e['slot']}: files are standard base64") from None
            if sum(len(b) for b in files.values()) > self.cfg.max_body_bytes:
                raise WitnessError(413, "too-large", "the observation files are too large")
            if p is not None:
                p.given_files[idx] = files
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
        refs = sorted([e["sha256"] for e in p.evidence if e["kind"] == "object"] + [e["url"] for e in p.evidence if e["kind"] == "url"]
                      + [e["id"] for e in p.evidence if e["kind"] == "observation"])
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
        ev = [dict(e, data=p.objects[e["sha256"]]) if e["kind"] == "object" else dict(e) for e in p.evidence]
        try:
            self.screener.screen_public(p.claim, statement, ev)
        except screen.ScreenRefused as e:
            raise WitnessError(422, e.code, e.detail) from None
        except screen.ScreenUnavailable as e:
            raise WitnessError(503, "screening-unavailable", f"a public claim cannot be screened now ({e}); nothing was signed") from None


def _index_of(p, e):
    """The position of evidence item e in p.evidence: given files and rows are kept by position, because judge.supports
    takes up to five items in one slot."""
    return next(i for i, x in enumerate(p.evidence) if x is e)


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
