"""The witness's storage interface (BD7): jobs (with Idempotency-Key and the object-only idempotency fingerprint), the
signing log, agent keys, nonces, attempts, key lists, and (B2b) observations with their files and the per-account daily
count of fresh observations. Times are integer epoch seconds. Two implementations of one
contract: MemoryStorage (unit tests; FileStorage persists it to a JSON file for the operator CLI on a laptop) and
pg.PostgresStorage (the deployed one)."""
import base64
import copy
import json
import os
import threading

OUTCOMES = ("SUPPORTED", "NOT_SUPPORTED", "CANNOT_WITNESS")
JOB_FIELDS = ("id", "account", "state", "created_at", "idem_key", "request_sha256", "auto_fp", "http_status", "answer", "error")
OBS_FIELDS = ("id", "account", "visibility", "lookup_tag", "fetched_at", "created_at", "envelope", "body_box", "signer", "kept")


class Conflict(Exception):
    pass


class Storage:
    """The interface. Every method is safe to call from several threads."""

    def create_job(self, job): raise NotImplementedError
    def update_job(self, job_id, **fields): raise NotImplementedError
    def get_job(self, job_id): raise NotImplementedError
    def all_jobs(self): raise NotImplementedError
    def find_job_by_idem(self, account, idem_key, since): raise NotImplementedError
    def find_job_by_auto(self, account, auto_fp, since): raise NotImplementedError
    def append_signing_log(self, payload_id, predicate_type, at): raise NotImplementedError
    def signing_log(self): raise NotImplementedError
    def add_agent_key(self, row): raise NotImplementedError
    def get_agent_key(self, agent_key_id): raise NotImplementedError
    def use_nonce(self, agent_key_id, nonce, at, window): raise NotImplementedError
    def add_attempt(self, tag, outcome, at): raise NotImplementedError
    def count_attempts(self, tag, since): raise NotImplementedError
    def put_key_list(self, seq, envelope, sha256, at): raise NotImplementedError
    def get_key_list(self, seq): raise NotImplementedError
    def latest_key_list(self): raise NotImplementedError
    def add_judge_output(self, row): raise NotImplementedError
    def judge_outputs(self, record_id=None): raise NotImplementedError
    def purge(self, jobs_before, nonces_before, attempts_before, outputs_expired_at=None, observations_before=None):
        raise NotImplementedError
    # observations (SPEC §2.3, §8 retention): a row per signed observation, its files beside it (sealed when private)
    def put_observation(self, row, files): raise NotImplementedError
    def get_observation(self, obs_id): raise NotImplementedError
    def get_observation_files(self, obs_id): raise NotImplementedError
    def find_observation(self, tags, since): raise NotImplementedError
    def bump_fresh(self, account, day): raise NotImplementedError
    def fresh_count(self, account, day): raise NotImplementedError


OUTPUT_FIELDS = ("record_id", "model", "provider", "served_model", "raw", "created_at", "expires_at")


class MemoryStorage(Storage):
    def __init__(self):
        self.lock = threading.RLock()
        self.jobs, self.log, self.agent_keys, self.nonces, self.attempts, self.key_lists = {}, [], {}, {}, [], {}
        self.outputs = []
        self.observations, self.obs_files, self.fresh = {}, {}, {}

    def _changed(self):
        pass

    def create_job(self, job):
        with self.lock:
            if job["id"] in self.jobs:
                raise Conflict("job id exists")
            self.jobs[job["id"]] = {k: job.get(k) for k in JOB_FIELDS}
            self._changed()

    def update_job(self, job_id, **fields):
        with self.lock:
            self.jobs[job_id].update(fields)
            self._changed()

    def get_job(self, job_id):
        with self.lock:
            j = self.jobs.get(job_id)
            return dict(j) if j else None

    def all_jobs(self):
        with self.lock:
            return [dict(j) for j in self.jobs.values()]

    def find_job_by_idem(self, account, idem_key, since):
        with self.lock:
            for j in sorted(self.jobs.values(), key=lambda j: j["created_at"]):
                if j["account"] == account and j["idem_key"] == idem_key and j["created_at"] >= since:
                    return dict(j)
        return None

    def find_job_by_auto(self, account, auto_fp, since):
        with self.lock:
            for j in sorted(self.jobs.values(), key=lambda j: j["created_at"]):
                if j["account"] == account and j["auto_fp"] == auto_fp and j["created_at"] >= since and j["state"] == "done":
                    return dict(j)
        return None

    def append_signing_log(self, payload_id, predicate_type, at):
        with self.lock:
            seq = len(self.log) + 1
            self.log.append({"seq": seq, "payload_id": payload_id, "predicate_type": predicate_type, "at": int(at)})
            self._changed()
            return seq

    def signing_log(self):
        with self.lock:
            return [dict(r) for r in self.log]

    def add_agent_key(self, row):
        with self.lock:
            self.agent_keys.setdefault(row["agent_key_id"], dict(row))
            self._changed()

    def get_agent_key(self, agent_key_id):
        with self.lock:
            r = self.agent_keys.get(agent_key_id)
            return dict(r) if r else None

    def use_nonce(self, agent_key_id, nonce, at, window):
        with self.lock:
            k = (agent_key_id, nonce)
            prev = self.nonces.get(k)
            if prev is not None and at - prev <= window:
                return False
            self.nonces[k] = int(at)
            self._changed()
            return True

    def add_attempt(self, tag, outcome, at):
        with self.lock:
            self.attempts.append((tag, outcome, int(at)))
            self._changed()

    def count_attempts(self, tag, since):
        with self.lock:
            out = {o: 0 for o in OUTCOMES}
            for t, o, at in self.attempts:
                if t == tag and at >= since:
                    out[o] += 1
            return out

    def put_key_list(self, seq, envelope, sha256, at):
        with self.lock:
            if seq in self.key_lists:
                raise Conflict(f"key list {seq} exists")
            self.key_lists[seq] = {"seq": seq, "envelope": copy.deepcopy(envelope), "sha256": sha256, "at": int(at)}
            self._changed()

    def get_key_list(self, seq):
        with self.lock:
            r = self.key_lists.get(seq)
            return copy.deepcopy(r["envelope"]) if r else None

    def latest_key_list(self):
        with self.lock:
            if not self.key_lists:
                return None
            return copy.deepcopy(self.key_lists[max(self.key_lists)])

    def add_judge_output(self, row):
        with self.lock:
            self.outputs.append({k: row.get(k) for k in OUTPUT_FIELDS})
            self._changed()

    def judge_outputs(self, record_id=None):
        with self.lock:
            return [dict(r) for r in self.outputs if record_id is None or r["record_id"] == record_id]

    def purge(self, jobs_before, nonces_before, attempts_before, outputs_expired_at=None, observations_before=None):
        with self.lock:
            self.jobs = {k: j for k, j in self.jobs.items() if j["created_at"] >= jobs_before}
            self.nonces = {k: at for k, at in self.nonces.items() if at >= nonces_before}
            self.attempts = [a for a in self.attempts if a[2] >= attempts_before]
            if outputs_expired_at is not None:
                self.outputs = [r for r in self.outputs if r["expires_at"] >= outputs_expired_at]
            if observations_before is not None:
                gone = [k for k, o in self.observations.items() if o["created_at"] < observations_before and not o.get("kept")]
                for k in gone:
                    self.observations.pop(k, None)
                    self.obs_files.pop(k, None)
                self.fresh = {k: n for k, n in self.fresh.items() if k[1] * 86400 >= observations_before - 2 * 86400}
            self._changed()

    def put_observation(self, row, files):
        with self.lock:
            if row["id"] in self.observations:
                raise Conflict("observation exists")
            self.observations[row["id"]] = {k: copy.deepcopy(row.get(k)) for k in OBS_FIELDS}
            self.observations[row["id"]]["kept"] = bool(row.get("kept"))
            self.obs_files[row["id"]] = {n: bytes(b) for n, b in files.items()}
            self._changed()

    def get_observation(self, obs_id):
        with self.lock:
            o = self.observations.get(obs_id)
            return copy.deepcopy(o) if o else None

    def get_observation_files(self, obs_id):
        with self.lock:
            return dict(self.obs_files.get(obs_id) or {})

    def find_observation(self, tags, since):
        with self.lock:
            rows = [o for o in self.observations.values() if o["lookup_tag"] in set(tags) and o["fetched_at"] >= since]
            if not rows:
                return None
            return copy.deepcopy(max(rows, key=lambda o: (o["fetched_at"], o["created_at"])))

    def bump_fresh(self, account, day):
        with self.lock:
            k = (account, int(day))
            self.fresh[k] = self.fresh.get(k, 0) + 1
            self._changed()
            return self.fresh[k]

    def fresh_count(self, account, day):
        with self.lock:
            return self.fresh.get((account, int(day)), 0)


class FileStorage(MemoryStorage):
    """MemoryStorage saved to one JSON file after every change: for the operator CLI and single-process local runs only."""

    def __init__(self, path):
        super().__init__()
        self.path = path
        if os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                doc = json.load(f)
            self.log = doc.get("log", [])
            self.agent_keys = doc.get("agent_keys", {})
            self.attempts = [tuple(a) for a in doc.get("attempts", [])]
            self.key_lists = {int(k): v for k, v in doc.get("key_lists", {}).items()}
            self.nonces = {tuple(k.split("\x00", 1)): v for k, v in doc.get("nonces", {}).items()}
            self.jobs = {k: dict(v, answer=base64.b64decode(v["answer"]) if v.get("answer") else None)
                         for k, v in doc.get("jobs", {}).items()}
            self.outputs = doc.get("judge_outputs", [])

    def _changed(self):
        jobs = {k: dict(v, answer=base64.b64encode(bytes(v["answer"])).decode() if v.get("answer") else None)
                for k, v in self.jobs.items()}
        doc = {"log": self.log, "agent_keys": self.agent_keys, "attempts": self.attempts,
               "key_lists": {str(k): v for k, v in self.key_lists.items()},
               "nonces": {"\x00".join(k): v for k, v in self.nonces.items()}, "jobs": jobs,
               "judge_outputs": getattr(self, "outputs", [])}
        tmp = f"{self.path}.{os.getpid()}.tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(doc, f)
        os.replace(tmp, self.path)


def from_env(env):
    """WITNESS_DATABASE_URL (Postgres: the first connection retried for up to WITNESS_DB_START_TIMEOUT_S, default 120 s, then
    migrated), else WITNESS_STORAGE_FILE (a JSON file), else memory."""
    url = (env.get("WITNESS_DATABASE_URL") or "").strip()
    if url:
        from .pg import PostgresStorage, connect_with_retry
        st = PostgresStorage(url)
        st.conn = connect_with_retry(url, max_wait_s=int(env.get("WITNESS_DB_START_TIMEOUT_S") or 120))
        st.migrate()
        return st
    path = (env.get("WITNESS_STORAGE_FILE") or "").strip()
    if path:
        return FileStorage(path)
    return MemoryStorage()
