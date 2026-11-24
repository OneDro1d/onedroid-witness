"""Postgres storage (BD7, psycopg 3). Migrations are the plain SQL files in claim_witness/migrations/, applied in file-name
order once each and recorded in schema_migrations. One autocommit connection behind a lock, reopened when it breaks.

At start (storage.from_env) the first connection is retried with bounded backoff (connect_with_retry): on a fresh deploy the
API and the signer may start before claim-pg resolves. Each attempt is logged without the DSN; after the bound the process
exits."""
import json
import pathlib
import sys
import threading
import time

import psycopg

from .storage import JOB_FIELDS, OBS_FIELDS, OUTCOMES, OUTPUT_FIELDS, Conflict, Storage

MIGRATIONS = pathlib.Path(__file__).resolve().parent / "migrations"
MIGRATION_LOCK = 0x636C6169  # "clai": the advisory lock key the migration holds


def _why(e, dsn):
    text = str(e).strip().splitlines()[0] if str(e).strip() else ""
    text = text.replace(dsn, "<dsn>")
    if "password" in text.lower():
        text = "authentication or connection error"
    return f"{type(e).__name__}: {text[:160]}"


def connect_with_retry(dsn, max_wait_s=120, log=None, sleep=time.sleep, clock=time.monotonic, connect=None, max_delay_s=15):
    """A connection, retrying OperationalError with doubling waits (1 s up to max_delay_s) for at most max_wait_s in total,
    one log line per failed attempt; then SystemExit."""
    log = log or (lambda line: print(line, file=sys.stderr, flush=True))
    connect = connect or psycopg.connect
    start, delay, n = clock(), 1.0, 0
    while True:
        n += 1
        try:
            return connect(dsn, autocommit=True)
        except psycopg.OperationalError as e:
            left = max_wait_s - (clock() - start)
            if left <= 0:
                log(f"postgres: attempt {n} failed ({_why(e, dsn)}); giving up after {max_wait_s} s")
                raise SystemExit(f"postgres is not reachable after {max_wait_s} s") from None
            wait = min(delay, max_delay_s, left)
            log(f"postgres: attempt {n} failed ({_why(e, dsn)}); retrying in {wait:g} s")
            sleep(wait)
            delay *= 2


class PostgresStorage(Storage):
    def __init__(self, dsn):
        self.dsn = dsn
        self.lock = threading.RLock()
        self.conn = None

    def _c(self):
        if self.conn is None or self.conn.closed or self.conn.broken:
            self.conn = psycopg.connect(self.dsn, autocommit=True)
        return self.conn

    def _q(self, sql, args=(), fetch=None):
        with self.lock:
            for attempt in (0, 1):
                try:
                    cur = self._c().execute(sql, args)
                    if fetch == "one":
                        return cur.fetchone()
                    if fetch == "all":
                        return cur.fetchall()
                    return cur.rowcount
                except psycopg.OperationalError:
                    self.conn = None
                    if attempt:
                        raise

    def migrate(self):
        """Apply the files not yet applied, in one transaction under an advisory lock: the API and the signer sidecar both
        migrate on start, and only one of them may do it."""
        with self.lock:
            c = self._c()
            with c.transaction():
                c.execute("SELECT pg_advisory_xact_lock(%s)", (MIGRATION_LOCK,))
                c.execute("CREATE TABLE IF NOT EXISTS schema_migrations (name text PRIMARY KEY, "
                          "applied_at timestamptz NOT NULL DEFAULT now())")
                done = {r[0] for r in c.execute("SELECT name FROM schema_migrations").fetchall()}
                for f in sorted(MIGRATIONS.glob("*.sql")):
                    if f.name in done:
                        continue
                    c.execute(f.read_text(encoding="utf-8"))
                    c.execute("INSERT INTO schema_migrations (name) VALUES (%s)", (f.name,))

    def applied_migrations(self):
        return [r[0] for r in self._q("SELECT name FROM schema_migrations ORDER BY name", fetch="all")]

    @staticmethod
    def _job(row):
        if row is None:
            return None
        j = dict(zip(JOB_FIELDS, row))
        if j["answer"] is not None:
            j["answer"] = bytes(j["answer"])
        return j

    def create_job(self, job):
        try:
            self._q("INSERT INTO jobs (id, account, state, created_at, idem_key, request_sha256, auto_fp, http_status, answer, error) "
                    "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                    (job["id"], job["account"], job["state"], int(job["created_at"]), job.get("idem_key"), job.get("request_sha256"),
                     job.get("auto_fp"), job.get("http_status"), job.get("answer"),
                     json.dumps(job["error"]) if job.get("error") is not None else None))
        except psycopg.errors.UniqueViolation:
            raise Conflict("job id exists") from None

    def update_job(self, job_id, **fields):
        cols, args = [], []
        for k, v in fields.items():
            if k not in JOB_FIELDS or k == "id":
                raise KeyError(k)
            cols.append(f"{k} = %s")
            args.append(json.dumps(v) if k == "error" and v is not None else v)
        self._q(f"UPDATE jobs SET {', '.join(cols)} WHERE id = %s", (*args, job_id))

    def get_job(self, job_id):
        return self._job(self._q(f"SELECT {', '.join(JOB_FIELDS)} FROM jobs WHERE id = %s", (job_id,), fetch="one"))

    def all_jobs(self):
        return [self._job(r) for r in self._q(f"SELECT {', '.join(JOB_FIELDS)} FROM jobs", fetch="all")]

    def find_job_by_idem(self, account, idem_key, since):
        return self._job(self._q(f"SELECT {', '.join(JOB_FIELDS)} FROM jobs WHERE account = %s AND idem_key = %s AND created_at >= %s "
                                 "ORDER BY created_at LIMIT 1", (account, idem_key, int(since)), fetch="one"))

    def find_job_by_auto(self, account, auto_fp, since):
        return self._job(self._q(f"SELECT {', '.join(JOB_FIELDS)} FROM jobs WHERE account = %s AND auto_fp = %s AND created_at >= %s "
                                 "AND state = 'done' ORDER BY created_at LIMIT 1", (account, auto_fp, int(since)), fetch="one"))

    def append_signing_log(self, payload_id, predicate_type, at):
        return self._q("INSERT INTO signing_log (payload_id, predicate_type, at) VALUES (%s, %s, %s) RETURNING seq",
                       (payload_id, predicate_type, int(at)), fetch="one")[0]

    def signing_log(self):
        return [{"seq": r[0], "payload_id": r[1], "predicate_type": r[2], "at": r[3]}
                for r in self._q("SELECT seq, payload_id, predicate_type, at FROM signing_log ORDER BY seq", fetch="all")]

    def add_agent_key(self, row):
        self._q("INSERT INTO agent_keys (agent_key_id, account, agent, public_key, created_at) VALUES (%s, %s, %s, %s, %s) "
                "ON CONFLICT (agent_key_id) DO NOTHING",
                (row["agent_key_id"], row["account"], row["agent"], row["public_key"], int(row["created_at"])))

    def get_agent_key(self, agent_key_id):
        r = self._q("SELECT agent_key_id, account, agent, public_key, created_at FROM agent_keys WHERE agent_key_id = %s",
                    (agent_key_id,), fetch="one")
        return dict(zip(("agent_key_id", "account", "agent", "public_key", "created_at"), r)) if r else None

    def use_nonce(self, agent_key_id, nonce, at, window):
        r = self._q("INSERT INTO nonces (agent_key_id, nonce, at) VALUES (%s, %s, %s) "
                    "ON CONFLICT (agent_key_id, nonce) DO UPDATE SET at = EXCLUDED.at WHERE nonces.at < %s RETURNING at",
                    (agent_key_id, nonce, int(at), int(at) - int(window)), fetch="one")
        return r is not None

    def add_attempt(self, tag, outcome, at):
        self._q("INSERT INTO attempts (tag, outcome, at) VALUES (%s, %s, %s)", (tag, outcome, int(at)))

    def count_attempts(self, tag, since):
        out = {o: 0 for o in OUTCOMES}
        for o, n in self._q("SELECT outcome, count(*) FROM attempts WHERE tag = %s AND at >= %s GROUP BY outcome",
                            (tag, int(since)), fetch="all"):
            out[o] = int(n)
        return out

    def put_key_list(self, seq, envelope, sha256, at):
        try:
            self._q("INSERT INTO key_lists (seq, envelope, sha256, at) VALUES (%s, %s, %s, %s)",
                    (int(seq), json.dumps(envelope), sha256, int(at)))
        except psycopg.errors.UniqueViolation:
            raise Conflict(f"key list {seq} exists") from None

    def get_key_list(self, seq):
        r = self._q("SELECT envelope FROM key_lists WHERE seq = %s", (int(seq),), fetch="one")
        return json.loads(r[0]) if r else None

    def latest_key_list(self):
        r = self._q("SELECT seq, envelope, sha256, at FROM key_lists ORDER BY seq DESC LIMIT 1", fetch="one")
        return {"seq": r[0], "envelope": json.loads(r[1]), "sha256": r[2], "at": r[3]} if r else None

    def add_judge_output(self, row):
        self._q("INSERT INTO judge_outputs (record_id, model, provider, served_model, raw, created_at, expires_at) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s)",
                tuple(row.get(k) for k in OUTPUT_FIELDS))

    def judge_outputs(self, record_id=None):
        cols = ", ".join(OUTPUT_FIELDS)
        if record_id is None:
            rows = self._q(f"SELECT {cols} FROM judge_outputs ORDER BY id", fetch="all")
        else:
            rows = self._q(f"SELECT {cols} FROM judge_outputs WHERE record_id = %s ORDER BY id", (record_id,), fetch="all")
        return [dict(zip(OUTPUT_FIELDS, r)) for r in rows]

    def purge(self, jobs_before, nonces_before, attempts_before, outputs_expired_at=None, observations_before=None):
        self._q("DELETE FROM jobs WHERE created_at < %s", (int(jobs_before),))
        self._q("DELETE FROM nonces WHERE at < %s", (int(nonces_before),))
        self._q("DELETE FROM attempts WHERE at < %s", (int(attempts_before),))
        if outputs_expired_at is not None:
            self._q("DELETE FROM judge_outputs WHERE expires_at < %s", (int(outputs_expired_at),))
        if observations_before is not None:
            self._q("DELETE FROM observations WHERE created_at < %s AND NOT kept", (int(observations_before),))
            self._q("DELETE FROM fresh_observations WHERE day < %s", (int(observations_before) // 86400 - 2,))

    _OBS_SELECT = "SELECT id, account, visibility, lookup_tag, fetched_at, created_at, envelope, body_box, signer, kept FROM observations"

    @staticmethod
    def _obs(row):
        if row is None:
            return None
        o = dict(zip(OBS_FIELDS, row))
        o["envelope"] = json.loads(o["envelope"])
        o["body_box"] = bytes(o["body_box"]) if o["body_box"] is not None else None
        return o

    def put_observation(self, row, files):
        with self.lock:
            c = self._c()
            try:
                with c.transaction():
                    c.execute("INSERT INTO observations (id, account, visibility, lookup_tag, fetched_at, created_at, envelope, body_box, "
                              "signer, kept) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                              (row["id"], row["account"], row["visibility"], row["lookup_tag"], int(row["fetched_at"]),
                               int(row["created_at"]), json.dumps(row["envelope"]), row.get("body_box"), row["signer"],
                               bool(row.get("kept"))))
                    for name, data in files.items():
                        c.execute("INSERT INTO observation_files (observation_id, name, data) VALUES (%s, %s, %s)",
                                  (row["id"], name, bytes(data)))
            except psycopg.errors.UniqueViolation:
                raise Conflict("observation exists") from None

    def get_observation(self, obs_id):
        return self._obs(self._q(self._OBS_SELECT + " WHERE id = %s", (obs_id,), fetch="one"))

    def get_observation_files(self, obs_id):
        return {r[0]: bytes(r[1]) for r in self._q("SELECT name, data FROM observation_files WHERE observation_id = %s",
                                                   (obs_id,), fetch="all")}

    def find_observation(self, tags, since):
        tags = list(tags)
        if not tags:
            return None
        return self._obs(self._q(self._OBS_SELECT + " WHERE lookup_tag = ANY(%s) AND fetched_at >= %s "
                                 "ORDER BY fetched_at DESC, created_at DESC LIMIT 1", (tags, int(since)), fetch="one"))

    def bump_fresh(self, account, day):
        return self._q("INSERT INTO fresh_observations (account, day, n) VALUES (%s, %s, 1) "
                       "ON CONFLICT (account, day) DO UPDATE SET n = fresh_observations.n + 1 RETURNING n",
                       (account, int(day)), fetch="one")[0]

    def fresh_count(self, account, day):
        r = self._q("SELECT n FROM fresh_observations WHERE account = %s AND day = %s", (account, int(day)), fetch="one")
        return int(r[0]) if r else 0
