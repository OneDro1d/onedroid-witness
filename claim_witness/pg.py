"""Postgres storage (BD7, psycopg 3). Migrations are the plain SQL files in claim_witness/migrations/, applied in file-name
order once each and recorded in schema_migrations. One autocommit connection behind a lock, reopened when it breaks."""
import json
import pathlib
import threading

import psycopg

from .storage import JOB_FIELDS, OUTCOMES, Conflict, Storage

MIGRATIONS = pathlib.Path(__file__).resolve().parent / "migrations"
MIGRATION_LOCK = 0x636C6169  # "clai": the advisory lock key the migration holds


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

    def purge(self, jobs_before, nonces_before, attempts_before):
        self._q("DELETE FROM jobs WHERE created_at < %s", (int(jobs_before),))
        self._q("DELETE FROM nonces WHERE at < %s", (int(nonces_before),))
        self._q("DELETE FROM attempts WHERE at < %s", (int(attempts_before),))
