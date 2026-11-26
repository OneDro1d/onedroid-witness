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

from .storage import (BATCH_FIELDS, EDGE_FIELDS, JOB_FIELDS, KEPT_FIELDS, NDIM_CHAIN_FIELDS, NODE_FIELDS, OBS_FIELDS, OUTCOMES,
                      OUTPUT_FIELDS,
                      SHARE_FIELDS, Conflict, Storage)

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
            # record_id (004_keep) is named only when set, so a row can still be written before that migration ran
            extra = ", record_id" if job.get("record_id") is not None else ""
            args = (job["id"], job["account"], job["state"], int(job["created_at"]), job.get("idem_key"), job.get("request_sha256"),
                    job.get("auto_fp"), job.get("http_status"), job.get("answer"),
                    json.dumps(job["error"]) if job.get("error") is not None else None)
            if extra:
                args += (job["record_id"],)
            self._q(f"INSERT INTO jobs (id, account, state, created_at, idem_key, request_sha256, auto_fp, http_status, answer, error"
                    f"{extra}) VALUES ({', '.join(['%s'] * len(args))})", args)
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

    def append_signing_log(self, payload_id, predicate_type, at, leaf=None, tier="public"):
        # tier (008_signing_log_tier): the column's CHECK refuses anything but public and own
        return self._q("INSERT INTO signing_log (payload_id, predicate_type, at, leaf, tier) VALUES (%s, %s, %s, %s, %s) "
                       "RETURNING seq", (payload_id, predicate_type, int(at), leaf, tier), fetch="one")[0]

    def signing_log(self):
        return [{"seq": r[0], "payload_id": r[1], "predicate_type": r[2], "at": r[3], "leaf": r[4], "batch_id": r[5], "tier": r[6]}
                for r in self._q("SELECT seq, payload_id, predicate_type, at, leaf, batch_id, tier FROM signing_log ORDER BY seq",
                                 fetch="all")]

    def log_tier(self, payload_id):
        r = self._q("SELECT tier FROM signing_log WHERE payload_id = %s ORDER BY seq LIMIT 1", (payload_id,), fetch="one")
        return r[0] if r else None

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

    def set_observation_kept(self, obs_id, kept):
        self._q("UPDATE observations SET kept = %s WHERE id = %s", (bool(kept), obs_id))

    def delete_observation(self, obs_id):
        self._q("DELETE FROM observations WHERE id = %s", (obs_id,))

    # ------------------------------------------------------------------------------------------------- B3: the sealer

    def log_has(self, payload_id):
        return self._q("SELECT 1 FROM signing_log WHERE payload_id = %s LIMIT 1", (payload_id,), fetch="one") is not None

    def pending_leaves(self, limit, max_seq=None, tier=None):
        sql = ("SELECT seq, payload_id, predicate_type, at, leaf, batch_id, tier FROM signing_log "
               "WHERE batch_id IS NULL AND leaf IS NOT NULL")
        args = []
        if max_seq is not None:
            sql += " AND seq <= %s"
            args.append(int(max_seq))
        if tier is not None:
            sql += " AND tier = %s"
            args.append(tier)
        rows = self._q(sql + " ORDER BY seq LIMIT %s", (*args, int(limit)), fetch="all")
        return [dict(zip(("seq", "payload_id", "predicate_type", "at", "leaf", "batch_id", "tier"), r)) for r in rows]

    def write_batch(self, batch, proofs):
        with self.lock:
            c = self._c()
            try:
                with c.transaction():
                    c.execute("INSERT INTO batches (id, first_seq, last_seq, size, root, header, notary, state, created_at) "
                              "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
                              (batch["id"], int(batch["first_seq"]), int(batch["last_seq"]), int(batch["size"]), batch["root"],
                               json.dumps(batch["header"]), json.dumps(batch["notary"]) if batch.get("notary") is not None else None,
                               batch["state"], int(batch["created_at"])))
                    seqs = [int(p["seq"]) for p in proofs]
                    n = c.execute("UPDATE signing_log SET batch_id = %s WHERE seq = ANY(%s) AND batch_id IS NULL",
                                  (batch["id"], seqs)).rowcount
                    if n != len(seqs):
                        raise Conflict("a leaf is already in a batch")
                    with c.cursor() as cur:
                        cur.executemany("INSERT INTO seals (payload_id, batch_id, leaf_index, path) VALUES (%s, %s, %s, %s) "
                                        "ON CONFLICT (payload_id) DO NOTHING",
                                        [(p["payload_id"], batch["id"], int(p["leaf_index"]), json.dumps(p["path"])) for p in proofs])
            except psycopg.errors.UniqueViolation:
                raise Conflict("batch exists") from None

    def update_batch(self, batch_id, **fields):
        cols, args = [], []
        for k, v in fields.items():
            if k not in ("notary", "state"):
                raise KeyError(k)
            cols.append(f"{k} = %s")
            args.append(json.dumps(v) if k == "notary" and v is not None else v)
        self._q(f"UPDATE batches SET {', '.join(cols)} WHERE id = %s", (*args, batch_id))

    @staticmethod
    def _batch(r):
        if r is None:
            return None
        b = dict(zip(BATCH_FIELDS, r))
        b["header"] = json.loads(b["header"])
        b["notary"] = json.loads(b["notary"]) if b["notary"] is not None else None
        return b

    def get_batch(self, batch_id):
        return self._batch(self._q(f"SELECT {', '.join(BATCH_FIELDS)} FROM batches WHERE id = %s", (batch_id,), fetch="one"))

    def batches(self, state=None):
        if state is None:
            rows = self._q(f"SELECT {', '.join(BATCH_FIELDS)} FROM batches ORDER BY first_seq", fetch="all")
        else:
            rows = self._q(f"SELECT {', '.join(BATCH_FIELDS)} FROM batches WHERE state = %s ORDER BY first_seq", (state,), fetch="all")
        return [self._batch(r) for r in rows]

    def get_seal(self, payload_id):
        r = self._q("SELECT batch_id, leaf_index, path FROM seals WHERE payload_id = %s", (payload_id,), fetch="one")
        return {"batch_id": r[0], "leaf_index": r[1], "path": json.loads(r[2])} if r else None

    # ------------------------------------------------------------------------------------------------- B3: kept records

    _JSON_KEPT = ("envelope", "ndim")

    def put_kept(self, row):
        vals = [json.dumps(row.get(k)) if k in self._JSON_KEPT else row.get(k) for k in KEPT_FIELDS]
        try:
            self._q(f"INSERT INTO kept_records ({', '.join(KEPT_FIELDS)}) VALUES ({', '.join(['%s'] * len(KEPT_FIELDS))})", vals)
        except psycopg.errors.UniqueViolation:
            raise Conflict("kept already") from None

    def _kept(self, r):
        if r is None:
            return None
        k = dict(zip(KEPT_FIELDS, r))
        for f in self._JSON_KEPT:
            k[f] = json.loads(k[f])
        for f in ("wrapped_key", "body_box", "evidence_key_box"):
            if k[f] is not None:
                k[f] = bytes(k[f])
        return k

    def get_kept(self, record_id):
        return self._kept(self._q(f"SELECT {', '.join(KEPT_FIELDS)} FROM kept_records WHERE record_id = %s", (record_id,),
                                  fetch="one"))

    def update_kept(self, record_id, **fields):
        cols, args = [], []
        for k, v in fields.items():
            if k not in KEPT_FIELDS or k == "record_id":
                raise KeyError(k)
            cols.append(f"{k} = %s")
            args.append(json.dumps(v) if k in self._JSON_KEPT else v)
        self._q(f"UPDATE kept_records SET {', '.join(cols)} WHERE record_id = %s", (*args, record_id))

    def kept_list(self, account=None, visibility=None):
        sql, args = f"SELECT {', '.join(KEPT_FIELDS)} FROM kept_records WHERE true", []
        if account is not None:
            sql += " AND account = %s"
            args.append(account)
        if visibility is not None:
            sql += " AND visibility = %s"
            args.append(visibility)
        return [self._kept(r) for r in self._q(sql + " ORDER BY kept_at, record_id", args, fetch="all")]

    def put_kept_evidence(self, record_id, rows):
        for r in rows:
            self._q("INSERT INTO kept_evidence (record_id, sha256, box) VALUES (%s, %s, %s) "
                    "ON CONFLICT (record_id, sha256) DO UPDATE SET box = EXCLUDED.box", (record_id, r["sha256"], bytes(r["box"])))

    def get_kept_evidence(self, record_id):
        return [{"sha256": r[0], "box": bytes(r[1])} for r in
                self._q("SELECT sha256, box FROM kept_evidence WHERE record_id = %s ORDER BY sha256", (record_id,), fetch="all")]

    def delete_kept_evidence(self, record_id):
        return self._q("DELETE FROM kept_evidence WHERE record_id = %s", (record_id,))

    def put_index(self, record_id, account, tokens):
        for t in tokens:
            self._q("INSERT INTO owner_index (record_id, account, token) VALUES (%s, %s, %s) ON CONFLICT DO NOTHING",
                    (record_id, account, t))

    def find_index(self, account, tokens):
        tokens = sorted(set(tokens))
        if not tokens:
            return set()
        rows = self._q("SELECT record_id FROM owner_index WHERE account = %s AND token = ANY(%s) GROUP BY record_id "
                       "HAVING count(DISTINCT token) = %s", (account, tokens, len(tokens)), fetch="all")
        return {r[0] for r in rows}

    def delete_index(self, record_id):
        return self._q("DELETE FROM owner_index WHERE record_id = %s", (record_id,))

    def put_share(self, row):
        self._q(f"INSERT INTO share_tokens ({', '.join(SHARE_FIELDS)}) VALUES ({', '.join(['%s'] * len(SHARE_FIELDS))})",
                [row.get(k) for k in SHARE_FIELDS])

    def get_share(self, token_hash):
        r = self._q(f"SELECT {', '.join(SHARE_FIELDS)} FROM share_tokens WHERE token_hash = %s", (token_hash,), fetch="one")
        return dict(zip(SHARE_FIELDS, r)) if r else None

    def shares_of(self, record_id):
        return [dict(zip(SHARE_FIELDS, r)) for r in self._q(
            f"SELECT {', '.join(SHARE_FIELDS)} FROM share_tokens WHERE record_id = %s ORDER BY created_at, token_id",
            (record_id,), fetch="all")]

    def update_share(self, token_id, **fields):
        cols, args = [], []
        for k, v in fields.items():
            if k not in ("revoked_at",):
                raise KeyError(k)
            cols.append(f"{k} = %s")
            args.append(v)
        self._q(f"UPDATE share_tokens SET {', '.join(cols)} WHERE token_id = %s", (*args, token_id))

    def delete_shares(self, record_id):
        return self._q("DELETE FROM share_tokens WHERE record_id = %s", (record_id,))

    def delete_jobs_for_record(self, record_id):
        return self._q("DELETE FROM jobs WHERE record_id = %s", (record_id,))

    # ------------------------------------------------------------------------------------------------- B3W: n-dim chains

    def get_ndim_chain(self, owner_tag):
        r = self._q(f"SELECT {', '.join(NDIM_CHAIN_FIELDS)} FROM ndim_chains WHERE owner_tag = %s", (owner_tag,), fetch="one")
        return dict(zip(NDIM_CHAIN_FIELDS, r)) if r else None

    def put_ndim_chain(self, row):
        try:
            self._q(f"INSERT INTO ndim_chains ({', '.join(NDIM_CHAIN_FIELDS)}) "
                    f"VALUES ({', '.join(['%s'] * len(NDIM_CHAIN_FIELDS))})", [row.get(k) for k in NDIM_CHAIN_FIELDS])
        except psycopg.errors.UniqueViolation:
            raise Conflict("chain exists") from None

    def update_ndim_chain(self, owner_tag, **fields):
        cols, args = [], []
        for k, v in fields.items():
            if k not in NDIM_CHAIN_FIELDS or k == "owner_tag":
                raise KeyError(k)
            cols.append(f"{k} = %s")
            args.append(v)
        self._q(f"UPDATE ndim_chains SET {', '.join(cols)} WHERE owner_tag = %s", (*args, owner_tag))

    def ndim_chains(self):
        return [dict(zip(NDIM_CHAIN_FIELDS, r)) for r in self._q(
            f"SELECT {', '.join(NDIM_CHAIN_FIELDS)} FROM ndim_chains ORDER BY created_at, owner_tag", fetch="all")]

    # ------------------------------------------------------------------------------------------------- B7: graph and search

    def put_nodes(self, rows):
        for r in rows:
            self._q(f"INSERT INTO graph_nodes ({', '.join(NODE_FIELDS)}) VALUES ({', '.join(['%s'] * len(NODE_FIELDS))}) "
                    "ON CONFLICT (id) DO NOTHING", [r.get(k) for k in NODE_FIELDS])

    def get_nodes(self, ids):
        ids = list(ids)
        if not ids:
            return {}
        rows = self._q(f"SELECT {', '.join(NODE_FIELDS)} FROM graph_nodes WHERE id = ANY(%s)", (ids,), fetch="all")
        return {r[0]: dict(zip(NODE_FIELDS, r)) for r in rows}

    def delete_node(self, node_id):
        self._q("DELETE FROM graph_nodes WHERE id = %s", (node_id,))

    def put_edges(self, rows):
        for r in rows:
            self._q(f"INSERT INTO graph_edges ({', '.join(EDGE_FIELDS)}) VALUES ({', '.join(['%s'] * len(EDGE_FIELDS))}) "
                    "ON CONFLICT (src, dst, rel) DO NOTHING", [int(r["at"]) if k == "at" else r.get(k) for k in EDGE_FIELDS])

    def edges_touching(self, ids):
        ids = list(ids)
        if not ids:
            return []
        rows = self._q(f"SELECT {', '.join(EDGE_FIELDS)} FROM graph_edges WHERE src = ANY(%s) OR dst = ANY(%s)", (ids, ids),
                       fetch="all")
        return [dict(zip(EDGE_FIELDS, r)) for r in rows]

    def delete_edges_touching(self, node_id):
        return self._q("DELETE FROM graph_edges WHERE src = %s OR dst = %s", (node_id, node_id))

    def clear_graph(self):
        self._q("DELETE FROM graph_edges")
        self._q("DELETE FROM graph_nodes")

    def put_search_doc(self, record_id, body, tokens, embedding=None):
        """The tokens are plain alphanumeric words already normalised in Python, so the tsvector and the query parse them the
        same way on both storage backends."""
        self._q("INSERT INTO search_docs (record_id, body, fts, embedding) VALUES (%s, %s, to_tsvector('simple', %s), %s::real[]) "
                "ON CONFLICT (record_id) DO UPDATE SET body = EXCLUDED.body, fts = EXCLUDED.fts, embedding = EXCLUDED.embedding",
                (record_id, body, " ".join(tokens), list(embedding) if embedding else None))

    def get_search_doc(self, record_id):
        r = self._q("SELECT record_id, body, embedding FROM search_docs WHERE record_id = %s", (record_id,), fetch="one")
        return {"record_id": r[0], "body": r[1], "embedding": [float(x) for x in r[2]] if r[2] else None} if r else None

    def delete_search_doc(self, record_id):
        self._q("DELETE FROM search_docs WHERE record_id = %s", (record_id,))

    def set_embedding(self, record_id, embedding):
        self._q("UPDATE search_docs SET embedding = %s::real[] WHERE record_id = %s", (list(embedding), record_id))

    def docs_missing_embedding(self, limit):
        return [(r[0], r[1]) for r in self._q("SELECT record_id, body FROM search_docs WHERE embedding IS NULL ORDER BY record_id "
                                              "LIMIT %s", (int(limit),), fetch="all")]

    @staticmethod
    def _filters(method, outcome, since):
        sql, args = "", []
        for col, v, op in (("k.method", method, "="), ("k.outcome", outcome, "="), ("k.witnessed_at", since, ">=")):
            if v is not None:
                sql += f" AND {col} {op} %s"
                args.append(v)
        return sql, args

    def search_records(self, tokens, method, outcome, since, account, limit, offset):
        """See MemoryStorage.search_records. The words go to plainto_tsquery as ONE bound parameter (alphanumeric words joined
        by spaces): no tsquery operator and no SQL can come out of a query."""
        flt, fargs = self._filters(method, outcome, since)
        if tokens:
            sql = ("SELECT k.record_id FROM search_docs d JOIN kept_records k ON k.record_id = d.record_id "
                   "WHERE k.visibility = 'public' AND k.taken_down_at IS NULL AND d.fts @@ plainto_tsquery('simple', %s)" + flt)
            args = [" ".join(tokens), *fargs]
        else:
            sql = ("SELECT k.record_id FROM kept_records k WHERE k.taken_down_at IS NULL AND (k.visibility = 'public' "
                   "OR (%s::text IS NOT NULL AND k.visibility = 'private' AND k.account = %s AND k.deleted_at IS NULL))" + flt)
            args = [account, account, *fargs]
        rows = self._q(sql + " ORDER BY k.kept_at DESC, k.record_id LIMIT %s OFFSET %s", (*args, int(limit), int(offset)), fetch="all")
        return [r[0] for r in rows]

    def semantic_docs(self, method, outcome, since, limit):
        flt, fargs = self._filters(method, outcome, since)
        rows = self._q("SELECT d.record_id, d.embedding FROM search_docs d JOIN kept_records k ON k.record_id = d.record_id "
                       "WHERE k.visibility = 'public' AND k.taken_down_at IS NULL AND d.embedding IS NOT NULL" + flt
                       + " ORDER BY k.kept_at DESC, k.record_id LIMIT %s", (*fargs, int(limit)), fetch="all")
        return [(r[0], [float(x) for x in r[1]]) for r in rows]
