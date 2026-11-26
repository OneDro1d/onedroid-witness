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
# Own model key (C2): the tier of a signing-log row. 'own' rows (signed while serving an own-key request) are sealed only in
# own batches, anchored on OneDroid's own chain; every other row, and every row from before migration 008, is 'public'.
TIERS = ("public", "own")
JOB_FIELDS = ("id", "account", "state", "created_at", "idem_key", "request_sha256", "auto_fp", "http_status", "answer", "error",
              "record_id")
OBS_FIELDS = ("id", "account", "visibility", "lookup_tag", "fetched_at", "created_at", "envelope", "body_box", "signer", "kept")
# B3: batches and proofs (SPEC §7.2), kept records with the BD1 custody, the owner index, share tokens
BATCH_FIELDS = ("id", "first_seq", "last_seq", "size", "root", "header", "notary", "state", "created_at")
KEPT_FIELDS = ("record_id", "account", "visibility", "method", "outcome", "witnessed_at", "envelope", "wrapped_key", "body_box",
               "evidence_key_box", "evidence_expires_at", "evidence_deleted_at", "kept_at", "deleted_at", "taken_down_at",
               "takedown_by", "ndim")
SHARE_FIELDS = ("token_id", "token_hash", "record_id", "account", "evidence", "created_at", "expires_at", "revoked_at")
# B3W: one n-dim claimant chain per owner, keyed by owner_tag = HMAC(key, account) (never the account itself)
NDIM_CHAIN_FIELDS = ("owner_tag", "case_id", "claimant_id", "state", "attempts", "next_try_at", "last_error", "created_at",
                     "updated_at")


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
    def append_signing_log(self, payload_id, predicate_type, at, leaf=None, tier="public"): raise NotImplementedError
    def signing_log(self): raise NotImplementedError
    def log_tier(self, payload_id): raise NotImplementedError  # "public" | "own" | None (not in the log)
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
    def set_observation_kept(self, obs_id, kept): raise NotImplementedError
    def delete_observation(self, obs_id): raise NotImplementedError
    # B3, the sealer: append_signing_log(..., leaf=H(0x00 || payload)); leaves not yet in a batch; a batch and its proofs
    def log_has(self, payload_id): raise NotImplementedError
    def pending_leaves(self, limit, max_seq=None, tier=None): raise NotImplementedError
    def write_batch(self, batch, proofs): raise NotImplementedError
    def update_batch(self, batch_id, **fields): raise NotImplementedError
    def get_batch(self, batch_id): raise NotImplementedError
    def batches(self, state=None): raise NotImplementedError
    def get_seal(self, payload_id): raise NotImplementedError
    # B3, kept records (BD1): ciphertext and wrapped keys only, the owner index as keyed tokens, share tokens as hashes
    def put_kept(self, row): raise NotImplementedError
    def get_kept(self, record_id): raise NotImplementedError
    def update_kept(self, record_id, **fields): raise NotImplementedError
    def kept_list(self, account=None, visibility=None): raise NotImplementedError
    def put_kept_evidence(self, record_id, rows): raise NotImplementedError
    def get_kept_evidence(self, record_id): raise NotImplementedError
    def delete_kept_evidence(self, record_id): raise NotImplementedError
    def put_index(self, record_id, account, tokens): raise NotImplementedError
    def find_index(self, account, tokens): raise NotImplementedError
    def delete_index(self, record_id): raise NotImplementedError
    def put_share(self, row): raise NotImplementedError
    def get_share(self, token_hash): raise NotImplementedError
    def shares_of(self, record_id): raise NotImplementedError
    def update_share(self, token_id, **fields): raise NotImplementedError
    def delete_shares(self, record_id): raise NotImplementedError
    def delete_jobs_for_record(self, record_id): raise NotImplementedError
    # B3W, n-dim: the claimant chain of each owner (state pending | ready | failed), created in the background with backoff
    def get_ndim_chain(self, owner_tag): raise NotImplementedError
    def put_ndim_chain(self, row): raise NotImplementedError
    def update_ndim_chain(self, owner_tag, **fields): raise NotImplementedError
    def ndim_chains(self): raise NotImplementedError
    # B7, the record graph: nodes (public ones hold no account), PROV-O edges with the visibility of their most private end
    def put_nodes(self, rows): raise NotImplementedError
    def get_nodes(self, ids): raise NotImplementedError
    def delete_node(self, node_id): raise NotImplementedError
    def put_edges(self, rows): raise NotImplementedError
    def edges_touching(self, ids): raise NotImplementedError
    def delete_edges_touching(self, node_id): raise NotImplementedError
    def clear_graph(self): raise NotImplementedError
    # B7, search: the text (and optional embedding) of public kept records; the query joins the kept rows
    def put_search_doc(self, record_id, body, tokens, embedding=None): raise NotImplementedError
    def get_search_doc(self, record_id): raise NotImplementedError
    def delete_search_doc(self, record_id): raise NotImplementedError
    def set_embedding(self, record_id, embedding): raise NotImplementedError
    def docs_missing_embedding(self, limit): raise NotImplementedError
    def search_records(self, tokens, method, outcome, since, account, limit, offset): raise NotImplementedError
    def semantic_docs(self, method, outcome, since, limit): raise NotImplementedError


NODE_FIELDS = ("id", "kind", "visibility", "account", "method", "outcome", "witnessed_at")
EDGE_FIELDS = ("src", "dst", "rel", "visibility", "src_account", "dst_account", "at")
OUTPUT_FIELDS = ("record_id", "model", "provider", "served_model", "raw", "created_at", "expires_at")


class MemoryStorage(Storage):
    def __init__(self):
        self.lock = threading.RLock()
        self.jobs, self.log, self.agent_keys, self.nonces, self.attempts, self.key_lists = {}, [], {}, {}, [], {}
        self.outputs = []
        self.observations, self.obs_files, self.fresh = {}, {}, {}
        self.batch_rows, self.seal_rows, self.kept, self.kept_ev, self.index, self.shares = {}, {}, {}, {}, set(), {}
        self.ndim_chain_rows = {}
        self.nodes, self.edges, self.docs = {}, {}, {}

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

    def append_signing_log(self, payload_id, predicate_type, at, leaf=None, tier="public"):
        if tier not in TIERS:
            raise ValueError(f"tier: one of {TIERS}")
        with self.lock:
            seq = len(self.log) + 1
            self.log.append({"seq": seq, "payload_id": payload_id, "predicate_type": predicate_type, "at": int(at), "leaf": leaf,
                             "batch_id": None, "tier": tier})
            self._changed()
            return seq

    def signing_log(self):
        with self.lock:
            return [dict(r, tier=r.get("tier") or "public") for r in self.log]

    def log_tier(self, payload_id):
        with self.lock:
            for r in self.log:
                if r["payload_id"] == payload_id:
                    return r.get("tier") or "public"
        return None

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


    def set_observation_kept(self, obs_id, kept):
        with self.lock:
            if obs_id in self.observations:
                self.observations[obs_id]["kept"] = bool(kept)
                self._changed()

    def delete_observation(self, obs_id):
        with self.lock:
            self.observations.pop(obs_id, None)
            self.obs_files.pop(obs_id, None)
            self._changed()

    # ------------------------------------------------------------------------------------------------- B3: the sealer

    def log_has(self, payload_id):
        with self.lock:
            return any(r["payload_id"] == payload_id for r in self.log)

    def pending_leaves(self, limit, max_seq=None, tier=None):
        with self.lock:
            rows = [dict(r, tier=r.get("tier") or "public") for r in self.log if r.get("leaf") and r.get("batch_id") is None
                    and (max_seq is None or r["seq"] <= max_seq) and (tier is None or (r.get("tier") or "public") == tier)]
            return rows[:limit]

    def write_batch(self, batch, proofs):
        with self.lock:
            by_seq = {r["seq"]: r for r in self.log}
            if batch["id"] in self.batch_rows or any(by_seq[p["seq"]].get("batch_id") for p in proofs):
                raise Conflict("a leaf is already in a batch")
            self.batch_rows[batch["id"]] = copy.deepcopy({k: batch.get(k) for k in BATCH_FIELDS})
            for p in proofs:
                by_seq[p["seq"]]["batch_id"] = batch["id"]
                self.seal_rows.setdefault(p["payload_id"], {"batch_id": batch["id"], "leaf_index": p["leaf_index"],
                                                            "path": list(p["path"])})
            self._changed()

    def update_batch(self, batch_id, **fields):
        with self.lock:
            self.batch_rows[batch_id].update(copy.deepcopy(fields))
            self._changed()

    def get_batch(self, batch_id):
        with self.lock:
            b = self.batch_rows.get(batch_id)
            return copy.deepcopy(b) if b else None

    def batches(self, state=None):
        with self.lock:
            return [copy.deepcopy(b) for b in self.batch_rows.values() if state is None or b["state"] == state]

    def get_seal(self, payload_id):
        with self.lock:
            s = self.seal_rows.get(payload_id)
            return copy.deepcopy(s) if s else None

    # ------------------------------------------------------------------------------------------------- B3: kept records

    def put_kept(self, row):
        with self.lock:
            if row["record_id"] in self.kept:
                raise Conflict("kept already")
            self.kept[row["record_id"]] = copy.deepcopy({k: row.get(k) for k in KEPT_FIELDS})
            self._changed()

    def get_kept(self, record_id):
        with self.lock:
            r = self.kept.get(record_id)
            return copy.deepcopy(r) if r else None

    def update_kept(self, record_id, **fields):
        with self.lock:
            for k in fields:
                if k not in KEPT_FIELDS or k == "record_id":
                    raise KeyError(k)
            self.kept[record_id].update(copy.deepcopy(fields))
            self._changed()

    def kept_list(self, account=None, visibility=None):
        with self.lock:
            rows = [copy.deepcopy(r) for r in self.kept.values()
                    if (account is None or r["account"] == account) and (visibility is None or r["visibility"] == visibility)]
            return sorted(rows, key=lambda r: (r["kept_at"], r["record_id"]))

    def put_kept_evidence(self, record_id, rows):
        with self.lock:
            for r in rows:
                self.kept_ev[(record_id, r["sha256"])] = bytes(r["box"])
            self._changed()

    def get_kept_evidence(self, record_id):
        with self.lock:
            return [{"sha256": s, "box": b} for (rid, s), b in sorted(self.kept_ev.items()) if rid == record_id]

    def delete_kept_evidence(self, record_id):
        with self.lock:
            gone = [k for k in self.kept_ev if k[0] == record_id]
            for k in gone:
                del self.kept_ev[k]
            self._changed()
            return len(gone)

    def put_index(self, record_id, account, tokens):
        with self.lock:
            for t in tokens:
                self.index.add((record_id, account, t))
            self._changed()

    def find_index(self, account, tokens):
        with self.lock:
            tokens = set(tokens)
            have = {}
            for rid, acct, t in self.index:
                if acct == account and t in tokens:
                    have.setdefault(rid, set()).add(t)
            return {rid for rid, ts in have.items() if ts == tokens}

    def delete_index(self, record_id):
        with self.lock:
            gone = {x for x in self.index if x[0] == record_id}
            self.index -= gone
            self._changed()
            return len(gone)

    def put_share(self, row):
        with self.lock:
            self.shares[row["token_id"]] = {k: row.get(k) for k in SHARE_FIELDS}
            self._changed()

    def get_share(self, token_hash):
        with self.lock:
            for r in self.shares.values():
                if r["token_hash"] == token_hash:
                    return dict(r)
            return None

    def shares_of(self, record_id):
        with self.lock:
            return sorted((dict(r) for r in self.shares.values() if r["record_id"] == record_id),
                          key=lambda r: (r["created_at"], r["token_id"]))

    def update_share(self, token_id, **fields):
        with self.lock:
            self.shares[token_id].update(fields)
            self._changed()

    def delete_shares(self, record_id):
        with self.lock:
            gone = [k for k, r in self.shares.items() if r["record_id"] == record_id]
            for k in gone:
                del self.shares[k]
            self._changed()
            return len(gone)

    def delete_jobs_for_record(self, record_id):
        with self.lock:
            gone = [k for k, j in self.jobs.items() if j.get("record_id") == record_id]
            for k in gone:
                del self.jobs[k]
            self._changed()
            return len(gone)

    def get_ndim_chain(self, owner_tag):
        with self.lock:
            r = self.ndim_chain_rows.get(owner_tag)
            return dict(r) if r else None

    def put_ndim_chain(self, row):
        with self.lock:
            if row["owner_tag"] in self.ndim_chain_rows:
                raise Conflict("chain exists")
            self.ndim_chain_rows[row["owner_tag"]] = {k: row.get(k) for k in NDIM_CHAIN_FIELDS}
            self._changed()

    def update_ndim_chain(self, owner_tag, **fields):
        with self.lock:
            for k in fields:
                if k not in NDIM_CHAIN_FIELDS or k == "owner_tag":
                    raise KeyError(k)
            self.ndim_chain_rows[owner_tag].update(fields)
            self._changed()

    def ndim_chains(self):
        with self.lock:
            return [dict(r) for r in sorted(self.ndim_chain_rows.values(), key=lambda r: (r["created_at"], r["owner_tag"]))]

    # ------------------------------------------------------------------------------------------------- B7: graph and search

    def put_nodes(self, rows):
        with self.lock:
            for r in rows:
                self.nodes.setdefault(r["id"], {k: r.get(k) for k in NODE_FIELDS})  # a node's visibility never changes
            self._changed()

    def get_nodes(self, ids):
        with self.lock:
            return {i: dict(self.nodes[i]) for i in ids if i in self.nodes}

    def delete_node(self, node_id):
        with self.lock:
            self.nodes.pop(node_id, None)
            self._changed()

    def put_edges(self, rows):
        with self.lock:
            for r in rows:
                self.edges.setdefault((r["src"], r["dst"], r["rel"]), {k: r.get(k) for k in EDGE_FIELDS})
            self._changed()

    def edges_touching(self, ids):
        with self.lock:
            ids = set(ids)
            return [dict(e) for e in self.edges.values() if e["src"] in ids or e["dst"] in ids]

    def delete_edges_touching(self, node_id):
        with self.lock:
            gone = [k for k, e in self.edges.items() if node_id in (e["src"], e["dst"])]
            for k in gone:
                del self.edges[k]
            self._changed()
            return len(gone)

    def clear_graph(self):
        with self.lock:
            self.nodes.clear()
            self.edges.clear()
            self._changed()

    def put_search_doc(self, record_id, body, tokens, embedding=None):
        with self.lock:
            self.docs[record_id] = {"body": body, "tokens": set(tokens), "embedding": list(embedding) if embedding else None}
            self._changed()

    def get_search_doc(self, record_id):
        with self.lock:
            d = self.docs.get(record_id)
            if d is None:
                return None
            return {"record_id": record_id, "body": d["body"], "embedding": list(d["embedding"]) if d["embedding"] else None}

    def delete_search_doc(self, record_id):
        with self.lock:
            self.docs.pop(record_id, None)
            self._changed()

    def set_embedding(self, record_id, embedding):
        with self.lock:
            if record_id in self.docs:
                self.docs[record_id]["embedding"] = list(embedding)
                self._changed()

    def docs_missing_embedding(self, limit):
        with self.lock:
            return [(rid, d["body"]) for rid, d in sorted(self.docs.items()) if d["embedding"] is None][:int(limit)]

    def _search_rows(self, method, outcome, since):
        for k in self.kept.values():
            if (method is None or k["method"] == method) and (outcome is None or k["outcome"] == outcome) \
                    and (since is None or k["witnessed_at"] >= since):
                yield k

    def search_records(self, tokens, method, outcome, since, account, limit, offset):
        """Record ids, newest kept first: the public kept records not taken down whose indexed words include every token;
        with no tokens, every such record and, for `account`, that account's own live private ones (listed, never matched)."""
        with self.lock:
            want, rows = set(tokens), []
            for k in self._search_rows(method, outcome, since):
                if k["taken_down_at"] is not None:
                    continue
                public = k["visibility"] == "public"
                mine = (not want and account is not None and k["visibility"] == "private" and k["account"] == account
                        and k["deleted_at"] is None)
                if not (public or mine):
                    continue
                if want:
                    d = self.docs.get(k["record_id"])
                    if d is None or not want <= d["tokens"]:
                        continue
                rows.append(k)
            rows.sort(key=lambda k: (-k["kept_at"], k["record_id"]))
            return [k["record_id"] for k in rows[int(offset):int(offset) + int(limit)]]

    def semantic_docs(self, method, outcome, since, limit):
        with self.lock:
            rows = [k for k in self._search_rows(method, outcome, since)
                    if k["visibility"] == "public" and k["taken_down_at"] is None
                    and (self.docs.get(k["record_id"]) or {}).get("embedding")]
            rows.sort(key=lambda k: (-k["kept_at"], k["record_id"]))
            return [(k["record_id"], list(self.docs[k["record_id"]]["embedding"])) for k in rows[:int(limit)]]


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
