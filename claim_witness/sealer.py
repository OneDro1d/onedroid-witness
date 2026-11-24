"""The sealer (SPEC §2.5, §7.1, §7.2; DECISIONS BD4). It runs in the API process as one background thread.

Each tick:
  1. closes batches. A batch is the signing-log leaves not yet in a batch, in log order, at most `batch_max_leaves`
     (100,000). It closes when it is full or when its oldest leaf is `batch_interval_s` old (3,600 s on dev), so every leaf is
     batched within the interval plus one poll. Leaves signed during the tick (its own batch headers) wait for the next tick;
  2. per batch: the Merkle tree (merkle.py, RFC 9162), the header {witness, batch_id, root, size, opened_at, closed_at,
     interval_s, key_id} signed by the signer sidecar (predicateType batch-header/v1, PAE over the canonical header), the
     proofs written, then the notary: over = "sha256:" + H(canonical signed header), key = that hex (NotaryClient);
  3. repeats the notary for batches whose seal has not landed or is not final on every chain (the same key and bytes, so the
     same request; B3W: the real notary answers final:false on base-sepolia at write time);
  4. brings each kept record's n-dim object up to date (records.Records.ndim_sync_all). In start() this runs in its own
     thread ("ndim"), because the first create of an owner's claimant chain can take minutes and must not hold up sealing.

batch_id = H(canonical {witness, first_seq, last_seq, root}). opened_at is the time of the batch's first leaf, closed_at the
tick's time. Without a notary a batch is closed and proved but never anchored (state "unanchored"; its seal stays pending)."""
import hashlib
import sys
import threading
import time

from . import jcs, merkle, notary as notary_mod
from .schemas import BATCH_TYPE


def iso(t):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(int(t)))


def over_of(signed_header):
    """The hex the notary seals: H(canonical signed batch header), the header with its `sig`."""
    return hashlib.sha256(jcs.canonical(signed_header)).hexdigest()


def batch_id_of(witness_id, first_seq, last_seq, root):
    return hashlib.sha256(jcs.canonical({"witness": witness_id, "first_seq": int(first_seq), "last_seq": int(last_seq),
                                         "root": root})).hexdigest()


def header_of(witness_id, key_id, rows, root, closed_at, interval_s):
    return {"witness": witness_id, "batch_id": batch_id_of(witness_id, rows[0]["seq"], rows[-1]["seq"], root), "root": root,
            "size": len(rows), "opened_at": iso(rows[0]["at"]), "closed_at": iso(closed_at), "interval_s": int(interval_s),
            "key_id": key_id}


def seal_of(batch, proof):
    """The seal object of SPEC §2.5 for one leaf of a stored batch."""
    return {"state": "anchored" if batch["state"] == "anchored" else "pending", "leaf_index": proof["leaf_index"],
            "path": list(proof["path"]), "batch_header": batch["header"], "notary": batch["notary"]}


class Sealer:
    def __init__(self, witness):
        self.w = witness
        self.lock = threading.Lock()
        self.ndim_lock = threading.Lock()
        self._stop = threading.Event()
        self.thread = None
        self.ndim_thread = None

    # ------------------------------------------------------------------------------------------------------- reads

    def seal_view(self, payload_id):
        """The seal of any payload id in the signing log ({"state": "pending"} until its batch closes), or None."""
        st = self.w.storage
        proof = st.get_seal(payload_id)
        if proof is None:
            return {"state": "pending"} if st.log_has(payload_id) else None
        return seal_of(st.get_batch(proof["batch_id"]), proof)

    # ------------------------------------------------------------------------------------------------------- the tick

    def tick(self, ndim=True):
        """Close what is due, repeat unlanded or not-yet-final notary calls, sync n-dim (unless ndim=False: the n-dim thread
        does that). Returns the ids of the batches closed."""
        with self.lock:
            closed = self._close_due()
            self._retry_notary()
        if ndim:
            self.ndim_tick()
        return closed

    def ndim_tick(self):
        with self.ndim_lock:
            try:
                self.w.records.ndim_sync_all()
            except Exception as e:  # noqa: BLE001 - n-dim never stops the sealing
                print(f"sealer: n-dim sync failed ({type(e).__name__})", file=sys.stderr, flush=True)

    def _close_due(self):
        cfg, st = self.w.cfg, self.w.storage
        now = self.w.now()
        closed, max_seq = [], None
        while True:
            rows = st.pending_leaves(cfg.batch_max_leaves, max_seq=max_seq)
            if not rows or (len(rows) < cfg.batch_max_leaves and now - rows[0]["at"] < cfg.batch_interval_s):
                return closed
            bid, header_seq = self._close(rows, now)
            closed.append(bid)
            if max_seq is None:
                max_seq = header_seq - 1  # the header signed now waits for the next tick

    def _close(self, rows, now):
        cfg, st = self.w.cfg, self.w.storage
        leaves = [r["leaf"] for r in rows]
        root, paths = merkle.root(leaves), merkle.paths(leaves)
        info = self.w.signer.info()
        header = header_of(cfg.witness_id, info["key_id"], rows, root, now, cfg.batch_interval_s)
        signed = self.w.signer.sign(BATCH_TYPE, header)
        full = dict(header, sig=signed["sig"])
        batch = {"id": header["batch_id"], "first_seq": rows[0]["seq"], "last_seq": rows[-1]["seq"], "size": len(rows),
                 "root": root, "header": full, "notary": None if cfg.notary is not None else notary_mod.off_result(),
                 "state": "pending" if cfg.notary is not None else "unanchored", "created_at": now}
        st.write_batch(batch, [{"seq": r["seq"], "payload_id": r["payload_id"], "leaf_index": i, "path": paths[i]}
                               for i, r in enumerate(rows)])
        if cfg.notary is not None:
            self._notarize(batch["id"], full)
        return batch["id"], signed["log_seq"]

    def _notarize(self, batch_id, signed_header):
        try:
            res = self.w.cfg.notary.seal(over_of(signed_header))
        except Exception as e:  # noqa: BLE001 - a notary failure leaves the seal pending, retried next tick
            res = {"status": "failed", "profile": notary_mod.PROFILE, "over": "sha256:" + over_of(signed_header),
                   "key": over_of(signed_header), "anchors": [], "reason": f"error: {type(e).__name__}"}
        self.w.storage.update_batch(batch_id, notary=res, state="anchored" if notary_mod.all_final(res) else "pending")

    def _retry_notary(self):
        if self.w.cfg.notary is None:
            return
        for b in self.w.storage.batches("pending"):
            self._notarize(b["id"], b["header"])

    # ------------------------------------------------------------------------------------------------------- the loop

    def start(self, poll_s=None):
        poll = float(poll_s if poll_s is not None else self.w.cfg.sealer_poll_s)
        self._stop.clear()
        if self.w.cfg.armarium is not None:
            self.w.records.ndim_rearm()  # what failed before a restart is tried again, once

        def loop():
            while not self._stop.wait(poll):
                try:
                    self.tick(ndim=False)
                except Exception as e:  # noqa: BLE001 - the loop keeps going; the next tick retries
                    print(f"sealer: tick failed ({type(e).__name__})", file=sys.stderr, flush=True)

        def ndim_loop():
            while not self._stop.wait(poll):
                self.ndim_tick()

        self.thread = threading.Thread(target=loop, daemon=True, name="sealer")
        self.thread.start()
        if self.w.cfg.armarium is not None:
            self.ndim_thread = threading.Thread(target=ndim_loop, daemon=True, name="ndim")
            self.ndim_thread.start()
        return self.thread

    def stop(self):
        self._stop.set()
        for t in (self.thread, self.ndim_thread):
            if t is not None:
                t.join(timeout=10)
