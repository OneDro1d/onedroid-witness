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
tick's time. Without a notary a batch is closed and proved but never anchored (state "unanchored"; its seal stays pending).

Own model key (C2): the signing log's rows have a tier (public | own). Batches are formed per tier and never mix them; the
header says `anchoring` (signed), and its own leaf takes the batch's tier. Public batches go to `cfg.notary` (hash/1); own
batches only to `cfg.notary_own` when its profile is not hash/1, else they close unanchored; an own answer naming any chain but
lab-qbft is a failed seal (own_seal_guard)."""
import hashlib
import sys
import threading
import time

from . import jcs, merkle, notary as notary_mod
from .schemas import BATCH_TYPE
from .storage import TIERS


def iso(t):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(int(t)))


def over_of(signed_header):
    """The hex the notary seals: H(canonical signed batch header), the header with its `sig`."""
    return hashlib.sha256(jcs.canonical(signed_header)).hexdigest()


def batch_id_of(witness_id, first_seq, last_seq, root):
    return hashlib.sha256(jcs.canonical({"witness": witness_id, "first_seq": int(first_seq), "last_seq": int(last_seq),
                                         "root": root})).hexdigest()


def header_of(witness_id, key_id, rows, root, closed_at, interval_s, anchoring=None):
    """The batch header. `anchoring` ("public" | "own", own model key C2) is added when given; the sealer always gives it, and a
    header without it (every seal before C2, and the B3 vectors) is public."""
    out = {"witness": witness_id, "batch_id": batch_id_of(witness_id, rows[0]["seq"], rows[-1]["seq"], root), "root": root,
           "size": len(rows), "opened_at": iso(rows[0]["at"]), "closed_at": iso(closed_at), "interval_s": int(interval_s),
           "key_id": key_id}
    if anchoring is not None:
        out["anchoring"] = anchoring
    return out


def anchoring_of(header):
    return (header or {}).get("anchoring", "public")


def own_seal_guard(res, signed_header):
    """Own model key (C2): a notary answer for an own batch that names any chain other than lab-qbft (or answers for the public
    profile) is a failed seal, never an anchor: status failed, no anchors kept, the reason naming the chain. The batch stays
    pending and is asked again on the next tick, with the own client only."""
    if not isinstance(res, dict):
        return res
    anchors = res.get("anchors") or []
    other = sorted({str(a.get("chain")) for a in anchors if isinstance(a, dict) and a.get("chain") != notary_mod.OWN_CHAIN})
    if not other and res.get("profile") != notary_mod.PROFILE:
        return res
    why = (f"own_chain: the notary answered {', '.join(other)} for an own batch; an own batch is anchored on "
           f"{notary_mod.OWN_CHAIN} only") if other else "own_chain: the notary answered for profile hash/1 for an own batch"
    return {"status": "failed", "profile": res.get("profile"), "over": res.get("over") or "sha256:" + over_of(signed_header),
            "key": res.get("key") or over_of(signed_header), "anchors": [], "reason": why}


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
        """Own model key (C2): batches are formed per tier, public first, and never mix tiers. The headers signed in this tick
        (of either tier) wait for the next one."""
        cfg, st = self.w.cfg, self.w.storage
        now = self.w.now()
        closed, max_seq = [], None
        for tier in TIERS:
            while True:
                rows = st.pending_leaves(cfg.batch_max_leaves, max_seq=max_seq, tier=tier)
                if not rows or (len(rows) < cfg.batch_max_leaves and now - rows[0]["at"] < cfg.batch_interval_s):
                    break
                bid, header_seq = self._close(rows, now, tier)
                closed.append(bid)
                if max_seq is None:
                    max_seq = header_seq - 1  # the header signed now waits for the next tick
        return closed

    def notary_for(self, tier):
        """The notary client for a tier, or None (the batch closes unanchored). Public: WITNESS_NOTARY_* (hash/1). Own: only the
        own client, and only when its profile is not hash/1 (a client without a profile counts as hash/1): an own batch is
        never sent with the public profile."""
        cfg = self.w.cfg
        if tier != "own":
            return cfg.notary
        own = getattr(cfg, "notary_own", None)
        if own is None or getattr(own, "profile", notary_mod.PROFILE) == notary_mod.PROFILE or own is cfg.notary:
            return None
        return own

    def _close(self, rows, now, tier="public"):
        cfg, st = self.w.cfg, self.w.storage
        if any((r.get("tier") or "public") != tier for r in rows):
            raise RuntimeError("a batch never mixes tiers")
        client = self.notary_for(tier)
        leaves = [r["leaf"] for r in rows]
        root, paths = merkle.root(leaves), merkle.paths(leaves)
        info = self.w.signer.info()
        header = header_of(cfg.witness_id, info["key_id"], rows, root, now, cfg.batch_interval_s, anchoring=tier)
        signed = self.w.signer.sign(BATCH_TYPE, header, tier=tier)  # the header's own leaf joins the next batch of its tier
        full = dict(header, sig=signed["sig"])
        batch = {"id": header["batch_id"], "first_seq": rows[0]["seq"], "last_seq": rows[-1]["seq"], "size": len(rows),
                 "root": root, "header": full, "notary": None if client is not None else notary_mod.off_result(),
                 "state": "pending" if client is not None else "unanchored", "created_at": now}
        st.write_batch(batch, [{"seq": r["seq"], "payload_id": r["payload_id"], "leaf_index": i, "path": paths[i]}
                               for i, r in enumerate(rows)])
        if client is not None:
            self._notarize(batch["id"], full, client)
        return batch["id"], signed["log_seq"]

    def _notarize(self, batch_id, signed_header, client):
        tier = anchoring_of(signed_header)
        try:
            res = client.seal(over_of(signed_header))
        except Exception as e:  # noqa: BLE001 - a notary failure leaves the seal pending, retried next tick
            res = {"status": "failed", "profile": getattr(client, "profile", notary_mod.PROFILE),
                   "over": "sha256:" + over_of(signed_header), "key": over_of(signed_header), "anchors": [],
                   "reason": f"error: {type(e).__name__}"}
        if tier == "own":
            res = own_seal_guard(res, signed_header)
        self.w.storage.update_batch(batch_id, notary=res, state="anchored" if notary_mod.all_final(res) else "pending")

    def _retry_notary(self):
        for b in self.w.storage.batches("pending"):
            client = self.notary_for(anchoring_of(b["header"]))
            if client is not None:
                self._notarize(b["id"], b["header"], client)

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
