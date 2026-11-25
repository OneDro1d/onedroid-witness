"""The record graph (SPEC §3, §10 VR-10 and VR-20; ARCHITECTURE §5 standalone): W3C PROV-O edges between records, observations and
agents, kept in the witness's own Postgres (graph_nodes, graph_edges; BD7: no Engram, no store-gateway).

Edges, written when a record is signed (record_signed) and again, idempotently, for records signed earlier (backfill):

    record  used            observation      every observation the record relied on (relied_on)
    record  wasDerivedFrom  record           a disclosed record the claim was built on (evidence kind "record": the B5b hook)
    record  wasAttributedTo witness          every record: this witness signed it
    record  wasAttributedTo agent            a PUBLIC record signed for an agent (the agent id agt_..., never its key or account)

An edge takes the visibility of its MOST private end. Each private end names its owner in src_account / dst_account (null for a
public end); a reader sees an edge only when every private end is theirs. A node is visible to the public when it is public (and
not taken down), and to its owner when private.

What a reader gets from GET /v1/records/{id}/graph?depth=N (a record or an observation id; breadth first, both directions):
the public nodes and edges, plus their own private ones; a share-token holder additionally gets the private edges and nodes
touching the one record the token opens. Another account's private node, edge, flag or count is never in the answer: the answer
to a reader is a function of what that reader may see alone (the truncation flag is computed from visible nodes only). A private
node the reader may not see answers exactly like an id that does not exist (404). The witness and agent nodes are leaves: the
traversal does not go through them, or two unrelated records would be one hop apart."""
import hmac
import re
import sys

from .service import WitnessError

MAX_DEPTH = 5
DEFAULT_DEPTH = 2
MAX_NODES = 300
HEX64 = re.compile(r"^[0-9a-f]{64}$")
UNKNOWN_OWNER = ""  # the owner marker of a private end whose account is not known: no account matches it
EXPAND = ("record", "observation")
PROV_TYPE = {"record": "Entity", "observation": "Entity", "witness": "Agent", "agent": "Agent"}


def _same(a, b):
    return a is not None and b is not None and hmac.compare_digest(str(a), str(b))


class Graph:
    def __init__(self, witness):
        self.w = witness

    @property
    def st(self):
        return self.w.storage

    # ------------------------------------------------------------------------------------------------------- writing

    @staticmethod
    def _node(node_id, kind, visibility, account=None, pred=None):
        n = {"id": node_id, "kind": kind, "visibility": visibility, "account": account if visibility == "private" else None,
             "method": None, "outcome": None, "witnessed_at": None}
        if pred is not None:
            n.update(method=(pred.get("method") or {}).get("id"), outcome=pred.get("outcome"), witnessed_at=pred.get("witnessed_at"))
        return n

    def _end(self, node_id, kind, record_visibility, record_account):
        """(visibility, account) of an edge's far end: the node when we have it, else the stored row, else a guess that errs
        private: an observation we do not hold is as visible as the record that names it, a record we do not know is hidden."""
        have = self.st.get_nodes([node_id]).get(node_id)
        if have is not None:
            return have["visibility"], have["account"]
        if kind == "observation":
            row = self.st.get_observation(node_id)
            if row is not None:
                return row["visibility"], row["account"] if row["visibility"] == "private" else None
            return record_visibility, record_account if record_visibility == "private" else None
        row = self.st.get_kept(node_id)
        if row is not None:
            return row["visibility"], row["account"] if row["visibility"] == "private" else None
        return "private", UNKNOWN_OWNER

    def observation_signed(self, obs_id, visibility, account):
        self.st.put_nodes([self._node(obs_id, "observation", visibility, account)])

    def record_signed(self, rid, pred, visibility, account):
        """Write the node of a signed record and its edges (idempotent); the number of edges. pred is the predicate with its
        relied_on (for a private record, the body: the payload alone does not carry it)."""
        pred = pred or {}
        private = visibility == "private"
        owner = account if private else None
        witness_id = (pred.get("witness") or {}).get("id") or self.w.cfg.witness_id
        nodes = [self._node(rid, "record", visibility, account, pred), self._node(witness_id, "witness", "public")]
        ends = [(witness_id, "witness", "public", None, "wasAttributedTo")]
        agent = (pred.get("submitter") or {}).get("agent")
        if not private and isinstance(agent, str) and agent:
            nodes.append(self._node(agent, "agent", "public"))
            ends.append((agent, "agent", "public", None, "wasAttributedTo"))
        for r in pred.get("relied_on") or []:
            if isinstance(r, dict) and isinstance(r.get("id"), str) and HEX64.match(r["id"]):
                vis, acct = self._end(r["id"], "observation", visibility, account)
                nodes.append(self._node(r["id"], "observation", vis, acct))
                ends.append((r["id"], "observation", vis, acct, "used"))
        for e in pred.get("evidence") or []:  # the B5b hook: a disclosed record this one was derived from
            if isinstance(e, dict) and e.get("kind") == "record" and isinstance(e.get("id"), str) and HEX64.match(e["id"]):
                vis, acct = self._end(e["id"], "record", visibility, account)
                ends.append((e["id"], "record", vis, acct, "wasDerivedFrom"))
        now = self.w.now()
        edges = []
        for dst, _kind, dvis, dacct, rel in ends:
            edges.append({"src": rid, "dst": dst, "rel": rel, "visibility": "private" if private or dvis == "private" else "public",
                          "src_account": owner, "dst_account": dacct if dvis == "private" else None, "at": now})
        self.st.put_nodes(nodes)
        self.st.put_edges(edges)
        return len(edges)

    def record_deleted(self, rid, observation_ids=()):
        """An owner delete: the record's edges go, and each private observation deleted with it loses its node and edges. The
        record's node stays so its owner can still ask for it (flagged deleted); nobody else can."""
        self.st.delete_edges_touching(rid)
        for oid in observation_ids:
            self.st.delete_edges_touching(oid)
            self.st.delete_node(oid)

    def backfill(self):
        """Edges (and nodes) for records signed before this slice, from the envelopes still held: every kept record (a private
        one through its sealed body, unless its owner deleted it) and every stored job answer. Idempotent; {"records": n,
        "edges": m} counts what was processed. A record signed earlier that was neither kept nor in a job's 24 h is only in
        the signing log: there is nothing to read its edges from."""
        from . import dsse
        import json
        rec = self.w.records
        done, edges = set(), 0
        for row in self.st.kept_list():
            rid = row["record_id"]
            done.add(rid)
            try:
                if row["visibility"] == "public":
                    pred = json.loads(dsse.payload_bytes(row["envelope"]))["predicate"]
                elif row["deleted_at"] is None and (d := rec._disclosure(row)) is not None:
                    pred = d["body"]
                else:
                    self.st.put_nodes([self._node(rid, "record", "private", row["account"],
                                                  json.loads(dsse.payload_bytes(row["envelope"]))["predicate"])])
                    continue
                edges += self.record_signed(rid, pred, row["visibility"], row["account"])
            except Exception as e:  # one unreadable row must not stop the rest
                print(f"graph backfill: {rid[:12]}: {type(e).__name__}", file=sys.stderr, flush=True)
        for job in self.st.all_jobs():
            try:
                if job["state"] != "done" or not job.get("answer") or not job.get("record_id") or job["record_id"] in done:
                    continue
                ans = self.w._answer_of(job)
                rid = ans.get("record_id")
                if rid != job["record_id"] or not isinstance(ans.get("envelope"), dict):
                    continue
                pred = json.loads(dsse.payload_bytes(ans["envelope"]))["predicate"]
                vis = pred.get("visibility")
                if vis == "private":
                    pred = (ans.get("disclosure") or {}).get("body")
                    if not isinstance(pred, dict):
                        continue
                done.add(rid)
                edges += self.record_signed(rid, pred, vis, job["account"])
            except Exception as e:
                print(f"graph backfill: job {str(job.get('id'))[:8]}: {type(e).__name__}", file=sys.stderr, flush=True)
        return {"records": len(done), "edges": edges}

    # ------------------------------------------------------------------------------------------------------- reading

    @staticmethod
    def _depth(raw):
        if raw is None:
            return DEFAULT_DEPTH
        if not isinstance(raw, str) or not raw.isascii() or not raw.isdigit() or int(raw) > MAX_DEPTH:
            raise WitnessError(422, "invalid-request", f"depth: an integer from 0 to {MAX_DEPTH}")
        return int(raw)

    def _root(self, rid):
        """The root's node, creating an observation's from its row when the graph was started after it (lazy backfill)."""
        if not isinstance(rid, str) or not HEX64.match(rid):
            return None
        node = self.st.get_nodes([rid]).get(rid)
        if node is None:
            row = self.st.get_observation(rid)
            if row is not None:
                self.observation_signed(rid, row["visibility"], row["account"])
                node = self.st.get_nodes([rid]).get(rid)
        return node if node is not None and node["kind"] in EXPAND else None

    def view(self, account, rid, depth_raw=None, token=None):
        depth = self._depth(depth_raw)
        gone = WitnessError(404, "not-found", "no record or observation with this id that this reader may see")
        root = self._root(rid)
        if root is None:
            raise gone
        kept = self.st.get_kept(rid) if root["kind"] == "record" else None
        owner_of_root = account is not None and (_same(root["account"], account) or (kept is not None and _same(kept["account"], account)))
        share_account = None
        if root["visibility"] == "private":
            if not owner_of_root:
                if kept is None or not token:
                    raise gone
                self.w.records._share(token, rid)  # 403 share-token-invalid
                share_account = kept["account"]
        elif kept is not None and kept["taken_down_at"] is not None and not owner_of_root:
            raise WitnessError(410, "taken-down", "this record was taken down; its seal is still served at "
                                                  f"/v1/records/{rid}/seal")
        ctx = _Reader(self.st, account, rid, share_account)
        nodes, edges, frontier, truncated = {rid: ctx.render(root)}, {}, [rid], False
        ctx.nodes[rid] = root
        for _level in range(depth):
            if not frontier:
                break
            touching = sorted(self.st.edges_touching(frontier), key=lambda e: (e["src"], e["rel"], e["dst"]))
            ctx.load({x for e in touching for x in (e["src"], e["dst"])})
            nxt = []
            for e in touching:
                if not ctx.edge_ok(e):
                    continue
                for end in (e["src"], e["dst"]):
                    if end not in nodes:
                        if len(nodes) >= MAX_NODES:
                            truncated = True
                            break
                        nodes[end] = ctx.render(ctx.nodes[end])
                        if ctx.nodes[end]["kind"] in EXPAND:
                            nxt.append(end)
                else:
                    edges[(e["src"], e["dst"], e["rel"])] = {"from": e["src"], "to": e["dst"], "rel": "prov:" + e["rel"],
                                                             "visibility": e["visibility"]}
            frontier = nxt
        return {"model": "W3C PROV-O", "root": rid, "depth": depth, "nodes": [nodes[k] for k in sorted(nodes)],
                "edges": [edges[k] for k in sorted(edges)], "truncated": truncated}


class _Reader:
    """What one reader may see: who they are, the record a share token opens (if any), and the nodes loaded so far."""

    def __init__(self, st, account, root, share_account):
        self.st, self.account, self.root, self.share_account = st, account, root, share_account
        self.nodes, self.kept = {}, {}
        # a share token opens the private edges and nodes touching its one record, and nothing else private
        self.shared = set()
        if share_account is not None:
            self.shared.add(root)
            for e in st.edges_touching([root]):
                if self._accounts_ok(e, share_account):
                    self.shared.update((e["src"], e["dst"]))

    @staticmethod
    def _accounts_ok(edge, account):
        owners = [a for a in (edge["src_account"], edge["dst_account"]) if a is not None]
        return all(_same(a, account) for a in owners)

    def load(self, ids):
        need = [i for i in ids if i not in self.nodes]
        got = self.st.get_nodes(need)
        for i, n in got.items():
            self.nodes[i] = n
            if n["kind"] == "record" and i not in self.kept:
                self.kept[i] = self.st.get_kept(i)

    def _node_ok(self, node_id):
        n = self.nodes.get(node_id)
        if n is None:
            return False
        if n["visibility"] == "private":
            return _same(n["account"], self.account) or node_id in self.shared
        k = self.kept.get(node_id)
        if k is not None and k["taken_down_at"] is not None:
            return _same(k["account"], self.account)  # taken down: its owner alone still sees it
        return True

    def edge_ok(self, e):
        if e["visibility"] == "private":
            mine = self.account is not None and self._accounts_ok(e, self.account)
            shared = self.share_account is not None and self.root in (e["src"], e["dst"]) and self._accounts_ok(e, self.share_account)
            if not (mine or shared):
                return False
        return self._node_ok(e["src"]) and self._node_ok(e["dst"])

    def render(self, n):
        out = {"id": n["id"], "kind": n["kind"], "prov": PROV_TYPE[n["kind"]], "visibility": n["visibility"]}
        if n["kind"] == "record":
            out.update(method=n["method"], outcome=n["outcome"], witnessed_at=n["witnessed_at"])
            k = self.kept.get(n["id"]) if n["id"] in self.kept else self.st.get_kept(n["id"])
            if k is not None and _same(k["account"], self.account):  # flags only for the owner, who is told about their own
                if k["taken_down_at"] is not None:
                    out["taken_down"] = True
                if k["deleted_at"] is not None:
                    out["deleted"] = True
        return out
