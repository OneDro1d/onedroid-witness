"""Search (SPEC §3 GET /v1/search; ARCHITECTURE §5 standalone): Postgres full text over PUBLIC kept records, an optional
embedding, and the reader's own private records listed but never content-matched.

    GET /v1/search?q=&mode=hybrid|keyword|semantic&outcome=&method=&since=&limit=&offset=

What is indexed. When a public record is kept (POST /v1/records/{id}/keep) its text (statement, claim, evidence names and URLs:
records.searchable) goes to search_docs, as a tsvector (GIN) and, when the host has an embedder, an embedding. A record that was
signed but never kept is not searchable (its envelope is not stored after the job's 24 h). A takedown deletes the row. A private
record is never indexed and never sent to an embedder: the witness holds no plaintext index of it. The owner's own plaintext
search stays GET /v1/records?q= (B3).

The query parser. q is cut into plain alphanumeric words (NFKC, casefolded, [^\\W_]+) in Python; the words are all that reaches
Postgres, as one bound parameter of plainto_tsquery('simple', ...). tsquery operators, quotes, backslashes, SQL and control
characters are separators, so no q can make a syntax error (every query is an AND of its words). q is at most 500 characters
and MAX_WORDS distinct words (422 otherwise). An empty q lists, newest kept first; a q with no word in it matches nothing.

Modes. keyword: the full-text match. semantic and hybrid need an embedder (WITNESS_EMBEDDER_URL, an OpenAI-compatible
/v1/embeddings endpoint; none on dev). Without one: semantic answers 503 semantic-unavailable (never keyword results under its
name), hybrid answers the keyword results with mode_used "keyword", degraded true and a note. With one but unreachable at query
time: semantic 503 embedder-unavailable, hybrid degraded the same way. hybrid fuses the keyword and semantic rankings by
reciprocal rank (k = 60). Every answer says mode (asked) and mode_used (done).

Private records. With no q the reader's own live private records are listed among the public ones (record_id, visibility, method,
outcome, witnessed_at, link: no statement, no label). With a q they are not matched, listed or counted; the answer says so
("private": {"searched": false}) to a signed-in reader. No total is ever returned, so a count cannot include what the reader
may not see."""
import json
import math
import re
import sys
import urllib.error
import urllib.request

from . import dsse, methods
from .records import _norm, searchable
from .service import WitnessError, iso, parse_iso
from .storage import OUTCOMES

MAX_Q = 500
MAX_WORDS = 32
DEFAULT_LIMIT = 20
MAX_LIMIT = 100
MAX_OFFSET = 10000
MAX_TEXT = 100000
MODES = ("hybrid", "keyword", "semantic")
RRF_K = 60
POOL = 1000  # candidates taken for the fusion and the semantic ranking
WORD = re.compile(r"[^\W_]+")
INT = re.compile(r"^[0-9]{1,9}$")


def words(text):
    """The distinct plain words of a text, in order of first appearance."""
    seen = {}
    for w in WORD.findall(_norm(text or "")):
        seen.setdefault(w, None)
    return list(seen)


class EmbedderError(Exception):
    pass


class HttpEmbedder:
    """An OpenAI-compatible embeddings endpoint: POST {url} {"model", "input": text} -> {"data": [{"embedding": [...]}]}."""

    def __init__(self, url, model=None, api_key=None, timeout=20):
        self.url, self.model, self.api_key, self.timeout = url, model, api_key, timeout

    def embed(self, text):
        body = {"input": text}
        if self.model:
            body["model"] = self.model
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        req = urllib.request.Request(self.url, data=json.dumps(body).encode("utf-8"), headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                vec = json.loads(r.read())["data"][0]["embedding"]
            return [float(x) for x in vec]
        except (urllib.error.URLError, OSError, ValueError, KeyError, IndexError, TypeError) as e:
            raise EmbedderError(type(e).__name__) from None


def embedder_from_env(env):
    """WITNESS_EMBEDDER_URL (the endpoint; unset or blank: no embedder), WITNESS_EMBEDDER_MODEL (optional),
    WITNESS_EMBEDDER_KEY_FILE (optional). Builds the client; makes no request."""
    url = (env.get("WITNESS_EMBEDDER_URL") or "").strip()
    if not url:
        return None
    key = None
    path = (env.get("WITNESS_EMBEDDER_KEY_FILE") or "").strip()
    if path:
        with open(path, encoding="utf-8") as f:
            key = f.read().strip()
    return HttpEmbedder(url, (env.get("WITNESS_EMBEDDER_MODEL") or "").strip() or None, key)


def cosine(a, b):
    if len(a) != len(b):
        return 0.0
    na, nb = math.sqrt(sum(x * x for x in a)), math.sqrt(sum(x * x for x in b))
    return sum(x * y for x, y in zip(a, b)) / (na * nb) if na and nb else 0.0


class Search:
    def __init__(self, witness):
        self.w = witness

    @property
    def st(self):
        return self.w.storage

    @property
    def embedder(self):
        return getattr(self.w.cfg, "embedder", None)

    # ------------------------------------------------------------------------------------------------------- indexing

    def _embed(self, text):
        """The embedding of a text, or None when there is no embedder or it did not answer (the record is then found by
        keyword, and embed_missing fills it in later)."""
        if self.embedder is None:
            return None
        try:
            return [float(x) for x in self.embedder.embed(text)]
        except Exception as e:
            print(f"search: embedder did not answer ({type(e).__name__})", file=sys.stderr, flush=True)
            return None

    def index(self, rid, pred):
        """Index one PUBLIC kept record from its predicate. Never called for a private one."""
        text = searchable(pred)[:MAX_TEXT]
        self.st.put_search_doc(rid, text, words(text), self._embed(text))

    def remove(self, rid):
        self.st.delete_search_doc(rid)

    def embed_missing(self, limit=100):
        """Embed the indexed records that have no embedding (the embedder was down or arrived later): the number done."""
        if self.embedder is None:
            return 0
        n = 0
        for rid, body in self.st.docs_missing_embedding(limit):
            vec = self._embed(body)
            if vec is None:
                break
            self.st.set_embedding(rid, vec)
            n += 1
        return n

    def backfill(self):
        """Index the public kept records that have no row yet (kept before this slice); the number indexed."""
        n = 0
        for row in self.st.kept_list(visibility="public"):
            if row["taken_down_at"] is None and self.st.get_search_doc(row["record_id"]) is None:
                self.index(row["record_id"], json.loads(dsse.payload_bytes(row["envelope"]))["predicate"])
                n += 1
        return n

    # ------------------------------------------------------------------------------------------------------- query

    @staticmethod
    def _int(raw, name, lo, hi, default):
        if raw is None:
            return default
        if not isinstance(raw, str) or not INT.match(raw) or not lo <= int(raw) <= hi:
            raise WitnessError(422, "invalid-request", f"{name}: an integer from {lo} to {hi}")
        return int(raw)

    def query(self, account, params):
        q = params.get("q") or ""
        if not isinstance(q, str) or len(q) > MAX_Q:
            raise WitnessError(422, "invalid-request", f"q: at most {MAX_Q} characters")
        mode = params.get("mode", "hybrid")
        if mode not in MODES:
            raise WitnessError(422, "invalid-request", "mode: hybrid, keyword or semantic")
        outcome, method = params.get("outcome"), params.get("method")
        if outcome is not None and outcome not in OUTCOMES:
            raise WitnessError(422, "invalid-request", f"outcome: one of {', '.join(OUTCOMES)}")
        if method is not None and method not in methods.METHODS:
            raise WitnessError(422, "invalid-request", "method: a method id from GET /v1/methods")
        since = None
        if params.get("since") is not None:
            try:
                since = iso(parse_iso(params["since"]))
            except (ValueError, TypeError, OverflowError):
                raise WitnessError(422, "invalid-request", "since: like 2026-11-24T10:41:07Z") from None
        limit = self._int(params.get("limit"), "limit", 1, MAX_LIMIT, DEFAULT_LIMIT)
        offset = self._int(params.get("offset"), "offset", 0, MAX_OFFSET, 0)
        toks = words(q)
        if len(toks) > MAX_WORDS:
            raise WitnessError(422, "invalid-request", f"q: at most {MAX_WORDS} distinct words")
        has_text = bool(q.strip())
        used, note, qvec = "keyword", None, None
        if mode in ("semantic", "hybrid") and has_text:
            if self.embedder is None:
                if mode == "semantic":
                    raise WitnessError(503, "semantic-unavailable", "this witness has no embedder (WITNESS_EMBEDDER_URL), so it "
                                                                    "cannot search by meaning; use mode=keyword")
                note = "no embedder is configured on this witness (WITNESS_EMBEDDER_URL): these are keyword results"
            else:
                try:
                    qvec = [float(x) for x in self.embedder.embed(q)]
                    used = mode
                except Exception:
                    if mode == "semantic":
                        raise WitnessError(503, "embedder-unavailable", "the embedder did not answer; try mode=keyword") from None
                    note = "the embedder did not answer: these are keyword results"
        elif mode == "semantic":
            raise WitnessError(422, "invalid-request", "q: semantic search needs a query")
        if has_text and not toks and used == "keyword":
            ids = []
            next_offset = None
        elif used == "keyword":
            ids = self.st.search_records(toks, method, outcome, since, account, limit + 1, offset)
            next_offset = offset + limit if len(ids) > limit else None
            ids = ids[:limit]
        else:
            ranked = self._rank(used, toks, qvec, method, outcome, since)
            ids = ranked[offset:offset + limit]
            next_offset = offset + limit if len(ranked) > offset + limit else None
        out = {"query": q, "mode": mode, "mode_used": used, "degraded": note is not None,
               "records": [x for x in (self._item(r) for r in ids) if x is not None], "next_offset": next_offset}
        if note:
            out["note"] = note
        if account is not None and has_text:
            out["private"] = {"searched": False, "note": "your private records are not content-searched here (the witness holds no "
                                                         "plaintext index of them); search them with GET /v1/records?q="}
        return out

    def _rank(self, used, toks, qvec, method, outcome, since):
        sem = []
        for rid, vec in self.st.semantic_docs(method, outcome, since, POOL):
            c = cosine(qvec, vec)
            if c > 0:
                sem.append((-c, rid))
        sem = [rid for _c, rid in sorted(sem)]
        if used == "semantic":
            return sem
        kw = self.st.search_records(toks, method, outcome, since, None, POOL, 0) if toks else []
        score = {}
        for lst in (kw, sem):
            for i, rid in enumerate(lst):
                score[rid] = score.get(rid, 0.0) + 1.0 / (RRF_K + i + 1)
        return [rid for rid, _s in sorted(score.items(), key=lambda kv: (-kv[1], kv[0]))]

    def _item(self, rid):
        row = self.st.get_kept(rid)
        if row is None:
            return None
        out = {"record_id": rid, "visibility": row["visibility"], "method": row["method"], "outcome": row["outcome"],
               "witnessed_at": row["witnessed_at"], "link": self.w.records._link(rid)}
        if row["visibility"] == "public":
            out["statement"] = json.loads(dsse.payload_bytes(row["envelope"]))["predicate"].get("statement")
        return out
