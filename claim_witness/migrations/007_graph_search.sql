-- claim witness B7: the record graph (W3C PROV-O edges) and search, on the witness's own Postgres (BD7).
-- (006 is left free for the parallel B5b branch.) All CREATE ... IF NOT EXISTS: the dev database (001 to 005 recorded) gains this
-- file alone and keeps its rows. Edges for records signed before this file are written at start (graph.backfill), not here:
-- the envelopes and private bodies they come from are sealed and only the running witness can open them.
--
-- graph_nodes: a record, an observation, the witness or an agent. `account` names the owner of a PRIVATE node only (null for a
-- public one, so a public row holds no account at all); an observation or record whose owner is not known gets '' (nobody matches).
-- graph_edges: PROV-O (`used`, `wasDerivedFrom`, `wasAttributedTo`) from a record to what it relied on. An edge has the visibility of
-- its MOST private end; src_account and dst_account name the owner of each private end (null for a public end), so a reader sees an
-- edge only when every private end is theirs. Neither table holds a word of any private body.
-- search_docs: the text of a PUBLIC kept record, once as `body` and once as a tsvector (GIN), plus an optional embedding
-- (real[], filled only when the host has an embedder; pgvector is not required). A private record has no row here, ever.

CREATE TABLE IF NOT EXISTS graph_nodes (
    id          text PRIMARY KEY,
    kind        text NOT NULL CHECK (kind IN ('record', 'observation', 'witness', 'agent')),
    visibility  text NOT NULL CHECK (visibility IN ('public', 'private')),
    account     text,
    method      text,
    outcome     text,
    witnessed_at text
);

CREATE TABLE IF NOT EXISTS graph_edges (
    seq          bigserial,
    src          text NOT NULL,
    dst          text NOT NULL,
    rel          text NOT NULL CHECK (rel IN ('used', 'wasDerivedFrom', 'wasAttributedTo')),
    visibility   text NOT NULL CHECK (visibility IN ('public', 'private')),
    src_account  text,
    dst_account  text,
    at           bigint NOT NULL,
    PRIMARY KEY (src, dst, rel)
);
CREATE INDEX IF NOT EXISTS graph_edges_dst ON graph_edges (dst);

CREATE TABLE IF NOT EXISTS search_docs (
    record_id  text PRIMARY KEY REFERENCES kept_records (record_id),
    body       text NOT NULL,
    fts        tsvector NOT NULL,
    embedding  real[]
);
CREATE INDEX IF NOT EXISTS search_docs_fts ON search_docs USING gin (fts);
