-- claim witness B3: the leaf of every signing-log row, batches and their proofs (SPEC §7.2), kept records with the BD1 custody
-- (a per-record data key wrapped by the master key; private bodies, salts and kept evidence only as AES-256-GCM ciphertext),
-- the owner's search index (keyed HMAC tokens, never words), share tokens (their sha256, never the token), and the n-dim
-- state of each kept record. Times are epoch seconds.

ALTER TABLE signing_log ADD COLUMN IF NOT EXISTS leaf text;          -- H(0x00 || payload); null for rows signed before B3
ALTER TABLE signing_log ADD COLUMN IF NOT EXISTS batch_id text;
CREATE INDEX IF NOT EXISTS signing_log_unbatched ON signing_log (seq) WHERE batch_id IS NULL AND leaf IS NOT NULL;
CREATE INDEX IF NOT EXISTS signing_log_payload ON signing_log (payload_id);

ALTER TABLE jobs ADD COLUMN IF NOT EXISTS record_id text;            -- so an owner delete also deletes the stored answer
CREATE INDEX IF NOT EXISTS jobs_record ON jobs (record_id) WHERE record_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS batches (
    id          text PRIMARY KEY,            -- the header's batch_id
    first_seq   bigint NOT NULL,
    last_seq    bigint NOT NULL,
    size        integer NOT NULL,
    root        text NOT NULL,
    header      text NOT NULL,               -- the signed header (with sig), exact JSON text
    notary      text,                        -- the notary result object, JSON text
    state       text NOT NULL CHECK (state IN ('pending', 'anchored', 'unanchored')),
    created_at  bigint NOT NULL
);

CREATE TABLE IF NOT EXISTS seals (
    payload_id  text PRIMARY KEY,
    batch_id    text NOT NULL REFERENCES batches (id),
    leaf_index  integer NOT NULL,
    path        text NOT NULL                -- JSON list of hex hashes, bottom up
);

CREATE TABLE IF NOT EXISTS kept_records (
    record_id           text PRIMARY KEY,
    account             text NOT NULL,
    visibility          text NOT NULL CHECK (visibility IN ('public', 'private')),
    method              text NOT NULL,
    outcome             text NOT NULL,
    witnessed_at        text NOT NULL,
    envelope            text NOT NULL,       -- the DSSE envelope (a private one holds commitments only)
    wrapped_key         bytea,               -- the record's data key under the master key; null once the owner deleted
    body_box            bytea,               -- private: AES-256-GCM(data key, {salt, body}); null once deleted
    evidence_key_box    bytea,               -- the evidence key under the data key; null without (or after) kept evidence
    evidence_expires_at bigint,
    evidence_deleted_at bigint,
    kept_at             bigint NOT NULL,
    deleted_at          bigint,
    taken_down_at       bigint,
    takedown_by         text,
    ndim                text NOT NULL        -- JSON: the n-dim state of the record object and of the evidence object
);
CREATE INDEX IF NOT EXISTS kept_records_account ON kept_records (account, kept_at);

CREATE TABLE IF NOT EXISTS kept_evidence (
    record_id  text NOT NULL REFERENCES kept_records (record_id),
    sha256     text NOT NULL,
    box        bytea NOT NULL,               -- AES-256-GCM(evidence key, {media_type, name, bytes})
    PRIMARY KEY (record_id, sha256)
);

CREATE TABLE IF NOT EXISTS owner_index (
    record_id  text NOT NULL REFERENCES kept_records (record_id),
    account    text NOT NULL,
    token      text NOT NULL,                -- HMAC(index key, account || word): no word is stored
    PRIMARY KEY (record_id, token)
);
CREATE INDEX IF NOT EXISTS owner_index_token ON owner_index (account, token);

CREATE TABLE IF NOT EXISTS share_tokens (
    token_id    text PRIMARY KEY,
    token_hash  text NOT NULL UNIQUE,         -- sha256 of the token; the token itself is returned once and never stored
    record_id   text NOT NULL REFERENCES kept_records (record_id),
    account     text NOT NULL,
    evidence    boolean NOT NULL,
    created_at  bigint NOT NULL,
    expires_at  bigint NOT NULL,
    revoked_at  bigint
);
CREATE INDEX IF NOT EXISTS share_tokens_record ON share_tokens (record_id);
