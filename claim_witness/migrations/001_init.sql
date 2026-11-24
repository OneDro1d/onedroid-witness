-- claim witness B1: jobs, the signing log, agent keys, nonces, attempts and key lists (BD7). Times are epoch seconds.

CREATE TABLE IF NOT EXISTS jobs (
    id             text PRIMARY KEY,
    account        text NOT NULL,
    state          text NOT NULL CHECK (state IN ('queued', 'running', 'done', 'failed')),
    created_at     bigint NOT NULL,
    idem_key       text,
    request_sha256 text,
    auto_fp        text,
    http_status    integer,
    answer         bytea,          -- AES-256-GCM ciphertext of the answer (crypto.seal_box), never plaintext
    error          jsonb
);
CREATE INDEX IF NOT EXISTS jobs_idem ON jobs (account, idem_key, created_at) WHERE idem_key IS NOT NULL;
CREATE INDEX IF NOT EXISTS jobs_auto ON jobs (account, auto_fp, created_at) WHERE auto_fp IS NOT NULL;
CREATE INDEX IF NOT EXISTS jobs_created ON jobs (created_at);

-- SPEC §7.1: one row per signature; every row's payload is a leaf. Append-only.
CREATE TABLE IF NOT EXISTS signing_log (
    seq            bigserial PRIMARY KEY,
    payload_id     text NOT NULL,
    predicate_type text NOT NULL,
    at             bigint NOT NULL
);

CREATE TABLE IF NOT EXISTS agent_keys (
    agent_key_id text PRIMARY KEY,
    account      text NOT NULL,
    agent        text NOT NULL,
    public_key   text NOT NULL,
    created_at   bigint NOT NULL
);

CREATE TABLE IF NOT EXISTS nonces (
    agent_key_id text NOT NULL,
    nonce        text NOT NULL,
    at           bigint NOT NULL,
    PRIMARY KEY (agent_key_id, nonce)
);
CREATE INDEX IF NOT EXISTS nonces_at ON nonces (at);

-- SPEC §7.3: keyed tags only, kept 30 days.
CREATE TABLE IF NOT EXISTS attempts (
    id      bigserial PRIMARY KEY,
    tag     text NOT NULL,
    outcome text NOT NULL CHECK (outcome IN ('SUPPORTED', 'NOT_SUPPORTED', 'CANNOT_WITNESS')),
    at      bigint NOT NULL
);
CREATE INDEX IF NOT EXISTS attempts_tag ON attempts (tag, at);

-- SPEC §7.4: every key list ever signed, by sequence number. The envelope is kept as the exact JSON text.
CREATE TABLE IF NOT EXISTS key_lists (
    seq      integer PRIMARY KEY,
    envelope text NOT NULL,
    sha256   text NOT NULL,
    at       bigint NOT NULL
);
