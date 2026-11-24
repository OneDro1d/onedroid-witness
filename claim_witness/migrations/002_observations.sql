-- claim witness B2b: observations (SPEC §2.3) with their files, and the per-account daily count of fresh observations (BD3).
-- A private observation's body and files are AES-256-GCM ciphertext (BD1 custody); lookup_tag is a keyed hash, never the URL.

CREATE TABLE IF NOT EXISTS observations (
    id          text PRIMARY KEY,           -- H(canonical payload)
    account     text NOT NULL,              -- the account that made it (private ones are visible to it alone)
    visibility  text NOT NULL CHECK (visibility IN ('public', 'private')),
    lookup_tag  text NOT NULL,              -- HMAC over (visibility, account for private, requested URL, capture)
    fetched_at  bigint NOT NULL,
    created_at  bigint NOT NULL,
    envelope    text NOT NULL,              -- the DSSE envelope, exact JSON text
    body_box    bytea,                      -- private: the sealed body; public: null
    signer      text NOT NULL,
    kept        boolean NOT NULL DEFAULT false
);
CREATE INDEX IF NOT EXISTS observations_lookup ON observations (lookup_tag, fetched_at);
CREATE INDEX IF NOT EXISTS observations_created ON observations (created_at) WHERE NOT kept;

CREATE TABLE IF NOT EXISTS observation_files (
    observation_id text NOT NULL REFERENCES observations (id) ON DELETE CASCADE,
    name           text NOT NULL,
    data           bytea NOT NULL,
    PRIMARY KEY (observation_id, name)
);

CREATE TABLE IF NOT EXISTS fresh_observations (
    account text NOT NULL,
    day     integer NOT NULL,               -- UTC day number (epoch seconds // 86400)
    n       integer NOT NULL,
    PRIMARY KEY (account, day)
);
