-- claim witness B3W: one n-dim claimant chain per owner (armarium's object service). The row is keyed by owner_tag =
-- HMAC(key derived from the master key, account): the account is never a column here, and armarium is sent only values
-- derived under the same key. state: pending (not created yet, or backing off), ready (claimant_id is armarium's chain),
-- failed (a configuration error or MAX_ATTEMPTS transient failures: not retried until the sealer restarts). Times are epoch seconds.

CREATE TABLE IF NOT EXISTS ndim_chains (
    owner_tag    text PRIMARY KEY,
    case_id      text NOT NULL,
    claimant_id  text,
    state        text NOT NULL CHECK (state IN ('pending', 'ready', 'failed')),
    attempts     integer NOT NULL DEFAULT 0,
    next_try_at  bigint NOT NULL DEFAULT 0,
    last_error   text,
    created_at   bigint NOT NULL,
    updated_at   bigint NOT NULL
);
