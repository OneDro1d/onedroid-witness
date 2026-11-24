-- claim witness B6: raw judge outputs (SPEC §5.8, §8). Public records only: a private record's raw outputs are never stored
-- in the clear (DECISIONS BD1). Unkept, they live 24 h; expires_at is the purge line. Times are epoch seconds.

CREATE TABLE IF NOT EXISTS judge_outputs (
    id           bigserial PRIMARY KEY,
    record_id    text NOT NULL,
    model        text NOT NULL,     -- the configured model id (never a router)
    provider     text,              -- the provider that served, as the endpoint named it
    served_model text,              -- the dated model id the endpoint answered with
    raw          text NOT NULL,     -- the model's message content, as received
    created_at   bigint NOT NULL,
    expires_at   bigint NOT NULL
);
CREATE INDEX IF NOT EXISTS judge_outputs_record ON judge_outputs (record_id);
CREATE INDEX IF NOT EXISTS judge_outputs_expires ON judge_outputs (expires_at);
