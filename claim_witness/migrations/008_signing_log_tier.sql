-- claim witness, own model key (DESIGN M-20261126-CLAIMS-DOCS-BYOK, C2): the tier of every signing-log row. A row signed while
-- serving an own-key request (the record, the observations fetched for it, and the header of a batch of such rows) is 'own';
-- everything else is 'public', and every row signed before this file is 'public'. The sealer never puts two tiers in one batch:
-- public batches go to the notary profile hash/1 (lab-qbft + base-sepolia), own batches only to the own profile (lab-qbft).
-- (006 stays free: it was left for the B5b branch, which needed no migration.)

ALTER TABLE signing_log ADD COLUMN IF NOT EXISTS tier text NOT NULL DEFAULT 'public' CHECK (tier IN ('public', 'own'));
CREATE INDEX IF NOT EXISTS signing_log_pending_tier ON signing_log (tier, seq) WHERE batch_id IS NULL AND leaf IS NOT NULL;
