-- NS-4A (M-20261127-NAME-SITE, NS-3-SPEC.md 3.5): the browse index beside search_docs. All CREATE ... IF NOT EXISTS and the seed
-- ON CONFLICT DO NOTHING, so the dev database (001 to 008 recorded) gains this file alone and keeps its rows. Rows for records kept
-- before this file are written at start (browse.backfill), not here: only the running witness can read the envelopes and the
-- observations behind them.
--
-- Rows are written only for PUBLIC kept records (at keep), deleted at takedown in the same request, and every read joins
-- kept_records with the listed predicate (public, not taken down, not deleted, not in unlisted_records), so counts are computed at
-- query time and can never go stale. No account, no private record and no text body is stored here beyond the subject keys,
-- the URL as the record wrote it (userinfo removed) and the keyword words of public records.
--
-- pos (record_subjects, record_keywords) keeps the record's own order (evidence order; keyword source order): an addition to the
-- spec's column list so an answer lists a record's subjects and keywords in the order they came from.

CREATE TABLE IF NOT EXISTS subjects (
    sid         text PRIMARY KEY,           -- first 32 hex of sha256(kind || '\n' || key)
    kind        text NOT NULL CHECK (kind IN ('page', 'site', 'profile')),
    key         text NOT NULL,              -- the canonical form, no scheme
    display     text NOT NULL,
    platform    text,
    parent_sid  text
);

CREATE TABLE IF NOT EXISTS record_subjects (
    record_id  text NOT NULL REFERENCES kept_records (record_id),
    sid        text NOT NULL REFERENCES subjects (sid),
    href       text,                        -- page rows: the URL as written (scheme kept, userinfo removed)
    pos        integer NOT NULL,
    PRIMARY KEY (record_id, sid)
);
CREATE INDEX IF NOT EXISTS record_subjects_sid ON record_subjects (sid);

CREATE TABLE IF NOT EXISTS record_keywords (
    record_id  text NOT NULL REFERENCES kept_records (record_id),
    word       text NOT NULL,
    pos        integer NOT NULL,
    PRIMARY KEY (record_id, word)
);
CREATE INDEX IF NOT EXISTS record_keywords_word ON record_keywords (word);

CREATE TABLE IF NOT EXISTS record_types (
    record_id  text PRIMARY KEY REFERENCES kept_records (record_id),
    type       text NOT NULL CHECK (type IN ('record', 'test-run', 'social-post', 'social-profile', 'web-page', 'document'))
);

CREATE TABLE IF NOT EXISTS unlisted_records (
    record_id  text PRIMARY KEY,
    at         bigint NOT NULL,
    reason     text NOT NULL CHECK (reason IN ('test', 'operator'))
);

-- the 28 test records of the site's lib/agent/seo-exclude.ts (claim_witness/unlisted_seed.py holds the same list)
INSERT INTO unlisted_records (record_id, at, reason) VALUES
    ('c8df58c9bea03790d99472230f60eb24f7760462866b12820e3142973009cd8f', 0, 'test'),
    ('cedf4af09d2256a38b200c073d4374b7895bf712c2039ae5284c7939dde98c97', 0, 'test'),
    ('376d99948669ae665390f8caefa3d86588d71d88f682b8ecbc6296708e5a29d3', 0, 'test'),
    ('c019fee4458c4256bb78ae3e20ec35e30b6a38b74ad1ff063f052e21e5c4b540', 0, 'test'),
    ('2b36464a7c1c0cc624a19862f64d6cb2df9a598e27ea6a7db6eae0bbc0ab3003', 0, 'test'),
    ('3fdbf8f9dd6434eb462c4b99c117c9e30f1e135ae4a1bd94a4077a653505ece5', 0, 'test'),
    ('1da9b0a4435c105b1a0c4d5d5d87be25a93107f745fe52d2efaa8b389ba88433', 0, 'test'),
    ('d4687a3f031b9dc8985d651472c5ac1cfca720190ba01ec674d8fa0a3cd0d7c0', 0, 'test'),
    ('f2e867c77d6df5f2c33d27ebf23d9b0a52332819b0ffe755d78db3e475103661', 0, 'test'),
    ('5af57975c41c7f922228037312177457f28ec311f39f2e49b1723851ba9779fd', 0, 'test'),
    ('b0973af489862740c8c8a7ca4a09d580a4f58aaf023918a4387ac752f4e738d3', 0, 'test'),
    ('88dd1e60d8f79ccbb3f55cf21a55fd92344214b5891b199e8e2446f39a724fc6', 0, 'test'),
    ('87f226022d482373d783cfbc4c2612219486f9df2945e84e14f660257db7a943', 0, 'test'),
    ('70f045b08431c6bd43fb85086b40ede7b6928c92a775a55ce2b304b20c66d320', 0, 'test'),
    ('fc8cefd460d5c0178077ff6489b2abd0899850c619cf58ab24a5740e93ef130d', 0, 'test'),
    ('7243fbedd364a18499ce077ef7e14320af7e8d4dd25db24448edd4294a4d1474', 0, 'test'),
    ('4d36fa9e0e7b6ed9487883dbac3e89eda4aaa2f8ebff121b464d5902a79e7a68', 0, 'test'),
    ('d68debe39cba7e3841dd337b156b627710fe9fce106e98ba19f958af5a980549', 0, 'test'),
    ('b447ab0eb306968dd3ae6036a27018e2cd6cbfd9580077b6f94c129bd77ece7e', 0, 'test'),
    ('ce353ec2695ccff519f7325d317ed940733e327f23d00e0a8895bd7d50e54219', 0, 'test'),
    ('29695e5b0a583b7c2453c4000e0f30b18c1bc0b6fa1e4084625ef261bd451c34', 0, 'test'),
    ('a5437dd3f725915ed055a33eb6242a2df51a77d7be39195222671934891de090', 0, 'test'),
    ('4a605064881f1bb41e5ec1cdc34f2ca9f0f3552dd6417072ede4292e455c2afd', 0, 'test'),
    ('7a8139b8f0400b0dfba9ee96423723a45f5e126b100cd712415fb30f0050acdb', 0, 'test'),
    ('1acf68b0133be9b8eb1656db7a7f2389265c95d3c1c33f5e2afbfefbc69b01f3', 0, 'test'),
    ('8b993c2ec5c719c44db75b6efb1325670bfcdbae321e02548d9f1f703b4a5b90', 0, 'test'),
    ('0654beac9522dc299595b7e31e221e331895a492d836ee72531665679d466ee5', 0, 'test'),
    ('8a6361088a23c4bbce5c581e4ca6a8d7e6fe857095df746e82420f5fa77d91d0', 0, 'test')
ON CONFLICT (record_id) DO NOTHING;
