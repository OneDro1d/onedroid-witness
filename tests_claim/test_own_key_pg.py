"""Own model key on real Postgres 16: migration 008 adds signing_log.tier (existing rows public), the tier is written and read
back, pending leaves are listed per tier, and the sealer suite of test_own_key.py runs again on PostgresStorage. TS-10's store
check for the key: no table, read as text, holds the own model key."""
import unittest

from tests_claim import helpers as h
from tests_claim import test_own_key as t
from tests_claim.test_storage import ThrowawayPostgres, pg_bin_dir

PG = None


def setUpModule():
    global PG
    if pg_bin_dir() is not None:
        PG = ThrowawayPostgres(pg_bin_dir())


def tearDownModule():
    if PG is not None:
        PG.stop()


N = [0]


def fresh_storage():
    import psycopg
    from claim_witness import pg
    N[0] += 1
    name = f"ownkey{N[0]}"
    with psycopg.connect(PG.dsn, autocommit=True) as c:
        c.execute(f"create database {name}")
    st = pg.PostgresStorage(PG.dsn.replace("dbname=postgres", f"dbname={name}"))
    st.migrate()
    return st


skip = unittest.skipIf(pg_bin_dir() is None, "no initdb/pg_ctl and no pgserver wheel: Postgres tests cannot run here")


@skip
class PostgresTier(unittest.TestCase):
    def test_migration_008_is_applied_and_old_rows_are_public(self):
        import psycopg
        from claim_witness import pg
        N[0] += 1
        name = f"ownkeyold{N[0]}"
        with psycopg.connect(PG.dsn, autocommit=True) as c:
            c.execute(f"create database {name}")
        dsn = PG.dsn.replace("dbname=postgres", f"dbname={name}")
        with psycopg.connect(dsn, autocommit=True) as c:  # a database as 007 left it, with one signed row
            c.execute("CREATE TABLE schema_migrations (name text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())")
            for f in sorted((h.ROOT / "claim_witness" / "migrations").glob("*.sql")):
                if f.name < "008":
                    c.execute(f.read_text(encoding="utf-8"))
                    c.execute("INSERT INTO schema_migrations (name) VALUES (%s)", (f.name,))
            c.execute("INSERT INTO signing_log (payload_id, predicate_type, at, leaf) VALUES ('old', 'x', 1, 'aa')")
        st = pg.PostgresStorage(dsn)
        st.migrate()
        self.assertIn("008_signing_log_tier.sql", st.applied_migrations())
        self.assertEqual(st.log_tier("old"), "public")
        self.assertEqual(st.signing_log()[0]["tier"], "public")

    def test_tier_is_written_read_and_listed_per_tier(self):
        st = fresh_storage()
        st.append_signing_log("p" * 64, "x", h.T0, leaf="1" * 64)
        st.append_signing_log("o" * 64, "x", h.T0, leaf="2" * 64, tier="own")
        self.assertEqual((st.log_tier("p" * 64), st.log_tier("o" * 64), st.log_tier("z" * 64)), ("public", "own", None))
        self.assertEqual([r["payload_id"] for r in st.pending_leaves(10, tier="own")], ["o" * 64])
        self.assertEqual([r["payload_id"] for r in st.pending_leaves(10, tier="public")], ["p" * 64])
        self.assertEqual(len(st.pending_leaves(10)), 2)
        self.assertEqual([r["tier"] for r in st.signing_log()], ["public", "own"])

    def test_a_bad_tier_is_refused_by_the_database(self):
        import psycopg
        st = fresh_storage()
        with self.assertRaises(psycopg.Error):
            st.append_signing_log("q" * 64, "x", h.T0, leaf="3" * 64, tier="gold")


@skip
class PostgresSealerTiers(t.SealerTiers):
    def setUp(self):
        self._orig = h.Stack.__init__

        def init(stack_self, storage=None, **kw):
            self._orig(stack_self, storage=storage if storage is not None else fresh_storage(), **kw)
        h.Stack.__init__ = init

    def tearDown(self):
        h.Stack.__init__ = self._orig


@skip
class PostgresOwnKeyStore(t.JudgeBase):
    def setUp(self):
        self._orig = h.Stack.__init__

        def init(stack_self, storage=None, **kw):
            self._orig(stack_self, storage=storage if storage is not None else fresh_storage(), **kw)
        h.Stack.__init__ = init
        try:
            super().setUp()
        finally:
            h.Stack.__init__ = self._orig

    def test_no_table_holds_the_key(self):
        import psycopg
        code, out, _ = self.s.witness_call(t.judge_request(), headers=t.HDR)
        self.assertEqual(code, 200, out)
        st = self.s.storage
        with psycopg.connect(st.dsn, autocommit=True) as c:
            tables = [r[0] for r in c.execute("SELECT tablename FROM pg_tables WHERE schemaname = 'public'").fetchall()]
            for tbl in tables:
                for row in c.execute(f"SELECT * FROM {tbl}").fetchall():
                    text = " ".join(x.hex() if isinstance(x, (bytes, memoryview)) and not isinstance(x, str) and
                                    hasattr(x, "hex") else str(x) for x in row)
                    self.assertNotIn(t.OWN_KEY, text, tbl)
                    self.assertNotIn(t.OWN_KEY.encode().hex(), text, tbl)
