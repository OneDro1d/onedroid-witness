"""NS-4A on real Postgres 16: the whole browse suite of test_browse.py again with PostgresStorage (migration 009_browse.sql), plus
the Postgres-only facts: the five tables, their keys and the word index exist, the 28 test ids are seeded by the migration, and
no browse table holds an account, a private record's id or a private canary."""
import json
import unittest

from tests_claim import test_browse as b
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
    name = f"br{N[0]}"
    with psycopg.connect(PG.dsn, autocommit=True) as c:
        c.execute(f"create database {name}")
    st = pg.PostgresStorage(PG.dsn.replace("dbname=postgres", f"dbname={name}"))
    st.migrate()
    return st


class OnPostgres:
    def make_storage(self):
        return fresh_storage()


skip = unittest.skipIf(pg_bin_dir() is None, "no initdb/pg_ctl and no pgserver wheel: Postgres tests cannot run here")

for cls in (b.Subjects, b.KeywordIndex, b.Categories, b.Api, b.Search, b.Listing, b.KeepAndTakedown):
    globals()["Postgres" + cls.__name__] = skip(type("Postgres" + cls.__name__, (OnPostgres, cls, unittest.TestCase), {}))


@skip
class PostgresBrowseFacts(OnPostgres, b.Base, unittest.TestCase):
    def test_migration_009_makes_the_tables_and_seeds_the_28_ids(self):
        st = self.s.storage
        self.assertEqual([m for m in st.applied_migrations() if m.startswith("009_")], ["009_browse.sql"])
        tables = {r[0] for r in st._q("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'", fetch="all")}
        self.assertTrue({"subjects", "record_subjects", "record_keywords", "record_types", "unlisted_records"} <= tables)
        idx = " ".join(r[0] for r in st._q("SELECT indexdef FROM pg_indexes WHERE tablename = 'record_keywords'", fetch="all"))
        self.assertIn("(word)", idx)
        rows = st._q("SELECT record_id, reason FROM unlisted_records", fetch="all")
        self.assertEqual({r[0] for r in rows}, set(b.browse.SEED_UNLISTED))
        self.assertEqual({r[1] for r in rows}, {"test"})
        with self.assertRaises(Exception):
            st._q("INSERT INTO subjects (sid, kind, key, display) VALUES ('x', 'user', 'k', 'd')")
        with self.assertRaises(Exception):
            st._q("INSERT INTO unlisted_records (record_id, at, reason) VALUES ('y', 0, 'because')")

    def test_no_browse_table_holds_an_account_or_a_private_record(self):
        f = self.fixture()
        st = self.s.storage
        dump = []
        for t in ("subjects", "record_subjects", "record_keywords", "record_types"):
            dump += [list(r) for r in st._q(f"SELECT * FROM {t}", fetch="all")]
        text = json.dumps(dump)
        for needle in ("acct_", "agt_", "secret-launch", f["r7"]):
            self.assertNotIn(needle, text)

    def test_migration_is_idempotent_on_restart(self):
        st = self.s.storage
        st.migrate()
        self.assertEqual(st._q("SELECT count(*) FROM unlisted_records", fetch="one")[0], 28)


if __name__ == "__main__":
    unittest.main()
