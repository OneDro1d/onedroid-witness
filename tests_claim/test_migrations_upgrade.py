"""Integration: one ordered migration sequence (001_init, 002_judge, 003_observations, and B3's 004_keep) on real Postgres 16.
A fresh database gets all four; the dev database as B6 left it (001 + 002_judge recorded in schema_migrations, rows in jobs
and judge_outputs) upgrades by applying 003_observations and 004_keep and keeps its rows; a database that ran B2b's branch
(its file was named 002_observations.sql) also upgrades cleanly."""
import unittest

from claim_witness import pg
from tests_claim import helpers as h
from tests_claim.test_storage import ThrowawayPostgres, pg_bin_dir

MIGRATIONS = h.ROOT / "claim_witness" / "migrations"


@unittest.skipIf(pg_bin_dir() is None, "no initdb/pg_ctl and no pgserver wheel: Postgres tests cannot run here")
class MigrationUpgrade(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pg = ThrowawayPostgres(pg_bin_dir())
        cls.n = 0

    @classmethod
    def tearDownClass(cls):
        cls.pg.stop()

    def database(self, applied):
        """A new database with exactly `applied` [(recorded name, file whose SQL ran)] applied the way the runner does it."""
        import psycopg
        MigrationUpgrade.n += 1
        name = f"up{MigrationUpgrade.n}"
        with psycopg.connect(self.pg.dsn, autocommit=True) as c:
            c.execute(f"create database {name}")
        dsn = self.pg.dsn.replace("dbname=postgres", f"dbname={name}")
        with psycopg.connect(dsn, autocommit=True) as c:
            with c.transaction():
                c.execute("CREATE TABLE IF NOT EXISTS schema_migrations (name text PRIMARY KEY, "
                          "applied_at timestamptz NOT NULL DEFAULT now())")
                for recorded, f in applied:
                    c.execute((MIGRATIONS / f).read_text(encoding="utf-8"))
                    c.execute("INSERT INTO schema_migrations (name) VALUES (%s)", (recorded,))
        return dsn

    def tables(self, st):
        return {r[0] for r in st._q("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'", fetch="all")}

    def test_the_sequence_is_ordered_and_numbered_once(self):
        names = sorted(f.name for f in MIGRATIONS.glob("*.sql"))
        self.assertEqual(names, ["001_init.sql", "002_judge.sql", "003_observations.sql", "004_keep.sql",
                         "005_ndim_chains.sql", "007_graph_search.sql", "008_signing_log_tier.sql",
                         "009_browse.sql"])
        self.assertEqual(len({n.split("_")[0] for n in names}), len(names), "no two files share a number")

    def test_fresh_database_gets_all_three(self):
        st = pg.PostgresStorage(self.database([]))
        st.migrate()
        st.migrate()
        self.assertEqual(st.applied_migrations(), ["001_init.sql", "002_judge.sql", "003_observations.sql", "004_keep.sql",
                         "005_ndim_chains.sql", "007_graph_search.sql", "008_signing_log_tier.sql",
                         "009_browse.sql"])
        self.assertTrue({"jobs", "judge_outputs", "observations", "observation_files", "fresh_observations"} <= self.tables(st))

    def test_dev_database_at_001_and_002_judge_upgrades_and_keeps_its_rows(self):
        dsn = self.database([("001_init.sql", "001_init.sql"), ("002_judge.sql", "002_judge.sql")])
        st = pg.PostgresStorage(dsn)
        self.assertEqual(st.applied_migrations(), ["001_init.sql", "002_judge.sql"])
        self.assertNotIn("observations", self.tables(st))
        st.create_job({"id": "j" * 32, "account": "acct_a", "state": "done", "created_at": 1000, "http_status": 200,
                       "answer": b"\x01sealed"})
        st.add_judge_output({"record_id": "r" * 64, "model": "acme/judge-1", "provider": "acme", "served_model": "acme/judge-1-x",
                             "raw": "{}", "created_at": 1000, "expires_at": 1000 + 86400})
        st.migrate()
        self.assertEqual(st.applied_migrations(), ["001_init.sql", "002_judge.sql", "003_observations.sql", "004_keep.sql",
                         "005_ndim_chains.sql", "007_graph_search.sql", "008_signing_log_tier.sql",
                         "009_browse.sql"])
        self.assertEqual(st.get_job("j" * 32)["answer"], b"\x01sealed")
        self.assertEqual(len(st.judge_outputs(record_id="r" * 64)), 1)
        st.put_observation({"id": "o" * 64, "account": "acct_a", "visibility": "public", "lookup_tag": "t", "fetched_at": 1000,
                            "created_at": 1000, "envelope": {"payload": "e30"}, "signer": "w:k"}, {"text.canonical.txt": b"x"})
        self.assertEqual(st.get_observation_files("o" * 64), {"text.canonical.txt": b"x"})
        self.assertEqual(st.bump_fresh("acct_a", 20000), 1)
        st.migrate()  # idempotent after the upgrade
        self.assertEqual(st.applied_migrations(), ["001_init.sql", "002_judge.sql", "003_observations.sql", "004_keep.sql",
                         "005_ndim_chains.sql", "007_graph_search.sql", "008_signing_log_tier.sql",
                         "009_browse.sql"])

    def test_database_from_the_b2b_branch_upgrades_too(self):
        # B2b's branch named the observations file 002_observations.sql; its SQL is the same as 003_observations.sql
        st = pg.PostgresStorage(self.database([("001_init.sql", "001_init.sql"), ("002_observations.sql", "003_observations.sql")]))
        st.put_observation({"id": "p" * 64, "account": "acct_a", "visibility": "public", "lookup_tag": "t", "fetched_at": 1,
                            "created_at": 1, "envelope": {"payload": "e30"}, "signer": "w:k"}, {"a": b"a"})
        st.migrate()
        self.assertEqual(st.applied_migrations(), ["001_init.sql", "002_judge.sql", "002_observations.sql", "003_observations.sql",
                                                   "004_keep.sql", "005_ndim_chains.sql", "007_graph_search.sql", "008_signing_log_tier.sql",
                         "009_browse.sql"])
        self.assertEqual(st.get_observation("p" * 64)["id"], "p" * 64)
        self.assertIn("judge_outputs", self.tables(st))


if __name__ == "__main__":
    unittest.main()
