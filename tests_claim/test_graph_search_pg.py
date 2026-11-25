"""B7 on real Postgres 16: the whole graph and search suite of test_graph_search.py again with PostgresStorage (migration 007),
plus the Postgres-only facts: the tables and the tsvector column exist, the full-text query is parameterised (a query full of
tsquery and SQL metacharacters is an ordinary query), and no graph or search table holds a private canary in the clear."""
import json
import unittest

from tests_claim import test_graph_search as g
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
    name = f"gs{N[0]}"
    with psycopg.connect(PG.dsn, autocommit=True) as c:
        c.execute(f"create database {name}")
    st = pg.PostgresStorage(PG.dsn.replace("dbname=postgres", f"dbname={name}"))
    st.migrate()
    return st


class OnPostgres:
    def make_storage(self):
        return fresh_storage()


skip = unittest.skipIf(pg_bin_dir() is None, "no initdb/pg_ctl and no pgserver wheel: Postgres tests cannot run here")

for cls in (g.GraphEdges, g.GraphDepth, g.GraphVisibility, g.GraphBackfill, g.SearchPublic, g.SearchPrivate, g.SearchModes,
            g.SearchWithEmbedder):
    globals()["Postgres" + cls.__name__] = skip(type("Postgres" + cls.__name__, (OnPostgres, cls, unittest.TestCase), {}))


@skip
class PostgresFacts(OnPostgres, g.Base, unittest.TestCase):
    def test_migration_007_is_applied_and_makes_the_tables(self):
        st = self.s.storage
        names = [m for m in st.applied_migrations() if m.startswith("007_")]
        self.assertEqual(names, ["007_graph_search.sql"])
        tables = {r[0] for r in st._q("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'", fetch="all")}
        self.assertTrue({"graph_nodes", "graph_edges", "search_docs"} <= tables)
        col = st._q("SELECT data_type FROM information_schema.columns WHERE table_name = 'search_docs' AND column_name = 'fts'",
                    fetch="one")
        self.assertEqual(col[0], "tsvector")
        idx = [r[0] for r in st._q("SELECT indexdef FROM pg_indexes WHERE tablename = 'search_docs'", fetch="all")]
        self.assertTrue(any("gin" in i.lower() and "fts" in i for i in idx), idx)

    def test_search_uses_the_full_text_index_and_survives_injection(self):
        out = self.check(statement="postgres fulltext words")
        self.keep(out)
        for q in ("'; DROP TABLE search_docs; --", "postgres & ( | ! :* <-> \\", "postgres:*", "' || (select 1) || '"):
            code, got, _ = self.search(q=q)
            self.assertIn(code, (200, 422), got)
        self.assertEqual(self.result_ids(self.search(q="postgres fulltext")[1]), [out["record_id"]])
        self.assertEqual(self.s.storage._q("SELECT count(*) FROM search_docs", fetch="one")[0], 1)

    def test_no_graph_or_search_table_holds_a_private_canary_or_an_account(self):
        po = self.observe(g.U1, visibility="private")
        out = self.check(po, visibility="private", statement=f"{g.CANARY} pg", label=f"label {g.CANARY}")
        self.keep(out)
        pub = self.check(statement="public pg thing", agent=True)
        self.keep(pub)
        st = self.s.storage
        for t in ("graph_nodes", "graph_edges", "search_docs"):
            text = "\n".join(r[0] for r in st._q(f'SELECT t::text FROM "{t}" t', fetch="all"))
            self.assertTrue(text, t)
            self.assertNotIn(g.CANARY, text, t)
            self.assertNotIn(g.CANARY.lower(), text.lower(), t)
        # public rows hold no account at all; a private row names its owner only in the account column
        public_text = "\n".join(r[0] for r in st._q("SELECT n::text FROM graph_nodes n WHERE visibility = 'public'", fetch="all"))
        self.assertNotIn("acct_", public_text)
        edges = "\n".join(r[0] for r in st._q("SELECT e::text FROM graph_edges e WHERE visibility = 'public'", fetch="all"))
        self.assertNotIn("acct_", edges)
        self.assertNotIn(self.agent["agent_key_id"], edges)
        docs = "\n".join(r[0] for r in st._q("SELECT d::text FROM search_docs d", fetch="all"))
        self.assertNotIn("acct_", docs)
        self.assertEqual(st._q("SELECT count(*) FROM search_docs", fetch="one")[0], 1)  # the public record only
        self.assertNotIn(g.CANARY, json.dumps(self.search(key=g.A)[1]))


if __name__ == "__main__":
    unittest.main()
