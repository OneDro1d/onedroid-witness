"""B3 (g) on real Postgres 16: the whole keep / seal / delete / n-dim suite of test_keep_api.py again with PostgresStorage, the
migration list, and TS-10's store check: every table, read as text (bytea as hex), holds no private canary in the clear."""
import json
import unittest

from tests_claim import helpers as h
from tests_claim import test_keep_api as k
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
    name = f"keep{N[0]}"
    with psycopg.connect(PG.dsn, autocommit=True) as c:
        c.execute(f"create database {name}")
    st = pg.PostgresStorage(PG.dsn.replace("dbname=postgres", f"dbname={name}"))
    st.migrate()
    return st


class OnPostgres:
    def make_storage(self):
        return fresh_storage()


skip = unittest.skipIf(pg_bin_dir() is None, "no initdb/pg_ctl and no pgserver wheel: Postgres tests cannot run here")

for cls in (k.KeepCases, k.PrivateReads, k.DeleteAndTakedown, k.Bundles, k.NdimWrites, k.NdimEvidence, k.NdimNotConfigured,
            k.Retention):
    globals()["Postgres" + cls.__name__] = skip(type("Postgres" + cls.__name__, (OnPostgres, cls, unittest.TestCase), {}))


@skip
class PostgresPrivacy(OnPostgres, k.Base, unittest.TestCase):
    def test_migration_004_is_applied(self):
        st = self.s.storage
        self.assertIn("004_keep.sql", st.applied_migrations())

    def test_ts10_no_table_holds_the_canary_in_clear(self):
        out = self.private_check()
        self.keep(out, keep_evidence_days=7, evidence=self.evidence(k.PRIVATE_SOURCE))
        code, sh, _ = self.s.call("POST", f"/v1/records/{out['record_id']}/shares", {})
        self.seal_all()
        code, res, _ = self.s.call("GET", f"/v1/records?q={k.CANARY}")
        self.assertEqual([r["record_id"] for r in res["records"]], [out["record_id"]])  # the store is really searchable
        st = self.s.storage
        tables = [r[0] for r in st._q("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'", fetch="all")]
        for t in ("kept_records", "kept_evidence", "owner_index", "share_tokens", "batches", "seals", "signing_log", "jobs"):
            self.assertIn(t, tables)
        needles = [k.CANARY, k.CANARY.lower(), k.CANARY.encode().hex(), k.PRIVATE_SOURCE.hex(), sh["token"]]
        for t in tables:
            rows = st._q(f'SELECT t::text FROM "{t}" t', fetch="all")
            text = "\n".join(r[0] for r in rows)
            for n in needles:
                self.assertNotIn(n, text, f"table {t}")
        self.assertNotIn(k.CANARY, self.arm.all_text())
        self.assertNotIn(k.CANARY, json.dumps(self.get(out["record_id"])[1]))


if __name__ == "__main__":
    unittest.main()
