"""The storage interface (BD7): one contract, run against the in-memory implementation and against real Postgres 16
(a throwaway cluster from initdb/pg_ctl on PATH, or the pgserver wheel's binaries). Then one witness check end to end on
Postgres."""
import os
import pathlib
import shutil
import socket
import subprocess
import tempfile
import time
import unittest

from claim_witness import storage as storage_mod
from tests_claim import helpers as h


def pg_bin_dir():
    """The directory holding initdb and pg_ctl: WITNESS_TEST_PG_BIN, PATH, or the pgserver package (pip install pgserver)."""
    env = os.environ.get("WITNESS_TEST_PG_BIN")
    if env and (pathlib.Path(env) / "initdb").exists():
        return pathlib.Path(env)
    initdb = shutil.which("initdb")
    if initdb and shutil.which("pg_ctl"):
        return pathlib.Path(initdb).parent
    try:
        import pgserver
        d = pathlib.Path(pgserver.__file__).parent / "pginstall" / "bin"
        if (d / "initdb").exists():
            return d
    except ImportError:
        pass
    return None


class ThrowawayPostgres:
    def __init__(self, bindir):
        self.bindir = bindir
        self.dir = pathlib.Path(tempfile.mkdtemp(prefix="cw-pg-"))
        self.data = self.dir / "data"
        self.sock = pathlib.Path(tempfile.mkdtemp(prefix="cwpg"))
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            self.port = s.getsockname()[1]
        run = lambda *a: subprocess.run([str(bindir / a[0]), *a[1:]], capture_output=True, text=True, timeout=120, check=True)
        run("initdb", "-D", str(self.data), "-U", "witness", "--auth=trust", "-E", "UTF8", "--locale=C")
        run("pg_ctl", "-D", str(self.data), "-l", str(self.dir / "log"), "-w", "-o",
            f"-p {self.port} -k {self.sock} -c listen_addresses=''", "start")
        self.dsn = f"host={self.sock} port={self.port} user=witness dbname=postgres"

    def stop(self):
        subprocess.run([str(self.bindir / "pg_ctl"), "-D", str(self.data), "-m", "immediate", "stop"], capture_output=True, timeout=60)
        shutil.rmtree(self.dir, ignore_errors=True)
        shutil.rmtree(self.sock, ignore_errors=True)


class Contract:
    """Each test gets a fresh storage from self.make()."""

    def test_jobs(self):
        st = self.make()
        st.create_job({"id": "j1", "account": "acct_a", "state": "queued", "created_at": 1000, "idem_key": "k", "request_sha256": "r",
                       "auto_fp": "f", "http_status": None, "answer": None, "error": None})
        self.assertEqual(st.get_job("j1")["state"], "queued")
        st.update_job("j1", state="done", http_status=200, answer=b"\x00ct")
        j = st.get_job("j1")
        self.assertEqual((j["state"], j["http_status"], bytes(j["answer"])), ("done", 200, b"\x00ct"))
        self.assertEqual(st.find_job_by_idem("acct_a", "k", since=0)["id"], "j1")
        self.assertIsNone(st.find_job_by_idem("acct_b", "k", since=0))
        self.assertIsNone(st.find_job_by_idem("acct_a", "k", since=2000))
        self.assertEqual(st.find_job_by_auto("acct_a", "f", since=0)["id"], "j1")
        self.assertIsNone(st.get_job("nope"))
        st.purge(jobs_before=2000, nonces_before=0, attempts_before=0)
        self.assertIsNone(st.get_job("j1"))

    def test_auto_lookup_only_finds_done_jobs(self):
        st = self.make()
        st.create_job({"id": "j2", "account": "acct_a", "state": "running", "created_at": 1000, "idem_key": None, "request_sha256": "r",
                       "auto_fp": "g", "http_status": None, "answer": None, "error": None})
        self.assertIsNone(st.find_job_by_auto("acct_a", "g", since=0))

    def test_signing_log_is_append_only_sequence(self):
        st = self.make()
        a = st.append_signing_log("p1", "t1", 1000)
        b = st.append_signing_log("p2", "t2", 1001)
        self.assertEqual(b, a + 1)
        rows = st.signing_log()
        self.assertEqual([(r["seq"], r["payload_id"], r["predicate_type"], r["at"]) for r in rows][-2:], [(a, "p1", "t1", 1000), (b, "p2", "t2", 1001)])

    def test_agent_keys(self):
        st = self.make()
        st.add_agent_key({"agent_key_id": "ak1", "account": "acct_a", "agent": "agt_1", "public_key": "cHVi", "created_at": 5})
        self.assertEqual(st.get_agent_key("ak1")["account"], "acct_a")
        self.assertIsNone(st.get_agent_key("ak2"))
        st.add_agent_key({"agent_key_id": "ak1", "account": "acct_a", "agent": "agt_1", "public_key": "cHVi", "created_at": 6})
        self.assertEqual(st.get_agent_key("ak1")["created_at"], 5)

    def test_nonces(self):
        st = self.make()
        self.assertTrue(st.use_nonce("ak1", "n1", at=1000, window=100))
        self.assertFalse(st.use_nonce("ak1", "n1", at=1050, window=100))
        self.assertTrue(st.use_nonce("ak2", "n1", at=1050, window=100))
        self.assertTrue(st.use_nonce("ak1", "n1", at=1101, window=100))

    def test_attempts(self):
        st = self.make()
        st.add_attempt("t", "SUPPORTED", 100)
        st.add_attempt("t", "SUPPORTED", 200)
        st.add_attempt("t", "CANNOT_WITNESS", 300)
        st.add_attempt("u", "NOT_SUPPORTED", 300)
        self.assertEqual(st.count_attempts("t", since=150), {"SUPPORTED": 1, "NOT_SUPPORTED": 0, "CANNOT_WITNESS": 1})
        self.assertEqual(st.count_attempts("t", since=0)["SUPPORTED"], 2)
        st.purge(jobs_before=0, nonces_before=0, attempts_before=250)
        self.assertEqual(st.count_attempts("t", since=0), {"SUPPORTED": 0, "NOT_SUPPORTED": 0, "CANNOT_WITNESS": 1})

    def test_judge_outputs_expire(self):
        """B6 (SPEC §5.8, §8): raw judge outputs of public records, kept 24 h with an expiry column."""
        st = self.make()
        st.add_judge_output({"record_id": "r1", "model": "acme/j", "provider": "P", "served_model": "acme/j-1", "raw": "{\"a\": 1}",
                             "created_at": 1000, "expires_at": 1000 + 86400})
        st.add_judge_output({"record_id": "r2", "model": "beta/j", "provider": None, "served_model": None, "raw": "x",
                             "created_at": 2000, "expires_at": 2000 + 86400})
        rows = st.judge_outputs()
        self.assertEqual([(r["record_id"], r["model"], r["raw"], r["expires_at"]) for r in rows],
                         [("r1", "acme/j", "{\"a\": 1}", 87400), ("r2", "beta/j", "x", 88400)])
        self.assertEqual([r["record_id"] for r in st.judge_outputs(record_id="r2")], ["r2"])
        st.purge(jobs_before=0, nonces_before=0, attempts_before=0, outputs_expired_at=88000)
        self.assertEqual([r["record_id"] for r in st.judge_outputs()], ["r2"])

    def test_key_lists(self):
        st = self.make()
        self.assertIsNone(st.latest_key_list())
        env = {"payloadType": "x", "payload": "eyJ9", "signatures": [{"keyid": "k", "sig": "c2ln"}]}
        st.put_key_list(1, env, "a" * 64, 10)
        st.put_key_list(2, dict(env, payload="eyJ8"), "b" * 64, 11)
        self.assertEqual(st.get_key_list(1), env)
        self.assertEqual(st.latest_key_list()["seq"], 2)
        self.assertEqual(st.latest_key_list()["envelope"]["payload"], "eyJ8")
        self.assertIsNone(st.get_key_list(3))
        with self.assertRaises(Exception):
            st.put_key_list(2, env, "c" * 64, 12)


class MemoryContract(Contract, unittest.TestCase):
    def make(self):
        return storage_mod.MemoryStorage()


@unittest.skipIf(pg_bin_dir() is None, "no initdb/pg_ctl and no pgserver wheel: Postgres tests cannot run here")
class PostgresContract(Contract, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pg = ThrowawayPostgres(pg_bin_dir())
        cls.n = 0

    @classmethod
    def tearDownClass(cls):
        cls.pg.stop()

    def make(self):
        import psycopg
        from claim_witness import pg
        PostgresContract.n += 1
        name = f"t{PostgresContract.n}"
        with psycopg.connect(self.pg.dsn, autocommit=True) as c:
            c.execute(f"create database {name}")
        st = pg.PostgresStorage(self.pg.dsn.replace("dbname=postgres", f"dbname={name}"))
        st.migrate()
        st.migrate()  # idempotent
        return st

    def test_migrations_are_plain_sql_files_applied_in_order(self):
        files = sorted((h.ROOT / "claim_witness" / "migrations").glob("*.sql"))
        self.assertTrue(files)
        st = self.make()
        self.assertEqual(st.applied_migrations(), [f.name for f in files])

    def test_witness_end_to_end_on_postgres(self):
        st = self.make()
        s = h.Stack(storage=st)
        try:
            code, out, _ = s.witness_call(h.exact_request(b"pg bytes", b"pg bytes"))
            self.assertEqual(code, 200, out)
            self.assertEqual(h.payload_of(out["envelope"])["predicate"]["outcome"], "SUPPORTED")
            self.assertEqual(st.signing_log()[-1]["payload_id"], out["record_id"])
            code, again, _ = s.witness_call(h.exact_request(b"pg bytes", b"pg bytes"))
            self.assertEqual(again["record_id"], out["record_id"])
            code, job, _ = s.witness_call(h.exact_request(b"pg async", b"pg async", wait=0))
            self.assertEqual(code, 202)
            deadline = time.time() + 10
            while time.time() < deadline:
                code, stj, _ = s.call("GET", f"/v1/jobs/{job['job_id']}")
                if stj.get("state") == "done":
                    break
                time.sleep(0.05)
            self.assertEqual(stj["state"], "done")
        finally:
            s.close()

    def test_judge_end_to_end_on_postgres(self):
        """B6: judge.supports through the real HTTP API on Postgres, with the local fake model server: a public record with its
        raw output stored (24 h), a 2-model disagreement, and a private run whose raw output is not stored."""
        import json
        from claim_witness import judge
        from tests_claim import fake_models as fm
        st = self.make()
        fake = fm.FakeModels()
        d = pathlib.Path(tempfile.mkdtemp(prefix="cw-pg-judge-"))
        (d / "key").write_text(fake.api_key)
        (d / "models.json").write_text(json.dumps([{"id": "acme/judge-1", "vendor": "acme", "price_factor": 1, "timeout": 5},
                                                   {"id": "beta/judge-2", "vendor": "beta", "price_factor": 1, "timeout": 5}]))
        j = judge.from_env({"WITNESS_JUDGE_BASE_URL": fake.base_url, "WITNESS_JUDGE_API_KEY_FILE": str(d / "key"),
                            "WITNESS_JUDGE_MODELS_FILE": str(d / "models.json")})
        s = h.Stack(storage=st, config_overrides={"judge": j})
        try:
            text = "The Model X widget ships with a two-year warranty."
            good = fm.answer("judged-supports", [fm.quote(0, text, "two-year warranty")])
            fake.script("acme/judge-1", good)
            fake.script("beta/judge-2", fm.answer("judged-silent"))
            body = h.request(h.claim("judge.supports", {}, True, "The widget has a two-year warranty."),
                             [h.obj_item("evidence", text.encode())], "public")
            code, out, _ = s.witness_call(body)
            self.assertEqual(code, 200, out)
            p = h.payload_of(out["envelope"])["predicate"]
            self.assertEqual((p["outcome"], p["finding"]), ("SUPPORTED", "judged-supports"))
            self.assertEqual(st.signing_log()[-1]["payload_id"], out["record_id"])
            rows = st.judge_outputs(record_id=out["record_id"])
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["expires_at"] - rows[0]["created_at"], 86400)
            body["options"]["models"] = {"count": 2}
            code, out2, _ = s.witness_call(body)
            p2 = h.payload_of(out2["envelope"])["predicate"]
            self.assertEqual((p2["reason"], p2["attempt"]["n"]), ("judges-disagree", 2))
            n = len(st.judge_outputs())
            body["options"] = {"visibility": "private", "allow_provider": True}
            code, out3, _ = s.witness_call(body)
            self.assertEqual(code, 200, out3)
            self.assertEqual(h.payload_of(out3["envelope"])["predicate"]["attempt"]["n"], 3)
            self.assertEqual(len(st.judge_outputs()), n, "a private record's raw outputs are not stored")
        finally:
            s.close()
            fake.close()


if __name__ == "__main__":
    unittest.main()
