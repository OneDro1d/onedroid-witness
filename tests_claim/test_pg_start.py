"""B2b (j): the API and the signer crashed on start when Postgres was not resolvable yet. The first connection is now retried
with bounded backoff for up to 120 s (WITNESS_DB_START_TIMEOUT_S), each attempt logged, then the process exits."""
import time
import unittest

import psycopg

from claim_witness import pg, storage


class FakeClock:
    def __init__(self):
        self.t = 0.0
        self.slept = []

    def now(self):
        return self.t

    def sleep(self, s):
        self.slept.append(s)
        self.t += s


class Retry(unittest.TestCase):
    def test_retries_then_connects(self):
        c, logs, calls = FakeClock(), [], []

        def connect(dsn, **kw):
            calls.append(dsn)
            if len(calls) < 3:
                raise psycopg.OperationalError("could not translate host name \"claim-pg\" to address")
            return "conn"

        got = pg.connect_with_retry("postgresql://claim-pg/x", max_wait_s=120, log=logs.append, sleep=c.sleep, clock=c.now,
                                    connect=connect)
        self.assertEqual(got, "conn")
        self.assertEqual(len(calls), 3)
        self.assertEqual(len([x for x in logs if "attempt" in x]), 2)
        self.assertEqual(c.slept, sorted(c.slept))  # backoff grows
        for line in logs:
            self.assertNotIn("postgresql://", line)  # the DSN (and its password) is never logged

    def test_gives_up_after_the_bound_and_exits(self):
        c, logs = FakeClock(), []

        def connect(dsn, **kw):
            raise psycopg.OperationalError("connection refused")

        with self.assertRaises(SystemExit):
            pg.connect_with_retry("postgresql://u:pw@claim-pg/x", max_wait_s=120, log=logs.append, sleep=c.sleep, clock=c.now,
                                  connect=connect)
        self.assertLessEqual(c.t, 120)
        self.assertGreaterEqual(c.t, 100)
        self.assertLessEqual(max(c.slept), 15)
        self.assertGreater(len(logs), 5)
        self.assertFalse(any("pw" in x for x in logs))

    def test_from_env_waits_and_exits_on_an_unresolvable_host(self):
        t0 = time.monotonic()
        with self.assertRaises(SystemExit):
            storage.from_env({"WITNESS_DATABASE_URL": "postgresql://witness:x@claim-pg.nonexistent.invalid:5432/db?connect_timeout=1",
                              "WITNESS_DB_START_TIMEOUT_S": "2"})
        self.assertLess(time.monotonic() - t0, 15)


if __name__ == "__main__":
    unittest.main()
