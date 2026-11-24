"""B5b on real Postgres 16: record.valid and record.disclose (test_record_methods.py) again with PostgresStorage. The storage
layer is not changed by B5b; this proves the kept-record, seal and batch reads the two methods rely on behave the same there."""
import unittest

from tests_claim import test_keep_pg as kp
from tests_claim import test_record_methods as m

setUpModule = kp.setUpModule
tearDownModule = kp.tearDownModule

for cls in (m.RecordValid, m.RerunInWitnessVerify, m.RecordDisclose):
    globals()["Postgres" + cls.__name__] = kp.skip(type("Postgres" + cls.__name__, (kp.OnPostgres, cls, unittest.TestCase), {}))

if __name__ == "__main__":
    unittest.main()
