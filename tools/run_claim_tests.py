#!/usr/bin/env python3
"""Run the claim witness tests (tests_claim/) from any working directory.

    .venv/bin/python tools/run_claim_tests.py              # everything
    .venv/bin/python tools/run_claim_tests.py test_canon   # modules whose file name starts with this
"""
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent


def main(argv):
    sys.path.insert(0, str(ROOT))
    pattern = (argv[0] + "*.py") if argv else "test*.py"
    suite = unittest.defaultTestLoader.discover(str(ROOT / "tests_claim"), pattern=pattern, top_level_dir=str(ROOT))
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
