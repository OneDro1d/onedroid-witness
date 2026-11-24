"""The B1 methods (SPEC §4): match.exact, quote.in-source, tests.pass with its parsers; templates (VR-17), finding classes,
fixed limits."""
import json
import unittest

from claim_witness import methods
from tests_claim.helpers import GO_TEST_FAIL, GO_TEST_PASS, sha


def ev(slot, data, media_type="text/plain", name="x.txt"):
    return {slot: {"slot": slot, "kind": "object", "sha256": sha(data), "media_type": media_type, "name": name, "data": data}}


JUNIT_PASS = b"""<?xml version="1.0" encoding="utf-8"?>
<testsuites><testsuite name="pytest" tests="2" failures="0" errors="0" skipped="1">
<properties><property name="git_commit" value="0e0bbf9a1b2c3d4e5f60718293a4b5c6d7e8f901"/></properties>
<testcase classname="tests.test_a" name="test_one" time="0.01"/>
<testcase classname="tests.test_a" name="test_two" time="0.01"/>
<testcase classname="tests.test_a" name="test_skip" time="0.0"><skipped message="later"/></testcase>
</testsuite></testsuites>"""

JUNIT_FAIL = b"""<testsuite name="suite" tests="3"><testcase classname="pkg.A" name="ok"/>
<testcase classname="pkg.A" name="bad"><failure message="boom">trace</failure></testcase>
<testcase classname="pkg.B" name="err"><error message="x"/></testcase></testsuite>"""

JEST_PASS = json.dumps({"numTotalTests": 2, "numPassedTests": 2, "numFailedTests": 0, "numPendingTests": 0,
                        "numRuntimeErrorTestSuites": 0, "success": True,
                        "testResults": [{"name": "/r/a.test.js", "status": "passed", "assertionResults": [
                            {"fullName": "a works", "status": "passed"}, {"fullName": "a still works", "status": "passed"}]}]}).encode()

JEST_FAIL = json.dumps({"numTotalTests": 2, "numPassedTests": 1, "numFailedTests": 1, "numPendingTests": 0,
                        "numRuntimeErrorTestSuites": 0, "success": False,
                        "testResults": [{"name": "/r/a.test.js", "status": "failed", "assertionResults": [
                            {"fullName": "a works", "status": "passed"}, {"fullName": "a breaks", "status": "failed"}]}]}).encode()

PYTEST_SUMMARY = b"""============================= test session starts ==============================
collected 3 items
tests/test_x.py ..F
=========================== short test summary info ============================
PASSED tests/test_x.py::test_a
PASSED tests/test_x.py::test_b
FAILED tests/test_x.py::test_c - assert 1 == 2
========================= 1 failed, 2 passed in 0.12s ==========================
"""


class MatchExact(unittest.TestCase):
    def test_equal_bytes_match(self):
        e = {**ev("submitted", b"abc"), **ev("target", b"abc")}
        r = methods.run("match.exact", {}, e)
        self.assertEqual(r.finding, "match")
        self.assertEqual(methods.finding_class("match.exact", "match"), "positive")

    def test_different_bytes_differ_with_offset(self):
        e = {**ev("submitted", b"abcd"), **ev("target", b"abXd")}
        r = methods.run("match.exact", {}, e)
        self.assertEqual(r.finding, "differs")
        self.assertEqual(r.detail["first_diff"], 2)
        self.assertEqual(methods.finding_class("match.exact", "differs"), "negative")

    def test_templates(self):
        a, b = sha(b"x"), sha(b"y")
        e = {**ev("submitted", b"x"), **ev("target", b"y")}
        r = methods.run("match.exact", {}, e)
        self.assertEqual(methods.render_statement("match.exact", True, r.vars), f"The submitted file {a} is byte-identical to {b}.")
        self.assertEqual(methods.render_statement("match.exact", False, r.vars), f"The submitted file {a} is not byte-identical to {b}.")
        self.assertEqual(methods.get("match.exact").limits, "Bytes only.")


class QuoteInSource(unittest.TestCase):
    SRC = "The witness signs one answer.\nIt is “not a judge of truth” — never."

    def test_found_with_offsets_after_canon(self):
        r = methods.run("quote.in-source", {"quote": '"not a judge of truth" - never'}, ev("source", self.SRC.encode()))
        self.assertEqual(r.finding, "quote-found")
        self.assertEqual(r.detail["end"] - r.detail["start"], len('"not a judge of truth" - never'))
        self.assertEqual(methods.finding_class("quote.in-source", "quote-found"), "positive")

    def test_quote_across_a_line_break_is_found(self):
        r = methods.run("quote.in-source", {"quote": "one answer. It is"}, ev("source", self.SRC.encode()))
        self.assertEqual(r.finding, "quote-found")

    def test_case_is_kept(self):
        r = methods.run("quote.in-source", {"quote": "the witness signs"}, ev("source", self.SRC.encode()))
        self.assertEqual(r.finding, "quote-absent")
        self.assertEqual(methods.finding_class("quote.in-source", "quote-absent"), "negative")

    def test_html_source_uses_visible_text(self):
        html = b"<p>Shown text</p><p hidden>secret passage</p>"
        self.assertEqual(methods.run("quote.in-source", {"quote": "secret passage"}, ev("source", html, "text/html")).finding,
                         "quote-absent")
        self.assertEqual(methods.run("quote.in-source", {"quote": "Shown text"}, ev("source", html, "text/html")).finding,
                         "quote-found")

    def test_binary_source_is_unreadable(self):
        r = methods.run("quote.in-source", {"quote": "x"}, ev("source", b"\x89PNG\r\n\x1a\n\xff\xfe", "image/png"))
        self.assertIsNone(r.finding)
        self.assertEqual(r.reason, "unreadable")

    def test_templates(self):
        s = sha(self.SRC.encode())
        r = methods.run("quote.in-source", {"quote": "one answer"}, ev("source", self.SRC.encode()))
        self.assertEqual(methods.render_statement("quote.in-source", True, r.vars), f"{s} contains the passage: “one answer”.")
        self.assertEqual(methods.render_statement("quote.in-source", False, r.vars),
                         f"{s} does not contain the passage: “one answer”.")
        self.assertEqual(methods.get("quote.in-source").limits,
                         "Exact passage after canon/1 (whitespace, quotes and dashes unified; case kept).")


class TestsPass(unittest.TestCase):
    def run_log(self, data, params=None, media_type="application/json"):
        return methods.run("tests.pass", params or {}, ev("log", data, media_type))

    def test_go_test_json_pass(self):
        r = self.run_log(GO_TEST_PASS)
        self.assertEqual(r.finding, "tests-passed")
        self.assertEqual((r.detail["format"], r.detail["tests"], r.detail["failed"]), ("go-test-json", 2, 0))
        self.assertEqual(methods.finding_class("tests.pass", "tests-passed"), "positive")

    def test_go_test_json_fail_names_failing_tests(self):
        r = self.run_log(GO_TEST_FAIL)
        self.assertEqual(r.finding, "tests-failed")
        self.assertEqual(r.failing_tests, ["example.com/x.TestBroken"])
        self.assertEqual(methods.finding_class("tests.pass", "tests-failed"), "negative")

    def test_junit_pass_and_fail(self):
        r = self.run_log(JUNIT_PASS, media_type="application/xml")
        self.assertEqual((r.finding, r.detail["format"], r.detail["tests"], r.detail["skipped"]), ("tests-passed", "junit-xml", 2, 1))
        r = self.run_log(JUNIT_FAIL, media_type="application/xml")
        self.assertEqual(r.finding, "tests-failed")
        self.assertEqual(sorted(r.failing_tests), ["pkg.A.bad", "pkg.B.err"])
        self.assertEqual((r.detail["failed"], r.detail["errors"]), (1, 1))

    def test_jest_json(self):
        self.assertEqual(self.run_log(JEST_PASS).finding, "tests-passed")
        r = self.run_log(JEST_FAIL)
        self.assertEqual((r.finding, r.failing_tests), ("tests-failed", ["a breaks"]))
        self.assertEqual(r.detail["format"], "jest-json")

    def test_pytest_summary(self):
        r = self.run_log(PYTEST_SUMMARY, media_type="text/plain")
        self.assertEqual((r.finding, r.detail["format"]), ("tests-failed", "pytest-summary"))
        self.assertEqual(r.failing_tests, ["tests/test_x.py::test_c"])

    def test_zero_tests_is_not_a_pass(self):
        r = self.run_log(b'{"Action":"pass","Package":"example.com/empty","Elapsed":0}\n')
        self.assertEqual(r.finding, "tests-failed")

    def test_prose_is_unreadable(self):
        r = self.run_log(b"All tests passed, trust me.\n", media_type="text/plain")
        self.assertIsNone(r.finding)
        self.assertEqual(r.reason, "unreadable")

    def test_doctype_is_unreadable(self):
        r = self.run_log(b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "b">]><testsuite><testcase name="a"/></testsuite>',
                         media_type="application/xml")
        self.assertEqual(r.reason, "unreadable")

    def test_commit_rules(self):
        good = "0e0bbf9a1b2c3d4e5f60718293a4b5c6d7e8f901"
        self.assertEqual(self.run_log(JUNIT_PASS, {"expect_commit": good}, "application/xml").finding, "tests-passed")
        self.assertEqual(self.run_log(JUNIT_PASS, {"expect_commit": "0e0bbf9"}, "application/xml").finding, "tests-passed")
        r = self.run_log(JUNIT_PASS, {"expect_commit": "deadbeefdeadbeef"}, "application/xml")
        self.assertEqual(r.finding, "commit-mismatch")
        self.assertEqual(methods.finding_class("tests.pass", "commit-mismatch"), "neutral")
        r = self.run_log(GO_TEST_PASS, {"expect_commit": good})
        self.assertEqual(r.finding, "commit-absent")
        self.assertEqual(methods.finding_class("tests.pass", "commit-absent"), "neutral")

    def test_templates_with_and_without_commit(self):
        s = sha(GO_TEST_PASS)
        r = self.run_log(GO_TEST_PASS)
        self.assertEqual(methods.render_statement("tests.pass", True, r.vars),
                         f"The test output {s} reports at least one test run and no failures.")
        self.assertEqual(methods.render_statement("tests.pass", False, r.vars),
                         f"The test output {s} does not report at least one test run and no failures.")
        r = self.run_log(GO_TEST_PASS, {"expect_commit": "abcdef1"})
        self.assertEqual(methods.render_statement("tests.pass", True, r.vars),
                         f"The test output {s} reports at least one test run and no failures for commit abcdef1.")
        self.assertEqual(methods.get("tests.pass").limits, "The log's origin was not verified.")


class Registry(unittest.TestCase):
    def test_b1_methods_and_fields(self):
        for mid in ("match.exact", "quote.in-source", "tests.pass"):
            m = methods.get(mid)
            self.assertEqual(m.major, 1)
            self.assertRegex(m.version, r"^1\.\d+\.\d+$")
            self.assertTrue(m.limits)
            self.assertTrue(m.mechanical)
            self.assertIn(True, m.templates)
            self.assertIn(False, m.templates)
        self.assertIsNone(methods.get("no.such"))

    def test_detail_holds_integers_and_enums_only(self):
        r = methods.run("tests.pass", {}, ev("log", GO_TEST_FAIL))
        for v in r.detail.values():
            self.assertIsInstance(v, (int, str))
            self.assertNotIsInstance(v, float)
        self.assertNotIn("TestBroken", json.dumps(r.detail))


if __name__ == "__main__":
    unittest.main()
