"""tests.pass 1.0.0 (SPEC §4): does a test runner's output report at least one test run and no failures?

Parsers, tried in this order: Jest JSON, `go test -json`, JUnit XML (pytest's --junitxml is JUnit XML), the pytest `-rA`
summary. Findings: + tests-passed (at least one test run, none failed or errored), - tests-failed, o commit-mismatch,
o commit-absent; no runner output recognised: no finding (unreadable).

A log "names a commit" when it carries a JUnit <property> called commit, git_commit, git.commit, vcs.revision, revision,
GIT_COMMIT or sha with a 7-40 hex value, or a line of the form `commit: <hex>` / `git_commit=<hex>` (any of those names,
`:` or `=`). expect_commit matches a named commit when one is a prefix of the other, case-insensitive. With expect_commit
set: no commit named gives commit-absent; any named commit that does not match gives commit-mismatch.
"""
import json
import re
import xml.etree.ElementTree as ET

from .result import Result

COMMIT_NAMES = ("commit", "git_commit", "git.commit", "vcs.revision", "revision", "git_sha", "sha")
COMMIT_LINE = re.compile(r"(?i)(?<![A-Za-z0-9_.])(?:git[_.]?commit|vcs\.revision|revision|git_sha|commit|sha)\s*[:=]\s*[\"']?"
                         r"([0-9a-f]{7,40})(?![0-9a-z])")
HEX = re.compile(r"^[0-9a-fA-F]{7,40}$")
PYTEST_FINAL = re.compile(r"^=+ (.*?) in [0-9.]+s(?: \([^)]*\))? =+$")
PYTEST_COUNT = re.compile(r"(\d+) (passed|failed|errors?|skipped|xfailed|xpassed|deselected|warnings?)")
PYTEST_LINE = re.compile(r"^(PASSED|FAILED|ERROR|SKIPPED|XFAIL|XPASS) (\S+)")


def _counts(fmt, passed, failed, errors, skipped):
    return {"format": fmt, "tests": passed + failed + errors, "passed": passed, "failed": failed, "errors": errors,
            "skipped": skipped}


def parse_jest(text):
    try:
        doc = json.loads(text)
    except ValueError:
        return None
    if not isinstance(doc, dict) or "numTotalTests" not in doc or "testResults" not in doc:
        return None
    try:
        failed_names = []
        for suite in doc.get("testResults") or []:
            for a in suite.get("assertionResults") or []:
                if a.get("status") == "failed":
                    failed_names.append(str(a.get("fullName") or a.get("title")))
        failed = int(doc.get("numFailedTests") or 0)
        passed = int(doc.get("numPassedTests") or 0)
        skipped = int(doc.get("numPendingTests") or 0) + int(doc.get("numTodoTests") or 0)
        errors = int(doc.get("numRuntimeErrorTestSuites") or 0)
    except (TypeError, ValueError, AttributeError):
        return None
    return _counts("jest-json", passed, failed, errors, skipped), failed_names


def parse_go(text):
    events = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            e = json.loads(line)
        except ValueError:
            return None
        if not isinstance(e, dict) or "Action" not in e:
            return None
        events.append(e)
    if not events:
        return None
    passed = failed = skipped = errors = 0
    failed_names = []
    for e in events:
        act, test, pkg = e.get("Action"), e.get("Test"), str(e.get("Package") or "")
        if test:
            if act == "pass":
                passed += 1
            elif act == "fail":
                failed += 1
                failed_names.append(f"{pkg}.{test}" if pkg else str(test))
            elif act == "skip":
                skipped += 1
        elif act == "fail":
            # a package that fails with no failing test of its own (a build failure, a panic in init) is an error
            if not any(x.get("Action") == "fail" and x.get("Test") and x.get("Package") == e.get("Package") for x in events):
                errors += 1
                failed_names.append(pkg or "(package)")
    return _counts("go-test-json", passed, failed, errors, skipped), failed_names


def parse_junit(text):
    if "<!DOCTYPE" in text.upper() or "<!ENTITY" in text.upper():
        return None
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return None
    if root.tag not in ("testsuites", "testsuite"):
        return None
    passed = failed = errors = skipped = 0
    failed_names = []
    for case in root.iter("testcase"):
        name = case.get("name") or ""
        cls = case.get("classname") or ""
        full = f"{cls}.{name}" if cls else name
        if case.find("failure") is not None:
            failed += 1
            failed_names.append(full)
        elif case.find("error") is not None:
            errors += 1
            failed_names.append(full)
        elif case.find("skipped") is not None:
            skipped += 1
        else:
            passed += 1
    return _counts("junit-xml", passed, failed, errors, skipped), failed_names


def parse_pytest_summary(text):
    final = None
    names = {"FAILED": [], "ERROR": []}
    for line in text.splitlines():
        line = line.strip()
        m = PYTEST_FINAL.match(line)
        if m and PYTEST_COUNT.search(m.group(1)):
            final = m.group(1)
        m = PYTEST_LINE.match(line)
        if m and m.group(1) in names:
            names[m.group(1)].append(m.group(2))
    if final is None:
        return None
    c = {"passed": 0, "failed": 0, "error": 0, "skipped": 0}
    for n, word in PYTEST_COUNT.findall(final):
        word = word.rstrip("s") if word.startswith("error") else word
        if word in c:
            c[word] += int(n)
        elif word == "xpassed":
            c["passed"] += int(n)
        elif word == "xfailed":
            c["skipped"] += int(n)
    return _counts("pytest-summary", c["passed"], c["failed"], c["error"], c["skipped"]), names["FAILED"] + names["ERROR"]


PARSERS = (parse_jest, parse_go, parse_junit, parse_pytest_summary)


def parse_log(text):
    """(counts, failing test names) from the first parser that recognises the text, or None."""
    for p in PARSERS:
        got = p(text)
        if got is not None:
            return got
    return None


def commits_named(text):
    found = set()
    if "<" in text and "<!DOCTYPE" not in text.upper():
        try:
            root = ET.fromstring(text)
            for prop in root.iter("property"):
                if (prop.get("name") or "").lower() in COMMIT_NAMES and HEX.match(prop.get("value") or ""):
                    found.add(prop.get("value").lower())
        except ET.ParseError:
            pass
    for m in COMMIT_LINE.finditer(text.replace("\\n", "\n")):
        found.add(m.group(1).lower())
    return found


def _matches(expect, named):
    e = expect.lower()
    return named.startswith(e) or e.startswith(named)


def run(params, evidence):
    log = evidence["log"]
    vars_ = {"sha": log["sha256"], "expect_commit": params.get("expect_commit")}
    data = log["data"]
    try:
        text = data.decode("utf-8-sig") if isinstance(data, bytes) else data
    except UnicodeDecodeError:
        return Result(None, {}, vars_, reason="unreadable")
    got = parse_log(text)
    if got is None:
        return Result(None, {}, vars_, reason="unreadable")
    detail, failing = got
    expect = params.get("expect_commit")
    if expect:
        named = commits_named(text)
        if not named:
            return Result("commit-absent", detail, vars_)
        if not all(_matches(expect, c) for c in named):
            return Result("commit-mismatch", detail, vars_)
    if detail["tests"] >= 1 and detail["failed"] == 0 and detail["errors"] == 0:
        return Result("tests-passed", detail, vars_)
    return Result("tests-failed", detail, vars_, failing_tests=failing)
