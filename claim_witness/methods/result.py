"""What a method returns: a finding (or None with a reason), detail (integers and enums only), the template variables,
and, for tests.pass, the failing test names that travel beside the envelope, never inside it."""


class Result:
    __slots__ = ("finding", "detail", "vars", "reason", "failing_tests")

    def __init__(self, finding, detail=None, vars=None, reason=None, failing_tests=None):
        self.finding = finding
        self.detail = dict(detail or {})
        self.vars = dict(vars or {})
        self.reason = finding if finding is not None else reason
        self.failing_tests = list(failing_tests or [])

    def __repr__(self):
        return f"Result(finding={self.finding!r}, reason={self.reason!r}, detail={self.detail!r})"
