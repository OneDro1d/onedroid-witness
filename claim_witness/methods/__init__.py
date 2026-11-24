"""The witness method library (SPEC §4): match.exact, quote.in-source, tests.pass (B1) and judge.supports (B6: its pure part
here, its model calls in claim_witness/judge.py).

Pure functions over bytes, standard library only, relative imports only: this package is published as the reproducible
tarball witness-methods-<LIBRARY_VERSION>.tar.gz whose sha256 is every method's `code_sha256` (SPEC §9.4), and
witness-verify imports it from that tarball to re-run a method offline.

Evidence passed to run(): {slot: {"slot", "kind", "sha256", "media_type", "name", "data": bytes}}. A slot takes
slot_counts[slot] = (min, max) items; every mechanical slot takes exactly one.
"""
import re
import unicodedata

from . import judge_supports, match_exact, quote_in_source, tests_pass
from .result import Result

LIBRARY_VERSION = "1.1.0"
POSITIVE, NEGATIVE, NEUTRAL = "positive", "negative", "neutral"
HEX_COMMIT = re.compile(r"^[0-9a-f]{7,40}$")
MAX_QUOTE = 4000


class ParamsError(ValueError):
    pass


class Method:
    def __init__(self, id, major, version, params_schema, slots, templates, findings, limits, run, check_params, mechanical=True,
                 determinism="pure", slot_counts=None):
        self.id, self.major, self.version = id, major, version
        self.params_schema, self.slots, self.templates = params_schema, slots, templates
        self.findings, self.limits, self._run, self.check_params = findings, limits, run, check_params
        self.mechanical, self.determinism = mechanical, determinism
        self.slot_counts = {s: tuple((slot_counts or {}).get(s, (1, 1))) for s in slots}

    def render(self, assertion, vars_):
        return render_template(self.templates[bool(assertion)], vars_)


def render_template(template, vars_):
    """Fill {name} fields; an optional part `{ ...{name}...}` (a brace group starting with a space) is kept only when its
    inner field has a value."""
    def optional(m):
        inner = m.group(1)
        names = re.findall(r"\{(\w+)\}", inner)
        if all(vars_.get(n) not in (None, "") for n in names):
            return re.sub(r"\{(\w+)\}", lambda x: str(vars_[x.group(1)]), inner)
        return ""
    out = re.sub(r"\{( [^{}]*\{\w+\}[^{}]*)\}", optional, template)
    return re.sub(r"\{(\w+)\}", lambda x: str(vars_.get(x.group(1), "")), out)


def _no_params(params):
    if params != {}:
        raise ParamsError("this method takes no params: {}")


def _text_param(value, name):
    if not isinstance(value, str) or not value.strip():
        raise ParamsError(f"{name}: a non-empty string")
    if len(value) > MAX_QUOTE:
        raise ParamsError(f"{name}: at most {MAX_QUOTE} characters")
    if unicodedata.normalize("NFC", value) != value:
        raise ParamsError(f"{name}: must be NFC-normalised Unicode")
    if any(unicodedata.category(c) == "Cc" and c not in "\n\t" for c in value):
        raise ParamsError(f"{name}: control characters are not allowed")


def _quote_params(params):
    if set(params) != {"quote"}:
        raise ParamsError("params: exactly {quote}")
    _text_param(params["quote"], "quote")


def _tests_params(params):
    if not set(params) <= {"expect_commit"}:
        raise ParamsError("params: {expect_commit?}")
    if "expect_commit" in params and not (isinstance(params["expect_commit"], str) and HEX_COMMIT.match(params["expect_commit"])):
        raise ParamsError("expect_commit: 7 to 40 lowercase hex characters")


METHODS = {
    "match.exact": Method(
        "match.exact", 1, "1.0.0", {"type": "object", "properties": {}, "additionalProperties": False},
        {"submitted": ("object",), "target": ("object",)},
        {True: "The submitted file {sha} is byte-identical to {target}.",
         False: "The submitted file {sha} is not byte-identical to {target}."},
        {"match": POSITIVE, "differs": NEGATIVE}, "Bytes only.", match_exact.run, _no_params),
    "quote.in-source": Method(
        "quote.in-source", 1, "1.0.0",
        {"type": "object", "properties": {"quote": {"type": "string", "minLength": 1, "maxLength": MAX_QUOTE}},
         "required": ["quote"], "additionalProperties": False},
        {"source": ("object",)},
        {True: "{source} contains the passage: “{quote}”.",
         False: "{source} does not contain the passage: “{quote}”."},
        {"quote-found": POSITIVE, "quote-absent": NEGATIVE},
        "Exact passage after canon/1 (whitespace, quotes and dashes unified; case kept).", quote_in_source.run, _quote_params),
    "tests.pass": Method(
        "tests.pass", 1, "1.0.0",
        {"type": "object", "properties": {"expect_commit": {"type": "string", "pattern": "^[0-9a-f]{7,40}$"}},
         "additionalProperties": False},
        {"log": ("object",)},
        {True: "The test output {sha} reports at least one test run and no failures{ for commit {expect_commit}}.",
         False: "The test output {sha} does not report at least one test run and no failures{ for commit {expect_commit}}."},
        {"tests-passed": POSITIVE, "tests-failed": NEGATIVE, "commit-mismatch": NEUTRAL, "commit-absent": NEUTRAL},
        "The log's origin was not verified.", tests_pass.run, _tests_params),
    "judge.supports": Method(
        "judge.supports", 1, judge_supports.VERSION, {"type": "object", "properties": {}, "additionalProperties": False},
        {"evidence": ("object", "observation")},
        {True: "{statement}", False: "Asserted false: {statement}"},
        {"judged-supports": POSITIVE, "judged-contradicted": NEGATIVE, "judged-silent": NEUTRAL},
        "A language model's reading of the visible text of the evidence, kept only with exact quotes the witness verified. "
        "It is not proof that the statement is true, and another model may read the evidence differently.",
        judge_supports.run, _no_params, mechanical=False, determinism="model", slot_counts={"evidence": (1, 5)}),
}


def get(method_id):
    return METHODS.get(method_id)


def finding_class(method_id, finding):
    """positive, negative or neutral for a finding; neutral for None (no finding)."""
    if finding is None:
        return NEUTRAL
    return METHODS[method_id].findings[finding]


def run(method_id, params, evidence):
    """Run a method over evidence by slot: a Result."""
    return METHODS[method_id]._run(params, evidence)


def render_statement(method_id, assertion, vars_):
    return METHODS[method_id].render(assertion, vars_)
