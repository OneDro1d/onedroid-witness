"""The witness method library (SPEC §4): match.exact, quote.in-source, tests.pass (B1); judge.supports (B6: its pure part
here, its model calls in claim_witness/judge.py); page.live, match.text, match.screenshot (B2b); post.by-author (B5a, Bluesky:
it reads the platform fields of a `capture: post` observation, post_by_author.py); record.valid and record.disclose (B5b:
they read kept records: record_valid.py, record_disclose.py, recordcheck.py).

Pure functions over bytes, standard library only, relative imports only: this package is published as the reproducible
tarball witness-methods-<LIBRARY_VERSION>.tar.gz whose sha256 is every method's `code_sha256` (SPEC §9.4), and
witness-verify imports it from that tarball to re-run a method offline.

Evidence passed to run(): {slot: {"slot", "kind", "sha256", "media_type", "name", "data": bytes}} for objects; an observation
is {"slot", "kind": "observation", "id", "manifest", "files": {name: bytes}} (observed.py); page.live gets its attempts
(page_live.py). match.screenshot is the one method that is not pure: the witness runs OCR first (match_screenshot.py).
A slot takes slot_counts[slot] = (min, max) items; every mechanical slot takes exactly one, judge.supports' `evidence` 1 to 5.
"""
import re
import urllib.parse
import unicodedata

from . import (canon, judge_supports, match_exact, match_screenshot, match_text, page_live, post_by_author,  # noqa: F401
               quote_in_source, record_disclose, record_valid, recordcheck, tests_pass)
from .result import Result

LIBRARY_VERSION = "1.7.0"
POSITIVE, NEGATIVE, NEUTRAL = "positive", "negative", "neutral"
HEX_COMMIT = re.compile(r"^[0-9a-f]{7,40}$")
MAX_QUOTE = 4000


class ParamsError(ValueError):
    pass


class Method:
    def __init__(self, id, major, version, params_schema, slots, templates, findings, limits, run, check_params, mechanical=True,
                 determinism="pure", slot_counts=None, thresholds=None, pure=True):
        self.id, self.major, self.version = id, major, version
        self.params_schema, self.slots, self.templates = params_schema, slots, templates
        self.findings, self.limits, self._run, self.check_params = findings, limits, run, check_params
        self.mechanical, self.determinism = mechanical, determinism
        self.slot_counts = {s: tuple((slot_counts or {}).get(s, (1, 1))) for s in slots}
        self.thresholds, self.pure = thresholds, pure

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


MAX_URL = 4096


def check_url(value, name="url"):
    """An absolute http(s) URL with a host, at most 4096 characters, NFC, no spaces or control characters. Ports, credentials
    and addresses are the fetcher's to refuse (a refusal is a signed `blocked`, not a 422)."""
    if not isinstance(value, str) or not value or len(value) > MAX_URL:
        raise ParamsError(f"{name}: an http(s) URL of at most {MAX_URL} characters")
    if unicodedata.normalize("NFC", value) != value or any(c.isspace() or unicodedata.category(c) == "Cc" for c in value):
        raise ParamsError(f"{name}: no spaces or control characters, NFC")
    try:
        u = urllib.parse.urlsplit(value)
        host = u.hostname
    except ValueError:
        raise ParamsError(f"{name}: not a URL") from None
    if u.scheme not in ("http", "https") or not host:
        raise ParamsError(f"{name}: an absolute http or https URL with a host")


def _url_params(params):
    if set(params) != {"url"}:
        raise ParamsError("params: exactly {url}")
    check_url(params["url"])


HANDLE_LABEL = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


def _handle_params(params):
    """post.by-author: exactly {handle}, an AT Protocol handle (a DNS name of two or more labels whose last label does not
    start with a digit), at most 253 characters. Compared case-insensitively; the template keeps it as written."""
    if not isinstance(params, dict) or set(params) != {"handle"}:
        raise ParamsError("params: exactly {handle}")
    h = params["handle"]
    if not isinstance(h, str) or not 3 <= len(h) <= 253 or not h.isascii():
        raise ParamsError("handle: an AT Protocol handle such as bsky.app")
    labels = h.split(".")
    if len(labels) < 2 or not all(HANDLE_LABEL.match(x) for x in labels) or labels[-1][0].isdigit():
        raise ParamsError("handle: an AT Protocol handle such as bsky.app (no @, no spaces)")


HANDLE_SCHEMA = {"type": "object", "properties": {"handle": {"type": "string", "minLength": 3, "maxLength": 253}},
                 "required": ["handle"], "additionalProperties": False}

URL_SCHEMA = {"type": "object", "properties": {"url": {"type": "string", "format": "uri", "maxLength": MAX_URL}},
              "required": ["url"], "additionalProperties": False}
NO_PARAMS = {"type": "object", "properties": {}, "additionalProperties": False}

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
    "page.live": Method(
        "page.live", 1, "1.0.0", URL_SCHEMA, {"page": ("url",)},
        {True: "{url} was live when observed at {fetched_at}.", False: "{url} was not live when observed at {fetched_at}."},
        {"live": POSITIVE, "not-live": NEGATIVE},
        "Live means a 2xx answer with visible text from the witness's network at that time.", page_live.run, _url_params,
        determinism="observed"),
    "match.text": Method(
        "match.text", 1, "1.0.0", NO_PARAMS, {"submitted": ("object",), "page": ("url", "observation")},
        {True: "The submitted text {sha} matches the content of {url} observed at {fetched_at}.",
         False: "The submitted text {sha} does not match the content of {url} observed at {fetched_at}."},
        {"match": POSITIVE, "differs": NEGATIVE},
        "Compared visible text after canon/1 at the stated layer. Images, scripts and hidden text were not compared.",
        match_text.run, _no_params, thresholds={"T_bp": match_text.T_BP, "F_bp": match_text.F_BP}),
    "match.screenshot": Method(
        "match.screenshot", 1, "1.0.0", NO_PARAMS, {"submitted": ("object",), "page": ("url", "observation")},
        {True: "The submitted image {sha} shows text consistent with {url} observed at {fetched_at}.",
         False: "The submitted image {sha} shows text not consistent with {url} observed at {fetched_at}."},
        {"consistent": POSITIVE, "differs": NEGATIVE},
        "Compared the text read from the image. The pixels were not proven; an image can be edited.", match_screenshot.run,
        _no_params, determinism="ocr", thresholds={"T_bp": match_screenshot.T_BP, "F_bp": match_screenshot.F_BP}, pure=False),
    "post.by-author": Method(
        "post.by-author", 1, "1.0.0", HANDLE_SCHEMA, {"post": ("url", "observation")},
        {True: "The post at {url} was published by the account {handle}.",
         False: "The post at {url} was not published by the account {handle}."},
        {"author-verified": POSITIVE, "author-platform": POSITIVE, "author-differs": NEGATIVE,
         "signature-unverifiable": NEUTRAL, "handle-unresolved": NEUTRAL},
        "Proves which account key or platform account published the post, not who controls the account. The post time is the "
        "author's own claim.", post_by_author.run, _handle_params, determinism="observed"),
    "record.valid": Method(
        "record.valid", 1, "1.0.0", NO_PARAMS, {"record": ("record",), "key_list": ("object",)},
        {True: "Record {id} is validly signed under key list {key_list_sha} and sealed.",
         False: "Record {id} is not validly signed under key list {key_list_sha} and sealed."},
        {"record-valid": POSITIVE, "record-invalid": NEGATIVE},
        "Checks signature, key validity and seal under the given key list only, not the record's content.",
        record_valid.run, _no_params),
    "record.disclose": Method(
        "record.disclose", 1, "1.0.0", NO_PARAMS, {"record": ("record",), "disclosure": ("object",)},
        {True: "Record {id}, sealed at {anchor_time}, had the content shown here.", False: None},
        {"disclosed": POSITIVE},
        "Publishes an earlier private record unchanged. No new check was made.", record_disclose.run, _no_params),
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
