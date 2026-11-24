"""What the observation-based methods share: reading an observation passed as evidence, its HTTP status as a no-finding
reason, the challenge-page test, and its two text layers (SPEC §9.3).

An observation in evidence is {"slot", "kind": "observation", "id", "manifest": the public-shape manifest (§2.3, for a
private observation its body), "files": {name: bytes}}.
"""
from . import canon

TEXT_FILE = "text.canonical.txt"
BLOCKED_STATUSES = {401, 403, 407, 429, 451}
CHALLENGE_MARKERS = ("just a moment...", "checking your browser before accessing", "challenge-platform", "cf-browser-verification",
                     "cf-chl-", "attention required! | cloudflare", "_incapsula_resource", "px-captcha", "ddos protection by",
                     "please verify you are a human", "captcha-delivery.com")


def file_entry(obs, name):
    for f in obs["manifest"].get("files") or []:
        if f.get("name") == name:
            return f
    return None


def status_reason(status):
    """None for 2xx; otherwise the no-finding reason a non-2xx answer gives a content method."""
    if isinstance(status, int) and 200 <= status < 300:
        return None
    if status in BLOCKED_STATUSES:
        return "blocked"
    return "unreachable"


def is_challenge(obs):
    """A bot challenge or captcha page instead of the content (any status)."""
    for name in ("response.body", "rendered.html"):
        data = obs["files"].get(name)
        if data:
            head = data[:65536].decode("utf-8", "replace").lower()
            if any(m in head for m in CHALLENGE_MARKERS):
                return True
    return False


def rendered_text(obs):
    """The rendered layer: text.canonical.txt, or None when the observation has none."""
    data = obs["files"].get(TEXT_FILE)
    if data is None:
        return None
    text = canon.decode(data)
    return text


def response_text(obs):
    """The response layer: response.body after canon/1 without render marks, or None when it is not text."""
    data = obs["files"].get("response.body")
    if data is None:
        return None
    entry = file_entry(obs, "response.body") or {}
    try:
        return canon.canon1(data, entry.get("media_type") or "text/html", layer="response")
    except ValueError:
        return None


def failure_detail(f):
    """detail for a fetch that failed: the fetcher's code, and what its partial manifest says (counts and enums only)."""
    detail = {"fetch_error": f["code"]}
    part = f.get("partial") or {}
    if isinstance(part.get("redirects"), list):
        detail["redirects"] = len(part["redirects"])
    if part.get("robots") in ("allowed", "disallowed", "unavailable"):
        detail["robots"] = part["robots"]
    return detail


def page_problem(obs):
    """(reason, detail) when an observation cannot be compared with (challenge page, non-2xx answer), else None."""
    status = obs["manifest"].get("status")
    if is_challenge(obs):
        return "blocked", {"status": status}
    reason = status_reason(status)
    if reason:
        return reason, {"status": status}
    return None


def vars_of(obs):
    m = obs["manifest"]
    return {"url": m.get("requested_url"), "fetched_at": m.get("fetched_at")}
