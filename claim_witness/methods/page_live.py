"""page.live 1.0.0 (SPEC §4). Slot `page` (url, capture page). Findings: + live (2xx and at least one visible character of
canonical text); - not-live (404/410 on the exact URL, or NXDOMAIN from two resolvers, either one confirmed by a second fetch
at least 60 s later). No finding: 401/403/429, a challenge page (blocked), 5xx and other statuses (unreachable), a timeout,
a connection error, or a refused fetch (the fetcher's reason); a 2xx with no visible text (unreadable); a first answer that
the second fetch does not confirm (undecided).

The evidence is the attempts the witness made, in order: {"slot": "page", "kind": "url", "url", "attempts": [...]}, each
attempt either {"observation": <observation evidence>} or {"failure": {"reason", "code", "nxdomain", "dns": [answers of the
resolvers], "partial": <partial manifest or None>, "at": <time>}}. The witness makes the second attempt only when assess()
of the first one says "gone"; run() turns the attempts into the finding.
"""
import calendar
import time

from . import observed
from .result import Result

GONE_STATUSES = (404, 410)
CONFIRM_MIN_S = 60  # the witness may be configured lower for tests; it passes its setting as page["confirm_min_s"]


def _t(s):
    return calendar.timegm(time.strptime(s, "%Y-%m-%dT%H:%M:%SZ"))


def _at(attempt):
    if "observation" in attempt:
        return attempt["observation"]["manifest"]["fetched_at"]
    return attempt["failure"]["at"]


def assess(attempt):
    """("live" | "gone" | None, reason or None, detail) for one attempt."""
    if "failure" in attempt:
        f = attempt["failure"]
        detail = {"fetch_error": f["code"]}
        part = f.get("partial") or {}
        if isinstance(part.get("redirects"), list):
            detail["redirects"] = len(part["redirects"])
        if part.get("robots") in ("allowed", "disallowed", "unavailable"):
            detail["robots"] = part["robots"]
        votes = f.get("dns") or []
        if f.get("nxdomain") and not detail.get("redirects"):
            if len(votes) >= 2 and all(v == "nxdomain" for v in votes):
                return "gone", None, dict(detail, dns="nxdomain", resolvers=len(votes))
            if votes:
                detail["dns"] = "disagree"
        return None, f["reason"], detail
    obs = attempt["observation"]
    m = obs["manifest"]
    status = m.get("status")
    detail = {"status": status}
    if observed.is_challenge(obs):
        return None, "blocked", detail
    if isinstance(status, int) and 200 <= status < 300:
        text = observed.rendered_text(obs)
        if text is None:
            text = observed.response_text(obs) or ""
        detail["text_chars"] = len(text)
        if text.strip():
            return "live", None, detail
        return None, "unreadable", detail
    exact = m.get("final_url") == m.get("requested_url") and not m.get("redirects")
    if status in GONE_STATUSES and exact:
        return "gone", None, detail
    if status in GONE_STATUSES:
        return None, "unreachable", detail
    return None, observed.status_reason(status), detail


def run(params, evidence):
    page = evidence["page"]
    attempts = page["attempts"]
    vars_ = {"url": params["url"], "fetched_at": _at(attempts[-1])}
    state, reason, detail = assess(attempts[0])
    if state == "live":
        return Result("live", detail, vars_)
    if state != "gone":
        return Result(None, detail, vars_, reason=reason)
    if len(attempts) < 2:
        return Result(None, detail, vars_, reason="undecided")
    state2, reason2, detail2 = assess(attempts[1])
    after = _t(_at(attempts[1])) - _t(_at(attempts[0]))
    detail = dict(detail, confirm_after_s=after)
    if state2 == "gone" and after >= page.get("confirm_min_s", CONFIRM_MIN_S):
        return Result("not-live", detail, vars_)
    if "status" in detail2:
        detail["confirm_status"] = detail2["status"]
    elif "fetch_error" in detail2:
        detail["confirm_error"] = detail2["fetch_error"]
    return Result(None, detail, vars_, reason="undecided")
