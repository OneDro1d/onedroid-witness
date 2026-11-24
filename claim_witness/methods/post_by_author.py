"""post.by-author 1.0.0 (SPEC §4, TS-5). Params {handle}. Slot `post`: a url (capture post) or an observation of capture post.

Bluesky only in this version. The fetcher's `capture: post` proves the post from AT Protocol (the commit signature against the
DID document's key, the MST path to the record) and resolves the claimed handle both ways (handle -> DID by DNS TXT or HTTPS
well-known, and the DID's document listing at://<handle>); the observation's `platform` holds the result (§2.3). This method
reads those fields only:

1. not a bsky.app post URL (X, LinkedIn, TikTok, anything else), or an observation with no Bluesky platform fields: no finding,
   method-not-applicable (the witness does not fetch such a URL at all);
2. a failed capture: its reason (blocked, unreachable, timeout, ...);
3. the observation resolved another handle than the claimed one, or the claimed handle is not bidirectional: handle-unresolved;
4. signature not verified (failed, not-available): signature-unverifiable;
5. the handle's DID is the post's author DID: author-verified; another DID, verified both ways: author-differs.

detail is enums only: platform, signature, resolution (dns-txt, well-known, none), bidirectional, handle_match, same_did.
"""
import re
import urllib.parse

from . import observed
from .result import Result

POST_URL = re.compile(r"^https://bsky\.app/profile/[A-Za-z0-9.:_-]{1,253}/post/[A-Za-z0-9._:~-]{1,512}$")
SIGNATURES = ("verified", "not-available", "failed")
RESOLUTIONS = ("dns-txt", "well-known")


def platform_of(url):
    """bluesky (a bsky.app post URL), x, linkedin, tiktok or other: an enum for detail."""
    if isinstance(url, str) and POST_URL.match(url):
        return "bluesky"
    try:
        host = (urllib.parse.urlsplit(url).hostname or "").lower()
    except (ValueError, AttributeError):
        return "other"
    for name, roots in (("x", ("x.com", "twitter.com")), ("linkedin", ("linkedin.com", "lnkd.in")),
                        ("tiktok", ("tiktok.com",))):
        if any(host == r or host.endswith("." + r) for r in roots):
            return name
    return "other"


def applicable(url):
    """True only for a bsky.app post URL: the one kind of URL the witness sends to the fetcher for this method."""
    return platform_of(url) == "bluesky"


def _yes(v):
    return "yes" if v else "no"


def run(params, evidence):
    post = evidence["post"]
    handle = params["handle"]
    claimed = handle.lower()
    if post.get("kind") == "url":
        vars_ = {"url": post.get("url"), "handle": handle}
        if not applicable(post.get("url")):
            return Result(None, {"platform": platform_of(post.get("url"))}, vars_, reason="method-not-applicable")
        if "failure" in post:
            f = post["failure"]
            return Result(None, observed.failure_detail(f), dict(vars_, fetched_at=f.get("at")), reason=f["reason"])
        return Result(None, {"platform": "bluesky"}, vars_, reason="unreadable")
    m = post["manifest"]
    vars_ = {"url": m.get("requested_url"), "handle": handle}
    p = m.get("platform")
    if not isinstance(p, dict) or p.get("name") != "bluesky":
        return Result(None, {"platform": platform_of(m.get("requested_url"))}, vars_, reason="method-not-applicable")
    hr = p.get("handle_resolution") if isinstance(p.get("handle_resolution"), dict) else {}
    sig = p.get("signature") if p.get("signature") in SIGNATURES else "failed"
    author, result_did = p.get("author_did"), hr.get("result_did")
    match = isinstance(p.get("handle"), str) and p["handle"].lower() == claimed
    both = match and hr.get("bidirectional") is True and isinstance(result_did, str) and bool(result_did)
    same = both and isinstance(author, str) and result_did == author
    detail = {"platform": "bluesky", "signature": sig,
              "resolution": hr.get("method") if hr.get("method") in RESOLUTIONS else "none",
              "bidirectional": _yes(hr.get("bidirectional") is True), "handle_match": _yes(match), "same_did": _yes(same)}
    if not both:
        return Result("handle-unresolved", detail, vars_)
    if sig != "verified" or not isinstance(author, str) or not author:
        return Result("signature-unverifiable", detail, vars_)
    if same:
        return Result("author-verified", detail, vars_)
    return Result("author-differs", detail, vars_)
