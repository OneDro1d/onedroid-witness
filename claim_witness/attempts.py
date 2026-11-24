"""The attempt table (SPEC §7.3): tag = HMAC-SHA256(attempt key, canonical {claim, sorted object sha256s, sorted requested
URLs, method id, account}), computed on the plaintext claim, kept 30 days, scope "account"."""
import hashlib
import hmac

from .jcs import canonical

WINDOW_DAYS = 30


def attempt_tag(key, claim, object_shas, urls, method_id, account):
    msg = canonical({"claim": claim, "objects": sorted(object_shas), "urls": sorted(urls), "method": method_id, "account": account})
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def attempt_field(prior):
    """The record's `attempt` from the prior counts."""
    return {"n": 1 + sum(prior.values()), "prior": dict(prior), "window_days": WINDOW_DAYS, "scope": "account"}
