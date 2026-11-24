"""The record builder (SPEC §2.4) and the private payload allow-list (§2.6).

The outcome table, the same for every method:
    finding class   assertion true    assertion false
    positive        SUPPORTED         NOT_SUPPORTED
    negative        NOT_SUPPORTED     SUPPORTED
    neutral / null  CANNOT_WITNESS    CANNOT_WITNESS
"""
import os

from . import ids, methods
from .dsse import STATEMENT_TYPE
from .schemas import CLAIM_TYPE, PRIVATE_KEYS

OUTCOME_TABLE = {("positive", True): "SUPPORTED", ("positive", False): "NOT_SUPPORTED",
                 ("negative", True): "NOT_SUPPORTED", ("negative", False): "SUPPORTED"}


def outcome_for(finding_class, assertion):
    return OUTCOME_TABLE.get((finding_class, bool(assertion)), "CANNOT_WITNESS")


def public_predicate(claim, statement, evidence, method, finding, reason, detail, limits, attempt, submitter, options_used,
                     witnessed_at, witness, visibility="public", relied_on=None, judgment=None):
    """The full public-shape predicate of §2.4 (also the body of a private record, with visibility "private")."""
    fclass = methods.finding_class(claim["method"], finding)
    return {"visibility": visibility, "claim": claim, "statement": statement, "evidence": evidence, "method": method,
            "finding": finding, "outcome": outcome_for(fclass, claim["assertion"]), "reason": reason, "detail": detail,
            "limits": limits, "judgment": judgment, "attempt": attempt, "relied_on": list(relied_on or []),
            "submitter": submitter, "options_used": options_used, "witnessed_at": witnessed_at, "witness": witness}


def build(predicate, visibility, label=None, salt=None):
    """(statement, disclosure or None). Public: subject = the claim id, predicate as given. Private: a fresh 16-byte salt
    (unless given, for test vectors); the body is the public-shape predicate plus the label; the payload holds only the
    two commitments and the allow-listed fields."""
    if visibility == "public":
        stmt = {"_type": STATEMENT_TYPE, "subject": [{"name": "claim", "digest": {"sha256": ids.claim_id(predicate["claim"])}}],
                "predicateType": CLAIM_TYPE, "predicate": predicate}
        return stmt, None
    salt = os.urandom(16) if salt is None else salt
    body = dict(predicate, visibility="private", label=label)
    payload_pred = {k: body[k] for k in PRIVATE_KEYS if k in body}
    payload_pred["visibility"] = "private"
    payload_pred["body_commitment"] = ids.body_commitment(salt, body)
    stmt = {"_type": STATEMENT_TYPE,
            "subject": [{"name": "claim", "digest": {"sha256": ids.claim_commitment(salt, body["claim"])}}],
            "predicateType": CLAIM_TYPE, "predicate": payload_pred}
    return stmt, {"salt": ids.b64url(salt), "body": body}
