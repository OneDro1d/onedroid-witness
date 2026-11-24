"""The payload schemas the signer checks before it signs (ARCHITECTURE TB4): claim records (public §2.4, private §2.6),
observations (§2.3, public and private) and batch headers (§2.5). Anything else is refused. Hand-written checks: the
standard library has no JSON Schema validator."""
import re

from . import ids, jcs

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
CLAIM_TYPE = "https://onedroid.ai/witness/claim/v1"
OBSERVATION_TYPE = "https://onedroid.ai/witness/observation/v1"
BATCH_TYPE = "https://onedroid.ai/witness/batch-header/v1"
KEYLIST_TYPE = "https://onedroid.ai/witness/key-list/v1"
SIGNABLE = (CLAIM_TYPE, OBSERVATION_TYPE, BATCH_TYPE)

PUBLIC_KEYS = ("visibility", "claim", "statement", "evidence", "method", "finding", "outcome", "reason", "detail", "limits",
               "judgment", "attempt", "relied_on", "submitter", "options_used", "witnessed_at", "witness")
PRIVATE_KEYS = ("visibility", "body_commitment", "finding", "outcome", "reason", "method", "limits", "detail", "attempt",
                "options_used", "witnessed_at", "witness")
OUTCOMES = ("SUPPORTED", "NOT_SUPPORTED", "CANNOT_WITNESS")
NULL_REASONS = ("unreachable", "blocked", "robots-disallowed", "unreadable", "too-large", "timeout", "undecided",
                "judges-disagree", "possible-injection", "method-not-applicable", "evidence-untrusted", "model-unavailable")
OBS_PUBLIC_KEYS = ("requested_url", "final_url", "redirects", "fetched_at", "fetch_ms", "status", "resolved_ips", "tls", "robots",
                   "fetcher", "files", "canonicaliser", "platform", "visibility")
BATCH_KEYS = ("witness", "batch_id", "root", "size", "opened_at", "closed_at", "interval_s", "key_id")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
TIME = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
TOKEN = re.compile(r"^[a-z0-9][a-z0-9.-]{0,63}$")


class SchemaError(ValueError):
    pass


def _need(cond, why):
    if not cond:
        raise SchemaError(why)


def _keys(obj, keys, where):
    _need(isinstance(obj, dict), f"{where}: an object")
    _need(set(obj) == set(keys), f"{where}: exactly the fields {sorted(keys)}, got {sorted(obj)}")


def _str(v, where, max_len=20000):
    _need(isinstance(v, str) and 0 < len(v) <= max_len, f"{where}: a non-empty string")


def _int(v, where, lo=0):
    _need(isinstance(v, int) and not isinstance(v, bool) and v >= lo, f"{where}: an integer >= {lo}")


def _time(v, where):
    _need(isinstance(v, str) and TIME.match(v), f"{where}: an RFC 3339 UTC time like 2026-11-24T10:41:07Z")


def _hex(v, where):
    _need(isinstance(v, str) and HEX64.match(v), f"{where}: 64 lowercase hex")


def check_statement(stmt, predicate_type, subject_name):
    _keys(stmt, ("_type", "subject", "predicateType", "predicate"), "statement")
    _need(stmt["_type"] == STATEMENT_TYPE, "statement: _type must be in-toto Statement v1")
    _need(stmt["predicateType"] == predicate_type, "statement: predicateType does not match the request")
    sub = stmt["subject"]
    _need(isinstance(sub, list) and len(sub) == 1, "subject: exactly one entry")
    _keys(sub[0], ("name", "digest"), "subject[0]")
    if subject_name is not None:
        _need(sub[0]["name"] == subject_name, f"subject[0].name must be {subject_name!r}")
    _keys(sub[0]["digest"], ("sha256",), "subject[0].digest")
    _hex(sub[0]["digest"]["sha256"], "subject[0].digest.sha256")


def _method(m):
    _keys(m, ("id", "version", "code_sha256", "runtime"), "method")
    _need(isinstance(m["id"], str) and TOKEN.match(m["id"]), "method.id")
    _need(isinstance(m["version"], str) and re.match(r"^\d+\.\d+\.\d+$", m["version"]), "method.version: semver")
    _hex(m["code_sha256"], "method.code_sha256")
    _str(m["runtime"], "method.runtime", 64)


def _detail(d):
    _need(isinstance(d, dict), "detail: an object")
    for k, v in d.items():
        _need(isinstance(v, (int, str, bool)) or v is None, f"detail.{k}: numbers, enums, offsets and lengths only")
        _need(not isinstance(v, str) or len(v) <= 64, f"detail.{k}: enums only, never evidence text")


def _attempt(a):
    _keys(a, ("n", "prior", "window_days", "scope"), "attempt")
    _int(a["n"], "attempt.n", 1)
    _keys(a["prior"], OUTCOMES, "attempt.prior")
    for o in OUTCOMES:
        _int(a["prior"][o], f"attempt.prior.{o}")
    _need(a["n"] == 1 + sum(a["prior"].values()), "attempt.n must be 1 + the prior answers")
    _int(a["window_days"], "attempt.window_days", 1)
    _need(a["scope"] == "account", "attempt.scope must be account")


def _common(p, witness):
    f, o, r = p["finding"], p["outcome"], p["reason"]
    _need(f is None or (isinstance(f, str) and TOKEN.match(f)), "finding: a finding name or null")
    _need(o in OUTCOMES, f"outcome: one of {OUTCOMES}")
    if f is None:
        _need(r in NULL_REASONS, "reason: one of the no-finding reasons when finding is null")
        _need(o == "CANNOT_WITNESS", "outcome: CANNOT_WITNESS when there is no finding")
    else:
        _need(r == f, "reason must equal finding")
    _method(p["method"])
    _str(p["limits"], "limits", 1000)
    _detail(p["detail"])
    _attempt(p["attempt"])
    _need(isinstance(p["options_used"], dict), "options_used: an object")
    _time(p["witnessed_at"], "witnessed_at")
    _keys(p["witness"], ("id", "key_id", "key_list_seq"), "witness")
    _int(p["witness"]["key_list_seq"], "witness.key_list_seq", 1)
    if witness is not None:
        _need(p["witness"]["id"] == witness["id"], "witness.id is not this witness")
        _need(p["witness"]["key_id"] == witness["key_id"], "witness.key_id is not the signer's key")
        _need(p["witness"]["key_list_seq"] == witness["key_list_seq"], "witness.key_list_seq is not the current key list")


def check_claim(stmt, witness=None):
    check_statement(stmt, CLAIM_TYPE, "claim")
    p = stmt["predicate"]
    _need(isinstance(p, dict) and p.get("visibility") in ("public", "private"), "predicate.visibility: public or private")
    if p["visibility"] == "private":
        _keys(p, PRIVATE_KEYS, "private predicate")
        _hex(p["body_commitment"], "body_commitment")
        _common(p, witness)
        return
    _keys(p, PUBLIC_KEYS, "public predicate")
    c = p["claim"]
    _keys(c, ("method", "method_major", "params", "assertion", "statement"), "claim")
    _need(c["method"] == p["method"]["id"], "claim.method must be method.id")
    _int(c["method_major"], "claim.method_major", 1)
    _need(isinstance(c["params"], dict), "claim.params: an object")
    _need(isinstance(c["assertion"], bool), "claim.assertion: true or false")
    _need(c["statement"] is None or isinstance(c["statement"], str), "claim.statement: a string or null")
    _need(stmt["subject"][0]["digest"]["sha256"] == ids.claim_id(c), "subject digest must be the claim id")
    _str(p["statement"], "statement", 8000)
    _need(isinstance(p["evidence"], list), "evidence: a list")
    for e in p["evidence"]:
        _need(isinstance(e, dict) and isinstance(e.get("slot"), str) and e.get("kind") in ("object", "url", "observation", "record"),
              "evidence item: {slot, kind, ...}")
    _need(p["judgment"] is None or isinstance(p["judgment"], dict), "judgment: null or an object")
    _need(isinstance(p["relied_on"], list), "relied_on: a list")
    _need(isinstance(p["submitter"], dict) and isinstance(p["submitter"].get("account"), str), "submitter.account")
    _need(set(p["submitter"]) in ({"account"}, {"account", "agent", "agent_key_id", "agent_sig", "nonce", "agent_time"}),
          "submitter: {account} or the agent fields")
    _common(p, witness)


def check_observation(stmt, witness=None):
    check_statement(stmt, OBSERVATION_TYPE, None)
    p = stmt["predicate"]
    _need(isinstance(p, dict) and p.get("visibility") in ("public", "private"), "predicate.visibility: public or private")
    if p["visibility"] == "private":
        _need(stmt["subject"][0]["name"] == "observation", "a private observation's subject is named observation")
        _keys(p, ("visibility", "body_commitment", "fetched_at", "fetcher"), "private observation")
        _hex(p["body_commitment"], "body_commitment")
        _need(stmt["subject"][0]["digest"]["sha256"] == p["body_commitment"], "subject digest must be the body commitment")
        _time(p["fetched_at"], "fetched_at")
        _keys(p["fetcher"], ("id", "version"), "fetcher")
        return
    _keys(p, OBS_PUBLIC_KEYS, "public observation")
    _str(p["requested_url"], "requested_url")
    _str(p["final_url"], "final_url")
    _need(stmt["subject"][0]["name"] == p["final_url"], "subject name must be the final URL")
    _need(stmt["subject"][0]["digest"]["sha256"] == ids.sha256_hex(jcs.canonical(p)),
          "subject digest must be H(canonical manifest)")
    _need(p["visibility"] == "public", "visibility")
    _need(p["platform"] is None or isinstance(p["platform"], dict), "platform: null or an object")
    _keys(p["fetcher"], ("id", "version", "browser", "viewport"), "fetcher")
    _time(p["fetched_at"], "fetched_at")
    _int(p["fetch_ms"], "fetch_ms")
    _int(p["status"], "status")
    _need(isinstance(p["files"], list), "files: a list")
    for f in p["files"]:
        _need(isinstance(f, dict) and isinstance(f.get("name"), str), "files[]: {name, sha256, ...}")
        _hex(f.get("sha256"), f"files[{f.get('name')}].sha256")
    _need(p["canonicaliser"] == "canon/1", "canonicaliser must be canon/1")


def check_batch_header(header, witness=None):
    _keys(header, BATCH_KEYS, "batch header")
    _str(header["witness"], "witness", 256)
    _hex(header["batch_id"], "batch_id")
    _hex(header["root"], "root")
    _int(header["size"], "size", 1)
    _time(header["opened_at"], "opened_at")
    _time(header["closed_at"], "closed_at")
    _int(header["interval_s"], "interval_s", 1)
    if witness is not None:
        _need(header["witness"] == witness["id"], "witness is not this witness")
        _need(header["key_id"] == witness["key_id"], "key_id is not the signer's key")


def check(predicate_type, payload, witness=None):
    """Raise SchemaError unless payload is a valid payload of predicate_type (and canonicalisable: integers only)."""
    _need(predicate_type in SIGNABLE, f"predicateType {predicate_type!r} is not signed by this signer")
    try:
        jcs.canonical(payload)
    except jcs.CanonicalError as e:
        raise SchemaError(f"not canonicalisable: {e}") from None
    if predicate_type == CLAIM_TYPE:
        check_claim(payload, witness)
    elif predicate_type == OBSERVATION_TYPE:
        check_observation(payload, witness)
    else:
        check_batch_header(payload, witness)
