"""record.valid 1.0.0 (SPEC §4, B5b): is a record validly signed under a given key list, and sealed? Findings: + record-valid,
- record-invalid (a bad signature, a key not in the list or not valid at the anchor time, a list for another witness, a bad seal).
Limits: signature, key validity and seal under the given key list only, not the record's content.

Evidence: `record` {id, envelope, seal, ed25519_verify} (the witness reads the envelope and the seal of a kept record from its
store; the Ed25519 primitive is the caller's: recordcheck.py), `key_list` an object (the key list envelope's JSON bytes).
A record whose seal is not anchored cannot be called sealed, and its key validity at the anchor time is not proven: no finding,
reason `undecided` with detail {"seal": "pending"} (VR-6: NOT_SUPPORTED only comes from a real negative finding). Bytes that are
not a readable record or key list give no finding either (`unreadable`)."""
from . import recordcheck
from .result import Result


def run(params, evidence):
    rec, kl = evidence["record"], evidence["key_list"]
    vars_ = {"id": rec["id"], "key_list_sha": kl["sha256"]}
    verdict, failed, anchor = recordcheck.assess_valid(rec["envelope"], rec.get("seal"), kl["data"], rec["id"],
                                                       rec["ed25519_verify"])
    if verdict == "valid":
        return Result("record-valid", {"seal": "anchored", "anchor_time": anchor}, vars_)
    if verdict == "invalid":
        return Result("record-invalid", {"failed": ",".join(failed)}, vars_)
    if verdict == "pending":
        return Result(None, {"seal": "pending"}, vars_, reason="undecided")
    return Result(None, {}, vars_, reason="unreadable")
