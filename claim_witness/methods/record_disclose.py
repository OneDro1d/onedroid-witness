"""record.disclose 1.0.0 (SPEC §4, B5b): publishes an earlier private record unchanged. Finding: + disclosed, when both
commitments of the private record's envelope (the claim commitment and the body commitment) match the disclosure {salt, body}
and its seal is anchored. There is no F template: a false assertion, a mismatch, a record that is not private and a record that
is not anchored yet are refused by the witness with 422 before anything is signed, so this method never answers them with a
record. Limits: no new check was made.

Evidence: `record` {id, envelope, seal}, `disclosure` an object (the disclosure JSON's bytes). `{anchor_time}` in the statement is
the earliest landed block time of the original's seal. Whether the seal itself verifies is record.valid's question, not this one's."""
from . import recordcheck
from .result import Result


def run(params, evidence):
    rec, d = evidence["record"], evidence["disclosure"]
    verdict, _, anchor = recordcheck.assess_disclose(rec["envelope"], rec.get("seal"), d["data"], rec["id"])
    vars_ = {"id": rec["id"], "anchor_time": anchor or ""}
    if verdict == "disclosed":
        return Result("disclosed", {"anchor_time": anchor}, vars_)
    return Result(None, {"commitments": verdict}, vars_, reason="undecided")
