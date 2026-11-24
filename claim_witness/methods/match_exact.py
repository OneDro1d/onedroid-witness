"""match.exact 1.0.0 (SPEC §4): are the submitted bytes the target's bytes? Findings: + match, - differs. Limits: bytes only."""
from .result import Result


def run(params, evidence):
    a, b = evidence["submitted"], evidence["target"]
    da, db = a["data"], b["data"]
    vars_ = {"sha": a["sha256"], "target": b["sha256"]}
    detail = {"submitted_bytes": len(da), "target_bytes": len(db)}
    if da == db:
        return Result("match", detail, vars_)
    n = min(len(da), len(db))
    first = next((i for i in range(n) if da[i] != db[i]), n)
    detail["first_diff"] = first
    return Result("differs", detail, vars_)
