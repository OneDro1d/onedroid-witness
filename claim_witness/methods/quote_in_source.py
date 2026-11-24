"""quote.in-source 1.0.0 (SPEC §4): does the source contain the passage, after canon/1 on both? Findings: + quote-found
(with offsets into the source's canon/1 text), - quote-absent. A source that is not readable text: no finding (unreadable).
A line break in the source counts as a space, so a passage may run across lines; case is kept."""
from . import canon
from .result import Result


def run(params, evidence):
    src = evidence["source"]
    vars_ = {"source": src["sha256"], "quote": params["quote"]}
    try:
        text = canon.canon1(src["data"], src.get("media_type"), layer="response")
    except ValueError:
        return Result(None, {}, vars_, reason="unreadable")
    quote = canon.normalise(params["quote"]).replace("\n", " ")
    flat = text.replace("\n", " ")
    detail = {"source_chars": len(text)}
    if not quote:
        return Result(None, detail, vars_, reason="unreadable")
    i = flat.find(quote)
    if i < 0:
        return Result("quote-absent", detail, vars_)
    detail.update(start=i, end=i + len(quote))
    return Result("quote-found", detail, vars_)
