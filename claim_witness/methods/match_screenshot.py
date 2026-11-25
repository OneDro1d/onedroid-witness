"""match.screenshot 1.0.0 (SPEC §4). Slots: submitted (image object) and page (url or observation). Findings: + consistent
(the OCR text after canon/1 has similarity >= T with the observation's text), - differs (below F); otherwise no finding
(undecided). Empty OCR text, or an image Tesseract cannot read: unreadable.

Not a pure method: the OCR runs in the witness image (Tesseract), so its code_sha256 is the image digest (§9.4) and
witness-verify skips its re-run. The witness puts the OCR text in evidence["submitted"]["ocr_text"] (None when OCR failed);
this module compares it.

A screenshot usually shows part of a page, so the OCR tokens are compared with the span of the page's tokens they line up
with (similarity.window), not with the whole page. T and F come from the widened screenshot calibration set
(tests_claim/fixtures/calibration/screenshots2/measured.json, measured inside the claim-witness image with its Tesseract):
honest screenshots 1343..10000, one-sentence forgeries 1343..9247, screenshots of another page 468..6250. A false `differs`
over an honest screenshot is worse than no finding (DECISIONS BD19), so F is below every honest screenshot (margin 143 bp) and
T above every forgery (margin 253 bp); everything between is no finding (`undecided`). See README_CLAIM.md, decision 157.
"""
from . import canon, observed, similarity
from .result import Result

T_BP = 9500
F_BP = 1200


def run(params, evidence):
    sub, page = evidence["submitted"], evidence["page"]
    if "failure" in page:
        return Result(None, observed.failure_detail(page["failure"]), {"sha": sub["sha256"], "url": page.get("url"),
                                                                        "fetched_at": page["failure"].get("at")},
                      reason=page["failure"]["reason"])
    vars_ = dict(observed.vars_of(page), sha=sub["sha256"])
    problem = observed.page_problem(page)
    if problem:
        return Result(None, problem[1], vars_, reason=problem[0])
    ocr_text = sub.get("ocr_text")
    if ocr_text is None:
        return Result(None, {"ocr": "failed"}, vars_, reason="unreadable")
    a = similarity.tokens(canon.normalise(ocr_text))
    if not a:
        return Result(None, {"ocr_tokens": 0}, vars_, reason="unreadable")
    page_text = observed.rendered_text(page)
    if page_text is None:
        page_text = observed.response_text(page) or ""
    b = similarity.tokens(page_text)
    detail = {"layer": "rendered", "ocr_tokens": len(a), "page_tokens": len(b), "T_bp": T_BP, "F_bp": F_BP}
    if len(a) > similarity.MAX_TOKENS or len(b) > similarity.MAX_TOKENS:
        return Result(None, detail, vars_, reason="too-large")
    w = similarity.window(a, b)
    bp = similarity.similarity_bp(a, w)
    detail.update(window_tokens=len(w), similarity_bp=bp)
    if bp >= T_BP:
        return Result("consistent", detail, vars_)
    if bp < F_BP:
        return Result("differs", detail, vars_)
    return Result(None, detail, vars_, reason="undecided")
