"""match.text 1.0.0 (SPEC §4, §9.3). Slots: submitted (object) and page (url or observation). Findings: + match, - differs;
between F and T no finding (undecided).

Layers: a text/html submission is compared first with the response layer (response.body after canon/1, no render marks); if
that does not match, with the rendered layer (text.canonical.txt). Any other text is compared with the rendered layer only.
detail.layer names the layer that decided.
Ladder at each layer (detail.rung): exact (the submitted sha256 equals a captured file's at that layer), canonical (the canon/1
texts are equal), similar (similarity >= T), differs (< F, with detail.first_diff_token), undecided (between). Similarity is
integer basis points (similarity.py); over 50,000 tokens on either side: no finding (too-large).

T and F were set from the calibration set (tests_claim/fixtures/calibration): honest copies of script-rendered pages and
pages with CSS-hidden menus scored 9765-9967 bp at the deciding layer, one-paragraph forgeries 6666-9387 bp.
"""
import hashlib

from . import canon, observed, similarity
from .result import Result

T_BP = 9700
F_BP = 9600
LAYER_FILES = {"response": ("response.body",), "rendered": (observed.TEXT_FILE, "rendered.html")}


def ladder(layer, sub_sha, sub_text, obs, page_text):
    """(finding, reason, detail) at one layer."""
    detail = {"layer": layer, "T_bp": T_BP, "F_bp": F_BP}
    shas = {hashlib.sha256(obs["files"][n]).hexdigest() for n in LAYER_FILES[layer] if n in obs["files"]}
    if sub_sha in shas:
        return "match", None, dict(detail, rung="exact", similarity_bp=10000)
    if sub_text == page_text:
        return "match", None, dict(detail, rung="canonical", similarity_bp=10000)
    a, b = similarity.tokens(sub_text), similarity.tokens(page_text)
    detail.update(submitted_tokens=len(a), page_tokens=len(b))
    if len(a) > similarity.MAX_TOKENS or len(b) > similarity.MAX_TOKENS:
        return None, "too-large", detail
    bp = similarity.similarity_bp(a, b)
    detail["similarity_bp"] = bp
    if bp >= T_BP:
        return "match", None, dict(detail, rung="similar")
    if bp < F_BP:
        return "differs", None, dict(detail, rung="differs", first_diff_token=similarity.first_diff(a, b))
    return None, "undecided", dict(detail, rung="undecided")


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
    try:
        sub_text = canon.canon1(sub["data"], sub.get("media_type"), layer="response")
    except ValueError:
        return Result(None, {}, vars_, reason="unreadable")
    layers = ("response", "rendered") if canon.is_html(sub.get("media_type")) else ("rendered",)
    last = None
    for layer in layers:
        page_text = observed.response_text(page) if layer == "response" else observed.rendered_text(page)
        if page_text is None:
            continue
        last = ladder(layer, sub["sha256"], sub_text, page, page_text)
        if last[0] == "match":
            break
    if last is None:
        return Result(None, {}, vars_, reason="unreadable")
    finding, reason, detail = last
    return Result(finding, detail, vars_, reason=reason)
