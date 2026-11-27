"""match.image-text 1.0.0 (NS-11, BRIEF-NS-11-OCR): the submitted image shows a given text. Params {text} (the claimed block,
1 to 20,000 characters); slot `image` (one PNG, JPEG or WebP object). Findings: + consistent (rule R1 finds the block in the
image's text), - differs (R1 finds a number or date of the block missing, or three or more of its tokens). No finding:
`unreadable` (the transcription is empty, or holds no readable token, or more than half of its tokens are [illegible]: a
property of the image's reading only, never of the claimed text), `model-unavailable` (every model of the list failed),
`too-large` (more than 50,000 tokens, or a transcription the model cut at its token budget that R1 would call `differs`).

The model ONLY transcribes: the witness sends it PROMPT (below, the OCR eval's prompt byte for byte: eval_vision.py, sha256
c57f8c28...3600) and the image, never the claimed text (claim_witness/transcribe.py). This module is pure and ships in the
methods tarball: the witness puts the transcription in evidence["image"]["transcription"] ({"text", "truncated"}, or None when
every model failed) and the record keeps it in its body (judgment.transcription), so witness-verify re-runs R1 offline.

Rule R1 is the OCR eval's strict rule (orch_strict_score.py, ported unchanged): both sides through canon/1 normalise and split
into tokens (similarity.tokens); a block token is covered when difflib's matching blocks of (block, transcription) cover it
(in order, autojunk off); `missing` is the uncovered block tokens, `missing_numbers` those that hold a digit or are a month name
(after stripping . , ; : ( ) and lower-casing). differs iff missing_numbers >= 1 or missing >= 3; else consistent. Measured on
the sealed set of 64 cases (32 honest, 32 forged: 12 one-sentence, 14 one-number, 6 unrelated): every model caught 32/32
forgeries; seed-2.0-mini and claude-haiku-5.5 (reasoning off) made no false `differs`, gemma-4-31b-it one.
"""
import difflib
import hashlib
import re

from . import canon, similarity
from .result import Result

PROMPT = (
    "Transcribe all of the text visible in this image, exactly as written.\n"
    "Output only the transcribed text: no introduction, no comments, no Markdown, no code fences, no table borders.\n"
    "Keep the reading order, top to bottom and left to right, with each line of the image on its own line.\n"
    "Copy every word, number, amount, currency symbol, date, time, percentage and punctuation mark exactly as it appears, "
    "even if it looks wrong or inconsistent. Do not correct, complete, summarise, translate or explain anything.\n"
    "For a table, write one row per line with its cells in order, separated by single spaces.\n"
    "If a word cannot be read, write [illegible] in its place. If the image has no text, output nothing."
)
PROMPT_SHA256 = hashlib.sha256(PROMPT.encode("utf-8")).hexdigest()
RULE = "R1"
MAX_TEXT = 20000
MAX_MISSING = 2            # consistent needs at most 2 missing tokens ...
MAX_MISSING_NUMBERS = 0    # ... and no missing number or date token
ILLEGIBLE = "[illegible]"
MONTHS = {m.lower() for m in ("January February March April May June July August September October November December "
                              "Jan Feb Mar Apr Jun Jul Aug Sep Sept Oct Nov Dec").split()}
DIGIT = re.compile(r"\d")
MEDIA_TYPES = ("image/png", "image/jpeg", "image/webp")


def is_num(tok):
    """A token that holds a digit or is a month name (amounts, dates, percentages, ids): orch_strict_score.py is_num."""
    return bool(DIGIT.search(tok)) or tok.strip(".,;:()").lower() in MONTHS


def decide(missing, missing_numbers):
    """R1: differs iff a number/date token is missing or 3 or more tokens are missing."""
    if missing_numbers > MAX_MISSING_NUMBERS or missing > MAX_MISSING:
        return "differs"
    return "consistent"


def text_sha256(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def r1(text, transcription):
    """R1 over a claimed block and a transcription: {verdict, missing_tokens, missing_number_tokens, text_tokens,
    transcription_tokens}. verdict is None when either side is over similarity.MAX_TOKENS (the matcher is not run)."""
    t = similarity.tokens(canon.normalise(text))
    o = similarity.tokens(canon.normalise(transcription or ""))
    out = {"text_tokens": len(t), "transcription_tokens": len(o)}
    if len(t) > similarity.MAX_TOKENS or len(o) > similarity.MAX_TOKENS:
        return dict(out, verdict=None, missing_tokens=None, missing_number_tokens=None)
    sm = difflib.SequenceMatcher(None, t, o, autojunk=False)
    covered = set()
    for m in sm.get_matching_blocks():
        covered.update(range(m.a, m.a + m.size))
    miss = [t[i] for i in range(len(t)) if i not in covered]
    num = [x for x in miss if is_num(x)]
    return dict(out, verdict=decide(len(miss), len(num)), missing_tokens=miss, missing_number_tokens=num)


def readable(transcription):
    """(readable, tokens, illegible): a transcription is read when it has at least one token with a letter or a digit that is
    not an [illegible] marker, and at most half of its tokens are markers. It looks at the transcription only."""
    toks = similarity.tokens(canon.normalise(transcription or ""))
    marks = sum(1 for x in toks if ILLEGIBLE in x.lower())
    words = sum(1 for x in toks if ILLEGIBLE not in x.lower() and any(c.isalnum() for c in x))
    return words > 0 and 2 * marks <= len(toks), len(toks), marks


def run(params, evidence):
    img = evidence["image"]
    text = params["text"]
    vars_ = {"sha": img["sha256"], "text_sha256": text_sha256(text)}
    tr = img.get("transcription")
    if tr is None:
        return Result(None, {"transcription": "failed"}, vars_, reason="model-unavailable")
    ok, n_tokens, marks = readable(tr.get("text"))
    if not ok:
        return Result(None, {"transcription_tokens": n_tokens, "illegible_tokens": marks}, vars_, reason="unreadable")
    r = r1(text, tr["text"])
    truncated = bool(tr.get("truncated"))
    if r["verdict"] is None:
        return Result(None, {"text_tokens": r["text_tokens"], "transcription_tokens": r["transcription_tokens"]}, vars_,
                      reason="too-large")
    detail = {"rule": RULE, "text_tokens": r["text_tokens"], "transcription_tokens": r["transcription_tokens"],
              "missing": len(r["missing_tokens"]), "missing_numbers": len(r["missing_number_tokens"]), "truncated": truncated}
    if r["verdict"] == "differs" and truncated:  # the model stopped at its budget: what is missing may be past the cut
        return Result(None, detail, vars_, reason="too-large")
    return Result(r["verdict"], detail, vars_)
