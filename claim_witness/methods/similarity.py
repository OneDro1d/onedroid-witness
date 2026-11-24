"""Similarity (SPEC §9.2) in integer basis points (BD9): difflib.SequenceMatcher(None, a, b, autojunk=False) over the
whitespace-split token lists of the canon/1 texts. ratio() is 2*M/T; the basis points are floor(2*M*10000/T), computed
exactly with integers, so no float is ever formatted or compared. Over MAX_TOKENS on either side there is no finding
(too-large) and the matcher is not run."""
import difflib

MAX_TOKENS = 50000


def tokens(text):
    return text.split()


def matched(a, b):
    return sum(m.size for m in difflib.SequenceMatcher(None, a, b, autojunk=False).get_matching_blocks())


def similarity_bp(a, b):
    total = len(a) + len(b)
    if total == 0:
        return 10000
    return 2 * matched(a, b) * 10000 // total


def first_diff(a, b):
    """The offset of the first token where a and b differ (the length of their common prefix)."""
    n = min(len(a), len(b))
    i = 0
    while i < n and a[i] == b[i]:
        i += 1
    return i


def window(a, b):
    """The span of b that a lines up with: from the first to the last matching block, widened by a's unmatched ends.
    A screenshot shows part of a page; its text is compared with that part (match.screenshot)."""
    blocks = [m for m in difflib.SequenceMatcher(None, a, b, autojunk=False).get_matching_blocks() if m.size]
    if not blocks:
        return b
    first, last = blocks[0], blocks[-1]
    start = max(0, first.b - first.a)
    end = min(len(b), last.b + last.size + (len(a) - (last.a + last.size)))
    return b[start:end]
