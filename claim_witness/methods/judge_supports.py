"""judge.supports 1.0.0 (SPEC §4, §5; DECISIONS BD2): the pure part of a model judgment, standard library only, shipped in the
methods tarball so anyone can rebuild the model input from the evidence and re-decide from stored model outputs.

The witness's model backend (claim_witness/judge.py) calls the models; everything that decides is here:
  1. items: each evidence item's visible canonical text (canon/1 for an object, text.canonical.txt for an observation) and its
     hidden nodes (elements an HTML object hides, or an observation's hidden-nodes.json); hidden text is never sent;
  2. pre-checks: at most MAX_INPUT_TOKENS (an estimate: ceil(characters / 4) of the prompt plus the input) -> too-large; an
     item with no visible text -> unreadable;
  3. injection rules (§5.5): hard flags (text addressed to a model, role markers at line start, chat-template tokens,
     instruction overrides, the statement's words in a hidden node) give possible-injection before any model is asked; the
     soft signal (verdict words) is recorded only;
  4. the input: the statement and the assertion, then each item, between marker lines carrying a nonce derived from the
     content, every space datamarked as U+02C6 (length-preserving, so offsets into the marked text are offsets into the
     visible text);
  5. one run per model: the first JSON object in the answer, a Markdown code fence stripped; a finding word outside the
     vocabulary is its own note; every quote is verified against the visible text, and a positive or negative finding with
     no verified quote is no finding (VR-7);
  6. agreement (BD2): a finding needs `require` runs agreeing and no other finding as large; two findings that both appear
     and none reaching `require` is judges-disagree (VR-8).
"""
import hashlib
import html.parser
import json
import math
import pathlib
import re

from . import canon

VERSION = "1.0.0"
PROMPT_FILE = pathlib.Path(__file__).resolve().parent / "prompts" / f"judge.supports-{VERSION}.txt"
FINDINGS = ("judged-supports", "judged-contradicted", "judged-silent")
QUOTED = ("judged-supports", "judged-contradicted")
MAX_INPUT_TOKENS = 200000
MAX_QUOTES = 10
MIN_QUOTE_CHARS = 2
MARK = "\u02c6"
UNDECIDED_NOTES = ("no-content", "not-parseable", "wrong-shape", "finding-not-in-vocabulary", "no-verified-quote")


def prompt_bytes():
    return PROMPT_FILE.read_bytes()


def prompt_text():
    return prompt_bytes().decode("utf-8")


def prompt_sha256():
    return hashlib.sha256(prompt_bytes()).hexdigest()


def run(params, evidence):
    raise RuntimeError("judge.supports runs through the witness's model backend (claim_witness/judge.py), not methods.run")


# ------------------------------------------------------------------------------------------------------------- items

class _Hidden(html.parser.HTMLParser):
    """The text of each element canon/1 drops for being hidden (hidden, aria-hidden, inline display:none or
    visibility:hidden, data-witness-hidden), one string per outermost hidden element. script, style and the like are not
    text and are skipped."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack = []  # (tag, state): state is "drop", an index into self.nodes, or None
        self.nodes = []

    def _state(self):
        return self.stack[-1][1] if self.stack else None

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if tag in canon.VOID:
            return
        st = self._state()
        if st is None:
            a = {k.lower(): (v if v is not None else "") for k, v in attrs}
            if tag in canon.DROP:
                st = "drop"
            elif ("hidden" in a or a.get("aria-hidden", "").strip().lower() == "true" or canon._hidden_style(a.get("style"))
                  or "data-witness-hidden" in a):
                self.nodes.append([])
                st = len(self.nodes) - 1
        elif isinstance(st, int) and tag in canon.BLOCK:
            self.nodes[st].append("\n")
        self.stack.append((tag, st))

    def handle_endtag(self, tag):
        tag = tag.lower()
        for i in range(len(self.stack) - 1, -1, -1):
            if self.stack[i][0] == tag:
                del self.stack[i:]
                return

    def handle_data(self, data):
        st = self._state()
        if isinstance(st, int):
            self.nodes[st].append(data)


def hidden_nodes_of_html(markup):
    p = _Hidden()
    p.feed(markup)
    p.close()
    out = []
    for parts in p.nodes:
        t = canon.normalise("".join(parts))
        if t:
            out.append(t)
    return out


def item_from_object(data, media_type):
    """{"visible", "hidden"} of an object; ValueError when the bytes are not readable text."""
    text = canon.decode(data)
    if text is None:
        raise ValueError("not UTF-8 text")
    visible = canon.canon1(text, media_type, layer="response")
    hidden = hidden_nodes_of_html(text) if canon.is_html(media_type) else []
    return {"visible": visible, "hidden": hidden}


def item_from_observation(text_canonical, hidden_nodes_json=None):
    """{"visible", "hidden"} of an observation: its text.canonical.txt and the excerpts of its hidden-nodes.json (a list of
    {xpath, excerpt, sha256, reason}, as the fetcher writes it). ValueError when the text is not UTF-8."""
    text = canon.decode(text_canonical)
    if text is None:
        raise ValueError("not UTF-8 text")
    hidden = []
    if hidden_nodes_json:
        try:
            nodes = json.loads(canon.decode(hidden_nodes_json) or "")
        except ValueError:
            nodes = []
        for n in nodes if isinstance(nodes, list) else []:
            t = n.get("text", n.get("excerpt")) if isinstance(n, dict) else n
            if isinstance(t, str) and canon.normalise(t):
                hidden.append(canon.normalise(t))
    return {"visible": canon.normalise(text), "hidden": hidden}


# ------------------------------------------------------------------------------------------------------------- input

def datamark(text):
    return text.replace(" ", MARK)


def input_nonce(statement, assertion, items):
    doc = json.dumps([statement, bool(assertion), [i["visible"] for i in items]], ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(b"judge.supports/nonce/1|" + doc.encode("utf-8")).hexdigest()[:16]


def build_input(statement, assertion, items):
    """The user message: delimited, datamarked, deterministic. Never anything about who asked or why."""
    n = input_nonce(statement, assertion, items)
    lines = [f"WITNESS-INPUT/1 {n}", f"ASSERTION: {'true' if assertion else 'false'}",
             f"STATEMENT {n} BEGIN", datamark(statement), f"STATEMENT {n} END"]
    for i, it in enumerate(items):
        lines += [f"EVIDENCE {i} chars={len(it['visible'])} {n} BEGIN", datamark(it["visible"]), f"EVIDENCE {i} {n} END"]
    return "\n".join(lines) + "\n"


def estimate_tokens(text):
    return math.ceil(len(text) / 4)


def prechecks(statement, assertion, items):
    user = build_input(statement, assertion, items)
    tokens = estimate_tokens(prompt_text()) + estimate_tokens(user)
    detail = {"evidence_items": len(items), "visible_chars": sum(len(i["visible"]) for i in items), "input_tokens_est": tokens}
    reason = None
    if tokens > MAX_INPUT_TOKENS:
        reason = "too-large"
    elif not items or any(not i["visible"] for i in items):
        reason = "unreadable"
    return {"reason": reason, "detail": detail, "input": user}


# ------------------------------------------------------------------------------------------------------------- injection

_F = re.IGNORECASE | re.MULTILINE
_MODEL = (r"(?:ai|a\.i\.|llms?|language models?|large language models?|ai assistants?|assistants?|chat ?bots?|ai models?|gpt|"
          r"chatgpt|claude|gemini|copilot|ai judges?|ai graders?|ai reviewers?|ai agents?|ai systems?)")
_VERDICT = r"(?:(?-i:SUPPORTED|NOT_SUPPORTED|CANNOT_WITNESS|EVIDENCED|CONTRADICTED)|judged-(?:supports|contradicted|silent))"
HARD_RULES = (
    ("instruction-override", re.compile(
        r"\b(?:ignore|disregard|forget|override|bypass)\b[^.\n]{0,40}?\b(?:previous|prior|above|earlier|preceding|all|any|your|"
        r"the|these|those|system|original)\b[^.\n]{0,25}?\b(?:instructions?|prompts?|rules|directions|guidelines|messages|"
        r"context|directives)\b|\bdo not follow\s+(?:the\s+|your\s+|any\s+)?(?:previous|prior|original|above|earlier)\s+"
        r"(?:instructions?|prompts?|rules)\b", _F)),
    ("role-marker", re.compile(r"^[ \t]*(?:system|assistant|developer)[ \t]*:|^[ \t]*#{1,6}[ \t]*(?:system|instructions?|"
                               r"assistant)\b|^[ \t]*\[(?:system|assistant)\]", _F)),
    ("chat-token", re.compile(r"<\|[a-z_]{2,40}\|>|\[/?inst\]|<</?sys>>|<(?:start|end)_of_turn>", _F)),
    ("addressed-to-model", re.compile(
        r"\b(?:dear|hey|hi|hello|attention|note to|message to|instructions? for|notice to|to)\s+(?:the\s+|all\s+|any\s+)?"
        + _MODEL + r"\s*[:,!]"
        r"|\b(?:you are|you're|act as|pretend to be|roleplay as)\s+(?:now\s+)?(?:an?\s+|the\s+)?(?:helpful\s+)?"
        r"(?:ai|a\.i\.|llm|language model|large language model|ai model|assistant|chat ?bot|gpt|ai judge|ai grader|ai assistant)\b"
        r"|\b(?:ai|llm|language model|assistant|chat ?bot|ai model|model|judge|grader|evaluator)s?\s*[:,]\s*(?:please\s+)?"
        r"(?:ignore|disregard|answer|respond|reply|output|return|say|mark|classify|grade|treat|consider|conclude)\b", _F)),
    ("verdict-instruction", re.compile(
        r"\b(?:answer|respond|reply|output|return|say|print|write|mark|classify|grade|conclude)\b(?:\s+(?:with|as|only|just|this|"
        r"it|that|the|claim|statement))*\s*[\"']?\s*" + _VERDICT + r"(?![\w-])", _F)),
    ("new-instructions", re.compile(
        r"\b(?:new|updated|revised|real|actual|hidden|secret|override)\s+(?:system\s+)?(?:instructions?|prompt)\s*:|"
        r"\bsystem\s+(?:prompt|message|instructions?|override)\s*:", _F)),
)
SOFT_RULES = (
    ("verdict-word", re.compile(r"(?-i:\b(?:NOT_SUPPORTED|NOT SUPPORTED|CANNOT_WITNESS|CANNOT WITNESS|SUPPORTED|EVIDENCED|"
                                r"CONTRADICTED|UNDECIDED|NO EVIDENCE PUBLISHED)\b)|\bjudged-(?:supports|contradicted|silent)\b",
                                _F)),
)
_WORD = re.compile(r"\w+")


def _words(text):
    return _WORD.findall(text.casefold())


def _statement_in(statement_words, node_words):
    if not statement_words or not node_words:
        return False
    if f" {' '.join(statement_words)} " in f" {' '.join(node_words)} ":
        return True
    content = {w for w in statement_words if len(w) >= 3}
    if len(content) < 4:
        return False
    return len(content & set(node_words)) * 10 >= len(content) * 9


def _flag(kind, rule, source, layer, start, end, count):
    return {"kind": kind, "rule": rule, "source": source, "layer": layer, "start": start, "end": end, "count": count}


def injection_flags(statement, items):
    """Every hard flag and soft signal in the evidence, as names, item indices and offsets only (no text)."""
    out = []
    sw = _words(statement)
    for i, it in enumerate(items):
        layers = [("visible", it["visible"])]
        if it.get("hidden"):
            layers.append(("hidden", "\n".join(it["hidden"])))
        for layer, text in layers:
            for kind, rules in (("hard", HARD_RULES), ("soft", SOFT_RULES)):
                for name, rx in rules:
                    ms = list(rx.finditer(text))
                    if ms:
                        out.append(_flag(kind, name, i, layer, ms[0].start(), ms[0].end(), len(ms)))
        pos = 0
        hits = []
        for node in it.get("hidden") or []:
            if _statement_in(sw, _words(node)):
                hits.append((pos, pos + len(node)))
            pos += len(node) + 1
        if hits:
            out.append(_flag("hard", "statement-in-hidden", i, "hidden", hits[0][0], hits[0][1], len(hits)))
    return out


def has_hard(flags):
    return any(f["kind"] == "hard" for f in flags)


# ------------------------------------------------------------------------------------------------------------- output

def _no_dupes(pairs):
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ValueError("duplicate key")
    return dict(pairs)


_FENCE = re.compile(r"```[A-Za-z0-9_-]*")


def first_object(text):
    """The first JSON object in the text, a Markdown code fence stripped; None when there is none."""
    text = _FENCE.sub("", text)
    dec = json.JSONDecoder(object_pairs_hook=_no_dupes)
    i = text.find("{")
    while i >= 0:
        try:
            obj, _ = dec.raw_decode(text, i)
        except ValueError:
            obj = None
        if isinstance(obj, dict):
            return obj
        i = text.find("{", i + 1)
    return None


def parse_output(text):
    """(finding or None, raw quotes, note). Notes: ok, no-content, not-parseable, wrong-shape, finding-not-in-vocabulary."""
    if not isinstance(text, str) or not text.strip():
        return None, [], "no-content"
    obj = first_object(text)
    if obj is None:
        return None, [], "not-parseable"
    f = obj.get("finding")
    if not isinstance(f, str):
        return None, [], "wrong-shape"
    if f not in FINDINGS:
        return None, [], "finding-not-in-vocabulary"
    quotes = obj.get("quotes", [])
    if quotes is None:
        quotes = []
    if not isinstance(quotes, list):
        return None, [], "wrong-shape"
    return f, quotes, "ok"


def _int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def verify_quotes(quotes, items):
    """(verified [{source, start, end}], rejected count). A quote verifies when its source is an item, 0 <= start < end <=
    the item's visible length, the span holds at least MIN_QUOTE_CHARS non-space characters, and its `text`, when given,
    equals the span (plain or datamarked)."""
    ok, rejected = [], 0
    for n, q in enumerate(quotes):
        if n >= MAX_QUOTES or not isinstance(q, dict):
            rejected += 1
            continue
        s, a, b = q.get("source"), q.get("start"), q.get("end")
        if not (_int(s) and _int(a) and _int(b)) or not 0 <= s < len(items):
            rejected += 1
            continue
        vis = items[s]["visible"]
        if not 0 <= a < b <= len(vis):
            rejected += 1
            continue
        span = vis[a:b]
        if len("".join(span.split())) < MIN_QUOTE_CHARS:
            rejected += 1
            continue
        t = q.get("text")
        if t is not None and (not isinstance(t, str) or t.replace(MARK, " ") != span):
            rejected += 1
            continue
        v = {"source": s, "start": a, "end": b}
        if v not in ok:
            ok.append(v)
    return ok, rejected


def judge_run(text, items):
    """One model's answer: {finding, quotes, note, rejected}."""
    f, quotes, note = parse_output(text)
    if f is None:
        return {"finding": None, "quotes": [], "note": note, "rejected": 0}
    if f not in QUOTED:
        return {"finding": f, "quotes": [], "note": "ok", "rejected": 0}
    ok, rejected = verify_quotes(quotes, items)
    if not ok:
        return {"finding": None, "quotes": [], "note": "no-verified-quote", "rejected": rejected}
    return {"finding": f, "quotes": ok, "note": "ok", "rejected": rejected}


def failed_run(note):
    return {"finding": None, "quotes": [], "note": note, "rejected": 0}


# ------------------------------------------------------------------------------------------------------------- decision

def _failure_reason(runs):
    notes = [r["note"] for r in runs if r["finding"] is None]
    if any(n in UNDECIDED_NOTES for n in notes):
        return "undecided"
    if "timeout" in notes:
        return "timeout"
    if "model-unavailable" in notes:
        return "model-unavailable"
    return "undecided"


def agree(runs, require):
    """(finding or None, reason when None, agreeing): the largest finding wins when at least `require` runs gave it and no
    other finding is as large; two findings without a winner is judges-disagree; otherwise the runs' failure decides."""
    counts = {}
    for r in runs:
        if r["finding"] is not None:
            counts[r["finding"]] = counts.get(r["finding"], 0) + 1
    top = max(counts.values()) if counts else 0
    winners = [f for f, c in counts.items() if c == top]
    if counts and len(winners) == 1 and top >= require:
        return winners[0], None, top
    if len(counts) >= 2:
        return None, "judges-disagree", top
    return None, _failure_reason(runs), top


def prepare(statement, assertion, items):
    """Everything before a model is asked: {stop (a reason or None), detail, flags, input, input_sha256}."""
    pc = prechecks(statement, assertion, items)
    detail = dict(pc["detail"])
    flags = [] if pc["reason"] == "too-large" else injection_flags(statement, items)
    detail["injection_hard"] = sum(1 for f in flags if f["kind"] == "hard")
    detail["injection_soft"] = sum(1 for f in flags if f["kind"] == "soft")
    stop = pc["reason"] if pc["reason"] == "too-large" else ("possible-injection" if has_hard(flags) else pc["reason"])
    return {"stop": stop, "detail": detail, "flags": flags, "input": pc["input"],
            "input_sha256": hashlib.sha256(pc["input"].encode("utf-8")).hexdigest()}


def conclude(prep, runs, count, require):
    """{finding, reason, detail, agreement} from the prepared input and the runs."""
    detail = dict(prep["detail"], models=count, require=require, models_run=len(runs))
    if prep["stop"] is not None:
        finding, reason, agreeing = None, prep["stop"], 0
    else:
        finding, reason, agreeing = agree(runs, require)
    detail["agreeing"] = agreeing
    return {"finding": finding, "reason": finding if finding is not None else reason, "detail": detail,
            "agreement": {"count": count, "require": require, "agreeing": agreeing, "finding": finding}}


def decide(statement, assertion, items, outputs, require):
    """The whole decision over fixed model outputs (raw texts, or None for a run that gave none), as the vectors replay it."""
    prep = prepare(statement, assertion, items)
    runs = []
    if prep["stop"] is None:
        for text in outputs:
            r = judge_run(text, items) if text is not None else failed_run("model-unavailable")
            r["raw_output_sha256"] = hashlib.sha256(text.encode("utf-8")).hexdigest() if text is not None else None
            runs.append(r)
    c = conclude(prep, runs, len(outputs), require)
    return {"finding": c["finding"], "reason": c["reason"], "detail": c["detail"], "vars": {"statement": statement},
            "runs": runs, "agreement": c["agreement"], "injection_flags": prep["flags"], "input_sha256": prep["input_sha256"]}
