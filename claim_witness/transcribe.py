"""The transcriber of match.image-text (NS-11, BRIEF-NS-11-OCR): a vision model reads the text of an image, nothing else.

The model ONLY transcribes. It gets one user message: the fixed prompt (methods/match_image_text.PROMPT, the OCR eval's prompt
byte for byte, sha256 c57f8c28...3600) and the image as a data URL. It never sees the claimed text, the claim, the account or
the options. The witness's own code (methods/match_image_text.r1, rule R1) compares the transcription with the claimed text.

    WITNESS_IMAGE_TEXT_MODELS_FILE   the ordered transcriber list, JSON: [{"id", "vendor", "timeout", "reasoning"?,
                                     "rank_note"?}] (at most 5, first first) or {"models": [...]}
    WITNESS_IMAGE_TEXT_MAX_TOKENS    max_tokens per call (default 8192: a 20,000-character text fits)
    WITNESS_JUDGE_BASE_URL, WITNESS_JUDGE_API_KEY_FILE   the same OpenAI-compatible endpoint and key as judge.supports

The request is the eval's (eval_vision.py `call`): {model, temperature 0, max_tokens, usage: {include: true}, messages: [{role:
user, content: [{type: text, text: PROMPT}, {type: image_url, image_url: {url: data:<media type>;base64,...}}]}]}, plus
`"reasoning": {"enabled": false}` as the last key for an entry listed with `"reasoning": false` (the eval's EXTRA_BODY_JSON for
seed-2.0-mini and claude-haiku-5.5). The models are tried in list order and the first one that answers with text is used; a
timeout, an HTTP error, an answer of the wrong shape or an empty answer moves on to the next. Nothing here raises: every
failure is a run note.
"""
import base64
import json
import os

from . import judge as judge_mod
from .methods import match_image_text as mit

MAX_MODELS = 5
DEFAULT_MAX_TOKENS = 8192
MODEL_KEYS = {"id", "vendor", "timeout"}
OPTIONAL_KEYS = {"reasoning", "rank_note"}


def load_models(path):
    """The ordered transcriber list from a JSON file: a list (or {"models": list}) of 1 to 5 entries {id, vendor, timeout}
    plus optional reasoning (only `false`) and rank_note. A router, an alias, a variant or a free tier is refused, as for the
    judge list. ValueError when it is not a valid list."""
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    if isinstance(doc, dict) and set(doc) == {"models"}:
        doc = doc["models"]
    if not isinstance(doc, list) or not doc:
        raise ValueError("the transcriber list is a non-empty JSON list of {id, vendor, timeout, reasoning?, rank_note?}")
    if len(doc) > MAX_MODELS:
        raise ValueError(f"the transcriber list holds at most {MAX_MODELS} models")
    out, seen = [], set()
    for e in doc:
        if not isinstance(e, dict) or not MODEL_KEYS <= set(e) <= MODEL_KEYS | OPTIONAL_KEYS:
            raise ValueError("each transcriber is {id, vendor, timeout} plus optional reasoning and rank_note")
        if not isinstance(e["id"], str) or not 0 < len(e["id"]) <= 200 or e["id"] in seen:
            raise ValueError("model id: a unique non-empty string")
        try:
            judge_mod.refuse_routers(e["id"])
        except judge_mod.RouterRefused as x:
            raise ValueError(str(x)) from None
        if e["id"].startswith("openrouter/"):
            raise ValueError(f"{e['id']} is a router, not a model identity")
        if not isinstance(e["vendor"], str) or not e["vendor"].strip():
            raise ValueError(f"{e['id']}: vendor is a non-empty string")
        if not judge_mod._number(e["timeout"]) or not 0 < e["timeout"] <= 600:
            raise ValueError(f"{e['id']}: timeout is seconds, above 0 and at most 600")
        if "reasoning" in e and e["reasoning"] is not False:
            raise ValueError(f"{e['id']}: reasoning is false or absent (false turns the model's reasoning off)")
        note = e.get("rank_note")
        if "rank_note" in e and (not isinstance(note, str) or not note.strip() or len(note) > judge_mod.MAX_RANK_NOTE):
            raise ValueError(f"{e['id']}: rank_note is a short sentence")
        seen.add(e["id"])
        out.append(judge_mod.ModelSpec(e["id"], e["vendor"], None, e["timeout"], rank=len(out) + 1, rank_note=note,
                                       reasoning=e.get("reasoning")))
    return out


def request_body(spec, image, media_type, max_tokens):
    """The eval's request (eval_vision.py `call`), key order included; reasoning off last when the entry says so."""
    body = {"model": spec.id, "temperature": 0, "max_tokens": max_tokens, "usage": {"include": True},
            "messages": [{"role": "user", "content": [
                {"type": "text", "text": mit.PROMPT},
                {"type": "image_url", "image_url": {"url": f"data:{media_type};base64," + base64.b64encode(image).decode("ascii")}}]}]}
    if getattr(spec, "reasoning", None) is False:
        body["reasoning"] = dict(judge_mod.REASONING_OFF)
    return body


def _content_text(content):
    if isinstance(content, list):  # some providers answer content parts (eval_vision.py does the same)
        parts = [p.get("text") for p in content if isinstance(p, dict)]
        if not all(isinstance(p, str) for p in parts):
            return None
        return "".join(parts)
    return content if isinstance(content, str) else None


class Transcriber:
    def __init__(self, backend, models, max_tokens=DEFAULT_MAX_TOKENS):
        self.backend, self.models, self.max_tokens = backend, list(models), int(max_tokens)

    def __repr__(self):
        return f"Transcriber(models={[m.id for m in self.models]}, max_tokens={self.max_tokens})"

    def public_models(self):
        """The ordered list as GET /v1/methods and /v1/price state it: {rank, id, vendor, timeout_s, reasoning?: false}."""
        out = []
        for m in self.models:
            e = {"rank": m.rank, "id": m.id, "vendor": m.vendor, "timeout_s": m.timeout}
            if m.reasoning is False:
                e["reasoning"] = False
            if m.rank_note:
                e["rank_note"] = m.rank_note
            out.append(e)
        return out

    def _one(self, spec, image, media_type, api_key):
        body = request_body(spec, image, media_type, self.max_tokens)
        ans, st = self.backend._post(self.backend.url, body, spec.timeout, api_key)
        out = {"text": None, "served_model": None, "provider": None, "finish_reason": None, "note": st["note"],
               "status": st["status"]}
        if ans is None:
            return out
        try:
            choice = ans["choices"][0]
            content = choice["message"].get("content")
        except (KeyError, IndexError, TypeError, AttributeError):
            out["note"] = "wrong-shape"
            return out
        if isinstance(ans.get("model"), str):
            out["served_model"] = ans["model"][:200]
        if isinstance(ans.get("provider"), str):
            out["provider"] = ans["provider"][:200]
        fr = choice.get("finish_reason") if isinstance(choice, dict) else None
        out["finish_reason"] = fr[:32] if isinstance(fr, str) else None
        text = _content_text(content)
        if content is not None and text is None:
            out["note"] = "wrong-shape"
        elif text is None or not text.strip():
            out["note"] = "no-content"
        else:
            out["text"] = text
        return out

    def run(self, image, media_type, api_key=None):
        """Try each model in order until one answers with text. Returns
            {"evidence": None | {"text", "truncated"},        what the method reads (None: every model failed)
             "served": None | {id, provider, version, rank},  the model that answered
             "runs": [{model, rank, note, status, finish_reason}], every model asked, in order
             "statuses": [...]}                               the HTTP status of each failed run (own key: all refused?)
        An empty answer (200, no text) is the image having no text when no later model reads any: evidence {"text": ""}."""
        runs, statuses, empty = [], [], False
        for spec in self.models:
            res = self.backend._timed(spec, lambda s=spec: self._one(s, image, media_type, api_key),
                                      {"text": None, "served_model": None, "provider": None, "finish_reason": None})
            runs.append({"model": spec.id, "rank": spec.rank, "note": res["note"], "status": res.get("status"),
                         "finish_reason": res.get("finish_reason")})
            statuses.append(res.get("status"))
            if res["note"] is None and res["text"] is not None:
                served = {"id": spec.id, "provider": res["provider"] or spec.vendor, "version": res["served_model"],
                          "rank": spec.rank}
                return {"evidence": {"text": res["text"], "truncated": res.get("finish_reason") == "length"},
                        "served": served, "runs": runs, "statuses": statuses}
            if res["note"] == "no-content":
                empty = True
        return {"evidence": {"text": "", "truncated": False} if empty else None, "served": None, "runs": runs,
                "statuses": statuses}


def from_env(env, log=None):
    """A Transcriber, or None when match.image-text is not configured (the model list, the base URL or the key file unset or
    absent): the method then answers 503 transcriber-not-configured. A file that is there but invalid stops the process."""
    names = ("WITNESS_JUDGE_BASE_URL", "WITNESS_JUDGE_API_KEY_FILE", "WITNESS_IMAGE_TEXT_MODELS_FILE")
    vals = {n: (env.get(n) or "").strip() for n in names}
    missing = [n for n in names if not vals[n]]
    missing += [n for n in names[1:] if vals[n] and not os.path.isfile(vals[n])]
    if missing:
        if log is not None:
            log(f"match.image-text: not configured ({', '.join(missing)} unset or absent)")
        return None
    try:
        models = load_models(vals["WITNESS_IMAGE_TEXT_MODELS_FILE"])
    except (ValueError, OSError) as e:
        raise SystemExit(f"WITNESS_IMAGE_TEXT_MODELS_FILE: {e}") from None
    try:
        backend = judge_mod.Backend(vals["WITNESS_JUDGE_BASE_URL"], judge_mod._read_key(vals["WITNESS_JUDGE_API_KEY_FILE"]))
    except ValueError as e:
        raise SystemExit(str(e)) from None
    return Transcriber(backend, models, max_tokens=int(env.get("WITNESS_IMAGE_TEXT_MAX_TOKENS") or DEFAULT_MAX_TOKENS))
