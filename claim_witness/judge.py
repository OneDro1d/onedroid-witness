"""The judge's model backend (SPEC §5.9, DECISIONS BD2, BD3), slice B6: any OpenAI-compatible endpoint (POST
<base>/chat/completions), configured by env only, and the price of each answer.

    WITNESS_JUDGE_BASE_URL      e.g. https://openrouter.ai/api/v1 (hosted dev), the host's vLLM in standalone
    WITNESS_JUDGE_API_KEY_FILE  a file holding the API key (mounted from a Secret; never an env value, never logged)
    WITNESS_JUDGE_MODELS_FILE   the ranked model list, JSON: [{"id", "vendor", "kind"?, "price_factor", "timeout",
                                "rank_note"?}] (at most 5, rank 1 first) or {"models": [...]}
    WITNESS_JUDGE_MAX_TOKENS    max_tokens per call (default 1024)
    WITNESS_JUDGE_DECISIONS_URL optional; default <base without /v1>/alpha/decisions (OpenRouter's Decisions API)
    WITNESS_JUDGE_CATALOGUE_URL optional; default <base>/models (OpenRouter's public model list, for unlisted ids)
    WITNESS_PRICE_LIST_FILE     optional JSON overriding the BD3 price list (integers)

A request carries the model id, the two messages (the fixed prompt, the datamarked input), temperature 0 and max_tokens:
no tools, no functions, no user field, nothing about the account, the agent, the options or the label. A timeout, an HTTP
error, a dead endpoint or an answer of the wrong shape is a note on that run, never an exception and never a 5xx.
A model id that is a router, an alias or a variant is refused when the list is loaded: a router is never a model identity;
the record names the configured id, the provider that served and the dated model id the provider answered with.

M-20261127-WITNESS-MODELS (WM-1..WM-4):
    the model list is the RANKING, at most 5 entries {id, vendor, kind?, price_factor, timeout, rank_note?}; kind "chat"
    (default, so the old list shape still reads) or "decision". A decision model is asked through OpenRouter's Decisions API
    (WITNESS_JUDGE_DECISIONS_URL, default <base without /v1>/alpha/decisions: https://openrouter.ai/api/alpha/decisions), body
    {model, state, questions} and nothing else. options.models is {count: 1..5, require?} (the top `count` in rank order) or
    {ids: [1..5], require?, max_credits_per_run?}: listed ids, or any plain OpenRouter model id ("unlisted"), whose price
    and kind come from OpenRouter's public model catalogue (WITNESS_JUDGE_CATALOGUE_URL, default <base>/models, read without
    a key and cached 1 h). An unlisted run costs ceil(usage.cost / US$0.001) + 2 credits, never more than
    max_credits_per_run (default 50, 1..1000); a model whose estimate (prompt tokens + max_tokens at its prices) is above the
    cap is refused before any model is called.
"""
import decimal
import hashlib
import json
import math
import os
import re
import socket
import threading
import time
import urllib.error
import urllib.request

from .methods import judge_supports as js

MODEL_KEYS = {"id", "vendor", "price_factor", "timeout"}
OPTIONAL_MODEL_KEYS = {"kind", "rank_note"}
KINDS = ("chat", "decision")
MAX_MODELS = 5
MAX_RANK_NOTE = 200
MAX_RESPONSE = 2 << 20
MAX_CATALOGUE = 32 << 20
PRICE_DEFAULTS = {"currency": "credits", "check": 1, "observation": 5, "model_run": 10, "kept_evidence_mb_month": 1}
VARIANTS = ("free", "beta", "nitro", "online", "extended", "floor", "exacto", "thinking")
# unlisted models (WM-3, WM-4)
UNLISTED_ID = re.compile(r"^[a-z0-9-]+/[a-z0-9._:-]+$")
UNLISTED_TIMEOUT = 60
RUN_FEE = 2
CREDIT_USD = decimal.Decimal("0.001")
CAP_DEFAULT, CAP_MIN, CAP_MAX = 50, 1, 1000
CATALOGUE_TTL = 3600
SHAPES = ("options.models is one of {count: 1..5, require?: 1..count} (the top models of GET /v1/models, in rank order) or "
          "{ids: [1 to 5 distinct model ids], require?: 1..len(ids), max_credits_per_run?: 1..1000 (default 50)} (those models, "
          "in the order given: a listed id, or any plain OpenRouter model id)")


class SelectionError(ValueError):
    """A model selection the witness refuses before anything runs: (status, error code, detail)."""

    def __init__(self, status, error, detail):
        super().__init__(detail)
        self.status, self.error, self.detail = status, error, detail


class RouterRefused(ValueError):
    pass


def refuse_routers(model_id):
    low = model_id.lower()
    variant = low.rsplit(":", 1)[1] if ":" in low else ""
    if low.startswith("~") or "router" in low or "/auto" in low or low == "auto" or low.endswith("-latest") or variant in VARIANTS:
        raise RouterRefused(f"{model_id} is a router, an alias, a variant or a free tier, not a model identity")
    return model_id


class ModelSpec:
    """One model: a listed one (from the ranked list; `rank` 1..5) or an unlisted one (any plain OpenRouter model id, made per
    request, with its catalogue `pricing`). `charged` and `cost_usd` are set on an unlisted spec by the run that used it."""
    __slots__ = ("id", "vendor", "price_factor", "timeout", "kind", "rank", "rank_note", "listed", "pricing", "charged",
                 "cost_usd", "estimate")

    def __init__(self, id, vendor, price_factor, timeout, kind="chat", rank=None, rank_note=None, listed=True, pricing=None):
        self.id, self.vendor, self.price_factor, self.timeout = id, vendor, price_factor, timeout
        self.kind, self.rank, self.rank_note, self.listed, self.pricing = kind, rank, rank_note, listed, pricing
        self.charged, self.cost_usd, self.estimate = None, None, None

    def __repr__(self):
        return f"ModelSpec({self.id!r}, {self.vendor!r}, {self.price_factor!r}, {self.timeout!r}, kind={self.kind!r}, " \
               f"listed={self.listed!r})"


def _number(v):
    return isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v)


def _int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def load_models(path):
    """The ranked model list from a JSON file (WM-1): a list (or {"models": list}) of at most 5 entries, rank 1 first, each
    {id, vendor, price_factor, timeout} plus optional kind ("chat" | "decision", default chat: the list shape before
    WM-1 still reads) and rank_note (a short public sentence). ValueError when it is not a valid list."""
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    if isinstance(doc, dict) and set(doc) == {"models"}:
        doc = doc["models"]
    if not isinstance(doc, list) or not doc:
        raise ValueError("the model list is a non-empty JSON list of {id, vendor, kind?, price_factor, timeout, rank_note?}")
    if len(doc) > MAX_MODELS:
        raise ValueError(f"the model list is the ranking: at most {MAX_MODELS} models")
    out, seen = [], set()
    for e in doc:
        if not isinstance(e, dict) or not MODEL_KEYS <= set(e) <= MODEL_KEYS | OPTIONAL_MODEL_KEYS:
            raise ValueError("each model is {id, vendor, price_factor, timeout} plus optional kind and rank_note")
        if not isinstance(e["id"], str) or not 0 < len(e["id"]) <= 200 or e["id"] in seen:
            raise ValueError("model id: a unique non-empty string")
        refuse_routers(e["id"])
        if not isinstance(e["vendor"], str) or not e["vendor"].strip():
            raise ValueError(f"{e['id']}: vendor is a non-empty string")
        if not _number(e["price_factor"]) or e["price_factor"] <= 0:
            raise ValueError(f"{e['id']}: price_factor is a positive number")
        if not _number(e["timeout"]) or not 0 < e["timeout"] <= 600:
            raise ValueError(f"{e['id']}: timeout is seconds, above 0 and at most 600")
        kind = e.get("kind", "chat")
        if kind not in KINDS:
            raise ValueError(f"{e['id']}: kind is \"chat\" or \"decision\"")
        note = e.get("rank_note")
        if "rank_note" in e and (not isinstance(note, str) or not note.strip() or len(note) > MAX_RANK_NOTE):
            raise ValueError(f"{e['id']}: rank_note is a short sentence (1 to {MAX_RANK_NOTE} characters)")
        seen.add(e["id"])
        out.append(ModelSpec(e["id"], e["vendor"], e["price_factor"], e["timeout"], kind=kind, rank=len(out) + 1,
                             rank_note=note))
    return out


def select_models(models, count):
    """The top `count` models in rank order (WM-3: called in that order; BD2's vendor-first reordering is dropped)."""
    if count > len(models):
        raise ValueError(f"{count} models asked, {len(models)} configured")
    return list(models[:count])


def models_option(o):
    """WM-3: options.models is exactly one of
        {count: 1..5, require?: 1..count}            -> {"shape": "count", "count", "require"}   (None: {count: 1})
        {ids: [1..5 distinct strings], require?: 1..len, max_credits_per_run?: 1..1000 (default 50)}
                                                     -> {"shape": "ids", "ids", "require", "max_credits_per_run"}
    strict integers, require defaulting to all; ValueError (naming both shapes) otherwise. Whether an id is listed or a plain
    OpenRouter id is decided by Judge.resolve, not here."""
    if o is None:
        return {"shape": "count", "count": 1, "require": 1}
    if not isinstance(o, dict):
        raise ValueError(SHAPES)
    if "count" in o and "ids" not in o and set(o) <= {"count", "require"}:
        c, r = o["count"], o.get("require", o["count"])
        if not (_int(c) and _int(r)) or not (1 <= c <= MAX_MODELS and 1 <= r <= c):
            raise ValueError(SHAPES)
        return {"shape": "count", "count": c, "require": r}
    if "ids" in o and "count" not in o and set(o) <= {"ids", "require", "max_credits_per_run"}:
        ids = o["ids"]
        if not isinstance(ids, list) or not 1 <= len(ids) <= MAX_MODELS or \
                not all(isinstance(i, str) and 0 < len(i) <= 200 for i in ids) or len(set(ids)) != len(ids):
            raise ValueError(SHAPES)
        r = o.get("require", len(ids))
        cap = o.get("max_credits_per_run", CAP_DEFAULT)
        if not (_int(r) and _int(cap)) or not (1 <= r <= len(ids) and CAP_MIN <= cap <= CAP_MAX):
            raise ValueError(SHAPES)
        return {"shape": "ids", "ids": list(ids), "require": r, "max_credits_per_run": cap}
    raise ValueError(SHAPES)


def check_unlisted_id(model_id):
    """An unlisted id must be a plain OpenRouter model id: ^[a-z0-9-]+/[a-z0-9._:-]+$, never a router, an alias ("~..."), a
    variant or a free tier (refuse_routers), never openrouter/auto. ValueError naming the id otherwise."""
    if not isinstance(model_id, str) or not UNLISTED_ID.match(model_id):
        raise ValueError(f"{model_id!r} is not a plain OpenRouter model id (vendor/model, lower case: ^[a-z0-9-]+/[a-z0-9._:-]+$)")
    if model_id.startswith("openrouter/"):
        raise ValueError(f"{model_id} is a router, not a model identity")
    try:
        refuse_routers(model_id)
    except RouterRefused as e:
        raise ValueError(str(e)) from None
    return model_id


# ----------------------------------------------------------------------------------------------------------------- price

def price_list(overrides=None):
    pl = dict(PRICE_DEFAULTS)
    for k, v in (overrides or {}).items():
        if k in PRICE_DEFAULTS and k != "currency":
            if not isinstance(v, int) or isinstance(v, bool) or v < 0:
                raise ValueError(f"price {k}: a non-negative integer")
            pl[k] = v
    return pl


def credits_per_run(spec, pl):
    """BD3: model_run x price_factor, rounded up to whole credits (decimal arithmetic, so 10 x 0.1 is 1)."""
    return int((decimal.Decimal(pl["model_run"]) * decimal.Decimal(str(spec.price_factor))).to_integral_value(decimal.ROUND_CEILING))


def _ceil_credits(usd):
    return int((decimal.Decimal(usd) / CREDIT_USD).to_integral_value(decimal.ROUND_CEILING))


def unlisted_credits(cost_usd, cap):
    """WM-4: one unlisted run's charge, ceil(usage.cost / US$0.001) + the run fee (2), never more than `cap`."""
    return min(_ceil_credits(str(cost_usd)) + RUN_FEE, cap)


def _price_number(v):
    """A catalogue price (US$ per token or per request, OpenRouter writes strings) as a Decimal >= 0, or None."""
    if v is None or isinstance(v, bool):
        return None
    try:
        d = decimal.Decimal(str(v))
    except (decimal.InvalidOperation, ValueError):
        return None
    return d if d.is_finite() and d >= 0 else None


def usable_pricing(pricing):
    """True when the catalogue entry's pricing has a prompt and a completion price >= 0 (and a request price, when given)."""
    if not isinstance(pricing, dict):
        return False
    if _price_number(pricing.get("prompt")) is None or _price_number(pricing.get("completion")) is None:
        return False
    return pricing.get("request") in (None, "", "0") or _price_number(pricing.get("request")) is not None


def estimate_credits(pricing, prompt_tokens, max_tokens):
    """WM-4: the most one run can cost, in credits with the run fee: prompt tokens x the prompt price + max_tokens x the
    completion price (+ the per-request price, when OpenRouter lists one), rounded up to US$0.001, + 2."""
    usd = _price_number(pricing["prompt"]) * prompt_tokens + _price_number(pricing["completion"]) * max_tokens
    usd += _price_number(pricing.get("request") or "0") or 0
    return _ceil_credits(usd) + RUN_FEE


def price_of(model_runs, pl, base="check"):
    """The answer's price: the base for the request type plus each model run made. A listed run is 10 x price_factor; an
    unlisted one is what its run charged (ceil(usage.cost / US$0.001) + 2, capped), marked unlisted with its usage.cost."""
    lines = [{"item": base, "credits": pl[base]}]
    for m in model_runs:
        if getattr(m, "listed", True):
            lines.append({"item": "model-run", "model": m.id, "credits": credits_per_run(m, pl)})
        else:
            lines.append({"item": "model-run", "model": m.id, "credits": m.charged if m.charged is not None else RUN_FEE,
                          "unlisted": True, "cost_usd": m.cost_usd})
    return {"credits": sum(x["credits"] for x in lines), "lines": lines}


def public_models(models, pl):
    """GET /v1/models (WM-1): the ranked list, rank 1 first."""
    return [{"rank": m.rank if m.rank is not None else i + 1, "id": m.id, "vendor": m.vendor, "kind": m.kind,
             "price_factor": m.price_factor, "credits_per_run": credits_per_run(m, pl), "timeout_s": m.timeout,
             "rank_note": m.rank_note} for i, m in enumerate(models)]


LISTED_RULE = ("A listed model (GET /v1/models) costs model_run x price_factor credits per run, rounded up; a run that timed "
               "out or failed was still made and counts.")
UNLISTED_RULE = ("Any other plain OpenRouter model id may be named in options.models.ids. Its run costs ceil(usage.cost / "
                 "US$0.001) + 2 credits (usage.cost: the US$ OpenRouter reports for that call; 2 is the run fee), never more "
                 "than options.models.max_credits_per_run (default 50, 1 to 1000). Before any model is called the witness "
                 "estimates the most a run can cost (prompt tokens + max_tokens at the model's OpenRouter prices, cached 1 h); "
                 "a model whose estimate is above the cap is refused (422 model-over-cap, no charge). A model OpenRouter does "
                 "not list is 422 unknown-model. A run that failed costs the run fee only.")
OWN_KEY_RULE = ("With your own key (billing own-key) every model call goes on your OpenRouter key: listed runs cost 0 credits "
                "and an unlisted run costs the run fee only (2 credits).")


def unlisted_terms():
    """The unlisted-model rule as GET /v1/price and GET /v1/models state it."""
    return {"rule": UNLISTED_RULE, "run_fee": RUN_FEE, "credit_usd": str(CREDIT_USD),
            "max_credits_per_run": {"default": CAP_DEFAULT, "min": CAP_MIN, "max": CAP_MAX}, "own_key": OWN_KEY_RULE,
            "id_pattern": UNLISTED_ID.pattern,
            "refused": "routers, aliases (~...), variants and free tiers (:free, -latest, ...), openrouter/auto"}


# ----------------------------------------------------------------------------------------------------------------- backend

# Own model key (C1): the statuses with which a router refuses the user's key itself. When every run of an own-key check
# answers one of them there is no record (422 model-key-rejected).
KEY_REJECTED = {401: "the key is not valid", 402: "the key's OpenRouter account is out of credit",
                403: "the key is disabled or not allowed to use this model"}
SCRUBBED = "[model-key]"


def _scrub(value, key):
    """value with every occurrence of key replaced (strings, and strings inside lists and dicts, keys included)."""
    if not key:
        return value
    if isinstance(value, str):
        return value.replace(key, SCRUBBED)
    if isinstance(value, list):
        return [_scrub(v, key) for v in value]
    if isinstance(value, dict):
        return {_scrub(k, key): _scrub(v, key) for k, v in value.items()}
    return value


def key_rejected_detail(status):
    return f"OpenRouter answered {status}: {KEY_REJECTED[status]}"


class CatalogueUnavailable(Exception):
    pass


def _cost_of(ans):
    """usage.cost of an answer (the US$ OpenRouter charged for the call), or None when it is absent or not a number >= 0."""
    usage = ans.get("usage") if isinstance(ans, dict) else None
    c = usage.get("cost") if isinstance(usage, dict) else None
    return c if _number(c) and c >= 0 else None


def default_decisions_url(base_url):
    """https://openrouter.ai/api/v1 -> https://openrouter.ai/api/alpha/decisions (the Decisions API sits beside /v1)."""
    b = base_url.rstrip("/")
    return (b[:-3] if b.endswith("/v1") else b) + "/alpha/decisions"


class Backend:
    def __init__(self, base_url, api_key, max_tokens=1024, opener=None, decisions_url=None, catalogue_url=None):
        if not isinstance(base_url, str) or not base_url.startswith(("http://", "https://")):
            raise ValueError("WITNESS_JUDGE_BASE_URL: an http(s) URL")
        for name, u in (("WITNESS_JUDGE_DECISIONS_URL", decisions_url), ("WITNESS_JUDGE_CATALOGUE_URL", catalogue_url)):
            if u is not None and (not isinstance(u, str) or not u.startswith(("http://", "https://"))):
                raise ValueError(f"{name}: an http(s) URL")
        self.url = base_url.rstrip("/") + "/chat/completions"
        self.decisions_url = decisions_url or default_decisions_url(base_url)
        self.catalogue_url = catalogue_url or base_url.rstrip("/") + "/models"
        self._key = api_key
        self.max_tokens = int(max_tokens)
        self.opener = opener or urllib.request.build_opener()
        self._cat, self._cat_at, self._cat_lock = None, None, threading.Lock()
        self.clock = time.monotonic

    def __repr__(self):
        return f"Backend({self.url!r}, max_tokens={self.max_tokens})"

    def _post(self, url, body, timeout, api_key):
        """(answer object or None, out with note/status set on failure). The body of an error answer is never read."""
        req = urllib.request.Request(url, data=json.dumps(body, ensure_ascii=False).encode("utf-8"), method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("Authorization", f"Bearer {api_key if api_key is not None else self._key}")
        out = {"note": None, "status": None}
        try:
            with self.opener.open(req, timeout=timeout) as r:
                data = r.read(MAX_RESPONSE + 1)
        except urllib.error.HTTPError as e:
            out["status"] = e.code if isinstance(e.code, int) else None  # the status only: the body is never read
            e.close()
            out["note"] = "model-unavailable"
            return None, out
        except (TimeoutError, socket.timeout):
            out["note"] = "timeout"
            return None, out
        except urllib.error.URLError as e:
            out["note"] = "timeout" if isinstance(e.reason, (TimeoutError, socket.timeout)) else "model-unavailable"
            return None, out
        except Exception:  # noqa: BLE001 - a backend failure is a note, never an exception
            out["note"] = "model-unavailable"
            return None, out
        try:
            if len(data) > MAX_RESPONSE:
                raise ValueError("too large")
            ans = json.loads(data)
            if not isinstance(ans, dict):
                raise ValueError("not an object")
        except ValueError:
            out["note"] = "wrong-shape"
            return None, out
        if api_key is not None:  # own model key: nothing the provider sends back may carry the key on
            ans = _scrub(ans, api_key)
        return ans, out

    def _call(self, spec, system, user, api_key=None):
        """One chat call. `api_key` (own model key, C1) replaces the configured key for this call only; it goes into the
        Authorization header and nowhere else, and every string taken from the provider's answer is scrubbed of it."""
        body = {"model": spec.id, "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
                "temperature": 0, "max_tokens": self.max_tokens}
        ans, st = self._post(self.url, body, spec.timeout, api_key)
        out = {"text": None, "served_model": None, "provider": None, "note": st["note"], "status": st["status"], "cost": None}
        if ans is None:
            return out
        try:
            content = ans["choices"][0]["message"].get("content")
        except (KeyError, IndexError, TypeError, AttributeError):
            out["note"] = "wrong-shape"
            return out
        if isinstance(ans.get("model"), str):
            out["served_model"] = ans["model"][:200]
        if isinstance(ans.get("provider"), str):
            out["provider"] = ans["provider"][:200]
        out["cost"] = _cost_of(ans)
        if content is None or (isinstance(content, str) and not content.strip()):
            out["note"] = "no-content"
        elif not isinstance(content, str):
            out["note"] = "wrong-shape"
        else:
            out["text"] = content
        return out

    def _decide_call(self, spec, state, questions, api_key=None):
        """One Decisions API call (WM-2), the shape trilix's decision_probe.py used: body {model, state, questions} and
        nothing else; read answers, model (the dated id that answered), provider and usage.cost."""
        body = {"model": spec.id, "state": state, "questions": questions}
        ans, st = self._post(self.decisions_url, body, spec.timeout, api_key)
        out = {"answer": None, "served_model": None, "provider": None, "note": st["note"], "status": st["status"], "cost": None}
        if ans is None:
            return out
        if isinstance(ans.get("model"), str):
            out["served_model"] = ans["model"][:200]
        if isinstance(ans.get("provider"), str):
            out["provider"] = ans["provider"][:200]
        out["cost"] = _cost_of(ans)
        if not isinstance(ans.get("answers"), dict):
            out["note"] = "wrong-shape"
            return out
        out["answer"] = ans["answers"]
        return out

    def _timed(self, spec, fn, empty):
        box = {}
        t0 = time.monotonic()

        def work():
            box["out"] = fn()

        th = threading.Thread(target=work, daemon=True, name=f"judge-{spec.id[:24]}")
        th.start()
        th.join(spec.timeout + 0.5)
        out = box.get("out") or dict(empty, note="timeout", status=None)
        out["ms"] = int((time.monotonic() - t0) * 1000)
        return out

    def chat(self, spec, system, user, api_key=None):
        """{text, served_model, provider, note, status, cost, ms}: note is None, timeout, model-unavailable, wrong-shape or
        no-content; status is the HTTP status of an error answer (else None); cost is usage.cost (US$) when the answer
        carries it. The whole call, connect to last byte, is held to spec.timeout. `api_key`: the own model key for this
        call (C1), else the configured key."""
        return self._timed(spec, lambda: self._call(spec, system, user, api_key),
                           {"text": None, "served_model": None, "provider": None, "cost": None})

    def decide(self, spec, state, questions, api_key=None):
        """A decision model's answer (WM-2): {answer (the `answers` object), served_model, provider, note, status, cost, ms},
        notes as chat()."""
        return self._timed(spec, lambda: self._decide_call(spec, state, questions, api_key),
                           {"answer": None, "served_model": None, "provider": None, "cost": None})

    def catalogue(self):
        """OpenRouter's public model catalogue (GET <base>/models, no key sent), as {id: {"pricing", "decisions"}}, cached
        CATALOGUE_TTL seconds. CatalogueUnavailable when it cannot be read."""
        with self._cat_lock:
            if self._cat is not None and self.clock() - self._cat_at < CATALOGUE_TTL:
                return self._cat
            req = urllib.request.Request(self.catalogue_url, method="GET")
            try:
                with self.opener.open(req, timeout=30) as r:
                    data = r.read(MAX_CATALOGUE + 1)
                if len(data) > MAX_CATALOGUE:
                    raise ValueError("too large")
                doc = json.loads(data)
                entries = doc["data"]
                if not isinstance(entries, list):
                    raise ValueError("data is not a list")
            except Exception:  # noqa: BLE001 - any failure: the catalogue is unavailable
                raise CatalogueUnavailable("the OpenRouter model catalogue could not be read") from None
            cat = {}
            for e in entries:
                if isinstance(e, dict) and isinstance(e.get("id"), str):
                    mods = (e.get("architecture") or {}).get("output_modalities") if isinstance(e.get("architecture"), dict) else None
                    cat[e["id"]] = {"pricing": e.get("pricing"), "decisions": isinstance(mods, list) and "decisions" in mods}
            self._cat, self._cat_at = cat, self.clock()
            return cat


def item_of(entry):
    """{"visible", "hidden"} of one evidence entry: an object (bytes, media_type), or an observation as the witness hands it
    to a method ({"kind": "observation", "files": {name: bytes}}). ValueError when the text is not UTF-8."""
    if isinstance(entry, dict) and entry.get("kind") == "observation":
        files = entry.get("files") or {}
        return js.item_from_observation(files.get("text.canonical.txt", b""), files.get("hidden-nodes.json"))
    data, media_type = entry
    return js.item_from_object(data, media_type)


class Judge:
    def __init__(self, backend, models):
        self.backend, self.models = backend, list(models)

    def __repr__(self):
        return f"Judge({self.backend!r}, models={[m.id for m in self.models]})"

    def no_run(self, statement, reason, n_items, count, require):
        """A judgment that called no model: unreadable evidence, or (integration) an observation the Evidence-trust rule
        refuses (`evidence-untrusted`)."""
        detail = {"evidence_items": n_items, "visible_chars": 0, "input_tokens_est": 0, "injection_hard": 0,
                  "injection_soft": 0, "reliance_requests": 0, "models": count, "require": require, "models_run": 0, "agreeing": 0}
        return {"finding": None, "reason": reason, "detail": detail, "vars": {"statement": statement}, "model_runs": [],
                "raw": [], "judgment": self._judgment([], [], {"count": count, "require": require, "agreeing": 0,
                                                               "finding": None}, [], None)}

    def resolve(self, option):
        """The models of a parsed options.models (models_option), in calling order (WM-3). {count}: the top `count` listed
        models in rank order. {ids}: each listed id is that listed model; any other id must be a plain OpenRouter model id
        (check_unlisted_id) that OpenRouter's catalogue lists with a usable price, and becomes an unlisted ModelSpec made for
        this request (kind decision when the catalogue lists it with output modality "decisions", else chat).
        SelectionError: 422 invalid-request (a router, an alias, not a plain id), 422 invalid-options (more models than
        listed), 422 unknown-model, 503 model-catalogue-unavailable. Nothing is called here but the catalogue."""
        if option["shape"] == "count":
            if option["count"] > len(self.models):
                raise SelectionError(422, "invalid-options", f"options.models.count: this witness has {len(self.models)} "
                                                             "model(s) (GET /v1/models)")
            return select_models(self.models, option["count"])
        listed = {m.id: m for m in self.models}
        out, unlisted = [], []
        for mid in option["ids"]:
            if mid in listed:
                out.append(listed[mid])
                continue
            try:
                check_unlisted_id(mid)
            except ValueError as e:
                raise SelectionError(422, "invalid-request", f"options.models.ids: {e}") from None
            out.append(mid)
            unlisted.append(mid)
        if unlisted:
            try:
                cat = self.backend.catalogue()
            except CatalogueUnavailable:
                raise SelectionError(503, "model-catalogue-unavailable", "the OpenRouter model catalogue could not be read, "
                                                                         "so an unlisted model cannot be priced; nothing was "
                                                                         "signed") from None
            for mid in unlisted:
                e = cat.get(mid)
                if e is None or not usable_pricing(e["pricing"]):
                    raise SelectionError(422, "unknown-model", f"{mid}: OpenRouter lists no such model with a price "
                                                               "(GET https://openrouter.ai/api/v1/models); nothing was run")
            out = [m if isinstance(m, ModelSpec) else
                   ModelSpec(m, m.split("/", 1)[0], None, UNLISTED_TIMEOUT, kind="decision" if cat[m]["decisions"] else "chat",
                             listed=False, pricing=dict(cat[m]["pricing"])) for m in out]
        return out

    def estimate(self, spec, prep):
        """WM-4: the most one run of an unlisted model can cost, in credits (with the run fee): its prompt tokens (the
        estimate of judge_supports, ceil(characters / 4)) and max_tokens at its catalogue prices."""
        if spec.kind == "decision":
            tokens = js.estimate_tokens(prep["input"]) + js.estimate_tokens(json.dumps(js.decision_questions(), ensure_ascii=False))
        else:
            tokens = prep["detail"]["input_tokens_est"]
        return estimate_credits(spec.pricing, tokens, self.backend.max_tokens)

    def run(self, statement, assertion, objects, count, require, api_key=None, selection=None, max_credits=CAP_DEFAULT):
        """One judgment over evidence entries, each an object (bytes, media_type) or an observation as method evidence
        ({"kind": "observation", "files": {...}}: its text.canonical.txt and hidden-nodes.json, SPEC §5.2):
        {finding, reason, detail, vars, judgment, raw, model_runs, key_rejected, over_cap}. `raw` holds each run's (spec,
        text, provider, served_model) for the caller to keep or discard; nothing is stored here. `api_key` (own model key,
        C1) is used for every model call instead of the configured key; `key_rejected` is then the HTTP status (401, 402,
        403) when every run was refused with one of them (the first run's), else None. `selection` (Judge.resolve) are the
        models to call in order (default: the top `count`). The injection gates run first, as before; then, on the
        witness's key, an unlisted model whose estimate is above `max_credits` stops everything before any model is called:
        `over_cap` is then {model, estimate, cap} and nothing is concluded."""
        vars_ = {"statement": statement}
        selection = list(selection) if selection is not None else select_models(self.models, count)
        count = len(selection)
        try:
            items = [item_of(o) for o in objects]
        except ValueError:
            return self.no_run(statement, "unreadable", len(objects), count, require)
        prep = js.prepare(statement, assertion, items)
        selected, results = [], []
        if prep["stop"] is None:
            for spec in selection:
                if not spec.listed:
                    spec.estimate = self.estimate(spec, prep)
                    if api_key is None and spec.estimate > max_credits:
                        return {"over_cap": {"model": spec.id, "estimate": spec.estimate, "cap": max_credits},
                                "model_runs": [], "raw": [], "key_rejected": None}
            selected = selection
            results = [None] * len(selected)
            system = js.prompt_text()
            questions = js.decision_questions()

            def one(i, spec):
                kw = {"api_key": api_key} if api_key is not None else {}
                if spec.kind == "decision":
                    results[i] = self.backend.decide(spec, prep["input"], questions, **kw)
                else:
                    results[i] = self.backend.chat(spec, system, prep["input"], **kw)

            threads = [threading.Thread(target=one, args=(i, m), daemon=True) for i, m in enumerate(selected)]
            for t in threads:
                t.start()
            for t, m in zip(threads, selected):
                t.join(m.timeout + 2)
            results = [r or {"text": None, "answer": None, "served_model": None, "provider": None, "note": "timeout"}
                       for r in results]
        runs, models_rec, raw = [], [], []
        any_decision = False
        for spec, res in zip(selected, results):
            if spec.kind == "decision":
                any_decision = True
                answer = res.get("answer")
                text = js.decision_output_text(answer) if answer is not None else None
                r = js.decision_run(answer) if res["note"] is None else js.failed_run(res["note"])
                runs.append({"model": spec.id, "kind": "decision", "version": res["served_model"],
                             "raw_output_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest() if text else None,
                             "finding": r["finding"], "quotes": [], "note": r["note"], "rejected": 0,
                             "probabilities_bp": {k: js.to_bp(v) for k, v in r["probabilities"].items()}
                             if r.get("probabilities") else None,
                             "confidence_bp": js.to_bp(r.get("confidence")), "threshold_bp": js.to_bp(js.DECISION_THRESHOLD),
                             "questions_sha256": js.decision_questions_sha256()})
                models_rec.append({"id": spec.id, "provider": res["provider"] or spec.vendor, "version": res["served_model"],
                                   "kind": "decision"})
            else:
                text = res.get("text")
                r = js.judge_run(text, items) if res["note"] is None else js.failed_run(res["note"])
                runs.append({"model": spec.id, "raw_output_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest() if text else None,
                             "finding": r["finding"], "quotes": r["quotes"], "note": r["note"], "rejected": r["rejected"]})
                models_rec.append({"id": spec.id, "provider": res["provider"] or spec.vendor, "version": res["served_model"]})
            raw.append((spec, text, res["provider"], res["served_model"]))
            if not spec.listed:  # WM-4: what this run costs the caller
                spec.cost_usd = res.get("cost")
                if api_key is not None or res["note"] is not None and spec.cost_usd is None:
                    spec.charged = RUN_FEE  # own key: the run fee only; a failed call: the run fee only
                elif spec.cost_usd is not None:
                    spec.charged = unlisted_credits(spec.cost_usd, max_credits)
                else:  # an answer without usage.cost: the estimate, never above the cap
                    spec.charged = min(spec.estimate, max_credits)
        statuses = [r.get("status") for r in results]
        key_rejected = statuses[0] if api_key is not None and statuses and all(s in KEY_REJECTED for s in statuses) else None
        if key_rejected is not None:  # nothing is concluded or signed from a refused key
            return {"key_rejected": key_rejected, "model_runs": selected, "raw": []}
        c = js.conclude(prep, runs, count, require)
        judgment = self._judgment(models_rec, runs, c["agreement"], prep["flags"], prep["input_sha256"])
        if any_decision:
            judgment["questions_sha256"] = js.decision_questions_sha256()
        return {"finding": c["finding"], "reason": c["reason"], "detail": c["detail"], "vars": vars_, "model_runs": selected,
                "raw": raw, "judgment": judgment, "key_rejected": None, "over_cap": None}

    def _judgment(self, models_rec, runs, agreement, flags, input_sha256):
        return {"models": models_rec, "prompt_sha256": js.prompt_sha256(), "rubric_version": js.VERSION,
                "sampling": {"temperature": 0, "max_tokens": self.backend.max_tokens}, "runs": runs, "agreement": agreement,
                "injection_flags": flags, "input_sha256": input_sha256}


def _read_key(path):
    with open(path, encoding="utf-8") as f:
        key = f.read().strip()
    if not key:
        raise SystemExit("WITNESS_JUDGE_API_KEY_FILE: the file is empty")
    return key


def from_env(env, log=None):
    """A Judge, or None when the backend is not configured (any of the three settings unset, or a mounted file absent):
    judge.supports then answers 503 judge-not-configured. A file that is there but invalid stops the process."""
    names = ("WITNESS_JUDGE_BASE_URL", "WITNESS_JUDGE_API_KEY_FILE", "WITNESS_JUDGE_MODELS_FILE")
    vals = {n: (env.get(n) or "").strip() for n in names}
    missing = [n for n in names if not vals[n]]
    missing += [n for n in names[1:] if vals[n] and not os.path.isfile(vals[n])]
    if missing:
        if log is not None:
            log(f"judge.supports: not configured ({', '.join(missing)} unset or absent)")
        return None
    try:
        models = load_models(vals["WITNESS_JUDGE_MODELS_FILE"])
    except (ValueError, OSError) as e:
        raise SystemExit(f"WITNESS_JUDGE_MODELS_FILE: {e}") from None
    try:
        backend = Backend(vals["WITNESS_JUDGE_BASE_URL"], _read_key(vals["WITNESS_JUDGE_API_KEY_FILE"]),
                          max_tokens=int(env.get("WITNESS_JUDGE_MAX_TOKENS") or 1024),
                          decisions_url=(env.get("WITNESS_JUDGE_DECISIONS_URL") or "").strip() or None,
                          catalogue_url=(env.get("WITNESS_JUDGE_CATALOGUE_URL") or "").strip() or None)
    except ValueError as e:
        raise SystemExit(str(e)) from None
    return Judge(backend, models)


def price_from_env(env):
    """The BD3 price list, with WITNESS_PRICE_LIST_FILE (JSON, integers) overriding the defaults when set."""
    pf = (env.get("WITNESS_PRICE_LIST_FILE") or "").strip()
    if not pf:
        return price_list()
    with open(pf, encoding="utf-8") as f:
        return price_list(json.load(f))
