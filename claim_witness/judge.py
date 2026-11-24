"""The judge's model backend (SPEC §5.9, DECISIONS BD2, BD3), slice B6: any OpenAI-compatible endpoint (POST
<base>/chat/completions), configured by env only, and the price of each answer.

    WITNESS_JUDGE_BASE_URL      e.g. https://openrouter.ai/api/v1 (hosted dev), the host's vLLM in standalone
    WITNESS_JUDGE_API_KEY_FILE  a file holding the API key (mounted from a Secret; never an env value, never logged)
    WITNESS_JUDGE_MODELS_FILE   the model list, JSON: [{"id", "vendor", "price_factor", "timeout"}] or {"models": [...]}
    WITNESS_JUDGE_MAX_TOKENS    max_tokens per call (default 1024)
    WITNESS_PRICE_LIST_FILE     optional JSON overriding the BD3 price list (integers)

A request carries the model id, the two messages (the fixed prompt, the datamarked input), temperature 0 and max_tokens:
no tools, no functions, no user field, nothing about the account, the agent, the options or the label. A timeout, an HTTP
error, a dead endpoint or an answer of the wrong shape is a note on that run, never an exception and never a 5xx.
A model id that is a router, an alias or a variant is refused when the list is loaded: a router is never a model identity;
the record names the configured id, the provider that served and the dated model id the provider answered with.
"""
import decimal
import hashlib
import json
import math
import os
import socket
import threading
import time
import urllib.error
import urllib.request

from .methods import judge_supports as js

MODEL_KEYS = {"id", "vendor", "price_factor", "timeout"}
MAX_RESPONSE = 2 << 20
PRICE_DEFAULTS = {"currency": "credits", "check": 1, "observation": 5, "model_run": 10, "kept_evidence_mb_month": 1}
VARIANTS = ("free", "beta", "nitro", "online", "extended", "floor", "exacto", "thinking")


class RouterRefused(ValueError):
    pass


def refuse_routers(model_id):
    low = model_id.lower()
    variant = low.rsplit(":", 1)[1] if ":" in low else ""
    if low.startswith("~") or "router" in low or "/auto" in low or low == "auto" or low.endswith("-latest") or variant in VARIANTS:
        raise RouterRefused(f"{model_id} is a router, an alias, a variant or a free tier, not a model identity")
    return model_id


class ModelSpec:
    __slots__ = ("id", "vendor", "price_factor", "timeout")

    def __init__(self, id, vendor, price_factor, timeout):
        self.id, self.vendor, self.price_factor, self.timeout = id, vendor, price_factor, timeout

    def __repr__(self):
        return f"ModelSpec({self.id!r}, {self.vendor!r}, {self.price_factor!r}, {self.timeout!r})"


def _number(v):
    return isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v)


def load_models(path):
    """The model list from a JSON file; ValueError when it is not a valid list."""
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    if isinstance(doc, dict) and set(doc) == {"models"}:
        doc = doc["models"]
    if not isinstance(doc, list) or not doc:
        raise ValueError("the model list is a non-empty JSON list of {id, vendor, price_factor, timeout}")
    out, seen = [], set()
    for e in doc:
        if not isinstance(e, dict) or set(e) != MODEL_KEYS:
            raise ValueError("each model is exactly {id, vendor, price_factor, timeout}")
        if not isinstance(e["id"], str) or not 0 < len(e["id"]) <= 200 or e["id"] in seen:
            raise ValueError("model id: a unique non-empty string")
        refuse_routers(e["id"])
        if not isinstance(e["vendor"], str) or not e["vendor"].strip():
            raise ValueError(f"{e['id']}: vendor is a non-empty string")
        if not _number(e["price_factor"]) or e["price_factor"] <= 0:
            raise ValueError(f"{e['id']}: price_factor is a positive number")
        if not _number(e["timeout"]) or not 0 < e["timeout"] <= 600:
            raise ValueError(f"{e['id']}: timeout is seconds, above 0 and at most 600")
        seen.add(e["id"])
        out.append(ModelSpec(e["id"], e["vendor"], e["price_factor"], e["timeout"]))
    return out


def select_models(models, count):
    """`count` models, one per vendor in list order while vendors last, then the rest in list order."""
    if count > len(models):
        raise ValueError(f"{count} models asked, {len(models)} configured")
    first, rest, vendors = [], [], set()
    for m in models:
        (rest if m.vendor in vendors else first).append(m)
        vendors.add(m.vendor)
    return (first + rest)[:count]


def models_option(o):
    """BD2: None -> {count: 1, require: 1}; {count: 1|2|3, require?: 1..count}, strict integers; ValueError otherwise."""
    if o is None:
        return {"count": 1, "require": 1}
    if not isinstance(o, dict) or not set(o) <= {"count", "require"} or "count" not in o:
        raise ValueError("options.models: {count: 1|2|3, require?: n <= count}")
    c, r = o["count"], o.get("require", o["count"])
    if not all(isinstance(x, int) and not isinstance(x, bool) for x in (c, r)) or not (1 <= c <= 3 and 1 <= r <= c):
        raise ValueError("options.models: {count: 1|2|3, require?: n <= count}")
    return {"count": c, "require": r}


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


def price_of(model_runs, pl, base="check"):
    """The answer's price: the base for the request type plus each model run made."""
    lines = [{"item": base, "credits": pl[base]}]
    lines += [{"item": "model-run", "model": m.id, "credits": credits_per_run(m, pl)} for m in model_runs]
    return {"credits": sum(x["credits"] for x in lines), "lines": lines}


def public_models(models, pl):
    return [{"id": m.id, "vendor": m.vendor, "price_factor": m.price_factor, "credits_per_run": credits_per_run(m, pl),
             "timeout_s": m.timeout} for m in models]


# ----------------------------------------------------------------------------------------------------------------- backend

class Backend:
    def __init__(self, base_url, api_key, max_tokens=1024, opener=None):
        if not isinstance(base_url, str) or not base_url.startswith(("http://", "https://")):
            raise ValueError("WITNESS_JUDGE_BASE_URL: an http(s) URL")
        self.url = base_url.rstrip("/") + "/chat/completions"
        self._key = api_key
        self.max_tokens = int(max_tokens)
        self.opener = opener or urllib.request.build_opener()

    def __repr__(self):
        return f"Backend({self.url!r}, max_tokens={self.max_tokens})"

    def _call(self, spec, system, user):
        body = {"model": spec.id, "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
                "temperature": 0, "max_tokens": self.max_tokens}
        req = urllib.request.Request(self.url, data=json.dumps(body, ensure_ascii=False).encode("utf-8"), method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("Authorization", f"Bearer {self._key}")
        out = {"text": None, "served_model": None, "provider": None, "note": None}
        try:
            with self.opener.open(req, timeout=spec.timeout) as r:
                data = r.read(MAX_RESPONSE + 1)
        except urllib.error.HTTPError as e:
            e.close()
            out["note"] = "model-unavailable"
            return out
        except (TimeoutError, socket.timeout):
            out["note"] = "timeout"
            return out
        except urllib.error.URLError as e:
            out["note"] = "timeout" if isinstance(e.reason, (TimeoutError, socket.timeout)) else "model-unavailable"
            return out
        except Exception:  # noqa: BLE001 - a backend failure is a note, never an exception
            out["note"] = "model-unavailable"
            return out
        try:
            if len(data) > MAX_RESPONSE:
                raise ValueError("too large")
            ans = json.loads(data)
            msg = ans["choices"][0]["message"]
            content = msg.get("content")
        except (ValueError, KeyError, IndexError, TypeError, AttributeError):
            out["note"] = "wrong-shape"
            return out
        if isinstance(ans.get("model"), str):
            out["served_model"] = ans["model"][:200]
        if isinstance(ans.get("provider"), str):
            out["provider"] = ans["provider"][:200]
        if content is None or (isinstance(content, str) and not content.strip()):
            out["note"] = "no-content"
        elif not isinstance(content, str):
            out["note"] = "wrong-shape"
        else:
            out["text"] = content
        return out

    def chat(self, spec, system, user):
        """{text, served_model, provider, note, ms}: note is None, timeout, model-unavailable, wrong-shape or no-content. The
        whole call, connect to last byte, is held to spec.timeout."""
        box = {}
        t0 = time.monotonic()

        def work():
            box["out"] = self._call(spec, system, user)

        th = threading.Thread(target=work, daemon=True, name=f"judge-{spec.id[:24]}")
        th.start()
        th.join(spec.timeout + 0.5)
        out = box.get("out") or {"text": None, "served_model": None, "provider": None, "note": "timeout"}
        out["ms"] = int((time.monotonic() - t0) * 1000)
        return out


class Judge:
    def __init__(self, backend, models):
        self.backend, self.models = backend, list(models)

    def __repr__(self):
        return f"Judge({self.backend!r}, models={[m.id for m in self.models]})"

    def run(self, statement, assertion, objects, count, require):
        """One judgment over objects [(bytes, media_type)]: {finding, reason, detail, vars, judgment, raw, model_runs}. `raw`
        holds each run's (spec, text, provider, served_model) for the caller to keep or discard; nothing is stored here."""
        vars_ = {"statement": statement}
        try:
            items = [js.item_from_object(d, mt) for d, mt in objects]
        except ValueError:
            detail = {"evidence_items": len(objects), "visible_chars": 0, "input_tokens_est": 0, "injection_hard": 0,
                      "injection_soft": 0, "models": count, "require": require, "models_run": 0, "agreeing": 0}
            return {"finding": None, "reason": "unreadable", "detail": detail, "vars": vars_, "model_runs": [], "raw": [],
                    "judgment": self._judgment([], [], {"count": count, "require": require, "agreeing": 0, "finding": None},
                                               [], None)}
        prep = js.prepare(statement, assertion, items)
        selected, results = [], []
        if prep["stop"] is None:
            selected = select_models(self.models, count)
            results = [None] * len(selected)
            system = js.prompt_text()

            def one(i, spec):
                results[i] = self.backend.chat(spec, system, prep["input"])

            threads = [threading.Thread(target=one, args=(i, m), daemon=True) for i, m in enumerate(selected)]
            for t in threads:
                t.start()
            for t, m in zip(threads, selected):
                t.join(m.timeout + 2)
            results = [r or {"text": None, "served_model": None, "provider": None, "note": "timeout"} for r in results]
        runs, models_rec, raw = [], [], []
        for spec, res in zip(selected, results):
            if res["note"] is None:
                r = js.judge_run(res["text"], items)
            else:
                r = js.failed_run(res["note"])
            text = res["text"]
            runs.append({"model": spec.id, "raw_output_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest() if text else None,
                         "finding": r["finding"], "quotes": r["quotes"], "note": r["note"], "rejected": r["rejected"]})
            models_rec.append({"id": spec.id, "provider": res["provider"] or spec.vendor, "version": res["served_model"]})
            raw.append((spec, text, res["provider"], res["served_model"]))
        c = js.conclude(prep, runs, count, require)
        return {"finding": c["finding"], "reason": c["reason"], "detail": c["detail"], "vars": vars_, "model_runs": selected,
                "raw": raw, "judgment": self._judgment(models_rec, runs, c["agreement"], prep["flags"], prep["input_sha256"])}

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
    backend = Backend(vals["WITNESS_JUDGE_BASE_URL"], _read_key(vals["WITNESS_JUDGE_API_KEY_FILE"]),
                      max_tokens=int(env.get("WITNESS_JUDGE_MAX_TOKENS") or 1024))
    return Judge(backend, models)


def price_from_env(env):
    """The BD3 price list, with WITNESS_PRICE_LIST_FILE (JSON, integers) overriding the defaults when set."""
    pf = (env.get("WITNESS_PRICE_LIST_FILE") or "").strip()
    if not pf:
        return price_list()
    with open(pf, encoding="utf-8") as f:
        return price_list(json.load(f))
