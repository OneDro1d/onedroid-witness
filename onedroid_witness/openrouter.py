"""The OpenRouter client: the chat endpoint for chat models, the Decisions API for decision models, prices for the estimate, a spend
ledger with a daily cap (3b.1). The key is read from a file or the environment by the caller and never logged.

Provider facts the contract wants recorded (3b.3): the provider that served, the served model id and version, tokens, cost, latency,
the finish reason; and for a chat model the max_tokens it ran with. A router id is refused (3e.1).
"""
import json
import threading
import time
import urllib.error
import urllib.request

CHAT_API = "https://openrouter.ai/api/v1/chat/completions"
DECISIONS_API = "https://openrouter.ai/api/alpha/decisions"
MODELS_API = "https://openrouter.ai/api/v1/models"
RETRY_CODES = (429, 500, 502, 503, 524, 529)
REFERER = "https://onedroid.ai/evidence"
TITLE = "OneDroid witness service"


class CapReached(Exception):
    pass


class RouterRefused(ValueError):
    pass


def refuse_routers(model_id):
    """A witness file names the model that answered, never a router or an alias that resolves per request (3e.1)."""
    low = model_id.lower()
    variant = low.rsplit(":", 1)[1] if ":" in low else ""
    if low.startswith("~") or "router" in low or "/auto" in low or low.endswith("-latest") or variant in ("free", "beta", "nitro", "online", "extended", "floor", "exacto", "thinking"):
        raise RouterRefused(f"{model_id} is a router, an alias, a variant or a free tier, not a model identity")
    return model_id


def fetch_prices(opener=urllib.request.urlopen, timeout=30):
    """model id -> {"prompt": $/token, "completion": $/token, "kind": chat|decision}; both lists, since the default hides decision models."""
    out = {}
    for url, kind in ((MODELS_API, "chat"), (MODELS_API + "?output_modalities=decisions", "decision")):
        req = urllib.request.Request(url, headers={"HTTP-Referer": REFERER, "X-Title": TITLE})
        with opener(req, timeout=timeout) as r:
            data = json.load(r).get("data", [])
        for m in data:
            p = m.get("pricing") or {}
            try:
                pi, po = float(p.get("prompt") or 0), float(p.get("completion") or 0)
            except (TypeError, ValueError):
                continue
            if pi < 0:
                continue  # variable pricing (a router)
            mods = (m.get("architecture") or {}).get("output_modalities") or []
            out[m["id"]] = {"prompt": pi, "completion": po, "kind": "decision" if "decisions" in mods else kind,
                            "context_length": m.get("context_length"), "canonical_slug": m.get("canonical_slug") or m["id"]}
    return out


class Ledger:
    """Spend so far today, persisted to one JSON file so a restart keeps the day's total; the cap is the service's configuration."""

    def __init__(self, path, daily_cap_usd):
        self.path, self.cap, self.lock = path, float(daily_cap_usd), threading.Lock()

    def _load(self):
        try:
            with open(self.path, encoding="utf-8") as f:
                d = json.load(f)
        except (OSError, ValueError):
            d = {}
        day = time.strftime("%Y-%m-%d", time.gmtime())
        if d.get("day") != day:
            d = {"day": day, "spent_usd": 0.0, "calls": 0}
        return d

    def spent(self):
        with self.lock:
            return self._load()["spent_usd"]

    def remaining(self):
        return max(0.0, self.cap - self.spent())

    def add(self, cost):
        with self.lock:
            d = self._load()
            d["spent_usd"] = round(d["spent_usd"] + float(cost or 0), 8)
            d["calls"] += 1
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(d, f)
            import os
            os.replace(tmp, self.path)
            return d["spent_usd"]


class Client:
    def __init__(self, key, ledger, opener=urllib.request.urlopen, timeout=120):
        self._key, self.ledger, self._open, self.timeout = key, ledger, opener, timeout

    def _post(self, url, body):
        req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST")
        req.add_unredirected_header("Authorization", "Bearer " + self._key)
        req.add_header("Content-Type", "application/json")
        req.add_header("HTTP-Referer", REFERER)
        req.add_header("X-Title", TITLE)
        t0 = time.monotonic()
        for attempt in range(3):
            if self.ledger.remaining() <= 0:
                raise CapReached("the daily cap is reached")
            try:
                with self._open(req, timeout=self.timeout) as r:
                    ans = json.load(r)
                return ans, round(time.monotonic() - t0, 2), None
            except urllib.error.HTTPError as e:
                detail = e.read(2000).decode("utf-8", "replace")
                if e.code in RETRY_CODES and attempt < 2:
                    time.sleep(2 * (attempt + 1))
                    continue
                return None, round(time.monotonic() - t0, 2), {"error": f"HTTP_{e.code}", "detail": detail[:600]}
            except (urllib.error.URLError, TimeoutError, OSError) as e:
                if attempt < 2:
                    time.sleep(2 * (attempt + 1))
                    continue
                return None, round(time.monotonic() - t0, 2), {"error": "CONNECTION", "detail": str(e)[:300]}
        return None, round(time.monotonic() - t0, 2), {"error": "RETRIES"}

    def _account(self, ans):
        usage = (ans or {}).get("usage") or {}
        cost = float(usage.get("cost") or 0)
        self.ledger.add(cost)
        return usage, cost

    def chat(self, model, system_prompt, user_text, max_tokens, providers=None):
        body = {"model": model, "temperature": 0, "max_tokens": int(max_tokens), "response_format": {"type": "json_object"},
                "messages": [{"role": "system", "content": system_prompt}, {"role": "user", "content": user_text}]}
        if providers:
            body["provider"] = {"order": list(providers), "allow_fallbacks": True}  # the pinned order (3b.3); a fallback that served is named in service.json
        ans, latency, err = self._post(CHAT_API, body)
        if err:
            return {"error": err["error"], "detail": err.get("detail"), "latency_s": latency}
        usage, cost = self._account(ans)
        choice = (ans.get("choices") or [{}])[0]
        text = ((choice.get("message") or {}).get("content")) or ""
        return {"text": text, "finish": choice.get("finish_reason"), "provider": ans.get("provider"), "served_model": ans.get("model"),
                "cost_usd": cost, "prompt_tokens": usage.get("prompt_tokens"), "completion_tokens": usage.get("completion_tokens"),
                "latency_s": latency, "provider_error": choice.get("error")}

    def decide(self, model, state, questions, providers=None):
        body = {"model": model, "state": state, "questions": questions}
        if providers:
            body["provider"] = {"order": list(providers), "allow_fallbacks": True}
        ans, latency, err = self._post(DECISIONS_API, body)
        if err:
            return {"error": err["error"], "detail": err.get("detail"), "latency_s": latency}
        usage, cost = self._account(ans)
        return {"answers": ans.get("answers"), "provider": ans.get("provider"), "served_model": ans.get("model"), "cost_usd": cost,
                "prompt_tokens": usage.get("input_tokens"), "completion_tokens": usage.get("output_tokens"), "latency_s": latency,
                "provider_error": ans.get("error")}
