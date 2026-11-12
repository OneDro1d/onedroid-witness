"""A fake OpenRouter client that replays recorded answers, so the whole run is tested offline and deterministically: the raw files the
12 Nov probes saved (raw-<model>.jsonl: id, raw text or answers, provider, served_model, cost_usd, finish) are the recording. A claim
with no recorded answer gets an empty answer, as a provider that returned nothing would."""
import json
import pathlib

from onedroid_witness.openrouter import Ledger


class FakeClient:
    def __init__(self, recordings_dir, ledger=None, served_override=None, fail_models=()):
        self.ledger = ledger or Ledger(str(pathlib.Path(recordings_dir) / "ledger-test.json"), 1000.0)
        self.rec = {}
        for f in pathlib.Path(recordings_dir).glob("raw-*.jsonl"):
            slug = f.name[len("raw-"):-len(".jsonl")]
            self.rec[slug] = {json.loads(l)["id"]: json.loads(l) for l in f.read_text(encoding="utf-8").splitlines() if l.strip()}
        self.served_override = served_override or {}
        self.fail_models = set(fail_models)
        self.calls = []

    @staticmethod
    def slug(model):
        import re
        return re.sub(r"[^a-z0-9]+", "-", model.lower()).strip("-")

    def _row(self, model, state_or_text):
        s = self.slug(model)
        for cid, row in self.rec.get(s, {}).items():
            if f"claim id: {cid}\n" in state_or_text:
                return row
        return None

    def chat(self, model, system_prompt, user_text, max_tokens, providers=None):
        self.calls.append(("chat", model, max_tokens, providers))
        if model in self.fail_models:
            return {"error": "HTTP_502", "detail": "fake provider error", "latency_s": 0.1}
        row = self._row(model, user_text)
        if row is None:
            return {"text": "", "finish": "length", "provider": "Fake", "served_model": model, "cost_usd": 0.0, "prompt_tokens": 900, "completion_tokens": 400, "latency_s": 0.1}
        self.ledger.add(row.get("cost_usd") or 0)
        return {"text": row.get("raw") or "", "finish": row.get("finish") or "stop", "provider": row.get("provider") or "Fake",
                "served_model": self.served_override.get(model, row.get("served_model") or model), "cost_usd": row.get("cost_usd") or 0,
                "prompt_tokens": 900, "completion_tokens": 100, "latency_s": row.get("latency_s") or 0.1}

    def decide(self, model, state, questions, providers=None):
        self.calls.append(("decide", model, len(questions), providers))
        if model in self.fail_models:
            return {"error": "HTTP_404", "detail": "fake: not served", "latency_s": 0.1}
        row = self._row(model, state)
        if row is None or not row.get("answers"):
            return {"error": "HTTP_502", "detail": "fake: no recorded answer", "latency_s": 0.1}
        self.ledger.add(row.get("cost_usd") or 0)
        return {"answers": row["answers"], "provider": row.get("provider") or "Fake", "served_model": self.served_override.get(model, row.get("served_model") or model),
                "cost_usd": row.get("cost_usd") or 0, "prompt_tokens": 1000, "completion_tokens": 0, "latency_s": row.get("latency_s") or 0.1}
