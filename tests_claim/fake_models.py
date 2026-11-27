"""A local fake OpenAI-compatible model server for the judge tests (B6). No test ever reaches a model provider: every judge
test points the witness at this server on 127.0.0.1.

    srv = FakeModels()                       # POST /v1/chat/completions on 127.0.0.1:<port>
    srv.script("acme/judge-1", answer("judged-supports", [quote(0, text, "phrase")]))
    srv.base_url                             # http://127.0.0.1:<port>/v1
    srv.requests                             # every request body received, parsed, with its Authorization header

A behaviour is a callable(request_body) -> one of
    ("content", text)                        200 with the OpenAI chat.completion shape and `text` as the message content
    ("sleep", seconds, text)                 the same, after sleeping
    ("status", code, body_bytes)             any status with any body
    ("raw", body_bytes)                      200 with a body that is not the chat.completion shape
    ("json", obj)                            200 with obj as the whole JSON body

Own key: `accepted_keys` are more Bearer keys the fake serves; `key_answers[key] = (status, body)` refuses a key.

Decision models (DESIGN M-20261127-WITNESS-MODELS WM-2): POST /alpha/decisions on the same server, the shape of OpenRouter's
Decisions API as trilix's decision_probe.py called it (request {model, state, questions}; answer {id, model, provider,
answers: {<key>: {type, choice, probabilities, confidence}}, usage: {input_tokens, output_tokens, cost}}).
    srv.script("acme/decider-1", decision({"supports": 0.9, "contradicts": 0.05, "silent": 0.05}, confidence=0.88))
    srv.decision_requests()

The OpenRouter model catalogue (WM-4): GET /v1/models answers {"data": srv.catalogue}; `catalogue_entry` builds one entry in
OpenRouter's shape (pricing in US$ per token as strings, architecture.output_modalities). `srv.costs[model]` is the US$ the
fake reports as usage.cost for that model (chat and decisions); absent, usage carries no cost.
"""
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from claim_witness.methods import canon


def answer(finding, quotes=(), fence=False, prefix="", extra=None):
    """A model answer as text: {"finding", "quotes"}; optionally in a ```json fence or after some prose."""
    obj = {"finding": finding, "quotes": list(quotes)}
    obj.update(extra or {})
    text = json.dumps(obj, ensure_ascii=False)
    if fence:
        text = "```json\n" + text + "\n```"
    return lambda body: ("content", prefix + text)


def quote(source, visible, phrase, with_text=True):
    """A quote of `phrase` at its real offsets in `visible` (the item's canon/1 text, computed by the test, not by the witness)."""
    i = visible.find(phrase)
    assert i >= 0, f"{phrase!r} is not in the visible text"
    q = {"source": source, "start": i, "end": i + len(phrase)}
    if with_text:
        q["text"] = phrase
    return q


def visible_of(data, media_type="text/plain"):
    return canon.canon1(data, media_type, layer="response")


def content(text):
    return lambda body: ("content", text)


def sleep_then(seconds, text):
    return lambda body: ("sleep", seconds, text)


def status(code, body=b'{"error": {"message": "upstream failed"}}'):
    return lambda request_body: ("status", code, body)


def raw(body_bytes):
    return lambda body: ("raw", body_bytes)


def completion(obj):
    """200 with exactly `obj` as the JSON body (a chat.completion whose fields the test chooses)."""
    return lambda body: ("json", obj)


def decision(probabilities, confidence=None, choice=None, served=None, provider="FakeDecider", key="verdict"):
    """A Decisions API answer to the choice question `key`: `choice` defaults to the argmax of `probabilities`, `served` is the
    dated model id the answer names (default <model>-20261014)."""
    def beh(body):
        ch = choice if choice is not None else max(probabilities, key=probabilities.get)
        ans = {"type": "choice", "choice": ch, "probabilities": dict(probabilities)}
        if confidence is not None:
            ans["confidence"] = confidence
        return ("decision", {key: ans}, served, provider)
    return beh


def catalogue_entry(model_id, prompt="0.0000001", completion="0.0000004", decisions=False, request=None, name=None):
    """One /api/v1/models entry in OpenRouter's shape (prices are US$ per token, as strings)."""
    pricing = {"prompt": prompt, "completion": completion}
    if request is not None:
        pricing["request"] = request
    return {"id": model_id, "name": name or model_id, "context_length": 131072, "pricing": pricing,
            "architecture": {"input_modalities": ["text"], "output_modalities": ["decisions"] if decisions else ["text"]}}


class FakeModels:
    def __init__(self, api_key="fake-model-key-0123456789"):
        self.api_key = api_key
        # own key (bring your own OpenRouter key): more keys the fake accepts, and keys it refuses with a status and body
        self.accepted_keys, self.key_answers = set(), {}
        self.behaviours = {}
        self.requests = []
        self.costs = {}  # model id -> the US$ the fake reports as usage.cost
        self.catalogue = []  # GET /v1/models answers {"data": catalogue}
        self.catalogue_status = 200
        self.lock = threading.Lock()
        fake = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def _send(self, code, data, ctype="application/json"):
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                try:
                    self.wfile.write(data)
                except (BrokenPipeError, ConnectionResetError):
                    pass

            def do_GET(self):
                with fake.lock:
                    fake.requests.append({"path": self.path, "authorization": self.headers.get("Authorization"),
                                          "headers": dict(self.headers), "raw": b"", "body": None, "method": "GET"})
                if self.path != "/v1/models":
                    return self._send(404, b'{"error": "no route"}')
                if fake.catalogue_status != 200:
                    return self._send(fake.catalogue_status, b'{"error": "catalogue down"}')
                return self._send(200, json.dumps({"data": fake.catalogue}).encode())

            def do_POST(self):
                n = int(self.headers.get("Content-Length") or 0)
                raw_body = self.rfile.read(n)
                try:
                    body = json.loads(raw_body)
                except ValueError:
                    body = None
                with fake.lock:
                    fake.requests.append({"path": self.path, "authorization": self.headers.get("Authorization"),
                                          "headers": dict(self.headers), "raw": raw_body, "body": body})
                if self.path not in ("/v1/chat/completions", "/alpha/decisions"):
                    return self._send(404, b'{"error": "no route"}')
                auth = self.headers.get("Authorization") or ""
                given = auth[len("Bearer "):] if auth.startswith("Bearer ") else None
                if given in fake.key_answers:
                    code, body_bytes = fake.key_answers[given]
                    return self._send(code, body_bytes)
                if given != fake.api_key and given not in fake.accepted_keys:
                    return self._send(401, b'{"error": "bad key"}')
                model = (body or {}).get("model")
                beh = fake.behaviours.get(model)
                if beh is None:
                    return self._send(404, json.dumps({"error": f"no model {model}"}).encode())
                out = beh(body)
                if out[0] == "sleep":
                    time.sleep(out[1])
                    out = ("content", out[2]) if len(out) == 3 else out[3]
                cost = fake.costs.get(model)
                if out[0] == "decision":
                    if self.path != "/alpha/decisions":
                        return self._send(400, b'{"error": "a decision model answers on the Decisions API only"}')
                    usage = {"input_tokens": 300, "output_tokens": 1}
                    if cost is not None:
                        usage["cost"] = cost
                    resp = {"id": "dec-fake", "model": out[2] or f"{model}-20261014", "provider": out[3], "answers": out[1],
                            "usage": usage}
                    return self._send(200, json.dumps(resp).encode())
                if out[0] in ("content", "json", "raw") and self.path == "/alpha/decisions":
                    return self._send(400, b'{"error": "not a decision model"}')
                if out[0] == "content":
                    usage = {"prompt_tokens": 100, "completion_tokens": 20, "total_tokens": 120}
                    if cost is not None:
                        usage["cost"] = cost
                    resp = {"id": "chatcmpl-fake", "object": "chat.completion", "created": 1795600000,
                            "model": f"{model}-2026-11-01", "provider": "FakeProvider",
                            "choices": [{"index": 0, "message": {"role": "assistant", "content": out[1]},
                                         "finish_reason": "stop"}],
                            "usage": usage}
                    return self._send(200, json.dumps(resp).encode())
                if out[0] == "status":
                    return self._send(out[1], out[2])
                if out[0] == "json":  # a whole chat.completion object of the test's own making
                    return self._send(200, json.dumps(out[1]).encode())
                return self._send(200, out[1], "text/plain")

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def base_url(self):
        return f"http://127.0.0.1:{self.port}/v1"

    def script(self, model, behaviour):
        self.behaviours[model] = behaviour

    def chat_requests(self):
        with self.lock:
            return [r for r in self.requests if r["path"] == "/v1/chat/completions"]

    def decision_requests(self):
        with self.lock:
            return [r for r in self.requests if r["path"] == "/alpha/decisions"]

    def model_requests(self):
        """Every request that asked a model, chat or decision (the catalogue GET is not one)."""
        with self.lock:
            return [r for r in self.requests if r["path"] in ("/v1/chat/completions", "/alpha/decisions")]

    def catalogue_requests(self):
        with self.lock:
            return [r for r in self.requests if r["path"] == "/v1/models"]

    @property
    def decisions_url(self):
        return f"http://127.0.0.1:{self.port}/alpha/decisions"

    def close(self):
        self.server.shutdown()
        self.server.server_close()
