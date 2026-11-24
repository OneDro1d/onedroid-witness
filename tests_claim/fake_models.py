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
    return lambda body: ("status", code, body)


def raw(body_bytes):
    return lambda body: ("raw", body_bytes)


class FakeModels:
    def __init__(self, api_key="fake-model-key-0123456789"):
        self.api_key = api_key
        self.behaviours = {}
        self.requests = []
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
                if self.path != "/v1/chat/completions":
                    return self._send(404, b'{"error": "no route"}')
                if self.headers.get("Authorization") != f"Bearer {fake.api_key}":
                    return self._send(401, b'{"error": "bad key"}')
                model = (body or {}).get("model")
                beh = fake.behaviours.get(model)
                if beh is None:
                    return self._send(404, json.dumps({"error": f"no model {model}"}).encode())
                out = beh(body)
                if out[0] == "sleep":
                    time.sleep(out[1])
                    out = ("content", out[2])
                if out[0] == "content":
                    resp = {"id": "chatcmpl-fake", "object": "chat.completion", "created": 1795600000,
                            "model": f"{model}-2026-11-01", "provider": "FakeProvider",
                            "choices": [{"index": 0, "message": {"role": "assistant", "content": out[1]},
                                         "finish_reason": "stop"}],
                            "usage": {"prompt_tokens": 100, "completion_tokens": 20, "total_tokens": 120}}
                    return self._send(200, json.dumps(resp).encode())
                if out[0] == "status":
                    return self._send(out[1], out[2])
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

    def close(self):
        self.server.shutdown()
        self.server.server_close()
