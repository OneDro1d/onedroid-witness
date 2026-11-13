"""The HTTP surface (contract sections 4, 5, 3b.5, 3c.9), standard library only:
  POST /witness                 multipart/form-data with the parts (manifest.json, audit.jsonl, audit.jsonl.sig, allowed_signers,
                                signatures.json optional, page.txt or the audited text) and the fields models (comma-separated ids),
                                max_cost_usd, published_url (public mode); or application/json {parts: {name: text}, models, ...}.
                                Answers 202 {job_id, estimate_usd} after the request is checked and the estimate made; 4xx with the refusal.
  GET  /witness/{job_id}        the status (queued | running | done | refused | failed) with the answer's sha256 when done
  GET  /witness/{job_id}/answer.tar  the answer folder as a tar; the sha256 is in the status and in the X-Answer-SHA256 header
  GET  /models                  the models the service runs, with kind, max_tokens and the price used for the estimate
  GET  /keys                    every key the service has ever used, with valid_from and valid_to; never deletes one
  GET  /healthz                 liveness, the daily cap remaining, the checker's pin
No identity: abuse control is the daily cap, the size cap and a per-address rate limit (section 7).
"""
import email.parser
import email.policy
import json
import pathlib
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import answer as answer_mod
from . import prompts, request as request_mod
from .checkpin import CHECK_PY_SHA256
from .openrouter import RouterRefused, refuse_routers

MAX_BODY = 64 * 1024 * 1024
PARTS_ALLOWED = {"manifest.json", "audit.jsonl", "audit.jsonl.sig", "allowed_signers", "signatures.json", "page.txt", "run.json", "claims.jsonl"}
RATE_PER_MINUTE = 30


class RateLimit:
    def __init__(self, per_minute=RATE_PER_MINUTE):
        self.per_minute, self.hits, self.lock = per_minute, {}, threading.Lock()

    def allow(self, addr):
        now = time.monotonic()
        with self.lock:
            h = [t for t in self.hits.get(addr, []) if now - t < 60]
            h.append(now)
            self.hits[addr] = h
            return len(h) <= self.per_minute


def make_handler(cfg):
    """cfg: store, worker, models_cfg (list), prices, ledger, keystore, private_mode, version."""
    rate = RateLimit()

    class Handler(BaseHTTPRequestHandler):
        server_version = "onedroid-witness/" + cfg["version"]

        def log_message(self, fmt, *args):  # one line per request, no bodies, no keys
            print(f"{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} {self.address_string()} {fmt % args}", flush=True)

        def _json(self, code, obj, extra=None):
            body = json.dumps(obj, ensure_ascii=False).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if not rate.allow(self.client_address[0]):
                return self._json(429, {"error": "rate limit"})
            path = self.path.split("?")[0]
            if path == "/healthz":
                served = list(cfg.get("profiles_served", request_mod.PROFILES_SERVED))
                return self._json(200, {"ok": True, "service": "onedroid-witness", "version": cfg["version"], "mode": "private" if cfg["private_mode"] else "public",
                                        "daily_cap_remaining_usd": round(cfg["ledger"].remaining(), 4), "check_py_sha256": CHECK_PY_SHA256,
                                        "profiles_served": served,
                                        "profiles_not_served": {p: request_mod.PROFILES_NOT_SERVED_WHY.get(p, "not in this service's configuration") for p in request_mod.PROFILES if p not in served},
                                        "prompt_sha256": {p: prompts.chat_prompt_sha256(p) for p in prompts.PROFILES},
                                        "questions_sha256": {p: prompts.decision_questions_sha256(p) for p in prompts.PROFILES}})
            if path == "/models":
                out = []
                for m in cfg["models_cfg"]:
                    p = cfg["prices"].get(m["id"], {})
                    out.append({**m, "price_per_million_input_usd": round(p.get("prompt", 0) * 1e6, 4), "price_per_million_output_usd": round(p.get("completion", 0) * 1e6, 4)})
                return self._json(200, {"models": out, "note": "a router, an alias or a free tier is never a model identity and is refused"})
            if path == "/keys":
                return self._json(200, cfg["keystore"].keys_list())
            if path.startswith("/witness/"):
                rest = path[len("/witness/"):]
                if rest.endswith("/answer.tar"):
                    jid = rest[:-len("/answer.tar")]
                    st = cfg["store"].status(jid)
                    if not st or st.get("state") != "done":
                        return self._json(404, {"error": "no answer for that job id"})
                    data, sha = cfg["store"].answer_tar(jid)
                    self.send_response(200)
                    self.send_header("Content-Type", "application/x-tar")
                    self.send_header("Content-Length", str(len(data)))
                    self.send_header("X-Answer-SHA256", sha)
                    self.end_headers()
                    self.wfile.write(data)
                    return
                st = cfg["store"].status(rest)
                if not st:
                    return self._json(404, {"error": "unknown job id"})
                return self._json(200, st)
            return self._json(404, {"error": "not found"})

        def do_POST(self):
            if not rate.allow(self.client_address[0]):
                return self._json(429, {"error": "rate limit"})
            if self.path.split("?")[0] != "/witness":
                return self._json(404, {"error": "not found"})
            length = int(self.headers.get("Content-Length") or 0)
            if length <= 0 or length > MAX_BODY:
                return self._json(413, {"error": f"body must be 1 to {MAX_BODY} bytes"})
            ctype = self.headers.get("Content-Type", "")
            raw = self.rfile.read(length)
            try:
                parts, params = _parse(ctype, raw, self.headers)
            except ValueError as e:
                return self._json(400, {"error": str(e)})
            missing = [n for n in ("manifest.json", "audit.jsonl", "audit.jsonl.sig", "allowed_signers") if n not in parts]
            if missing:
                return self._json(400, {"error": f"missing parts: {', '.join(missing)}"})
            models = [m.strip() for m in (params.get("models") or "").split(",") if m.strip()]
            if not models:
                return self._json(400, {"error": "name at least one model from GET /models"})
            known = {m["id"]: m for m in cfg["models_cfg"]}
            try:
                for m in models:
                    refuse_routers(m)
                    if m not in known:
                        return self._json(400, {"error": f"{m} is not one of the service's models (GET /models)"})
            except RouterRefused as e:
                return self._json(400, {"error": str(e)})
            # the parts are checked in an incoming folder; a refused request is discarded with its bytes and gets no job id (gate D11).
            # Second re-gate P1 (the claims session, 13 Nov 2026): EVERYTHING after incoming() runs inside one try, and the finally
            # discards the folder unless the request became a job, so no path, whatever raises and wherever, can answer nothing and
            # leave bytes behind (64 MB bodies at 30 a minute against a 5 Gi volume).
            # The answer is computed first and sent LAST, after the finally has discarded the folder: a caller that reads "nothing was
            # kept" must find nothing kept.
            d = cfg["store"].incoming()
            kept = {"jid": None}
            try:
                status, body = self._accept(d, parts, params, models, known, kept)
            except Exception as e:  # P1's backstop: an exception the checks did not foresee still gets an answer; its text is not echoed
                if kept["jid"] is None:
                    status, body = 500, {"error": f"the request could not be processed ({type(e).__name__}); nothing was kept"}
                else:
                    status, body = 500, {"error": f"the job was kept but could not be queued ({type(e).__name__})", "job_id": kept["jid"], "status_url": f"/witness/{kept['jid']}"}
            finally:
                if kept["jid"] is None:
                    cfg["store"].discard(d)
            return self._json(status, body)

        def _accept(self, d, parts, params, models, known, kept):
            """Everything between incoming() and the answer: the parts written, checked (Request, the published copy), rendered for the
            estimate, the budget applied, then the folder adopted as a job. Returns (status, body); sets kept["jid"] once the folder is a
            job, so the caller's finally knows what to discard."""
            for name, data in parts.items():
                (d / name).write_bytes(data)
            try:
                req = request_mod.Request(d, private_mode=cfg["private_mode"], profiles_served=cfg.get("profiles_served", request_mod.PROFILES_SERVED))
                if not cfg["private_mode"]:
                    request_mod.check_published(req, params.get("published_url"), cfg.get("catalogue_lookup"))
            except request_mod.Refused as e:
                return 422, {"error": str(e)}
            except Exception as e:  # re-gate N3: a part that does not read answers 422 and leaves no bytes, whatever raised
                return 422, {"error": f"the parts do not read ({type(e).__name__}); nothing was kept"}
            models_cfg = [known[m] for m in models]
            render_mod = __import__("onedroid_witness.render", fromlist=["render"])
            by_url = render_mod.source_index(req.manifest)
            rendered_chars = sum(len(render_mod.render(r, req.page, by_url)) for r in req.audit)
            per_model, total = answer_mod.estimate(models_cfg, cfg["prices"], rendered_chars, len(req.audit), len(prompts.chat_prompt(req.profile)))
            try:
                max_cost = float(params["max_cost_usd"]) if params.get("max_cost_usd") not in (None, "") else None
            except ValueError:
                return 400, {"error": "max_cost_usd must be a number"}
            remaining = cfg["ledger"].remaining()
            budget = min(remaining, max_cost if max_cost is not None else float("inf"))
            # a partial run (3b.1, gate D5): the models that fit the bound in the order asked run, the rest are named as skipped with the
            # estimate; only when none fits is the request refused. answer.run applies the same rule when it runs.
            planned, skipped, running = [], [], 0.0
            for m in models:
                e_ = per_model.get(m, 0)
                if running + e_ <= budget:
                    planned.append(m)
                    running += e_
                else:
                    skipped.append({"model": m, "reason": "estimate", "detail": f"estimate {e_} would cross the bound {round(budget, 5)} with {round(running, 5)} already planned"})
            if not planned:
                return 422, {"error": "the estimate alone crosses max_cost_usd or the day's remaining cap for every model asked", "estimate_usd": per_model, "estimate_total_usd": total,
                             "max_cost_usd": max_cost, "daily_cap_remaining_usd": round(remaining, 4)}
            (d / "params.json").write_text(json.dumps({"models": models, "max_cost_usd": max_cost, "published_url": params.get("published_url")}), encoding="utf-8")
            jid = cfg["store"].adopt(d)
            kept["jid"] = jid
            cfg["store"].write_status(jid, {"job_id": jid, "state": "queued", "claims": len(req.audit), "profile": req.profile, "models": models, "models_run_planned": planned,
                                            "models_skipped": skipped, "estimate_usd": per_model, "estimate_total_usd": total, "max_cost_usd": max_cost})
            cfg["worker"].submit(jid)
            return 202, {"job_id": jid, "status_url": f"/witness/{jid}", "claims": len(req.audit), "profile": req.profile, "models_run_planned": planned,
                         "models_skipped": skipped, "estimate_usd": per_model, "estimate_total_usd": total}

    return Handler


def _parse(ctype, raw, headers):
    """multipart/form-data (files by field name) or JSON {parts: {name: text}, models, max_cost_usd, published_url}."""
    parts, params = {}, {}
    if ctype.startswith("application/json"):
        try:
            body = json.loads(raw.decode("utf-8"))
        except ValueError as e:
            raise ValueError(f"body is not JSON: {e}")
        for name, text in (body.get("parts") or {}).items():
            if name not in PARTS_ALLOWED:
                raise ValueError(f"part {name} is not accepted")
            parts[name] = text.encode("utf-8") if isinstance(text, str) else bytes(text)
        for k in ("models", "max_cost_usd", "published_url"):
            if body.get(k) is not None:
                params[k] = body[k] if not isinstance(body[k], list) else ",".join(body[k])
        return parts, params
    if ctype.startswith("multipart/form-data"):
        # the cgi module is gone from Python 3.13; the email parser reads multipart bodies with a constructed header
        msg = email.parser.BytesParser(policy=email.policy.HTTP).parsebytes(b"Content-Type: " + ctype.encode() + b"\r\nMIME-Version: 1.0\r\n\r\n" + raw)
        if not msg.is_multipart():
            raise ValueError("multipart body could not be parsed")
        for part in msg.iter_parts():
            name = part.get_param("name", header="content-disposition")
            if not name:
                continue
            data = part.get_payload(decode=True) or b""
            if part.get_filename() is not None or name in PARTS_ALLOWED:
                if name not in PARTS_ALLOWED:
                    raise ValueError(f"part {name} is not accepted")
                parts[name] = data
            else:
                params[name] = data.decode("utf-8", "replace").strip()
        return parts, params
    raise ValueError("send multipart/form-data or application/json")


def serve(cfg, host="0.0.0.0", port=8080):
    httpd = ThreadingHTTPServer((host, port), make_handler(cfg))
    print(f"onedroid-witness {cfg['version']} listening on {host}:{port} ({'private' if cfg['private_mode'] else 'public'} mode)", flush=True)
    httpd.serve_forever()
