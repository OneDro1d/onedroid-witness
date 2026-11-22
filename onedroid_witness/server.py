"""The HTTP surface (contract sections 4, 5, 3b.5, 3c.9), standard library only:
  POST /witness                 multipart/form-data with the parts (manifest.json, audit.jsonl, audit.jsonl.sig, allowed_signers,
                                signatures.json optional, page.txt or the audited text) and the fields models (comma-separated ids),
                                max_cost_usd, published_url (public mode); or application/json {parts: {name: text}, models, ...}.
                                A published_url on a gist needs the gist's REVISION URL (raw/<revision>/audit.jsonl): a raw gist URL names
                                one blob under any file name, so manifest.json beside it would answer the audit bytes (0.1.7).
                                Answers 202 {job_id, estimate_usd} after the request is checked and the estimate made; 4xx with the refusal.
  GET  /witness/{job_id}        the status (queued | running | done | refused | failed) with the answer's sha256 when done
  GET  /witness/{job_id}/answer.tar  the answer folder as a tar; the sha256 is in the status and in the X-Answer-SHA256 header
  GET  /models                  the models the service runs, with kind, max_tokens and the price used for the estimate; and under
                                not_served the models the configuration names as NOT served, with the reason (0.1.7, models_not_served)
  GET  /keys                    every key the service has ever used, with valid_from and valid_to; never deletes one
  GET  /healthz                 liveness, the daily cap remaining, the checker's pin
No identity: abuse control is the daily cap, the size cap and a per-address rate limit (section 7).
"""
import email.parser
import email.policy
import json
import math
import pathlib
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import answer as answer_mod
from . import prompts, render, request as request_mod, respsign
from .respsign import KeyServiceUnavailable
from .checkpin import CHECK_PY_SHA256
from .openrouter import RouterRefused, refuse_routers

MAX_BODY = 64 * 1024 * 1024
PARTS_ALLOWED = {"manifest.json", "audit.jsonl", "audit.jsonl.sig", "allowed_signers", "signatures.json", "page.txt", "run.json", "claims.jsonl"}
# plus, since S-1, any part named `sources/<...>` or `sessions/<...>` (request.is_carried_part): the files the manifest lists, hash-checked
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
    """cfg: store, worker, models_cfg (list), prices, ledger, keystore, private_mode, version; optional profiles_served, models_not_served
    ({model id: reason}, 0.1.7), catalogue_lookup, fetch (tests only)."""
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
                                        "models_not_served": dict(cfg.get("models_not_served") or {}),
                                        "vocabulary_rule": render.VOCABULARY_RULE_TEXT,  # 0.1.9 (V2)
                                        "prompt_sha256": {p: prompts.chat_prompt_sha256(p) for p in prompts.PROFILES},
                                        "questions_sha256": {p: prompts.decision_questions_sha256(p) for p in prompts.PROFILES}})
            if path == "/models":
                out = []
                for m in cfg["models_cfg"]:
                    p = cfg["prices"].get(m["id"], {})
                    out.append({**m, "price_per_million_input_usd": round(p.get("prompt", 0) * 1e6, 4), "price_per_million_output_usd": round(p.get("completion", 0) * 1e6, 4)})
                return self._json(200, {"models": out, "not_served": dict(cfg.get("models_not_served") or {}),
                                        "note": "a router, an alias or a free tier is never a model identity and is refused"})
            if path == "/keys":
                doc = dict(cfg["keystore"].keys_list())
                if cfg.get("responder") is not None:  # SIG3 R2: the model keys as before, plus the key the service signs receipts and results with
                    doc["service"] = cfg["responder"].keys_doc()
                return self._json(200, doc)
            if path.startswith("/witness/"):
                rest = path[len("/witness/"):]
                if rest.endswith("/result"):  # SIG3 R5
                    if cfg.get("responder") is None:
                        return self._json(404, {"error": "not found"})
                    code, body = cfg["responder"].result_response(rest[:-len("/result")])
                    return self._json(code, body)
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
            # third re-gate F3 (13 Nov 2026): the length read and the body parse answer 400 by name whatever they raise; before, a
            # Content-Length "abc", a JSON array body, a list for parts, an object for a part or a list of numbers for models closed the
            # connection with no answer (nothing was kept: no folder exists yet)
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                return self._json(400, {"error": "Content-Length is not a number"})
            if length <= 0 or length > MAX_BODY:
                return self._json(413, {"error": f"body must be 1 to {MAX_BODY} bytes"})
            ctype = self.headers.get("Content-Type", "")
            raw = self.rfile.read(length)
            # SIG3 R3: the caller's signature is checked over the exact body bytes before anything is parsed or written. 0.1.21 (R4c-5): the
            # same headers verify against the store key list (WITNESS_KEY_SOURCE=store) or, failing that, the caller key list
            # (WITNESS_CALLER_KEYS_URL, the audit service's keys, respsign.CallerKeys); a signed request neither list verifies is 401
            account = None
            verifiers = [v for v in (cfg.get("verifier"), cfg.get("caller_verifier")) if v is not None]
            if verifiers:
                signed = any(self.headers.get(h) for h in ("X-Store-Key", "X-Store-Time", "X-Store-Signature"))
                if signed or cfg.get("require_key"):
                    unavailable = False
                    for verifier in verifiers:
                        try:
                            account = verifier.verify_request("POST", "/witness", raw, self.headers)
                        except KeyServiceUnavailable:
                            unavailable = True
                            continue
                        if account is not None:
                            break
                    if account is None and unavailable:
                        return self._json(503, {"error": "the key service is not available; try again shortly"})
                    if account is None:
                        return self._json(401, {"error": "a valid signed request is required (X-Store-Key, X-Store-Time, X-Store-Signature)"})
                    if account.get("key_source") != respsign.CALLER_KEY_SOURCE and respsign.SCOPE_WITNESS not in account["scopes"]:
                        return self._json(403, {"error": "this key does not carry the witness scope"})
            try:
                parts, params = _parse(ctype, raw, self.headers)
            except ValueError as e:
                return self._json(400, {"error": str(e)})
            except Exception as e:
                return self._json(400, {"error": f"the body does not parse ({type(e).__name__}); nothing was kept"})
            missing = [n for n in ("manifest.json", "audit.jsonl", "audit.jsonl.sig", "allowed_signers") if n not in parts]
            if missing:
                return self._json(400, {"error": f"missing parts: {', '.join(missing)}"})
            models = [m.strip() for m in (params.get("models") or "").split(",") if m.strip()]
            if not models:
                return self._json(400, {"error": "name at least one model from GET /models"})
            known = {m["id"]: m for m in cfg["models_cfg"]}
            not_served = cfg.get("models_not_served") or {}
            try:
                for m in models:
                    refuse_routers(m)
                    if m in not_served:  # 0.1.7 (M1): a model the configuration names as not served is refused by name with the reason, before any job; this refusal wins over `models`
                        return self._json(400, {"error": f"{m} is not served by this service: {not_served[m]}"})
                    if m not in known:
                        return self._json(400, {"error": f"{m} is not one of the service's models (GET /models)"})
            except RouterRefused as e:
                return self._json(400, {"error": str(e)})
            if not any(known[m].get("kind") == "decision" for m in models):
                # 0.1.8 (seventh re-gate H2, A1): a chat model's EVIDENCED stands only with a decision model's agreement on the row, so a
                # request names at least one decision model; refused before any job, nothing is kept
                return self._json(400, {"error": "name at least one decision model (kind decision on GET /models): since 0.1.8 a chat model's EVIDENCED stands only with a decision model's agreement on the row"})
            # the parts are checked in an incoming folder; a refused request is discarded with its bytes and gets no job id (gate D11).
            # Second re-gate P1 (the claims session, 13 Nov 2026): EVERYTHING after incoming() runs inside one try, and the finally
            # discards the folder unless the request became a job, so no path, whatever raises and wherever, can answer nothing and
            # leave bytes behind (64 MB bodies at 30 a minute against a 5 Gi volume).
            # The answer is computed first and sent LAST, after the finally has discarded the folder: a caller that reads "nothing was
            # kept" must find nothing kept.
            d = cfg["store"].incoming()
            kept = {"jid": None}
            try:
                status, body = self._accept(d, parts, params, models, known, kept, raw, account)
            except Exception as e:  # P1's backstop: an exception the checks did not foresee still gets an answer; its text is not echoed
                if kept["jid"] is None:
                    status, body = 500, {"error": f"the request could not be processed ({type(e).__name__}); nothing was kept"}
                else:
                    status, body = 500, {"error": f"the job was kept but could not be queued ({type(e).__name__})", "job_id": kept["jid"], "status_url": f"/witness/{kept['jid']}"}
            finally:
                if kept["jid"] is None:
                    cfg["store"].discard(d)
            return self._json(status, body)

        def _accept(self, d, parts, params, models, known, kept, raw=b"", account=None):
            """Everything between incoming() and the answer: the parts written, checked (Request, the published copy), rendered for the
            estimate, the budget applied, then the folder adopted as a job. Returns (status, body); sets kept["jid"] once the folder is a
            job, so the caller's finally knows what to discard."""
            for name, data in parts.items():  # a carried part's name is a checked relative path under sources/ or sessions/ (S-1, _parse)
                (d / name).parent.mkdir(parents=True, exist_ok=True)
                (d / name).write_bytes(data)
            unpublished_caller = None
            try:
                req = request_mod.Request(d, private_mode=cfg["private_mode"], profiles_served=cfg.get("profiles_served", request_mod.PROFILES_SERVED))
                if not cfg["private_mode"]:
                    if req.is_document and _unpublished(req, params, cfg.get("catalogue_lookup")):
                        # 0.1.21 (R4c-5): an unpublished document part (no published_url, no catalogue record) comes only from a caller whose
                        # signature verified against the caller key list (the audit service's keys); else it is refused by name, nothing kept
                        if cfg.get("caller_verifier") is None:
                            return 422, {"error": UNPUBLISHED_NO_CALLER_KEYS}
                        if account is None or account.get("key_source") != respsign.CALLER_KEY_SOURCE:
                            return 422, {"error": UNPUBLISHED_NOT_VERIFIED}
                        unpublished_caller = respsign.unpublished_caller(account)
                    else:
                        # 0.1.6 (H1): the manifest is bound to the published snapshot here too; `fetch` is injectable for tests only (the
                        # production configuration has no `fetch` key). The worker re-runs the same check before the models run.
                        request_mod.check_published(req, params.get("published_url"), cfg.get("catalogue_lookup"), fetch=cfg.get("fetch", request_mod.fetch_published))
            except request_mod.Refused as e:
                return 422, {"error": str(e)}
            except Exception as e:  # re-gate N3: a part that does not read answers 422 and leaves no bytes, whatever raised
                return 422, {"error": f"the parts do not read ({type(e).__name__}); nothing was kept"}
            models_cfg = [known[m] for m in models]
            # the estimate (0.1.21, R4c-7: answer.estimate_request; for a document only the claims sent to the models count)
            per_model, total = answer_mod.estimate_request(req, models_cfg, cfg["prices"])
            try:
                max_cost = float(params["max_cost_usd"]) if params.get("max_cost_usd") not in (None, "") else None
            except (ValueError, TypeError):
                return 400, {"error": "max_cost_usd must be a number"}
            if max_cost is not None and not math.isfinite(max_cost):
                # fourth re-gate note (13 Nov 2026): "nan" ran with no caller limit and NaN landed in the status
                return 400, {"error": "max_cost_usd must be a finite number"}
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
            job_params = {"models": models, "max_cost_usd": max_cost, "published_url": params.get("published_url")}
            if unpublished_caller is not None:  # R4c-5: the worker takes the unpublished document part on this record, written by the server alone
                job_params["unpublished_caller"] = unpublished_caller
            (d / "params.json").write_text(json.dumps(job_params), encoding="utf-8")
            jid = cfg["store"].adopt(d)
            kept["jid"] = jid
            cfg["store"].write_status(jid, {"job_id": jid, "state": "queued", "claims": len(req.audit), "profile": req.profile, "models": models, "models_run_planned": planned,
                                            "models_skipped": skipped, "estimate_usd": per_model, "estimate_total_usd": total, "max_cost_usd": max_cost})
            body = {"job_id": jid, "status_url": f"/witness/{jid}", "claims": len(req.audit), "profile": req.profile, "models_run_planned": planned,
                    "models_skipped": skipped, "estimate_usd": per_model, "estimate_total_usd": total}
            if cfg.get("responder") is not None:  # SIG3 R4: the signed receipt exists before the worker can see the job
                body.update(cfg["responder"].issue_receipt(jid, raw, account))
            cfg["worker"].submit(jid)
            return 202, body

    return Handler


UNPUBLISHED_NO_CALLER_KEYS = ("an unpublished document part (no published_url, no catalogue record) is accepted only from a verified caller, and "
                              "this service has no caller key list (WITNESS_CALLER_KEYS_URL is not set): name the published_url of its audit.jsonl; nothing was kept")
UNPUBLISHED_NOT_VERIFIED = ("an unpublished document part (no published_url, no catalogue record) is accepted only with a caller signature "
                            "(X-Store-Key, X-Store-Time, X-Store-Signature over onedroid-req/1 onedroid-witness POST /witness) that verifies against the "
                            "caller key list at WITNESS_CALLER_KEYS_URL; this request carries none that does: sign it with the audit service's key or "
                            "name the published_url of its audit.jsonl; nothing was kept")


def _unpublished(req, params, catalogue_lookup):
    """R4c-5: a request names no published copy: no published_url and no catalogue record for its audit.jsonl."""
    if params.get("published_url"):
        return False
    return not (catalogue_lookup is not None and catalogue_lookup(req.audit_sha256))


def _no_constant(name):
    raise ValueError(f"{name} is not a JSON number")


SOURCES_SIG_REFUSAL = "part manifest.sources.sig is not accepted: the sources signature travels in signatures.json; leave the file out of the request"


def _check_part_name(name, pending=None):
    """A part name the request takes: one of PARTS_ALLOWED or a carried path (request.is_carried_part). 0.1.10 (the ninth re-gate's S15): a
    sources-signed publisher's `manifest.sources.sig` is refused by name with the reason (its signatures.json entry is what travels); every
    other unknown name keeps the old refusal. 0.1.21 (R4c): with `pending` (a list), an unknown name is kept there instead, for
    _check_pending: a document's pages are named by its manifest (pages[].file), which is only read once every part is in."""
    if name == "manifest.sources.sig":
        raise ValueError(SOURCES_SIG_REFUSAL)
    if name not in PARTS_ALLOWED and not request_mod.is_carried_part(name):
        if pending is None:
            raise ValueError(f"part {name} is not accepted")
        pending.append(name)


def _check_pending(pending, parts):
    """0.1.21 (R4c): the parts whose name is none of the fixed or carried names are accepted only as the pages a document manifest names
    (request.document_page_names: grading.profile document, pages[].file, never a fixed part or a job file); the first other one is refused
    by the old line, as before."""
    if not pending:
        return
    try:
        manifest = json.loads(parts.get("manifest.json", b"").decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        manifest = None
    pages = request_mod.document_page_names(manifest)
    for name in pending:
        if name not in pages:
            raise ValueError(f"part {name} is not accepted")


def _parse(ctype, raw, headers):
    """multipart/form-data (files by field name) or JSON {parts: {name: text}, models, max_cost_usd, published_url}."""
    parts, params, pending = {}, {}, []
    if ctype.startswith("application/json"):
        try:
            body = json.loads(raw.decode("utf-8"), parse_constant=_no_constant)
        except ValueError as e:
            raise ValueError(f"body is not JSON: {e}")
        if not isinstance(body, dict):
            raise ValueError("the JSON body is not an object")
        if body.get("parts") is not None and not isinstance(body["parts"], dict):
            raise ValueError("parts is not an object of name to text")
        for name, text in (body.get("parts") or {}).items():
            _check_part_name(name, pending)
            if isinstance(text, str):
                parts[name] = text.encode("utf-8")
            elif isinstance(text, list) and all(isinstance(b, int) and 0 <= b < 256 for b in text):
                parts[name] = bytes(text)
            else:
                raise ValueError(f"part {name} is neither a string nor a list of bytes")
        for k in ("models", "max_cost_usd", "published_url"):
            v = body.get(k)
            if v is None:
                continue
            if isinstance(v, list):
                if not all(isinstance(x, str) for x in v):
                    raise ValueError(f"{k} is a list holding something that is not a string")
                params[k] = ",".join(v)
            elif isinstance(v, str):
                params[k] = v
            elif k == "max_cost_usd" and isinstance(v, (int, float)) and not isinstance(v, bool):
                params[k] = v
            else:
                # fourth re-gate G1 (13 Nov 2026): a number for models reached do_POST's split and closed the connection with no answer
                raise ValueError(f"{k} is neither a string nor a list of strings")
        _check_pending(pending, parts)
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
                # S-1, D1: beside the fixed parts, a file part named by a normalised relative path under sources/ or sessions/ is a carried
                # file (checked against the manifest in Request); any other unknown name is refused as before (manifest.sources.sig by name, 0.1.10)
                _check_part_name(name, pending)
                parts[name] = data
            else:
                params[name] = data.decode("utf-8", "replace").strip()
        _check_pending(pending, parts)
        return parts, params
    raise ValueError("send multipart/form-data or application/json")


def serve(cfg, host="0.0.0.0", port=8080):
    httpd = ThreadingHTTPServer((host, port), make_handler(cfg))
    print(f"onedroid-witness {cfg['version']} listening on {host}:{port} ({'private' if cfg['private_mode'] else 'public'} mode)", flush=True)
    httpd.serve_forever()
