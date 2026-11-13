"""The run and the answer (contract sections 4 and 5): for each model, every claim rendered once and asked once, the answers normalised
to witness rows, one witness file per model identity signed by the service's key for that identity, the manifest and signatures
entries, service.json (what ran, what was skipped and why, provider facts, the estimate), split.jsonl. The shape add_witness.py takes.
"""
import concurrent.futures
import datetime
import hashlib
import json
import pathlib

from . import normalise, prompts, render
from .openrouter import CapReached, refuse_routers
from .signing import now

VERDICTS = prompts.VERDICTS
TOKENS_PER_CHAR = 1 / 3.6  # the estimate's rule of thumb, recorded in service.json; the measured input was about 970 tokens per claim


def estimate(models_cfg, prices, rendered_chars, n_claims, chat_system_chars):
    """Per model: input tokens ≈ (rendered + prompt) / 3.6 per claim, output ≈ max_tokens / 4 for chat (JSON answers are short), 0 for decisions."""
    out, total = {}, 0.0
    for m in models_cfg:
        p = prices.get(m["id"]) or {"prompt": 0, "completion": 0}
        in_tokens = (rendered_chars + (chat_system_chars if m["kind"] == "chat" else 600)) * TOKENS_PER_CHAR
        out_tokens = (m.get("max_tokens", 400) / 4) * n_claims if m["kind"] == "chat" else 0
        usd = in_tokens * p["prompt"] + out_tokens * p["completion"]
        out[m["id"]] = round(usd, 5)
        total += usd
    return out, round(total, 5)


def _score(check, audit, rows, name):
    merged = [m for m in check.merge_rows(audit, rows, name) if m.get("verdict") != "UNDECIDED"]
    s = check.evidence_score(merged)
    return {k: s.get(k) for k in ("coverage_pct", "contradiction_pct", "band")}


def run(request, models_cfg, client, keystore, check, answer_dir, prices=None, in_flight=6, max_cost_usd=None, service_name="onedroid-witness",
        private_mode=False, published=None):
    """Run the model step over a checked Request. models_cfg: [{id, kind: chat|decision, max_tokens}]. Returns the service record."""
    answer = pathlib.Path(answer_dir)
    (answer / "witness").mkdir(parents=True, exist_ok=True)
    by_url = render.source_index(request.manifest)
    profile = request.profile
    system_prompt = prompts.chat_prompt(profile)
    prompt_sha = prompts.chat_prompt_sha256(profile)
    questions_sha = prompts.decision_questions_sha256(profile)
    evidence = render.evidence_index(request.manifest, request.root)  # S-1: the carried files the evidence pointers resolve from
    rendered = {r["id"]: render.render(r, request.page, by_url, evidence) for r in request.audit}
    copy_none = {r["id"]: render.all_copy_none(r, by_url) for r in request.audit}
    copy_none_idx = {r["id"]: render.copy_none_indices(r, by_url) for r in request.audit}
    unreadable_idx = {r["id"]: render.unreadable_indices(r, evidence, request.root) for r in request.audit}
    all_unreadable = {r["id"]: render.all_unreadable(r, evidence, request.root) for r in request.audit}
    prices = prices or {}
    pass_through = {r["id"]: normalise.passthrough(r) for r in request.audit}
    asked = [m["id"] for m in models_cfg]
    for m in models_cfg:
        refuse_routers(m["id"])
    est_per_model, est_total = estimate(models_cfg, prices or {}, sum(len(t) for t in rendered.values()), len(request.audit), len(system_prompt))
    # 0.1.6 (fifth re-gate H1): what the models read, recorded in service.json and in every witness header (so the witness signature covers
    # it): the request manifest's sha256 and the sha256 of every carried file, by manifest path, keys sorted ({} when nothing was carried)
    carried = {p: hashlib.sha256(b).hexdigest() for p, b in sorted(request.carried.items())}
    service = {"service": service_name, "mode": "private" if private_mode else "public", "published": published,
               "request_sha256": request.audit_sha256, "manifest_sha256": request.manifest_sha256, "carried": carried,
               "profile": profile, "claims": len(request.audit), "models_asked": asked, "models_run": [],
               "models_skipped": [], "estimate_usd": {"per_model": est_per_model, "total": est_total, "rule": "input chars / 3.6 per claim + chat output max_tokens / 4"},
               "prompt_sha256": {profile: prompt_sha}, "questions_sha256": {profile: questions_sha}, "parse_rule": "the first JSON object in the text, a code fence stripped",
               "candidate_rule_decision_models": "argmax of the yes-probabilities on the verdict's side",
               "daily_cap_remaining_usd_at_start": client.ledger.remaining(), "max_cost_usd": max_cost_usd, "per_model": {}, "started_at": now()}
    budget = min(client.ledger.remaining(), max_cost_usd if max_cost_usd is not None else float("inf"))
    running_est = 0.0
    entries_m, entries_s, signers, per_model_rows, spent = [], [], [], {}, 0.0
    primary_verdict = {}
    if request.primary:
        pf = request.root / request.primary["file"]
        if pf.is_file():
            primary_verdict = {r["id"]: r.get("verdict") for r in (json.loads(l) for l in pf.read_text(encoding="utf-8").splitlines()[1:] if l.strip())}
    for m in models_cfg:
        model, kind, max_tokens = m["id"], m["kind"], int(m.get("max_tokens", 400))
        provider_order = list(m.get("providers") or []) or None  # the configured provider order, pinned on every call when set (3b.3)
        if running_est + est_per_model.get(model, 0) > budget - spent:
            service["models_skipped"].append({"model": model, "reason": "estimate", "detail": f"estimate {est_per_model.get(model)} would cross the remaining budget {round(budget - spent, 5)}"})
            continue
        running_est += est_per_model.get(model, 0)
        started = now()
        results = {}

        def call(row):
            if pass_through[row["id"]] is not None:
                return {"passthrough": True}
            extra = {"providers": provider_order} if provider_order else {}
            try:
                if kind == "chat":
                    return client.chat(model, system_prompt, prompts.wrap_data(rendered[row["id"]]), max_tokens, **extra)
                return client.decide(model, rendered[row["id"]], prompts.decision_questions(profile, row), **extra)
            except CapReached:
                return {"error": "CAP"}
        with concurrent.futures.ThreadPoolExecutor(max_workers=in_flight) as ex:
            futs = {ex.submit(call, r): r for r in request.audit}
            for f in concurrent.futures.as_completed(futs):
                results[futs[f]["id"]] = f.result()
        rows, raw, providers, served, errors, lat, cost, pt, ct = [], [], {}, {}, {}, [], 0.0, 0, 0
        for r in request.audit:
            res = results[r["id"]]
            if res.get("passthrough"):
                body, ok = pass_through[r["id"]], True
            elif res.get("error"):
                body, ok = {"verdict": "UNDECIDED", "on": {"proofs": [], "counter": []}, "note": f"no answer from the provider ({res['error']})"}, False
                errors[res["error"]] = errors.get(res["error"], 0) + 1
            else:
                if kind == "chat":
                    body, ok = normalise.chat_answer(res.get("text"), res.get("finish"), r)
                else:
                    body, ok = normalise.decision_answer(res.get("answers"), r)
                body = normalise.apply_row_rules(body, r, copy_none[r["id"]], copy_none_idx[r["id"]], unreadable_idx[r["id"]], all_unreadable[r["id"]])
                cost += res.get("cost_usd") or 0
                pt += res.get("prompt_tokens") or 0
                ct += res.get("completion_tokens") or 0
                lat.append(res.get("latency_s") or 0)
                providers[res.get("provider")] = providers.get(res.get("provider"), 0) + 1
                served[res.get("served_model")] = served.get(res.get("served_model"), 0) + 1
            row = {"id": r["id"], "verdict": body["verdict"], "confidence": body.get("confidence"), "on": body["on"], "note": body["note"], "graded_at": now()}
            rows.append(row)
            raw.append({"id": r["id"], "ok": ok, "raw": res.get("text"), "answers": res.get("answers"), "finish": res.get("finish"), "provider": res.get("provider"),
                        "served_model": res.get("served_model"), "cost_usd": res.get("cost_usd"), "latency_s": res.get("latency_s"), "error": res.get("error"),
                        "detail": res.get("detail"), "provider_error": res.get("provider_error")})
        finished = now()
        spent += cost
        if errors.get("CAP", 0) == len(request.audit) or (len(served) == 0 and errors):
            service["models_skipped"].append({"model": model, "reason": "cap" if errors.get("CAP") else "provider error", "detail": errors})
            (answer / f"raw-{_slug(model)}.jsonl").write_text("".join(json.dumps(x, ensure_ascii=False) + "\n" for x in raw), encoding="utf-8")
            continue
        served_id = max(served, key=served.get) if served else model
        if len([s for s in served if s]) > 1:
            service["models_skipped"].append({"model": model, "reason": "router", "detail": f"the id served more than one model: {served}"})
            continue
        # the witness is named by the provider's id WITH its version (section 14, gate D9): OpenRouter's canonical_slug carries the dated
        # snapshot for chat models (openai/gpt-4.1-nano -> openai/gpt-4.1-nano-2025-04-14); decision models already serve a dated id
        versioned = (prices.get(served_id) or prices.get(model) or {}).get("canonical_slug") or served_id
        name = f"onedroid-witness-{_slug(versioned)}"
        principal, priv, signer_line, fp, ktype = keystore.key_for(versioned)
        fallback_served = sorted(p for p in providers if p and provider_order and p not in provider_order)
        header = {"witness": name, "kind": "model", "model": versioned, "method": "classify", "over": {"file": "audit.jsonl", "sha256": request.audit_sha256},
                  "manifest_sha256": request.manifest_sha256, "carried": carried,
                  "started_at": started, "finished_at": finished,
                  "note": (f"{service_name}: {'chat' if kind == 'chat' else 'decision'} model through OpenRouter; "
                           + (f"prompt sha256 {prompt_sha}; temperature 0, max_tokens {max_tokens}, response_format json_object; parse: the first JSON object in the text, a code fence stripped"
                              if kind == "chat" else f"questions sha256 {questions_sha}; the model returns typed answers with probabilities and no text, so every note is written by the service from the probabilities; a decided verdict names its best-scoring candidate")
                           + f"; served by {', '.join(f'{k} x{v}' for k, v in providers.items())}; the signature proves the service says this model answered, never that a model signed")}
        wfile = answer / "witness" / f"{name}.jsonl"
        wfile.write_text("\n".join(json.dumps(x, ensure_ascii=False) for x in [header] + rows) + "\n", encoding="utf-8")
        (answer / f"raw-{_slug(model)}.jsonl").write_text("".join(json.dumps(x, ensure_ascii=False) + "\n" for x in raw), encoding="utf-8")
        wsha = hashlib.sha256(wfile.read_bytes()).hexdigest()
        # third re-gate F2 (13 Nov 2026): the signed line is the format's prescribed line from the vendored checker (SPEC.md 3a keeps the
        # "claims-snapshot/0.4" prefix in every revision), never one re-spelt from the manifest's format, which failed K13 on every 0.5
        # and 0.6 folder
        line = check.signed_line("witness", f"witness/{name}.jsonl", wsha, over=request.audit_sha256)
        keystore.sign(priv, line, wfile.with_suffix(".jsonl.sig"))
        if signer_line not in signers:
            signers.append(signer_line)
        n_und = sum(1 for x in rows if x["verdict"] == "UNDECIDED")
        entries_m.append({"name": name, "kind": "model", "model": versioned, "method": "classify", "signer": f"{principal} <{fp}>", "file": f"witness/{name}.jsonl",
                          "sha256": wsha, "primary": False, "score": _score(check, request.audit, rows, name), "missing_claims": 0, "undecided": n_und})
        entries_s.append({"role": "witness", "file": f"witness/{name}.jsonl", "sha256": wsha, "line": line, "signer": {"name": principal, "key_id": fp, "kind": ktype},
                          "signed_at": now(), "signature": f"witness/{name}.jsonl.sig", "commit": None})
        decided = [x for x in rows if x["verdict"] not in ("UNDECIDED", "EVIDENCE AVAILABLE ON REQUEST", "WITHDRAWN")]
        agree = sum(1 for x in decided if x["verdict"] == primary_verdict.get(x["id"]))
        service["models_run"].append(model)
        service["per_model"][model] = {"kind": kind, "served": served, "model_versioned": versioned, "providers": providers, "provider_order": provider_order,
                                       "fallback_served": fallback_served, "max_tokens": max_tokens if kind == "chat" else None, "temperature": 0 if kind == "chat" else None,
                                       "calls": len(request.audit), "cost_usd": round(cost, 5), "prompt_tokens": pt, "completion_tokens": ct,
                                       "latency_s_median": sorted(lat)[len(lat) // 2] if lat else None, "errors": errors, "undecided": n_und,
                                       "verdicts": {v: sum(1 for x in rows if x["verdict"] == v) for v in VERDICTS},
                                       "agrees_with_primary": f"{agree} of {len(decided)} decided" if primary_verdict else None, "score": entries_m[-1]["score"]}
        per_model_rows[name] = {x["id"]: x for x in rows}
    (answer / "allowed_signers").write_text("\n".join(signers) + ("\n" if signers else ""), encoding="utf-8")
    (answer / "manifest-entry.json").write_text(json.dumps(entries_m, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    (answer / "signatures-entry.json").write_text(json.dumps(entries_s, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    split = []
    for r in request.audit:
        vs = {n: per_model_rows[n][r["id"]]["verdict"] for n in per_model_rows}
        base = {primary_verdict.get(r["id"])} if primary_verdict else set()
        if len(set(vs.values()) | base) > 1:
            split.append({"id": r["id"], "primary": primary_verdict.get(r["id"]), **vs,
                          "notes": {n: per_model_rows[n][r["id"]]["note"] for n in per_model_rows if per_model_rows[n][r["id"]]["verdict"] != primary_verdict.get(r["id"])}})
    (answer / "split.jsonl").write_text("".join(json.dumps(x, ensure_ascii=False) + "\n" for x in split), encoding="utf-8")
    service["finished_at"] = now()
    service["total_cost_usd"] = round(spent, 5)
    service["split_claims"] = len(split)
    # the service's own signature over service.json (section 5, gate D7): the service key's principal is onedroid-witness-service, its
    # allowed_signers line travels with the answer; the line signed is `onedroid-witness/1 service.json sha256:<hex of the bytes written>`.
    # The signature entry is recorded in the status and in service.json.sig's sidecar, not inside service.json (a file cannot carry its own hash).
    body = json.dumps(service, indent=1, ensure_ascii=False) + "\n"
    (answer / "service.json").write_text(body, encoding="utf-8")
    s_principal, s_priv, s_line, s_fp, s_ktype = keystore.key_for("service")
    s_sha = hashlib.sha256(body.encode("utf-8")).hexdigest()
    signed_line = f"onedroid-witness/1 service.json sha256:{s_sha}"
    keystore.sign(s_priv, signed_line, answer / "service.json.sig")
    if s_line not in signers:
        signers.append(s_line)
        (answer / "allowed_signers").write_text("\n".join(signers) + "\n", encoding="utf-8")
    service["signature"] = {"role": "service", "file": "service.json", "sha256": s_sha, "line": signed_line, "signature": "service.json.sig",
                            "signer": {"name": s_principal, "key_id": s_fp, "kind": s_ktype}, "signed_at": now()}
    (answer / "service-signature.json").write_text(json.dumps(service["signature"], indent=1) + "\n", encoding="utf-8")
    return service


def _slug(model):
    import re
    return re.sub(r"[^a-z0-9]+", "-", model.lower()).strip("-")
