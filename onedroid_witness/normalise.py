"""From a model's answer to a witness row body (contract 3.3, 3d.1, 3d.3, 3e.3, 3e.4). Every failure is UNDECIDED with a note that
names it; nothing is retried with another prompt; nothing is normalised from a near-miss.

Notes used (the contract's words):
  model answer not parseable                       the text holds no JSON object
  no content returned (finish: <reason>)           empty content (a reasoning budget spent, a provider error)
  the model's verdict word is not in the vocabulary: <word>
  the model's answer shape is not the shape: <what>
  the model named a candidate index that does not exist (...)
  the model answered EVIDENCED and named no proof / CONTRADICTED and named no counter
  the candidates were fetched and not saved        NO EVIDENCE PUBLISHED on an all copy-none row
"""
import json
import re

from .prompts import MAX_CANDIDATES_ASKED, NOUL_HIGH_CONFIDENCE, VERDICTS, WORD_OF

NOT_PARSEABLE = "model answer not parseable"
UND = {"proofs": [], "counter": []}


def _undecided(note):
    return {"verdict": "UNDECIDED", "on": dict(UND), "note": note}, False


def _within(indices, n):
    return all(isinstance(i, int) and not isinstance(i, bool) and 0 <= i < n for i in indices)


def _is_evidence_row(row):
    return isinstance(row.get("evidence"), list) and not row.get("proofs") and not row.get("counter")


def _sides(row):
    """(n FOR, n AGAINST) a model may index: the proofs and counter lists, or, for a row with one `evidence` list (agent-work and test-run,
    SPEC 4b), the evidence list on BOTH sides, as check.py 880 counts them."""
    if _is_evidence_row(row):
        return len(row["evidence"]), len(row["evidence"])
    return len(row.get("proofs") or []), len(row.get("counter") or [])


def chat_answer(text, finish, row):
    """A chat model's text to a row body. Parse rule (3d.1): the first JSON object in the text, a code fence around it ignored."""
    if not text or not text.strip():
        return _undecided(f"no content returned (finish: {finish or 'unknown'})")
    m = re.search(r"\{.*\}", text, re.S)
    try:
        a = json.loads(m.group(0) if m else text)
    except (ValueError, TypeError):
        return _undecided(NOT_PARSEABLE)
    if not isinstance(a, dict):
        return _undecided(NOT_PARSEABLE)
    v = a.get("verdict")
    if v not in VERDICTS:
        return _undecided(f"the model's verdict word is not in the vocabulary: {str(v)[:40]}")
    on = a.get("on")
    if on is None:
        on = {}
    if not isinstance(on, dict):
        return _undecided("the model's answer shape is not the shape: on is not an object")
    unknown_keys = sorted(set(on) - {"proofs", "counter"})
    if unknown_keys:
        return _undecided(f"the model's answer shape is not the shape: {', '.join(unknown_keys)}")
    p, c = on.get("proofs") or [], on.get("counter") or []
    if not isinstance(p, list) or not isinstance(c, list):
        return _undecided("the model's answer shape is not the shape: proofs or counter is not a list")
    note = str(a.get("note") or "").strip()
    if not note:
        return _undecided("the model gave no note")
    np_, nc = _sides(row)
    if _is_evidence_row(row) and not row["evidence"] and v in ("EVIDENCED", "CONTRADICTED"):
        return _undecided("the auditor named no pointer: " + note)
    if not _within(p, np_) or not _within(c, nc):
        return _undecided(f"the model named a candidate index that does not exist (proofs {p}, counter {c}; the row has {np_} FOR and {nc} AGAINST): " + note)
    if v == "EVIDENCED" and not p:
        return _undecided("the model answered EVIDENCED and named no proof: " + note)
    if v == "CONTRADICTED" and not c:
        return _undecided("the model answered CONTRADICTED and named no counter: " + note)
    body = {"verdict": v, "on": {"proofs": sorted(set(p)) if v == "EVIDENCED" else [], "counter": sorted(set(c)) if v == "CONTRADICTED" else []}, "note": note}
    if v == "CONTRADICTED":
        body["confidence"] = "low" if ("low" in note.lower() and "confiden" in note.lower()) else "high"
    return body, True


def decision_answer(answers, row, proofs_allowed=None):
    """A decision model's typed answers to a row body (3e.4): the verdict from the choice, the candidate by argmax of the yes-probabilities
    on the needed side, the note written here from the probabilities, confidence from the choice confidence. `proofs_allowed` (0.1.21, R4c,
    the document profile): the FOR indices an EVIDENCED may rest on (the artefact proofs); the argmax runs over those alone, and with none
    asked about the row is UNDECIDED. A decision model names no candidate itself, so this is the service's candidate rule, not a change to
    the model's answer."""
    if not isinstance(answers, dict) or not isinstance(answers.get("verdict"), dict):
        return _undecided("decision answer not in the expected shape: no verdict question answered")
    v = answers["verdict"]
    choice = v.get("choice")
    if choice not in WORD_OF:
        return _undecided(f"the model's verdict word is not in the vocabulary: {str(choice)[:40]}")
    word = WORD_OF[choice]
    probs = v.get("probabilities") or {}
    conf = v.get("confidence")
    nf, nc = _sides(row)

    def nouls(prefix, n):
        out = []
        for i in range(min(n, MAX_CANDIDATES_ASKED)):
            a = answers.get(f"{prefix}_{i}")
            try:
                out.append(float(a.get("noul")) if isinstance(a, dict) and a.get("noul") is not None else None)
            except (TypeError, ValueError):
                out.append(None)
        return out
    pn, cn = nouls("proof", nf), nouls("counter", nc)
    ptxt = ", ".join(f"{k} {float(probs.get(k, 0) or 0):.2f}" for k in WORD_OF)
    ntxt = "; ".join([f"FOR[{i}] {x:.2f}" for i, x in enumerate(pn) if x is not None] + [f"AGAINST[{i}] {x:.2f}" for i, x in enumerate(cn) if x is not None])
    note = f"decision model, no text: verdict probabilities {ptxt}, confidence {conf}" + (f"; candidate yes-probabilities {ntxt}" if ntxt else "")
    if word == "EVIDENCED":
        known = [(x, i) for i, x in enumerate(pn) if x is not None and (proofs_allowed is None or i in proofs_allowed)]
        if not known and proofs_allowed is not None:
            return _undecided("the model chose EVIDENCED and the row has no artefact FOR candidate it was asked about (a restatement never evidences a claim in the document profile): " + note)
        if not known:
            return _undecided("the model chose EVIDENCED and the row has no FOR candidate it was asked about: " + note)
        best = max(known)[1]
        return {"verdict": word, "on": {"proofs": [best], "counter": []}, "note": note}, True
    if word == "CONTRADICTED":
        known = [(x, i) for i, x in enumerate(cn) if x is not None]
        if not known:
            return _undecided("the model chose CONTRADICTED and the row has no AGAINST candidate it was asked about: " + note)
        best = max(known)[1]
        return {"verdict": word, "on": {"proofs": [], "counter": [best]}, "note": note,
                "confidence": "high" if (conf or 0) >= NOUL_HIGH_CONFIDENCE else "low"}, True
    return {"verdict": word, "on": dict(UND), "note": note}, True


def apply_row_rules(body, row, row_all_copy_none, copy_none_idx=None, unreadable_idx=None, all_unreadable=False):
    """Rules that stand above any model's answer (section 14 and 3d.3). A candidate the auditor fetched and did not save (copy: none) is
    not visible to a classifier, so: NO EVIDENCE PUBLISHED on an all copy-none row is UNDECIDED (the model cannot know nothing was
    published); and a decided verdict that rests ONLY on copy-none candidates (every index it names is one, or the row has nothing
    else) is UNDECIDED, never EVIDENCED or CONTRADICTED (gate D3). `copy_none_idx` = {"proofs": {i...}, "counter": {i...}}.
    For a row with one `evidence` list (S-1, D4): `unreadable_idx` = the evidence indices whose pointer cannot be read here (not sent,
    held by hash, not listed, malformed), `all_unreadable` = the list is non-empty and every pointer is one. A row all unreadable is
    UNDECIDED whatever the model said; a decided verdict whose named pointers are all unreadable is UNDECIDED; EVIDENCED or
    CONTRADICTED on an empty list is UNDECIDED (the auditor named no pointer); NO EVIDENCE PUBLISHED on an empty list passes through."""
    v = body["verdict"]
    idx = copy_none_idx or {"proofs": set(), "counter": set()}
    if row_all_copy_none and v in ("NO EVIDENCE PUBLISHED", "EVIDENCED", "CONTRADICTED"):
        return {"verdict": "UNDECIDED", "on": dict(UND), "note": "the candidates were fetched and not saved; the model said: " + body["note"]}
    side = "proofs" if v == "EVIDENCED" else ("counter" if v == "CONTRADICTED" else None)
    if side:
        named = [i for i in (body.get("on") or {}).get(side, []) if isinstance(i, int)]
        if named and all(i in idx.get(side, set()) for i in named):
            return {"verdict": "UNDECIDED", "on": dict(UND), "note": f"the {side} candidate(s) the model named were fetched and not saved (copy: none), so the verdict rests on nothing a reader can see; the model said: " + body["note"]}
    if _is_evidence_row(row):
        if not row["evidence"] and side:
            return {"verdict": "UNDECIDED", "on": dict(UND), "note": "the auditor named no pointer; the model said: " + body["note"]}
        if all_unreadable:
            return {"verdict": "UNDECIDED", "on": dict(UND), "note": "every pointer of this claim is unreadable here (not sent or held by hash); the model said: " + body["note"]}
        if side:
            named = [i for i in (body.get("on") or {}).get(side, []) if isinstance(i, int)]
            if named and all(i in (unreadable_idx or set()) for i in named):
                return {"verdict": "UNDECIDED", "on": dict(UND), "note": "the named pointer(s) cannot be read here (not sent or held by hash): " + body["note"]}
    return body


def vocabulary_rule(hits):
    """0.1.8 (seventh re-gate H2, V1): the body of a row whose evidence text names a witness verdict (render.witness_vocabulary_hits), decided
    UNDECIDED by rule for every model with no model call; None when there is no hit."""
    if not hits:
        return None
    return {"verdict": "UNDECIDED", "on": dict(UND),
            "note": "the evidence addresses the witness: " + "; ".join(hits) + " (a text that names a verdict is not evidence of a claim; a reader decides this row)"}


# ---- the document profile (0.1.21, R4c; claims-snapshot 0.9, SPEC 17) ----
DOCUMENT_VERDICTS = ("EVIDENCED", "CONTRADICTED", "NO EVIDENCE PUBLISHED", "UNDECIDED")  # the three verdicts and UNDECIDED (check.py K11)


def artefact_proofs(row):
    """The FOR indices whose candidate the auditor marked artefact: the only proofs that can evidence a document claim."""
    return {i for i, c in enumerate(row.get("proofs") or []) if isinstance(c, dict) and c.get("kind") == "artefact"}


def restatement_rule(row):
    """R4c-3: a document claim whose candidates include no proof of kind artefact and no counter is NO EVIDENCE PUBLISHED by rule, before
    any model call, at no cost: nothing in it can evidence or contradict the claim. The body, or None when the row goes to the models."""
    proofs = row.get("proofs") or []
    if row.get("counter") or artefact_proofs(row):
        return None
    n = sum(1 for c in proofs if isinstance(c, dict) and c.get("kind") == "restatement")
    what = (f"its {n} FOR candidate(s) are restatements, which never evidence a claim" if n else "it has no candidate at all")
    return {"verdict": "NO EVIDENCE PUBLISHED", "on": dict(UND),
            "note": f"settled by the restatement rule before any model call: the auditor named no artefact proof and no counter ({what}); no model was asked and nothing was spent"}


def document_rules(body, row):
    """R4c-4: rules on a document row that stand above any model's answer and above a pass-through. A verdict outside the profile's
    vocabulary (EVIDENCE AVAILABLE ON REQUEST, WITHDRAWN: SPEC 17 has neither) is UNDECIDED naming it; an EVIDENCED whose on.proofs names
    no artefact proof (a restatement alone) is UNDECIDED naming the indices and keeping the model's note. Never a near-miss normalisation:
    an index is never dropped, a verdict never changed into another verdict."""
    v = body.get("verdict")
    if v not in DOCUMENT_VERDICTS:
        return {"verdict": "UNDECIDED", "on": dict(UND), "note": f"{v} is not a document-profile verdict (the three verdicts and UNDECIDED, SPEC 17): " + str(body.get("note") or "")}
    if v == "EVIDENCED":
        named = [i for i in (body.get("on") or {}).get("proofs", []) if isinstance(i, int)]
        if not any(i in artefact_proofs(row) for i in named):
            return {"verdict": "UNDECIDED", "on": dict(UND),
                    "note": f"the model answered EVIDENCED on restatement proof(s) only (proofs {named}); in the document profile only an artefact evidences a claim; the model said: " + str(body.get("note") or "")}
    return body


def passthrough(row):
    """Rows the models never see (3.5): an auditor row marked on request is passed through as EVIDENCE AVAILABLE ON REQUEST; a withdrawn
    row as WITHDRAWN; a promise is not checkable. Returns a body or None."""
    if row.get("on_request"):
        return {"verdict": "EVIDENCE AVAILABLE ON REQUEST", "on": dict(UND), "note": "passed through: the auditor marked the evidence as held by its owner, which a classifier cannot see"}
    if row.get("withdrawn"):
        return {"verdict": "WITHDRAWN", "on": dict(UND), "note": "passed through: the publisher withdrew the claim"}
    if row.get("kind") == "promise":
        return {"verdict": "UNDECIDED", "on": dict(UND), "note": "a promise is a statement about the future and not checkable"}
    return None
