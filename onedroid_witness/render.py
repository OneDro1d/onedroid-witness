"""Rendering of one audit row for a model: the claim, the page lines around it, and the candidates by type (contract section 4).

The text a model sees is DATA from a publisher's page and an auditor's record; the prompt says so and the caller's bytes never
reach the prompt itself. The same rendering goes to every model (chat or decision), so two models' answers are about one text.
"""


def source_index(manifest):
    """url -> the manifest's source entry (n, url, copy, status, file)."""
    return {s.get("url"): s for s in manifest.get("sources", []) if s.get("url")}


def _where(c, by_url):
    """Where a candidate comes from, in words a model can use: the page itself, a numbered source with its copy status, or unknown."""
    if c.get("file") == "page.txt" or (c.get("url") is None and c.get("file") in (None, "page.txt")):
        return "the audited page itself (page.txt)"
    src = by_url.get(c.get("url"))
    if src is None:
        if c.get("file"):
            return f"saved file {c['file']} (not in the manifest's source list)"
        return f"source {c.get('url')} (not in the manifest)"
    copy = src.get("copy")
    copy_text = "fetched and not saved: copy: none" if copy in (None, "none") else f"copy: {copy}"
    return f"source [{src.get('n')}] {src.get('url')} ({copy_text}, http {src.get('status')})"


def _candidate_line(i, c, by_url):
    where = _where(c, by_url)
    if c.get("quote") is not None:
        body = f'quote "{c["quote"]}"'
    elif c.get("expect_status") is not None:
        body = f"status proof: the URL answered {c.get('expect_status')}, no quote"
    elif c.get("file") and c.get("url") is None:
        body = "existence proof: the named file exists at the pinned commit, no quote"
    else:
        body = "existence or status proof, no quote"
    note = f"; note: {c['note']}" if c.get("note") else ""
    return f"[{i}] from {where}: {body}{note}"


def page_context(row, page_lines, around=1, width=600):
    out = []
    for loc in row.get("location") or []:
        n = loc.get("line")
        if isinstance(n, int) and 1 <= n <= len(page_lines):
            for i in range(max(1, n - around), min(len(page_lines), n + around) + 1):
                out.append(f"page.txt line {i}: {page_lines[i - 1][:width]}")
    return out


def render(row, page, by_url):
    """The rendered claim: id, kind, text, page context, candidates FOR and AGAINST, consulted, searched."""
    lines = page.splitlines()
    out = [f"claim id: {row['id']}", f"kind: {row.get('kind')}", f"claim text: {row['text']}", "",
           "page context (the lines around the claim):"]
    out += page_context(row, lines) or ["(no location)"]
    for name, items in (("FOR", row.get("proofs") or []), ("AGAINST", row.get("counter") or [])):
        out += ["", f"candidates {name} ({len(items)}):"]
        out += [_candidate_line(i, c, by_url) for i, c in enumerate(items)] or ["(none)"]
    if row.get("consulted"):
        out += ["", "what the auditor consulted and found where it looked:"]
        out += [f"- {c.get('url') or c.get('file')}: {str(c.get('quote'))[:400]}" for c in row["consulted"]]
    if row.get("searched"):
        out += ["", f"what the auditor searched for and did not find: {row['searched']}"]
    return "\n".join(out)


def all_copy_none(row, by_url):
    """True when every candidate of the row is a source the auditor fetched and did not save (section 14: never EVIDENCED)."""
    cands = (row.get("proofs") or []) + (row.get("counter") or [])
    if not cands:
        return False
    for c in cands:
        if c.get("file") == "page.txt" or c.get("url") is None:
            return False
        src = by_url.get(c.get("url"))
        if src is None or src.get("copy") not in (None, "none"):
            return False
    return True
