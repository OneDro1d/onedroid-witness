"""Rendering of one audit row for a model: the claim, the page lines around it, and the candidates by type (contract section 4).

The text a model sees is DATA from a publisher's page and an auditor's record; the prompt says so and the caller's bytes never
reach the prompt itself. The same rendering goes to every model (chat or decision), so two models' answers are about one text.
"""
import re
import urllib.parse


PUBLISHER = ("publisher-host",)  # the key under which source_index keeps the audited page's site; a tuple never collides with a URL


def _site(url):
    """The site of a URL for the publisher relation: the host, lower-cased, a leading www. dropped; None when there is none."""
    try:
        host = (urllib.parse.urlsplit(str(url)).hostname or "").lower()
    except ValueError:
        return None
    return host[4:] if host.startswith("www.") else (host or None)


def source_index(manifest):
    """url -> the manifest's source entry (n, url, copy, status, file), plus the audited page's site under PUBLISHER (re-gate N1: the
    publisher-surfaces rule turns on whether a source is one of the publisher's own surfaces, so the rendering has to say which are)."""
    idx = {s.get("url"): s for s in manifest.get("sources", []) if s.get("url")}
    idx[PUBLISHER] = _site((manifest.get("subject") or {}).get("url")) if isinstance(manifest.get("subject"), dict) else None
    return idx


def _relation(url, by_url):
    """' , the publisher's own surface (same site as the audited page)' or ' , another site', or nothing when no subject URL is known."""
    site = by_url.get(PUBLISHER)
    if not site:
        return ""
    return ", the publisher's own surface (same site as the audited page)" if _site(url) == site else ", another site"


def _where(c, by_url):
    """Where a candidate comes from, in words a model can use: the page itself, a numbered source with its copy status and whether it is
    one of the publisher's own surfaces, or unknown."""
    if c.get("file") == "page.txt" or (c.get("url") is None and c.get("file") in (None, "page.txt")):
        return "the audited page itself (page.txt)"
    src = by_url.get(c.get("url"))
    if src is None:
        if c.get("file"):
            return f"saved file {c['file']} (not in the manifest's source list)"
        return f"source {c.get('url')} (not in the manifest)"
    copy = src.get("copy")
    copy_text = "fetched and not saved: copy: none" if copy in (None, "none") else f"copy: {copy}"
    return f"source [{src.get('n')}] {src.get('url')} ({copy_text}, http {src.get('status')}{_relation(src.get('url'), by_url)})"


FENCE_CHARS = set("=-_~*#")


# every separator str.splitlines() honours (re-gate N2): \r\n, \n, \r, \v, \f, the C1 and Unicode line and paragraph separators
LINE_SEPARATORS = re.compile("\r\n|[\n\r\x0b\x0c\x1c\x1d\x1e\x85  ]")


def one_line(s, width=None):
    """Caller text as ONE line: a line separator inside a quote, a note or a claim text would otherwise end the item's line and could
    close the data fence the prompt names (gate D4). Every separator str.splitlines() knows becomes a visible mark, nothing is removed."""
    t = LINE_SEPARATORS.sub(" ⏎ ", str(s))
    return t[:width] if width else t


def neutralise_fence_lines(text, fence):
    """No line of caller data may equal the fence, nor consist of fence-like characters alone (a run of = or -): such a line gets a
    visible prefix. The data is kept, only its line shape changes. Lines are what str.splitlines() sees (re-gate N2), joined with \\n."""
    out = []
    for l in text.splitlines():
        s = l.strip()
        if l == fence or (len(s) >= 8 and set(s) <= FENCE_CHARS):
            out.append("| " + l)
        else:
            out.append(l)
    return "\n".join(out)


def copy_none_indices(row, by_url):
    """The candidate indices, per side, whose source the auditor fetched and did not save (copy: none): a verdict resting only on those
    is UNDECIDED, never EVIDENCED or CONTRADICTED (section 14, gate D3)."""
    out = {"proofs": set(), "counter": set()}
    for side in ("proofs", "counter"):
        for i, c in enumerate(row.get(side) or []):
            if c.get("file") == "page.txt" or c.get("url") is None:
                continue
            src = by_url.get(c.get("url"))
            if src is not None and src.get("copy") in (None, "none"):
                out[side].add(i)
    return out


def _candidate_line(i, c, by_url):
    where = _where(c, by_url)
    if c.get("quote") is not None:
        body = f'quote "{one_line(c["quote"])}"'
    elif c.get("expect_status") is not None:
        body = f"status proof: the URL answered {c.get('expect_status')}, no quote"
    elif c.get("file") and c.get("url") is None:
        body = "existence proof: the named file exists at the pinned commit, no quote"
    else:
        body = "existence or status proof, no quote"
    note = f"; note: {one_line(c['note'])}" if c.get("note") else ""
    return f"[{i}] from {one_line(where)}: {body}{note}"


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
    out = [f"claim id: {one_line(row['id'])}", f"kind: {one_line(row.get('kind'))}", f"claim text: {one_line(row['text'])}", "",
           "page context (the lines around the claim):"]
    out += page_context(row, lines) or ["(no location)"]
    for name, items in (("FOR", row.get("proofs") or []), ("AGAINST", row.get("counter") or [])):
        out += ["", f"candidates {name} ({len(items)}):"]
        out += [_candidate_line(i, c, by_url) for i, c in enumerate(items)] or ["(none)"]
    if row.get("consulted"):
        out += ["", "what the auditor consulted and found where it looked:"]
        out += [f"- {one_line(c.get('url') or c.get('file'))}: {one_line(str(c.get('quote')), 400)}" for c in row["consulted"]]
    if row.get("searched"):
        out += ["", f"what the auditor searched for and did not find: {one_line(row['searched'])}"]
    from .prompts import DATA_FENCE
    return neutralise_fence_lines("\n".join(out), DATA_FENCE)


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
