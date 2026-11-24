"""Public screening at check time (SPEC §3 rules, VR-21, BD11).

The signed text fields of a public claim (every string in `params`, the rendered `statement`, each evidence `name`) are
screened two ways, and any hit refuses the claim with 422 personal-data and the hint to submit it as private:
  1. the evidence store's own credential rules, through the redact helper named by WITNESS_REDACT_BIN (tools/redact-copy,
     built into the image at /app/bin/redact-copy; the approach of onedroid-audit package_step.py redact_copy());
  2. personal-data rules the redact rules do not cover: email addresses, phone numbers, IBANs, payment card numbers and
     US-style national id numbers.
Image and PDF objects (by declared media type or by their first bytes) are refused on public claims (422 media-not-allowed).
A public claim cannot be screened without the helper: 503, nothing signed. Private claims are not screened.
"""
import json
import os
import pathlib
import re
import subprocess

REDACT_ENV = "WITNESS_REDACT_BIN"
REDACT_TIMEOUT = 60

EMAIL = re.compile(r"(?<![\w.+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}(?![\w-])")
PHONE = re.compile(r"(?<![0-9A-Za-z+])\+?\(?\d[\d \t().-]{7,}\d(?![0-9A-Za-z])")
CARD = re.compile(r"(?<![0-9A-Za-z])\d(?:[ -]?\d){12,18}(?![0-9A-Za-z])")
IBAN = re.compile(r"(?<![0-9A-Za-z])[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?(?![0-9A-Za-z])")
NATIONAL_ID = re.compile(r"(?<![0-9A-Za-z])\d{3}-\d{2}-\d{4}(?![0-9A-Za-z])")
MAGIC = (b"\x89PNG", b"\xff\xd8\xff", b"GIF87a", b"GIF89a", b"%PDF-", b"BM", b"II*\x00", b"MM\x00*")


class ScreenRefused(Exception):
    def __init__(self, code, detail):
        super().__init__(code)
        self.code, self.detail = code, detail


class ScreenUnavailable(Exception):
    pass


def _luhn(digits):
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2:
            d = d * 2 - 9 if d > 4 else d * 2
        total += d
    return total % 10 == 0


def _iban_ok(s):
    s = s.replace(" ", "")
    if not 15 <= len(s) <= 34:
        return False
    moved = s[4:] + s[:4]
    try:
        return int("".join(str(int(c, 36)) for c in moved)) % 97 == 1
    except ValueError:
        return False


def personal_data_hits(text):
    """The personal-data rule ids that match text (no values)."""
    hits = []
    if EMAIL.search(text):
        hits.append("email")
    for m in PHONE.finditer(text):
        n = sum(c.isdigit() for c in m.group(0))
        if 9 <= n <= 15:
            hits.append("phone")
            break
    for m in IBAN.finditer(text):
        if _iban_ok(m.group(0)):
            hits.append("iban")
            break
    for m in CARD.finditer(text):
        digits = re.sub(r"\D", "", m.group(0))
        if 13 <= len(digits) <= 19 and _luhn(digits):
            hits.append("payment-card")
            break
    if NATIONAL_ID.search(text):
        hits.append("national-id")
    return hits


def is_image_or_pdf(media_type, data):
    mt = (media_type or "").split(";")[0].strip().lower()
    if mt.startswith("image/") or mt == "application/pdf":
        return True
    head = bytes(data[:16]) if data else b""
    if any(head.startswith(m) for m in MAGIC):
        return True
    return head[:4] == b"RIFF" and head[8:12] == b"WEBP" or head[4:8] == b"ftyp" and head[8:12] in (b"heic", b"heix", b"avif", b"mif1")


def _strings(v):
    if isinstance(v, str):
        yield v
    elif isinstance(v, dict):
        for k, x in v.items():
            yield str(k)
            yield from _strings(x)
    elif isinstance(v, list):
        for x in v:
            yield from _strings(x)


def _env():
    return {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C.UTF-8"}


class Screener:
    def __init__(self, redact_bin):
        self.redact_bin = redact_bin

    def fault(self):
        p = self.redact_bin
        if not p:
            return f"{REDACT_ENV} is not set"
        if not pathlib.Path(p).is_file():
            return f"{REDACT_ENV}: no such file"
        if not os.access(p, os.X_OK):
            return f"{REDACT_ENV}: not executable"
        return None

    def credential_rules(self, text):
        """The redact helper's rule ids for text (never the matched values)."""
        fault = self.fault()
        if fault:
            raise ScreenUnavailable(fault)
        try:
            done = subprocess.run([str(self.redact_bin)], input=text.encode("utf-8"), capture_output=True, timeout=REDACT_TIMEOUT,
                                  check=False, env=_env())
        except (OSError, subprocess.SubprocessError) as e:
            raise ScreenUnavailable(f"the redact helper did not run: {type(e).__name__}") from None
        if done.returncode == 3:
            return ["credential"]  # still matching after every replacement round: certainly a hit
        if done.returncode != 0:
            raise ScreenUnavailable(f"the redact helper exited {done.returncode}")
        try:
            out = json.loads(done.stdout.decode("utf-8"))
            return sorted({m["rule"] for m in out["matches"]})
        except (ValueError, KeyError, TypeError):
            raise ScreenUnavailable("the redact helper's answer is not {text, matches}") from None

    def screen_public(self, claim, statement, evidence):
        """Raise ScreenRefused or ScreenUnavailable; return None when the public claim may be signed."""
        for e in evidence:
            if e.get("kind") == "object" and is_image_or_pdf(e.get("media_type"), e.get("data") or b""):
                raise ScreenRefused("media-not-allowed", "Image and PDF objects are not accepted on a public claim in v1. "
                                                         "Submit it as private (options.visibility = \"private\").")
        texts = list(_strings(claim.get("params")))
        if claim.get("statement"):
            texts.append(claim["statement"])
        if statement:
            texts.append(statement)
        texts += [e["name"] for e in evidence if isinstance(e.get("name"), str)]
        rules = set()
        for t in texts:
            rules.update(personal_data_hits(t))
        rules.update(self.credential_rules("\n".join(texts)))
        if rules:
            raise ScreenRefused("personal-data", f"A signed field of this public claim holds personal data or a credential "
                                                 f"(rules: {', '.join(sorted(rules))}). Submit it as private "
                                                 "(options.visibility = \"private\").")
