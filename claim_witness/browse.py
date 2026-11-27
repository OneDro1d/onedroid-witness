"""Browse (NS-3-SPEC.md sections 2-4 and 7, M-20261127-NAME-SITE): subjects, keywords and record types of the LISTED public
records, written at keep, removed at takedown in the same request and back-filled at start, and the public read routes

    GET /v1/browse/subjects?kind=page|site|profile&parent=&prefix=&limit=&offset=
    GET /v1/browse/subjects/{sid}
    GET /v1/browse/keywords?sort=alpha|records&prefix=&limit=&offset=
    GET /v1/browse/keywords/{word}            (301 to the canonical spelling)
    GET /v1/browse/categories
    GET /v1/browse/records/{id}
    POST /v1/records/{id}/unlist              (an operator account only)

plus the subject, keyword and type filters and the two hit fields of GET /v1/search (search.py).

Listed (V34): public, kept, not taken down, not deleted and not in unlisted_records (seeded with the 28 test ids,
unlisted_seed.py). Every list, count and existence test joins the kept rows with that predicate at query time, so a takedown
or an unlist can never leave a stale count. A private record writes no row here, ever (V35). The answers are the same bytes for
every reader: no route here reads a credential (V27), and no answer carries an account, an agent, a label or a file (V30).

Subjects (P3, P4, Table 1-3). A subject is a canonical URL at one of three levels: page (one URL), site (one host) and profile
(an account on a platform host; a platform host has no site). The URL is the one the claim names (params.url, the evidence url,
or a public observation's requested_url), never the redirect target. canon() is Table 1, applied until it no longer changes
anything (so canon is idempotent, V2: "one www." and "one trailing /" are removed repeatedly). sid = the first 32 hex of
sha256(kind + "\\n" + key).

Keywords (P6, P7, 3.2). No model: the search tokeniser over claim.params.quote, claim.statement and the path and query values of
the record's page subjects (a platform profile's handle is never a source), a stop list of English function words, URL noise
and every fixed word of every method template (generated from methods.METHODS), and the operator's denylist
(WITNESS_KEYWORD_DENYLIST_FILE). At most 8 a record. A keyword is listed at 3 listed records from at least 2 accounts; the
accounts never leave this module."""
import encodings.idna
import hashlib
import json
import re
import string
import sys
import unicodedata
import urllib.parse

from . import dsse, methods
from .records import _norm
from .service import WitnessError, iso
from .storage import OUTCOMES
from .unlisted_seed import SEED_UNLISTED  # noqa: F401 (re-exported)

KINDS = ("page", "site", "profile")
TYPES = ("record", "test-run", "social-post", "social-profile", "web-page", "document")
TYPE_LABELS = {"record": "Record", "test-run": "Test run", "social-post": "Social post", "social-profile": "Social profile",
               "web-page": "Web page", "document": "Document"}
PREFIXES = tuple(string.ascii_lowercase) + ("other",)
SID = re.compile(r"^[0-9a-f]{32}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
INT = re.compile(r"^[0-9]{1,9}$")
WORD = re.compile(r"[^\W_]+")
DEFAULT_LIMIT, MAX_LIMIT, MAX_OFFSET = 50, 100, 10000
MAX_SUBJECTS = 5     # V1: page subjects (distinct URLs) a record can have
MAX_KEYWORDS = 8     # V18
MIN_RECORDS, MIN_ACCOUNTS = 3, 2  # V19
MAX_WORD_BYTES = 128

# ------------------------------------------------------------------------------------------------------------ canon (Table 1)

UNRESERVED = frozenset(string.ascii_letters + string.digits + "-._~")
PATH_SAFE = frozenset("!$&'()*+,;=:@/")
QUERY_SAFE = frozenset("!$'()*,;:@/?")
TRACKING = frozenset({"gclid", "dclid", "gbraid", "wbraid", "fbclid", "msclkid", "yclid", "twclid", "igshid", "mc_cid", "mc_eid",
                      "_hsenc", "_hsmi", "ref_src", "ref_url"})
HOST_LABEL = re.compile(r"^[a-z0-9_-]+$")
IPV4 = re.compile(r"^[0-9]+(\.[0-9]+){3}$")
SCHEME = re.compile(r"^([A-Za-z][A-Za-z0-9+.-]*):(.*)$", re.S)
PCT = re.compile(r"%[0-9A-Fa-f]{2}")


def _pct(s, safe):
    """Unreserved escapes decoded, other escapes' hex upper-cased, every other byte that is not safe percent-encoded."""
    out, i = [], 0
    while i < len(s):
        c = s[i]
        if c == "%" and PCT.match(s, i):
            ch = chr(int(s[i + 1:i + 3], 16))
            out.append(ch if ch in UNRESERVED else "%" + s[i + 1:i + 3].upper())
            i += 3
            continue
        if c in UNRESERVED or c in safe or c == "%":
            out.append(c)
        else:
            out.extend("%%%02X" % b for b in c.encode("utf-8", "surrogatepass"))
        i += 1
    return "".join(out)


def _host(raw):
    """(A-label host, display host) or None. IP literals are kept as written."""
    if raw.startswith("["):
        return (raw, raw) if re.match(r"^\[[0-9A-Fa-f:.]+\]$", raw) else None
    host = urllib.parse.unquote(raw).rstrip(".")
    if not host:
        return None
    if IPV4.match(host):
        return host, host
    labels, shown = [], []
    for label in host.split("."):
        if not label:
            return None
        label = unicodedata.normalize("NFKC", label).casefold()
        if not label.isascii():
            try:
                label = encodings.idna.ToASCII(label).decode("ascii").lower()
            except UnicodeError:
                return None
        if not HOST_LABEL.match(label) or len(label) > 63:
            return None
        labels.append(label)
    while len(labels) > 2 and labels[0] == "www":  # one leading www. while at least two labels remain (V4)
        labels = labels[1:]
    for label in labels:
        try:
            shown.append(encodings.idna.ToUnicode(label) if label.startswith("xn--") else label)
        except UnicodeError:
            shown.append(label)
    return ".".join(labels), ".".join(shown)


def _path(raw):
    path = _pct(raw, PATH_SAFE)
    if not path.startswith("/"):
        path = "/" + path
    segs, out = path.split("/")[1:], []
    for i, s in enumerate(segs):
        last = i == len(segs) - 1
        if s in (".", ".."):
            if s == ".." and out:
                out.pop()
            if last:
                out.append("")
            continue
        out.append(s)
    path = "/" + "/".join(out)
    while len(path) > 1 and path.endswith("/"):  # one trailing / unless the path is / (repeated: V2)
        path = path[:-1]
    return path


def _query(raw):
    pairs = []
    for part in raw.split("&"):
        if part == "":
            continue
        k, eq, v = part.partition("=")
        if k == "" and v == "":
            continue
        nk, nv = _pct(k.replace("+", " "), QUERY_SAFE), _pct(v.replace("+", " "), QUERY_SAFE)
        dk = urllib.parse.unquote(nk).lower()
        if dk.startswith("utm_") or dk in TRACKING:
            continue
        pairs.append((nk, nv, eq))
    pairs.sort(key=lambda p: (p[0], p[1]))
    return "&".join(k + eq + v for k, v, eq in pairs)


def _parse(u):
    """{host, display_host, port, path, query} of an http(s) URL after Table 1, or None."""
    if not isinstance(u, str):
        return None
    u = re.sub(r"[\t\n\r]", "", u).strip(" \x00\x01\x02\x03\x04\x05\x06\x07\x08\x0b\x0c\x0e\x0f\x10\x11\x12\x13\x14\x15\x16"
                                            "\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f")
    m = SCHEME.match(u)
    if not m or m.group(1).lower() not in ("http", "https"):
        return None
    rest = m.group(2).replace("\\", "/").lstrip("/")
    am = re.match(r"^([^/?#]*)(.*)$", rest, re.S)
    auth, tail = am.group(1), am.group(2).split("#", 1)[0]
    if "@" in auth:
        auth = auth.rsplit("@", 1)[1]  # userinfo dropped (V6)
    if auth.startswith("["):
        end = auth.find("]")
        if end < 0:
            return None
        hostpart, after = auth[:end + 1], auth[end + 1:]
        if after and not after.startswith(":"):
            return None
        port = after[1:]
    else:
        hostpart, _, port = auth.partition(":")
    if port:
        if not port.isdigit() or int(port) > 65535:
            return None
        port = str(int(port))
    if port in ("80", "443"):
        port = ""
    h = _host(hostpart)
    if h is None:
        return None
    path, _, query = tail.partition("?")
    return {"host": h[0], "display_host": h[1], "port": port, "path": _path(path), "query": _query(query)}


def _key(p, host=None, path=None):
    return (host or p["host"]) + (":" + p["port"] if p["port"] else "") + (path or p["path"]) + ("?" + p["query"] if p["query"] else "")


def canon(u):
    """The subject key of a URL (Table 1): host[:port] + path + [?query], no scheme; None when the URL makes no subject."""
    p = _parse(u)
    return _key(p) if p is not None else None


def sid(kind, key):
    """V11: the first 32 hex characters of sha256(UTF-8 of kind + "\\n" + key)."""
    return hashlib.sha256((kind + "\n" + key).encode("utf-8")).hexdigest()[:32]


# ------------------------------------------------------------------------------------------------------------ Table 2

PLATFORM_HOSTS = {"bsky.app": "bsky", "x.com": "x", "twitter.com": "x", "mobile.twitter.com": "x", "mobile.x.com": "x",
                  "linkedin.com": "linkedin", "m.linkedin.com": "linkedin", "github.com": "github", "youtube.com": "youtube",
                  "m.youtube.com": "youtube", "tiktok.com": "tiktok", "instagram.com": "instagram", "facebook.com": "facebook",
                  "m.facebook.com": "facebook"}
MAIN_HOST = {"bsky": "bsky.app", "x": "x.com", "linkedin": "linkedin.com", "github": "github.com", "youtube": "youtube.com",
             "tiktok": "tiktok.com", "instagram": "instagram.com", "facebook": "facebook.com"}
PLATFORM_NAMES = {"bsky": "Bluesky", "x": "X", "linkedin": "LinkedIn", "github": "GitHub", "youtube": "YouTube", "tiktok": "TikTok",
                  "instagram": "Instagram", "facebook": "Facebook"}
X_RESERVED = frozenset({"home", "i", "search", "explore", "settings", "intent", "share", "hashtag", "login"})
INSTAGRAM_RESERVED = frozenset({"p", "reel", "explore", "accounts"})
FACEBOOK_RESERVED = frozenset({"groups", "events", "watch", "share", "login"})


def _fold_name(seg):
    return seg if seg.lower().startswith("did:") else seg.lower()


def _profile(platform, segs):
    """(profile path segments, how many URL segments they replace) or None (Table 2)."""
    first = segs[0] if segs else ""
    low = first.lower()
    if platform == "bsky":
        if low == "profile" and len(segs) >= 2 and segs[1]:
            return ["profile", _fold_name(segs[1])], 2
    elif platform == "x":
        if first and low not in X_RESERVED:
            return [low], 1
    elif platform == "linkedin":
        if low in ("in", "company") and len(segs) >= 2 and segs[1]:
            return [low, segs[1].lower()], 2
    elif platform == "github":
        if first:
            return [low], 1
    elif platform in ("youtube", "tiktok"):
        if low.startswith("@") and len(low) > 1:
            return [low], 1
    elif platform == "instagram":
        if len(segs) == 1 and first and low not in INSTAGRAM_RESERVED:
            return [low], 1
    elif platform == "facebook":
        if len(segs) == 1 and first and low not in FACEBOOK_RESERVED:
            return [low], 1
    return None


def _profile_display(platform, segs):
    name = segs[-1]
    if platform in ("bsky", "x", "instagram"):
        return f"@{name} on {PLATFORM_NAMES[platform]}"
    return f"{name} on {PLATFORM_NAMES[platform]}"


def _subject(kind, key, display, platform, parent):
    return {"sid": sid(kind, key), "kind": kind, "key": key, "display": display, "platform": platform,
            "parent_sid": parent["sid"] if parent else None}


def profile_subject(platform, segs):
    key = MAIN_HOST[platform] + "/" + "/".join(segs)
    return _subject("profile", key, _profile_display(platform, segs), platform, None)


def subjects_for_url(u):
    """[page, parent] (parent: a site, or a profile on a platform host, or none) for one URL; [] when it makes no subject.
    Each page carries two internal fields the index uses and no answer shows: role (post | profile | web) and kwtext (the
    URL's text a keyword may come from: the path past a profile's handle and the query values)."""
    p = _parse(u)
    if p is None:
        return []
    platform = PLATFORM_HOSTS.get(p["host"]) if not p["port"] else None
    if platform is None:
        port = ":" + p["port"] if p["port"] else ""
        site = _subject("site", p["host"] + port, p["display_host"] + port, None, None)
        disp = site["display"] + _key(p)[len(site["key"]):]
        page = _subject("page", _key(p), disp, None, site)
        page.update(role="web", kwtext=_kwtext(p["path"], p["query"]))
        return [page, site]
    host = MAIN_HOST[platform]
    segs = p["path"].split("/")[1:] if p["path"] != "/" else []
    prof = _profile(platform, segs)
    if prof is None:
        key = _key(p, host=host)
        page = _subject("page", key, key, platform, None)
        post = (platform == "instagram" and segs and segs[0].lower() in ("p", "reel")) or \
               (platform == "x" and len(segs) >= 3 and segs[0].lower() == "i" and segs[1].lower() == "status")
        page.update(role="post" if post else "web", kwtext=_kwtext(p["path"], p["query"]))
        return [page]
    psegs, n = prof
    parent = profile_subject(platform, psegs)
    rest = segs[n:]
    path = "/" + "/".join(psegs + rest)
    key = _key(p, host=host, path=path)
    page = _subject("page", key, key, platform, parent)
    page.update(role="profile" if key == parent["key"] else "post", kwtext=_kwtext("/" + "/".join(rest), p["query"]))
    return [page, parent]


def _kwtext(path, query):
    vals = [urllib.parse.unquote(pv.partition("=")[2]) for pv in query.split("&")] if query else []
    return " ".join([urllib.parse.unquote(path).replace("/", " ")] + vals)


def _href(u):
    """The URL as written, without its userinfo (V6: never shown)."""
    m = re.match(r"^([A-Za-z][A-Za-z0-9+.-]*:[\\/]*)([^/?#\\]*)(.*)$", u.strip(), re.S)
    if m and "@" in m.group(2):
        return m.group(1) + m.group(2).rsplit("@", 1)[1] + m.group(3)
    return u.strip()


# ------------------------------------------------------------------------------------------------------------ keywords (3.2)

# (a) English function words (the NLTK English list, 179 words)
FUNCTION_WORDS = frozenset("""i me my myself we our ours ourselves you you're you've you'll you'd your yours yourself yourselves he
him his himself she she's her hers herself it it's its itself they them their theirs themselves what which who whom this that
that'll these those am is are was were be been being have has had having do does did doing a an the and but if or because as
until while of at by for with about against between into through during before after above below to from up down in out on off
over under again further then once here there when where why how all any both each few more most other some such no nor not only
own same so than too very s t can will just don don't should should've now d ll m o re ve y ain aren aren't couldn couldn't didn
didn't doesn doesn't hadn hadn't hasn hasn't haven haven't isn isn't ma mightn mightn't mustn mustn't needn needn't shan shan't
shouldn shouldn't wasn wasn't weren weren't won won't wouldn wouldn't""".split())
# (b) URL noise
URL_NOISE = frozenset("www http https html htm php asp aspx index amp com org net".split())


def _template_words():
    """(c) every fixed word of every method's T and F templates, from the registry (so a new method's words join by itself)."""
    out = set()
    for m in methods.METHODS.values():
        for tmpl in (m.templates or {}).values():
            if isinstance(tmpl, str):
                out.update(WORD.findall(_norm(re.sub(r"\{\w+\}", " ", tmpl))))
    return frozenset(out)


def _split_words(words):
    out = set()
    for w in words:
        out.update(WORD.findall(_norm(w)))
    return out


STOP_WORDS = frozenset(_split_words(FUNCTION_WORDS) | set(FUNCTION_WORDS) | URL_NOISE | _template_words())


def normalize_word(w):
    return _norm(w) if isinstance(w, str) else ""


def candidates(text, deny=frozenset()):
    """V16-V17: the distinct tokens of a text (NFKC, casefold, [^\\W_]+) that have 3 to 32 characters, no digit, and are in
    neither the stop list nor the denylist, in order."""
    seen = {}
    for w in WORD.findall(_norm(text or "")):
        if 3 <= len(w) <= 32 and not any(c.isdigit() for c in w) and w not in STOP_WORDS and w not in deny:
            seen.setdefault(w, None)
    return list(seen)


def keywords_of(pred, kwtexts, deny=frozenset()):
    """V15, V18: the first 8 distinct candidates of claim.params.quote, claim.statement, then the page subjects' URL text."""
    claim = pred.get("claim") if isinstance(pred, dict) else None
    claim = claim if isinstance(claim, dict) else {}
    params = claim.get("params") if isinstance(claim.get("params"), dict) else {}
    texts = [params.get("quote"), claim.get("statement")] + list(kwtexts or [])
    out = []
    for t in texts:
        if not isinstance(t, str):
            continue
        for w in candidates(t, deny):
            if w not in out:
                out.append(w)
            if len(out) == MAX_KEYWORDS:
                return out
    return out


def denylist_from_env(env):
    """WITNESS_KEYWORD_DENYLIST_FILE: one word a line (blank lines and # comments skipped); unset: no denylist."""
    path = (env.get("WITNESS_KEYWORD_DENYLIST_FILE") or "").strip()
    if not path:
        return set()
    with open(path, encoding="utf-8") as f:
        return {normalize_word(line) for line in f if line.strip() and not line.strip().startswith("#")}


def _letter(text):
    c = (text or "").lstrip("@")[:1].casefold()
    return c if c in string.ascii_lowercase and c != "" else "other"


# ------------------------------------------------------------------------------------------------------------ the index

class Browse:
    def __init__(self, witness):
        self.w = witness

    @property
    def st(self):
        return self.w.storage

    def deny(self):
        return frozenset(normalize_word(x) for x in (getattr(self.w.cfg, "keyword_denylist", None) or ()))

    # ---------------------------------------------------------------------------------------------------- writing

    def _obs_url(self, oid):
        """V12: a PUBLIC observation's requested_url; None when it cannot be read (gone, private)."""
        o = self.st.get_observation(oid) if isinstance(oid, str) else None
        if o is None or o.get("visibility") != "public":
            return None
        try:
            u = json.loads(dsse.payload_bytes(o["envelope"]))["predicate"].get("requested_url")
        except (KeyError, TypeError, ValueError):
            return None
        return u if isinstance(u, str) else None

    def _item_url(self, e):
        if not isinstance(e, dict):
            return None
        if e.get("kind") == "url":
            return e.get("url") if isinstance(e.get("url"), str) else None
        if e.get("kind") == "observation":
            return self._obs_url(e.get("id"))
        return None

    def _urls(self, method, claim, evidence):
        """Table 3: the URLs a record names, in evidence order."""
        ev = [e for e in evidence if isinstance(e, dict)]
        if method == "page.live":
            u = (claim.get("params") or {}).get("url") if isinstance(claim.get("params"), dict) else None
            if isinstance(u, str):
                return [u]
            return [self._item_url(e) for e in ev if e.get("slot") == "page"]
        if method in ("match.text", "match.screenshot"):
            return [self._item_url(e) for e in ev if e.get("slot") == "page"]
        if method == "post.by-author":
            return [self._item_url(e) for e in ev if e.get("slot") == "post"]
        if method == "judge.supports":
            return [self._item_url(e) for e in ev if e.get("kind") in ("url", "observation")]
        return []

    def listed(self, rid):
        row = self.st.get_kept(rid) if isinstance(rid, str) else None
        return (row is not None and row["visibility"] == "public" and row["taken_down_at"] is None and row["deleted_at"] is None
                and self.st.get_unlisted(rid) is None)

    def _compute(self, pred, depth=0):
        """(subjects, links [(sid, href)], keyword texts, the predicate the keywords come from)."""
        claim = pred.get("claim") if isinstance(pred.get("claim"), dict) else {}
        method = claim.get("method") or (pred.get("method") or {}).get("id")
        evidence = pred.get("evidence") if isinstance(pred.get("evidence"), list) else []
        if method == "record.valid":  # V13: the subjects of the record it checks, iff that record is listed
            ref = next((e.get("id") for e in evidence if isinstance(e, dict) and e.get("kind") == "record"), None)
            got = self.st.get_browse(ref) if ref and self.listed(ref) else None
            if not got or not got["links"]:
                return [], [], [], pred
            rows = self.st.get_subjects([s for s, _h in got["links"]])
            # no href: the record.valid did not write the URL, so a page's href stays the one its own records wrote (S41)
            return [rows[s] for s, _h in got["links"] if s in rows], [(s, None) for s, _h in got["links"]], [], pred
        if method == "record.disclose":  # V13: Table 3 over the disclosed body (public by the owner's act)
            if depth:
                return [], [], [], pred
            body = None
            for e in evidence:
                if isinstance(e, dict) and e.get("slot") == "disclosure" and isinstance(e.get("content"), dict):
                    body = e["content"].get("body")
            if not isinstance(body, dict):
                return [], [], [], pred
            return self._compute(body, 1)
        pages, keys = [], set()
        for u in self._urls(method, claim, evidence):
            subs = subjects_for_url(u) if isinstance(u, str) else []
            if not subs or subs[0]["key"] in keys:
                continue
            if len(pages) == MAX_SUBJECTS:  # V1: the first 5 distinct URLs
                break
            page, parent = subs[0], (subs[1] if len(subs) > 1 else None)
            handle = (claim.get("params") or {}).get("handle") if isinstance(claim.get("params"), dict) else None
            if method == "post.by-author" and page["platform"] == "bsky" and isinstance(handle, str) and handle:
                parent = profile_subject("bsky", ["profile", handle.lower()])  # V8: the account the claim names
                page = dict(page, parent_sid=parent["sid"], role="profile" if page["key"] == parent["key"] else "post")
            keys.add(page["key"])
            pages.append((page, parent, _href(u)))
        subjects, links, texts, seen = [], [], [], set()
        for page, parent, href in pages:
            for s, hr in ((page, href), (parent, None)):
                if s is not None and s["sid"] not in seen:
                    seen.add(s["sid"])
                    subjects.append(s)
                    links.append((s["sid"], hr))
            texts.append(page.get("kwtext", ""))
        return subjects, links, texts, pred

    @staticmethod
    def _type(method, subjects):
        """V23: exactly one type, by the priority of 3.3."""
        if method in ("record.valid", "record.disclose"):
            return "record"
        if method == "tests.pass":
            return "test-run"
        roles = {s.get("role") for s in subjects if s["kind"] == "page"}
        if "post" in roles:
            return "social-post"
        if "profile" in roles:
            return "social-profile"
        if roles:
            return "web-page"
        return "document"

    def index(self, rid, pred):
        """Index one PUBLIC kept record (never called for a private one)."""
        subjects, links, texts, kpred = self._compute(pred)
        method = (pred.get("claim") or {}).get("method") or (pred.get("method") or {}).get("id")
        words = keywords_of(kpred, texts, self.deny())
        rows = [{k: s[k] for k in ("sid", "kind", "key", "display", "platform", "parent_sid")} for s in subjects]
        self.st.put_browse(rid, rows, links, words, self._type(method, subjects))

    def _dependents(self, rid):
        """Re-index the record.valid records that check rid (V13: their subjects are rid's only while rid is listed)."""
        for row in self.st.kept_list(visibility="public"):
            if row["method"] != "record.valid" or row["taken_down_at"] is not None or not self.st.has_browse(row["record_id"]):
                continue
            pred = json.loads(dsse.payload_bytes(row["envelope"]))["predicate"]
            if any(isinstance(e, dict) and e.get("kind") == "record" and e.get("id") == rid for e in pred.get("evidence") or []):
                self.index(row["record_id"], pred)

    def record_words(self, rid):
        """The keywords stored for one record, in order (listed or not): for tests and the operator."""
        got = self.st.get_browse(rid)
        return list(got["words"]) if got else []

    def remove(self, rid):
        """At takedown, in the same request: the record's rows go, and the records that inherited its subjects lose them."""
        self.st.delete_browse(rid)
        self._dependents(rid)

    def backfill(self):
        """Index the public kept records with no browse row yet (kept before this slice); the number indexed."""
        n = 0
        for row in self.st.kept_list(visibility="public"):
            if row["taken_down_at"] is None and row["deleted_at"] is None and not self.st.has_browse(row["record_id"]):
                try:
                    self.index(row["record_id"], json.loads(dsse.payload_bytes(row["envelope"]))["predicate"])
                    n += 1
                except Exception as e:  # one unreadable record must not stop the rest
                    print(f"browse: backfill of {row['record_id'][:12]} failed ({type(e).__name__})", file=sys.stderr, flush=True)
        return n

    def unlist(self, account, rid, body):
        """POST /v1/records/{id}/unlist (V37): an operator account only; the record leaves every list and count."""
        if account not in (self.w.cfg.operator_accounts or ()):
            raise WitnessError(403, "not-operator", "only an operator account (WITNESS_OPERATOR_ACCOUNTS) may unlist a record")
        body = body if body is not None else {}
        if not isinstance(body, dict) or set(body) - {"reason"} or not isinstance(body.get("reason", ""), str) \
                or len(body.get("reason", "")) > 500:
            raise WitnessError(422, "invalid-request", "an unlist is {reason?: text}; the reason is not stored")
        if not isinstance(rid, str) or not HEX64.match(rid) or self.st.get_kept(rid) is None:
            raise WitnessError(404, "not-found", "no kept record with this id")
        if self.st.get_unlisted(rid) is None:
            self.st.unlist(rid, self.w.now(), "operator")
            self._dependents(rid)
        u = self.st.get_unlisted(rid)
        return {"record_id": rid, "unlisted": True, "at": iso(u["at"]), "reason": u["reason"],
                "note": "the record leaves every browse list and count; its own page, its seal and the signed record stay"}

    # ---------------------------------------------------------------------------------------------------- reading

    def snapshot(self):
        """The listed records' browse data, aggregated: {records, subjects, by_sid, by_word, links, words}."""
        snap = self.st.browse_snapshot()
        recs, rows = snap["records"], snap["subjects"]
        by_sid, links = {}, {}
        for rid, s, href, _pos in sorted(snap["links"], key=lambda x: (x[0], x[3])):
            links.setdefault(rid, []).append((s, href))
            by_sid.setdefault(s, []).append((rid, href))
        words, by_word = {}, {}
        for rid, w, _pos in sorted(snap["words"], key=lambda x: (x[0], x[2])):
            words.setdefault(rid, []).append(w)
            by_word.setdefault(w, []).append(rid)
        return {"records": recs, "subjects": rows, "by_sid": by_sid, "by_word": by_word, "links": links, "words": words}

    def _listed_words(self, snap):
        deny = self.deny()
        out = {}
        for w, rids in snap["by_word"].items():
            if w in deny or len(rids) < MIN_RECORDS:
                continue
            if len({snap["records"][r]["account"] for r in rids}) < MIN_ACCOUNTS:
                continue
            out[w] = rids
        return out

    @staticmethod
    def _ref(row):
        return {k: row[k] for k in ("sid", "kind", "key", "display", "platform", "parent_sid")}

    def _full(self, snap, s):
        row, att = snap["subjects"][s], snap["by_sid"].get(s, [])
        recs = [snap["records"][r] | {"record_id": r} for r, _h in att]
        counts = {o: 0 for o in OUTCOMES}
        for r in recs:
            if r["outcome"] in counts:
                counts[r["outcome"]] += 1
        href = None
        if row["kind"] == "page":
            hrefs = [(snap["records"][r]["witnessed_at"], snap["records"][r]["kept_at"], r, h) for r, h in att if h]
            href = max(hrefs)[3] if hrefs else None
        times = sorted(r["witnessed_at"] for r in recs)
        return dict(self._ref(row), href=href, records=len(recs), counts=counts,
                    first_witnessed_at=times[0] if times else None, last_witnessed_at=times[-1] if times else None)

    @staticmethod
    def _int(raw, name, lo, hi, default):
        if raw is None:
            return default
        if not isinstance(raw, str) or not INT.match(raw) or not lo <= int(raw) <= hi:
            raise WitnessError(422, "invalid-request", f"{name}: an integer from {lo} to {hi}")
        return int(raw)

    @staticmethod
    def _only(params, allowed):
        extra = set(params) - set(allowed)
        if extra:
            raise WitnessError(422, "invalid-request", f"unknown parameter(s): {', '.join(sorted(extra))}"
                                                       + (f" (this route takes {', '.join(allowed)})" if allowed else " (this route takes none)"))

    def _page(self, items, params):
        limit = self._int(params.get("limit"), "limit", 1, MAX_LIMIT, DEFAULT_LIMIT)
        offset = self._int(params.get("offset"), "offset", 0, MAX_OFFSET, 0)
        return items[offset:offset + limit], (offset + limit if len(items) > offset + limit else None)

    def subjects(self, params):
        self._only(params, ("kind", "parent", "prefix", "limit", "offset"))
        kind = params.get("kind")
        if kind not in KINDS:
            raise WitnessError(422, "invalid-request", "kind: page, site or profile (required)")
        parent = params.get("parent")
        if parent is not None and (kind != "page" or not SID.match(parent)):
            raise WitnessError(422, "invalid-request", "parent: a site or profile sid (32 lower-case hex), with kind=page only")
        prefix = params.get("prefix")
        if prefix is not None and prefix not in PREFIXES:
            raise WitnessError(422, "invalid-request", "prefix: a letter a-z or other")
        snap = self.snapshot()
        rows = [snap["subjects"][s] for s in snap["by_sid"] if s in snap["subjects"]]
        rows = [r for r in rows if r["kind"] == kind and (parent is None or r["parent_sid"] == parent)
                and (prefix is None or _letter(r["display"]) == prefix)]
        rows.sort(key=lambda r: (r["display"], r["sid"]))  # V38: A-Z only
        page, nxt = self._page(rows, params)
        return {"subjects": [self._full(snap, r["sid"]) for r in page], "next_offset": nxt}

    def subject(self, s, params):
        self._only(params, ())
        if not SID.match(s):
            raise WitnessError(422, "invalid-request", "a sid is 32 lower-case hex characters")
        snap = self.snapshot()
        if s not in snap["by_sid"] or s not in snap["subjects"]:
            raise WitnessError(404, "not-found", "no subject with a listed record has this sid")
        full = self._full(snap, s)
        prow = snap["subjects"].get(full["parent_sid"]) if full["parent_sid"] else None
        if prow is None and full["parent_sid"]:
            prow = self.st.get_subjects([full["parent_sid"]]).get(full["parent_sid"])
        children = sum(1 for c in snap["by_sid"] if c in snap["subjects"] and snap["subjects"][c]["kind"] == "page"
                       and snap["subjects"][c]["parent_sid"] == s)
        tcount = {}
        for r, _h in snap["by_sid"][s]:
            t = snap["records"][r]["type"]
            tcount[t] = tcount.get(t, 0) + 1
        return {"subject": full, "parent": self._ref(prow) if prow else None, "children": children,
                "types": [{"value": t, "records": tcount[t]} for t in TYPES if tcount.get(t)]}

    def _keyword(self, snap, w, rids):
        return {"word": w, "records": len(rids), "last_witnessed_at": max(snap["records"][r]["witnessed_at"] for r in rids)}

    def keywords(self, params):
        self._only(params, ("sort", "prefix", "limit", "offset"))
        sort = params.get("sort", "alpha")
        if sort not in ("alpha", "records"):
            raise WitnessError(422, "invalid-request", "sort: alpha or records")
        prefix = params.get("prefix")
        if prefix is not None and prefix not in PREFIXES:
            raise WitnessError(422, "invalid-request", "prefix: a letter a-z or other")
        snap = self.snapshot()
        items = [self._keyword(snap, w, rids) for w, rids in self._listed_words(snap).items()
                 if prefix is None or _letter(w) == prefix]
        items.sort(key=(lambda k: k["word"]) if sort == "alpha" else (lambda k: (-k["records"], k["word"])))
        page, nxt = self._page(items, params)
        return {"keywords": page, "next_offset": nxt}

    def keyword(self, raw, params):
        """(status, body, headers): 200, 301 to the canonical spelling (V21), or WitnessError 404."""
        self._only(params, ())
        try:
            word = urllib.parse.unquote(raw, errors="strict")
        except UnicodeDecodeError:
            raise WitnessError(404, "not-found", "no listed keyword") from None
        if not 1 <= len(word.encode("utf-8")) <= MAX_WORD_BYTES or any(unicodedata.category(c) == "Cc" for c in word):
            raise WitnessError(404, "not-found", "no listed keyword")
        canonical = normalize_word(word)
        if not WORD.fullmatch(canonical or ""):
            raise WitnessError(404, "not-found", "no listed keyword (a keyword is one word)")
        if canonical != word:
            return 301, {"canonical": canonical}, {"Location": "/v1/browse/keywords/" + urllib.parse.quote(canonical, safe="")}
        snap = self.snapshot()
        rids = self._listed_words(snap).get(canonical)
        if not rids:
            raise WitnessError(404, "not-found", "no listed keyword (a keyword is listed once three public records from at least "
                                                 "two accounts use it)")
        subj = {s for r in rids for s, _h in snap["links"].get(r, [])
                if s in snap["subjects"] and snap["subjects"][s]["kind"] in ("site", "profile")}
        return 200, {"keyword": self._keyword(snap, canonical, rids), "subjects": len(subj)}, {}

    def categories(self, params):
        self._only(params, ())
        snap = self.snapshot()
        tc, mc = {}, {}
        for r in snap["records"].values():
            tc[r["type"]] = tc.get(r["type"], 0) + 1
            if r["method"] in methods.METHODS:  # V24
                mc[r["method"]] = mc.get(r["method"], 0) + 1
        return {"facets": [
            {"facet": "type", "values": [{"facet": "type", "value": t, "label": TYPE_LABELS[t], "records": tc[t]}
                                         for t in TYPES if tc.get(t)]},
            {"facet": "method", "values": [{"facet": "method", "value": m, "label": m, "records": mc[m]} for m in sorted(mc)]}]}

    def record(self, rid, params):
        self._only(params, ())
        row = self.st.get_kept(rid)
        if row is None or row["visibility"] != "public" or row["deleted_at"] is not None:
            raise WitnessError(404, "not-found", "no listed public record with this id")
        if row["taken_down_at"] is not None:
            raise WitnessError(410, "taken-down", "this record was taken down")
        snap = self.snapshot()
        if rid not in snap["records"]:
            raise WitnessError(404, "not-found", "no listed public record with this id")
        listed = self._listed_words(snap)
        return {"record_id": rid, "type": snap["records"][rid]["type"],
                "subjects": [self._ref(snap["subjects"][s]) for s, _h in snap["links"].get(rid, []) if s in snap["subjects"]],
                "keywords": [w for w in snap["words"].get(rid, []) if w in listed], "method": row["method"]}

    def route(self, path, params):
        """(status, body, headers) for a GET /v1/browse/... path; WitnessError otherwise."""
        tail = path[len("/v1/browse/"):]
        if tail == "subjects":
            return 200, self.subjects(params), {}
        if tail.startswith("subjects/") and "/" not in tail[len("subjects/"):]:
            return 200, self.subject(tail[len("subjects/"):], params), {}
        if tail == "keywords":
            return 200, self.keywords(params), {}
        if tail.startswith("keywords/") and "/" not in tail[len("keywords/"):] and tail[len("keywords/"):]:
            return self.keyword(tail[len("keywords/"):], params)
        if tail == "categories":
            return 200, self.categories(params), {}
        if tail.startswith("records/") and HEX64.match(tail[len("records/"):]):
            return 200, self.record(tail[len("records/"):], params), {}
        raise WitnessError(404, "not-found", f"no route GET {path}")

    # ---------------------------------------------------------------------------------------------------- search

    def filter_ids(self, subject=None, keyword=None, rtype=None):
        """V31: the listed record ids matching every given browse filter."""
        snap = self.snapshot()
        ids = set(snap["records"])
        if subject is not None:
            ids &= {r for r, _h in snap["by_sid"].get(subject, [])}
        if keyword is not None:
            ids &= set(self._listed_words(snap).get(keyword, []))
        if rtype is not None:
            ids &= {r for r, x in snap["records"].items() if x["type"] == rtype}
        return ids

    def hit_fields(self, snap, rid):
        """V32: {type, subjects} of a search hit; null and [] for a record that is not listed."""
        if rid not in snap["records"]:
            return {"type": None, "subjects": []}
        return {"type": snap["records"][rid]["type"],
                "subjects": [self._ref(snap["subjects"][s]) for s, _h in snap["links"].get(rid, []) if s in snap["subjects"]]}
