"""canon/1 (SPEC §9.1), pure Python, standard library only.

1. Parse: HTML through html.parser; drop script, style, noscript, template, svg, iframe, head; drop elements with `hidden`,
   aria-hidden="true", inline display:none or visibility:hidden; at the rendered layer only, also data-witness-hidden.
2. Lines: block elements end a line.
3. Characters: NFKC, then quotes, dashes and the ellipsis unified, every space character a space.
4. Relative times become <reltime>.
5. Whitespace: runs folded to one space, each line trimmed, empty lines dropped, lines joined with \\n. Case is kept.
Plain-text input skips step 1.
"""
import html.parser
import re
import unicodedata

CANON_ID = "canon/1"
DROP = {"script", "style", "noscript", "template", "svg", "iframe", "head"}
BLOCK = {"p", "div", "li", "h1", "h2", "h3", "h4", "h5", "h6", "tr", "br", "section", "article", "header", "footer", "main",
         "nav", "aside", "blockquote", "pre", "table"}
VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}
HTML_TYPES = {"text/html", "application/xhtml+xml"}

CHAR_MAP = str.maketrans({
    "‘": "'", "’": "'", "‚": "'", "′": "'",
    "“": '"', "”": '"', "„": '"', "″": '"',
    "–": "-", "—": "-", "‒": "-", "−": "-",
    "…": "...",
})
RELTIME = re.compile(r"\b\d+\s+(?:second|minute|hour|day|week|month|year)s?\s+ago\b|\bjust now\b|\byesterday\b", re.IGNORECASE)
INLINE_WS = re.compile(r"[^\S\n]+")


def _hidden_style(style):
    s = re.sub(r"\s+", "", (style or "").lower())
    return any(d in s.split(";") for d in ("display:none", "visibility:hidden")) or \
        bool(re.search(r"(^|;)display:none(!important)?(;|$)|(^|;)visibility:hidden(!important)?(;|$)", s))


class _Text(html.parser.HTMLParser):
    def __init__(self, layer):
        super().__init__(convert_charrefs=True)
        self.layer = layer
        self.stack = []  # open (tag, dropping) entries
        self.out = []

    def _dropping(self):
        return bool(self.stack) and self.stack[-1][1]

    def _drops(self, tag, attrs):
        if tag in DROP:
            return True
        a = {k.lower(): (v if v is not None else "") for k, v in attrs}
        if "hidden" in a:
            return True
        if a.get("aria-hidden", "").strip().lower() == "true":
            return True
        if _hidden_style(a.get("style")):
            return True
        if self.layer == "rendered" and "data-witness-hidden" in a:
            return True
        return False

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        # implicit closes, as a browser would: a block start closes an open <p>; <li> closes an open <li>
        if self.stack and self.stack[-1][0] == "p" and tag in BLOCK and tag != "br":
            self._close("p")
        if tag == "li" and self.stack and self.stack[-1][0] == "li":
            self._close("li")
        if tag == "body":
            self._close("head")
        dropping = self._dropping() or self._drops(tag, attrs)
        if tag in BLOCK and not dropping:
            self.out.append("\n")
        if tag in VOID:
            return
        self.stack.append((tag, dropping))

    def handle_startendtag(self, tag, attrs):
        tag = tag.lower()
        if tag in BLOCK and not (self._dropping() or self._drops(tag, attrs)):
            self.out.append("\n")

    def _close(self, tag):
        for i in range(len(self.stack) - 1, -1, -1):
            if self.stack[i][0] == tag:
                popped = self.stack[i:]
                del self.stack[i:]
                if not popped[0][1] and tag in BLOCK:
                    self.out.append("\n")
                return

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag in VOID:
            if tag == "br" and not self._dropping():
                self.out.append("\n")
            return
        self._close(tag)

    def handle_data(self, data):
        if not self._dropping():
            self.out.append(data)


def html_text(markup, layer="response"):
    p = _Text(layer)
    p.feed(markup)
    p.close()
    return "".join(p.out)


def normalise(text):
    """Steps 3 to 5 over text that already has its line structure."""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = unicodedata.normalize("NFKC", text.translate(CHAR_MAP)).translate(CHAR_MAP)
    text = "".join(" " if (unicodedata.category(c) == "Zs" or c in "\t\f\v") else c for c in text)
    text = RELTIME.sub("<reltime>", text)
    lines = (INLINE_WS.sub(" ", line).strip() for line in text.split("\n"))
    return "\n".join(line for line in lines if line)


def decode(data):
    """UTF-8 text of bytes (a BOM dropped), or None when the bytes are not UTF-8 or hold NUL bytes."""
    if isinstance(data, str):
        return data
    if data.startswith(b"\xef\xbb\xbf"):
        data = data[3:]
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if "\x00" in text:
        return None
    return text


def is_html(media_type):
    return (media_type or "").split(";")[0].strip().lower() in HTML_TYPES


def canon1(data, media_type="text/plain", layer="response"):
    """The canon/1 text of data (bytes or str). Raises ValueError when bytes are not readable text."""
    text = decode(data)
    if text is None:
        raise ValueError("not UTF-8 text")
    if is_html(media_type):
        text = html_text(text, layer)
    return normalise(text)
