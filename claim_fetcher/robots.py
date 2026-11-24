"""robots.txt: read through the capture's own egress proxy before the page, decided by RFC 9309 rules.

decide() maps the answer to the manifest's value:
- 2xx: the rules for AGENT (its own groups, else the '*' groups) -> "allowed" or "disallowed";
- 4xx (including 401 and 403): "allowed" (RFC 9309 2.3.1.3: no rules apply);
- 5xx, too many redirects, a refusal or a network failure: "unavailable".
"disallowed" stops the capture. "unavailable" lets it go ahead and is recorded (Builder decision 3 in
README_FETCHER.md); FETCHER_ROBOTS_UNAVAILABLE=deny turns it into a refusal, which is what the argus-claims toolkit does.
The parser is the toolkit's (fetch.py robots_rules / robots_allow), copied, not imported.
"""
import asyncio
import contextlib
import re
import ssl
import urllib.parse

from . import addr

AGENT = "OneDroidWitness"
AGENT_VERSION = "1.0"
CONTACT = "+https://onedroid.ai/witness"
MAX_ROBOTS_BYTES = 512 * 1024


def user_agent_for(browser_version=None):
    """The user agent: a desktop Chrome string with the browser's real version, then the witness's own token and a
    contact URL, so sites see an honest, identifiable bot. Without a version (robots.txt, read before the browser
    starts) only the token and the contact URL."""
    token = f"{AGENT}/{AGENT_VERSION} ({CONTACT})"
    if not browser_version:
        return token
    return ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
            f"Chrome/{browser_version} Safari/537.36 {token}")


def rules(text, agent=AGENT):
    groups, current, in_rules = [], None, False
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        key, sep, value = line.partition(":")
        key, value = key.strip().lower(), value.strip()
        if not sep:
            continue
        if key == "user-agent":
            if current is None or in_rules:
                current, in_rules = {"agents": set(), "rules": []}, False
                groups.append(current)
            token = value.split("/", 1)[0].split()[0].lower() if value.split() else ""
            current["agents"].add(token)
        elif key in ("allow", "disallow") and current is not None:
            in_rules = True
            if value:
                current["rules"].append((value, key == "allow"))
    mine = [r for g in groups if agent.lower() in g["agents"] for r in g["rules"]]
    if any(agent.lower() in g["agents"] for g in groups):
        return mine
    return [r for g in groups if "*" in g["agents"] for r in g["rules"]]


def _pattern(pattern):
    anchored = pattern.endswith("$")
    body = re.escape(pattern[:-1] if anchored else pattern).replace(r"\*", ".*")
    return re.compile(body + ("$" if anchored else ""))


def allow(rule_list, target):
    """Longest matching rule wins, Allow on a tie; no match allows."""
    if target == "/robots.txt":
        return True
    best = None
    for pattern, is_allow in rule_list:
        if _pattern(pattern).match(target):
            if best is None or len(pattern) > best[0] or (len(pattern) == best[0] and is_allow):
                best = (len(pattern), is_allow)
    return True if best is None else best[1]


def target_of(url):
    parts = urllib.parse.urlsplit(url)
    return (parts.path or "/") + (f"?{parts.query}" if parts.query else "")


def decide(status, body, path, agent=AGENT):
    if status is None:
        return "unavailable"
    if 200 <= status < 300:
        text = (body or b"").decode("utf-8", "replace")
        return "allowed" if allow(rules(text, agent), path) else "disallowed"
    if 400 <= status < 500:
        return "allowed"
    return "unavailable"


# fetching through the proxy -------------------------------------------------------------------------------------------

def _dechunk(data):
    out, i = bytearray(), 0
    while True:
        j = data.find(b"\r\n", i)
        if j < 0:
            break
        size_s = data[i:j].split(b";", 1)[0].strip()
        try:
            size = int(size_s, 16)
        except ValueError:
            break
        if size == 0:
            break
        out += data[j + 2:j + 2 + size]
        i = j + 2 + size + 2
    return bytes(out)


async def _get_once(proxy_socket, url, user_agent, ssl_context):
    """One GET through the proxy: (status, headers dict, body) or None on any failure."""
    scheme, host, port = addr.check_url(url)
    path = target_of(url)
    host_header = f"[{host}]" if ":" in host else host
    if port != (443 if scheme == "https" else 80):
        host_header += f":{port}"
    reader, writer = await asyncio.open_unix_connection(proxy_socket)
    try:
        if scheme == "https":
            authority = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
            writer.write(f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n".encode())
            await writer.drain()
            head = await reader.readuntil(b"\r\n\r\n")
            if head.split(b" ", 2)[1] != b"200":
                return None
            await writer.start_tls(ssl_context or ssl.create_default_context(), server_hostname=host)
            line = f"GET {path} HTTP/1.1"
        else:
            line = f"GET http://{host_header}{path} HTTP/1.1"
        writer.write((f"{line}\r\nHost: {host_header}\r\nUser-Agent: {user_agent}\r\nAccept: text/plain,*/*\r\n"
                      "Accept-Encoding: identity\r\nConnection: close\r\n\r\n").encode())
        await writer.drain()
        head = await reader.readuntil(b"\r\n\r\n")
        lines = head.decode("latin-1").split("\r\n")
        status = int(lines[0].split(" ")[1])
        headers = {}
        for h in lines[1:]:
            k, sep, v = h.partition(":")
            if sep:
                headers[k.strip().lower()] = v.strip()
        body = bytearray()
        while len(body) <= MAX_ROBOTS_BYTES:
            chunk = await reader.read(65536)
            if not chunk:
                break
            body += chunk
        body = bytes(body[:MAX_ROBOTS_BYTES + 16])
        if "chunked" in headers.get("transfer-encoding", "").lower():
            body = _dechunk(body)
        return status, headers, body[:MAX_ROBOTS_BYTES]
    except (OSError, asyncio.IncompleteReadError, asyncio.LimitOverrunError, ValueError, IndexError, ssl.SSLError):
        return None
    finally:
        with contextlib.suppress(Exception):
            writer.close()


async def fetch(proxy_socket, page_url, user_agent, ssl_context=None, max_redirects=addr.MAX_REDIRECTS):
    """(status, body) of the robots.txt for page_url's origin, following redirects through the proxy; (None, None)
    when it cannot be read."""
    parts = urllib.parse.urlsplit(page_url)
    url = f"{parts.scheme}://{parts.netloc}/robots.txt"
    for hop in range(max_redirects + 1):
        got = await _get_once(proxy_socket, url, user_agent, ssl_context)
        if got is None:
            return None, None
        status, headers, body = got
        if status in (301, 302, 303, 307, 308) and headers.get("location"):
            try:
                url = addr.next_hop(url, headers["location"], hop + 1, max_redirects)
            except addr.Refused:
                return None, None
            continue
        return status, body
    return None, None
