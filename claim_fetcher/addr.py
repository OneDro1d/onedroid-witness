"""Egress address rules: which URLs, ports, host names and addresses the fetcher may reach. Standard library only.

Every decision the proxy and the API make goes through here:
- check_url: http or https, no credentials, a host, port 80 or 443 (whatever the scheme);
- vet_host: the name rules, then one resolution, then every address must be allowed (a mixed answer is refused);
- ip_allowed: global, outside the refused ranges and the configured cluster CIDRs, with IPv4-mapped addresses judged
  as the IPv4 they carry and every other IPv4-carrying IPv6 form (compat, NAT64, 6to4, Teredo) refused outright;
- next_hop: a redirect's absolute URL, checked like a first URL, at most MAX_REDIRECTS hops.

Ideas reused from the argus-claims toolkit's fetch.py (is_public, Fetcher._vet): resolve once, refuse unless every
address is public, dial only the vetted address.
"""
import ipaddress
import re
import socket
import urllib.parse

ALLOWED_PORTS = frozenset({80, 443})
ALLOWED_SCHEMES = ("http", "https")
MAX_REDIRECTS = 5

REFUSED_NETWORKS = tuple(ipaddress.ip_network(n) for n in (
    # IPv4
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "168.63.129.16/32",
    "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15",
    "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
    # IPv6; the IPv4-carrying forms: compat ::/96, NAT64 64:ff9b::/96 and 64:ff9b:1::/48, 6to4 2002::/16, Teredo
    "::/128", "::1/128", "::/96", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64", "2001::/32", "2001:db8::/32",
    "2002::/16", "fc00::/7", "fe80::/10", "fec0::/10", "ff00::/8",
))

# names that resolve inside a cluster, a host or a LAN, refused before any DNS (defence in depth: the address rules
# would refuse what they resolve to anyway)
REFUSED_SUFFIXES = ("localhost", "local", "localdomain", "internal", "home.arpa", "lan", "svc", "cluster.local")
_HOST_CHARS = re.compile(r"^[a-z0-9_.-]+$")
_NUMERIC_CHARS = re.compile(r"^[0-9a-fx.]+$")


class Refused(Exception):
    """A refusal with one of the API's reason codes: blocked, scheme, port, unreachable."""

    def __init__(self, code, detail=""):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code, self.detail = code, detail


def parse_cidrs(text):
    """Comma or space separated CIDRs (FETCHER_BLOCKED_CIDRS) -> tuple of networks. Anything unparsable raises
    ValueError, so a placeholder left in a manifest stops the service at start rather than being ignored."""
    if not text:
        return ()
    out = []
    for item in re.split(r"[\s,]+", text.strip()):
        if item:
            out.append(ipaddress.ip_network(item, strict=False))
    return tuple(out)


def _parse_ip(ip):
    if not isinstance(ip, str) or not ip:
        return None
    ip = ip.strip()
    if ip.startswith("[") and ip.endswith("]"):
        ip = ip[1:-1]
    if "%" in ip:  # a zone id: only link-local addresses carry one
        return None
    try:
        return ipaddress.ip_address(ip)
    except ValueError:
        return None


def ip_allowed(ip, extra=()):
    """True only for a global address outside REFUSED_NETWORKS and `extra`. IPv4-mapped IPv6 is judged as its IPv4."""
    a = _parse_ip(ip)
    if a is None:
        return False
    if a.version == 6 and a.ipv4_mapped is not None:
        a = a.ipv4_mapped
    for net in REFUSED_NETWORKS + tuple(extra):
        if net.version == a.version and a in net:
            return False
    return bool(a.is_global)


def numeric_host(host):
    """The address a host string denotes without DNS (dotted, bracketed IPv6, and the legacy inet_aton forms a browser
    or resolver also accepts: 2130706433, 0x7f000001, 017700000001, 127.1), else None."""
    h = host.strip().lower()
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    a = _parse_ip(h)
    if a is not None:
        return str(a)
    if _NUMERIC_CHARS.match(h):
        try:
            return socket.inet_ntoa(socket.inet_aton(h))
        except OSError:
            return None
    return None


def resolve(host):
    """The system resolver, asked for the absolute name (a trailing dot: the pod's DNS search list never expands it).
    Addresses in the resolver's order, without duplicates."""
    ips = []
    for info in socket.getaddrinfo(host.rstrip(".") + ".", 443, type=socket.SOCK_STREAM):
        if info[4][0] not in ips:
            ips.append(info[4][0])
    return ips


def name_refused(host):
    """A reason when a host name is refused by name alone, else None."""
    h = host.rstrip(".").lower()
    if not h or not _HOST_CHARS.match(h) or ".." in h:
        return "bad-host"
    if "." not in h:
        return "single-label"
    for suffix in REFUSED_SUFFIXES:
        if h == suffix or h.endswith("." + suffix):
            return "internal-name"
    return None


def vet_host(host, port, resolver=None, extra=()):
    """The vetted addresses for host:port, in the resolver's order; resolves exactly once. Raises Refused."""
    if port not in ALLOWED_PORTS:
        raise Refused("port", str(port))
    num = numeric_host(host)
    if num is not None:
        if not ip_allowed(num, extra):
            raise Refused("blocked", f"address-not-public {num}")
        return [num]
    why = name_refused(host)
    if why:
        raise Refused("blocked", f"{why} {host}")
    try:
        ips = list((resolver or resolve)(host.rstrip(".").lower()))
    except (OSError, UnicodeError, ValueError):
        raise Refused("unreachable", f"host-not-found {host}") from None
    if not ips:
        raise Refused("unreachable", f"host-not-found {host}")
    bad = [ip for ip in ips if not ip_allowed(ip, extra)]
    if bad:
        raise Refused("blocked", f"host-not-public {host}")
    return ips


def check_url(url):
    """(scheme, host, port) of an allowed URL; the host lowercased and IDNA-encoded. Raises Refused."""
    if not isinstance(url, str) or not url:
        raise Refused("scheme", "no-url")
    try:
        parts = urllib.parse.urlsplit(url.strip())
    except ValueError:
        raise Refused("scheme", "unparsable") from None
    scheme = parts.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise Refused("scheme", scheme or "none")
    try:
        port = parts.port
    except ValueError:
        raise Refused("port", "invalid") from None
    if parts.username is not None or parts.password is not None:
        raise Refused("blocked", "credentials-in-url")
    host = parts.hostname
    if not host:
        raise Refused("blocked", "no-host")
    if port is None:
        port = 443 if scheme == "https" else 80
    if port not in ALLOWED_PORTS:
        raise Refused("port", str(port))
    try:
        host.encode("ascii")
    except UnicodeEncodeError:
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError:
            raise Refused("blocked", "bad-host") from None
    return scheme, host.lower(), port


def check_target(url, resolver=None, extra=()):
    """check_url, then vet_host: (scheme, host, port, vetted addresses)."""
    scheme, host, port = check_url(url)
    return scheme, host, port, vet_host(host, port, resolver=resolver, extra=extra)


def next_hop(current, location, hops, max_redirects=MAX_REDIRECTS):
    """The absolute URL a redirect at hop number `hops` (1-based) points to, after the URL rules. Raises Refused."""
    if hops > max_redirects:
        raise Refused("blocked", f"too-many-redirects ({hops} > {max_redirects})")
    url = urllib.parse.urljoin(current, location)
    check_url(url)
    return url
