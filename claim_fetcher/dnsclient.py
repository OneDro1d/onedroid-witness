"""A small DNS stub client (standard library only): the fetcher's one way to turn a capture target's name into
addresses. It never calls the system resolver (getaddrinfo), so no query goes to the pod's cluster DNS service, which
sits on a private address the fetcher must not talk to.

- The resolvers are configured (FETCHER_RESOLVERS, default 1.1.1.1,8.8.8.8) and each must pass the egress address
  rules itself (addr.ip_allowed: public, outside FETCHER_BLOCKED_CIDRS); otherwise ValueError, and the service does not
  start.
- For a name it asks the first resolver for A, then AAAA, over UDP (a connected socket, so only that resolver's replies
  are read, a random 16-bit ID and the kernel's random source port), retrying over TCP when the answer is truncated.
  A resolver that does not answer, or answers SERVFAIL/REFUSED, is passed over for the next one.
- An answer is used only when its ID, flags and question match the query; addresses are taken from the CNAME chain that
  starts at the asked name (other records in the answer are ignored). A first, then AAAA.
- NXDOMAIN is an answer (no second opinion is asked): NXDomain, an OSError, which addr.vet_host turns into
  `unreachable`, like every other failure here.
The query name is always absolute: there is no search list.
"""
import ipaddress
import re
import secrets
import socket
import struct
import time

from . import addr

DEFAULT_RESOLVERS = ("1.1.1.1", "8.8.8.8")
PORT = 53
TYPE_A, TYPE_CNAME, TYPE_AAAA = 1, 5, 28
CLASS_IN = 1
RCODE_NOERROR, RCODE_NXDOMAIN = 0, 3
MAX_UDP = 4096
MAX_CNAME_HOPS = 16


class DNSError(OSError):
    """No usable answer (timeouts, SERVFAIL, a malformed or mismatched reply)."""


class NXDomain(DNSError):
    """The resolver answered that the name does not exist."""


def parse_resolvers(text, extra=()):
    """FETCHER_RESOLVERS (comma or space separated IP addresses) -> a tuple of addresses. ValueError for an empty list,
    anything that is not an IP address, or an address the egress rules refuse."""
    items = [i for i in re.split(r"[\s,]+", (text or "").strip()) if i]
    if not items:
        raise ValueError("FETCHER_RESOLVERS lists no resolver")
    out = []
    for item in items:
        try:
            ip = str(ipaddress.ip_address(item))
        except ValueError:
            raise ValueError(f"resolver {item!r} is not an IP address") from None
        if not addr.ip_allowed(ip, extra):
            raise ValueError(f"resolver {ip} is not a public address (the fetcher talks only to public addresses)")
        if ip not in out:
            out.append(ip)
    return tuple(out)


# wire format ----------------------------------------------------------------------------------------------------------

def encode_query(qid, name, qtype):
    out = bytearray(struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0))  # RD, one question
    labels = name.rstrip(".").split(".")
    for label in labels:
        raw = label.encode("ascii")
        if not 0 < len(raw) <= 63:
            raise DNSError(f"bad name {name!r}")
        out += bytes([len(raw)]) + raw
    out += b"\x00"
    if len(out) - 12 > 255:
        raise DNSError(f"name too long {name!r}")
    out += struct.pack("!HH", qtype, CLASS_IN)
    return bytes(out)


def _read_name(msg, off):
    """(lowercased name, offset after it), following compression pointers (bounded)."""
    labels, end, hops = [], None, 0
    while True:
        if off >= len(msg):
            raise DNSError("truncated name")
        n = msg[off]
        if n & 0xC0 == 0xC0:
            if off + 1 >= len(msg):
                raise DNSError("truncated pointer")
            if end is None:
                end = off + 2
            hops += 1
            ptr = ((n & 0x3F) << 8) | msg[off + 1]
            if hops > 64 or ptr >= len(msg):
                raise DNSError("bad compression pointer")
            off = ptr
            continue
        if n & 0xC0:
            raise DNSError("bad label type")
        off += 1
        if n == 0:
            break
        if off + n > len(msg):
            raise DNSError("truncated label")
        labels.append(msg[off:off + n].decode("ascii", "replace").lower())
        off += n
    return ".".join(labels), (end if end is not None else off)


def parse_response(msg, qid, name, qtype):
    """(rcode, truncated, addresses) of a reply to the query (qid, name, qtype). DNSError when it is not one."""
    if len(msg) < 12:
        raise DNSError("short reply")
    rid, flags, qdcount, ancount, _ns, _ar = struct.unpack("!HHHHHH", msg[:12])
    if rid != qid or not flags & 0x8000 or (flags >> 11) & 0xF != 0 or qdcount != 1:
        raise DNSError("not an answer to this query")
    qname, off = _read_name(msg, 12)
    if off + 4 > len(msg):
        raise DNSError("truncated question")
    qt, qc = struct.unpack("!HH", msg[off:off + 4])
    off += 4
    want = name.rstrip(".").lower()
    if qname != want or qt != qtype or qc != CLASS_IN:
        raise DNSError("answer to another question")
    truncated, rcode = bool(flags & 0x0200), flags & 0xF
    if truncated:
        return rcode, True, []
    records = []
    for _ in range(ancount):
        owner, off = _read_name(msg, off)
        if off + 10 > len(msg):
            raise DNSError("truncated record")
        rtype, rclass, _ttl, rdlen = struct.unpack("!HHIH", msg[off:off + 10])
        off += 10
        if off + rdlen > len(msg):
            raise DNSError("truncated record data")
        if rclass == CLASS_IN:
            if rtype == TYPE_CNAME:
                records.append((owner, rtype, _read_name(msg, off)[0]))
            elif rtype == qtype and rtype in (TYPE_A, TYPE_AAAA) and rdlen == (4 if rtype == TYPE_A else 16):
                records.append((owner, rtype, str(ipaddress.ip_address(msg[off:off + rdlen]))))
        off += rdlen
    # the CNAME chain from the asked name; only its addresses count
    chain, current = {want}, want
    cnames = {o: v for o, t, v in records if t == TYPE_CNAME}
    for _ in range(MAX_CNAME_HOPS):
        if current not in cnames:
            break
        current = cnames[current]
        chain.add(current)
    ips = []
    for owner, rtype, value in records:
        if rtype == qtype and owner in chain and value not in ips:
            ips.append(value)
    return rcode, False, ips


# transports (module functions, so tests can stand in for the network) --------------------------------------------------

def _socket_for(server, kind):
    return socket.socket(socket.AF_INET6 if ":" in server else socket.AF_INET, kind)


def udp_exchange(server, packet, timeout):
    """Send `packet` to server:53 over UDP; the first reply carrying the same ID. socket.timeout when none comes."""
    deadline = time.monotonic() + timeout
    with _socket_for(server, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        s.connect((server, PORT))  # a numeric address: no lookup; a connected socket reads only that peer's datagrams
        s.send(packet)
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                raise socket.timeout("dns udp timeout")
            s.settimeout(left)
            data = s.recv(MAX_UDP)
            if data[:2] == packet[:2]:
                return data


def _recv_exact(s, n, deadline):
    buf = b""
    while len(buf) < n:
        left = deadline - time.monotonic()
        if left <= 0:
            raise socket.timeout("dns tcp timeout")
        s.settimeout(left)
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise DNSError("dns tcp connection closed")
        buf += chunk
    return buf


def tcp_exchange(server, packet, timeout):
    """The same query over TCP (two-byte length prefix), for a truncated UDP answer."""
    deadline = time.monotonic() + timeout
    with _socket_for(server, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        s.connect((server, PORT))
        s.sendall(struct.pack("!H", len(packet)) + packet)
        size = struct.unpack("!H", _recv_exact(s, 2, deadline))[0]
        return _recv_exact(s, size, deadline)


# the resolver ---------------------------------------------------------------------------------------------------------

class PublicResolver:
    """resolver(host) -> [addresses], A first then AAAA, or an OSError (NXDomain, DNSError). Used by addr.vet_host,
    the egress proxy and the capture's pre-check in place of the system resolver."""

    def __init__(self, servers, extra=(), timeout=4.0, per_try=2.0, udp=None, tcp=None):
        self.servers = parse_resolvers(",".join(servers), extra)
        self.timeout, self.per_try = timeout, per_try
        self._udp, self._tcp = udp, tcp

    def __repr__(self):
        return f"PublicResolver({list(self.servers)})"

    def _query(self, server, name, qtype, deadline):
        qid = secrets.randbits(16)
        packet = encode_query(qid, name, qtype)
        left = min(self.per_try, deadline - time.monotonic())
        if left <= 0:
            raise DNSError("resolve-timeout")
        reply = (self._udp or udp_exchange)(server, packet, left)
        rcode, truncated, ips = parse_response(reply, qid, name, qtype)
        if truncated:
            left = min(self.per_try, deadline - time.monotonic())
            if left <= 0:
                raise DNSError("resolve-timeout")
            rcode, truncated, ips = parse_response((self._tcp or tcp_exchange)(server, packet, left), qid, name, qtype)
            if truncated:
                raise DNSError("truncated over tcp")
        return rcode, ips

    def __call__(self, host):
        name = host.rstrip(".").lower()
        deadline = time.monotonic() + self.timeout
        last, partial = None, []
        for server in self.servers:
            try:
                rc_a, ips_a = self._query(server, name, TYPE_A, deadline)
                if rc_a == RCODE_NXDOMAIN:
                    raise NXDomain(f"nxdomain {name} ({server})")
                rc_6, ips_6 = self._query(server, name, TYPE_AAAA, deadline)
            except NXDomain:
                raise
            except OSError as e:  # socket.timeout and DNSError included
                last = e
                continue
            ips = ips_a + [ip for ip in ips_6 if ip not in ips_a]
            if rc_a == RCODE_NOERROR and rc_6 in (RCODE_NOERROR, RCODE_NXDOMAIN):
                return ips
            last = DNSError(f"rcode A={rc_a} AAAA={rc_6} from {server}")
            partial = partial or ips
        if partial:
            return partial
        raise DNSError(f"no resolver answered for {name}: {type(last).__name__ if last else ''} {last or ''}".strip())


def default_resolver(extra=()):
    return PublicResolver(DEFAULT_RESOLVERS, extra=extra)
