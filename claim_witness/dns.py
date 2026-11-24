"""A minimal DNS client (standard library, UDP, one A query) for page.live's "NXDOMAIN from two resolvers" (SPEC §4).

query(host) answers "nxdomain" (RCODE 3), "exists" (RCODE 0, with or without an A answer: the name exists) or "error"
(a timeout, another RCODE, a malformed or mismatched answer). Resolvers come from WITNESS_RESOLVERS, comma separated
`ip[:port]`, default two public resolvers from different operators.
"""
import os
import socket
import struct

DEFAULT_RESOLVERS = "1.1.1.1,8.8.8.8"


class UdpResolver:
    def __init__(self, host, port=53, timeout=3.0):
        self.host, self.port, self.timeout = host, int(port), float(timeout)

    def __repr__(self):
        return f"UdpResolver({self.host}:{self.port})"

    def query(self, host):
        try:
            qname = b"".join(bytes([len(p)]) + p for p in host.rstrip(".").encode("idna").split(b".")) + b"\x00"
        except UnicodeError:
            return "error"
        qid = os.urandom(2)
        packet = qid + struct.pack(">HHHHH", 0x0100, 1, 0, 0, 0) + qname + struct.pack(">HH", 1, 1)
        fam = socket.AF_INET6 if ":" in self.host else socket.AF_INET
        try:
            with socket.socket(fam, socket.SOCK_DGRAM) as s:
                s.settimeout(self.timeout)
                s.sendto(packet, (self.host, self.port))
                while True:
                    data, _ = s.recvfrom(4096)
                    if len(data) >= 12 and data[:2] == qid:
                        break
        except OSError:
            return "error"
        flags = struct.unpack(">H", data[2:4])[0]
        if not flags & 0x8000:
            return "error"
        rcode = flags & 0x000F
        if rcode == 3:
            return "nxdomain"
        if rcode == 0:
            return "exists"
        return "error"


def resolvers_from_env(env):
    out = []
    for item in (env.get("WITNESS_RESOLVERS") or DEFAULT_RESOLVERS).split(","):
        item = item.strip()
        if not item:
            continue
        if item.count(":") == 1:
            host, port = item.split(":")
            out.append(UdpResolver(host, int(port)))
        else:
            out.append(UdpResolver(item.strip("[]")))
    return out
