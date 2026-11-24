"""B2b (d): the "two resolvers" NXDOMAIN check uses a small standard-library DNS client (claim_witness/dns.py) against
configurable resolvers (WITNESS_RESOLVERS). Tested against a local UDP DNS server."""
import socket
import struct
import threading
import unittest

from claim_witness import dns


class FakeDNS:
    """Answers each A query: rcode 3 (NXDOMAIN) for names in `gone`, rcode 0 with no answer otherwise; `silent` drops all."""

    def __init__(self, gone=(), silent=False):
        self.gone, self.silent, self.asked = set(gone), silent, []
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self.serve, daemon=True).start()

    def serve(self):
        while True:
            try:
                data, addr = self.sock.recvfrom(512)
            except OSError:
                return
            qid = data[:2]
            labels, i = [], 12
            while data[i]:
                labels.append(data[i + 1:i + 1 + data[i]].decode())
                i += 1 + data[i]
            name = ".".join(labels)
            self.asked.append(name)
            if self.silent:
                continue
            rcode = 3 if name in self.gone else 0
            flags = 0x8180 | rcode
            self.sock.sendto(qid + struct.pack(">HHHHH", flags, 1, 0, 0, 0) + data[12:i + 5], addr)

    def close(self):
        self.sock.close()


class Resolver(unittest.TestCase):
    def test_nxdomain_exists_and_error(self):
        srv = FakeDNS(gone={"gone.example"})
        try:
            r = dns.UdpResolver("127.0.0.1", port=srv.port, timeout=2)
            self.assertEqual(r.query("gone.example"), "nxdomain")
            self.assertEqual(r.query("there.example"), "exists")
            self.assertEqual(srv.asked, ["gone.example", "there.example"])
        finally:
            srv.close()
        quiet = FakeDNS(silent=True)
        try:
            self.assertEqual(dns.UdpResolver("127.0.0.1", port=quiet.port, timeout=0.3).query("x.example"), "error")
        finally:
            quiet.close()

    def test_resolvers_from_env(self):
        rs = dns.resolvers_from_env({"WITNESS_RESOLVERS": "1.1.1.1, 9.9.9.9:5353"})
        self.assertEqual([(r.host, r.port) for r in rs], [("1.1.1.1", 53), ("9.9.9.9", 5353)])
        self.assertEqual(len(dns.resolvers_from_env({})), 2)  # the defaults: two public resolvers


if __name__ == "__main__":
    unittest.main()
