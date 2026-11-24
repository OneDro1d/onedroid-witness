"""B2b (a): the witness's fetcher client (env FETCHER_URL, FETCHER_SECRET_FILE). It sends X-Fetcher-Secret, reads the tar
(manifest.json first), checks every file against the manifest, and maps the fetcher's error codes to the SPEC reasons
(blocked, unreachable, timeout, too-large, robots-disallowed). The error body may carry a partial manifest or not. Fetcher-side
failures (busy after retries, unauthorized, internal, no answer, a bad tar) are `unreachable` with code fetcher-unavailable:
never an exception the caller sees as 5xx."""
import socket
import unittest

from claim_witness import fetcher
from tests_claim import helpers as h
from tests_claim.fakefetch import FakeFetcher, drop, error, page

U = "https://a.example/page"


class Client(unittest.TestCase):
    def setUp(self):
        self.clock = h.Clock()
        self.ff = FakeFetcher(self.clock)
        self.c = self.ff.client()

    def tearDown(self):
        self.ff.close()

    def test_capture_reads_the_tar_and_checks_files(self):
        self.ff.set(U, page(b"<p>Hi</p>"))
        cap = self.c.capture(U)
        self.assertEqual(cap.manifest["requested_url"], U)
        self.assertEqual(cap.manifest["status"], 200)
        self.assertEqual(cap.files["response.body"], b"<p>Hi</p>")
        self.assertEqual(set(cap.files), {e["name"] for e in cap.manifest["files"]})
        self.assertEqual(self.ff.calls[0]["capture"], "page")

    def test_error_codes_map_to_spec_reasons(self):
        cases = {"blocked": "blocked", "robots-disallowed": "robots-disallowed", "timeout": "timeout", "too-large": "too-large",
                 "unreachable": "unreachable", "scheme": "blocked", "port": "blocked", "bad-request": "blocked"}
        for code, reason in cases.items():
            self.ff.set(U, error(code, "why"))
            with self.assertRaises(fetcher.FetchFailed) as cm:
                self.c.capture(U)
            self.assertEqual((cm.exception.reason, cm.exception.code), (reason, code), code)
            self.assertIn(cm.exception.reason, ("blocked", "unreachable", "timeout", "too-large", "robots-disallowed"))

    def test_nxdomain_is_flagged_from_the_detail(self):
        self.ff.set(U, error("unreachable", "host-not-found a.example"))
        with self.assertRaises(fetcher.FetchFailed) as cm:
            self.c.capture(U)
        self.assertTrue(cm.exception.nxdomain)
        self.ff.set(U, error("unreachable", "connect-failed OSError"))
        with self.assertRaises(fetcher.FetchFailed) as cm:
            self.c.capture(U)
        self.assertFalse(cm.exception.nxdomain)

    def test_error_body_with_and_without_partial_manifest(self):
        partial = {"requested_url": U, "redirects": [{"url": U, "status": 302, "location": "http://10.0.0.1/"}],
                   "fetched_at": h.iso(self.clock()), "fetch_ms": 40, "resolved_ips": ["93.184.215.14"], "robots": "allowed"}
        self.ff.set(U, error("blocked", "redirect to a private address", manifest=partial))
        with self.assertRaises(fetcher.FetchFailed) as cm:
            self.c.capture(U)
        self.assertEqual(cm.exception.partial["redirects"], partial["redirects"])
        self.assertEqual(cm.exception.partial["robots"], "allowed")
        self.ff.set(U, error("blocked", "private address"))
        with self.assertRaises(fetcher.FetchFailed) as cm:
            self.c.capture(U)
        self.assertIsNone(cm.exception.partial)

    def test_silent_drop_from_the_fetcher_is_timeout_408(self):
        self.ff.set(U, error("timeout", "connect-timeout", status=408))
        with self.assertRaises(fetcher.FetchFailed) as cm:
            self.c.capture(U)
        self.assertEqual(cm.exception.reason, "timeout")

    def test_busy_is_retried(self):
        self.ff.set(U, error("busy", "two captures"), page())
        cap = self.c.capture(U)
        self.assertEqual(cap.manifest["status"], 200)
        self.assertEqual(len(self.ff.calls), 2)

    def test_always_busy_is_fetcher_unavailable(self):
        self.ff.set(U, error("busy", "two captures"))
        with self.assertRaises(fetcher.FetchFailed) as cm:
            self.c.capture(U)
        self.assertEqual((cm.exception.reason, cm.exception.code), ("unreachable", "fetcher-unavailable"))
        self.assertGreaterEqual(len(self.ff.calls), 2)

    def test_wrong_secret_internal_and_no_answer_are_fetcher_unavailable(self):
        bad = fetcher.FetcherClient(self.ff.url, "not-the-secret-0123456789", busy_delay_s=0)
        self.ff.set(U, page())
        for client, answer in ((bad, page()), (self.c, error("internal", "RuntimeError")), (self.c, drop())):
            self.ff.set(U, answer)
            with self.assertRaises(fetcher.FetchFailed) as cm:
                client.capture(U)
            self.assertEqual((cm.exception.reason, cm.exception.code), ("unreachable", "fetcher-unavailable"))

    def test_fetcher_down_is_fetcher_unavailable(self):
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        c = fetcher.FetcherClient(f"http://127.0.0.1:{port}", "x" * 20, busy_delay_s=0)
        with self.assertRaises(fetcher.FetchFailed) as cm:
            c.capture(U)
        self.assertEqual((cm.exception.reason, cm.exception.code), ("unreachable", "fetcher-unavailable"))

    def test_a_file_that_does_not_match_the_manifest_is_refused(self):
        self.ff.set(U, page(tamper="response.body"))
        with self.assertRaises(fetcher.FetchFailed) as cm:
            self.c.capture(U)
        self.assertEqual(cm.exception.code, "fetcher-unavailable")

    def test_from_env(self):
        c = fetcher.FetcherClient.from_env({"FETCHER_URL": self.ff.url, "FETCHER_SECRET_FILE": str(self.ff.secret_file)})
        self.ff.set(U, page())
        self.assertEqual(c.capture(U).manifest["status"], 200)
        self.assertIsNone(fetcher.FetcherClient.from_env({}))
        with self.assertRaises(SystemExit):
            fetcher.FetcherClient.from_env({"FETCHER_URL": self.ff.url})


if __name__ == "__main__":
    unittest.main()
