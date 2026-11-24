"""Public screening (§3, VR-21, TS-22, BD11): signed fields through the redact helper (WITNESS_REDACT_BIN, tools/redact-copy)
plus the personal-data rules; image and PDF objects refused on public claims; private claims are not screened."""
import unittest

from claim_witness import screen
from tests_claim import helpers as h
from tests_claim.helpers import claim, obj_item, payload_of, request

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32
PDF = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n1 0 obj\n"


class Base(unittest.TestCase):
    redact = None

    def setUp(self):
        self.s = h.Stack(redact_bin=self.redact)

    def tearDown(self):
        self.s.close()

    def call(self, body):
        before = self.s.log_count()
        code, out, _ = self.s.witness_call(body)
        if code != 200:
            self.assertEqual(self.s.log_count(), before)
        return code, out


class PersonalDataTS22(Base):
    def quote(self, q, visibility="public", name="source.txt", data=None):
        data = data if data is not None else f"prefix {q} suffix".encode()
        return request(claim("quote.in-source", {"quote": q}), [obj_item("source", data, name=name)], visibility)

    def test_email_in_public_quote_422_personal_data(self):
        code, out = self.call(self.quote("write to jan.kowalski@example.pl today"))
        self.assertEqual(code, 422, out)
        self.assertEqual(out["error"], "personal-data")
        self.assertIn("private", out["detail"])

    def test_phone_in_public_quote_422(self):
        code, out = self.call(self.quote("call +48 601 234 567 now"))
        self.assertEqual((code, out["error"]), (422, "personal-data"))

    def test_personal_data_in_evidence_name_422(self):
        code, out = self.call(self.quote("plain words", name="anna.nowak@example.com.txt"))
        self.assertEqual((code, out["error"]), (422, "personal-data"))

    def test_credential_found_by_redact_helper_422(self):
        code, out = self.call(self.quote("key sk-ant-abcdefghijklmnopqrstuvwxyz0123"))
        self.assertEqual((code, out["error"]), (422, "personal-data"))

    def test_same_claim_private_is_accepted(self):
        code, out = self.call(self.quote("write to jan.kowalski@example.pl today", visibility="private"))
        self.assertEqual(code, 200, out)

    def test_hashes_and_ordinary_numbers_pass(self):
        code, out = self.call(self.quote("revenue grew 12% in 2026-11, see build 1.2.3"))
        self.assertEqual(code, 200, out)
        code, out = self.s.witness_call(request(claim("tests.pass", {"expect_commit": "0e0bbf9a1b2c3d4e5f6071829304"}),
                                                [obj_item("log", h.GO_TEST_PASS, "application/json")]))
        self.assertEqual(code, 200, out)

    def test_png_object_public_422_private_ok(self):
        body = request(claim("match.exact"), [obj_item("submitted", PNG, "image/png", "a.png"), obj_item("target", PNG, "image/png", "b.png")])
        code, out = self.call(body)
        self.assertEqual(code, 422, out)
        self.assertEqual(out["error"], "media-not-allowed")
        body["options"]["visibility"] = "private"
        code, out = self.call(body)
        self.assertEqual(code, 200, out)
        self.assertEqual(payload_of(out["envelope"])["predicate"]["outcome"], "SUPPORTED")

    def test_pdf_or_image_bytes_under_a_text_media_type_422(self):
        for data in (PNG, PDF, b"\xff\xd8\xff\xe0" + b"\x00" * 16):
            body = request(claim("match.exact"), [obj_item("submitted", data, "text/plain"), obj_item("target", data, "text/plain")])
            code, out = self.call(body)
            self.assertEqual((code, out["error"]), (422, "media-not-allowed"))
        body = request(claim("match.exact"), [obj_item("submitted", b"x", "application/pdf"), obj_item("target", b"x")])
        self.assertEqual(self.call(body)[0], 422)

    def test_helper_missing_public_refused_503(self):
        self.s.close()
        self.s = h.Stack(redact_bin="/nonexistent/redact-copy")
        code, out = self.call(self.quote("plain words"))
        self.assertEqual(code, 503, out)
        code, out = self.call(self.quote("plain words", visibility="private"))
        self.assertEqual(code, 200, out)


class Rules(unittest.TestCase):
    def test_personal_data_rules(self):
        self.assertIn("email", screen.personal_data_hits("mail a.b@c.io"))
        self.assertIn("phone", screen.personal_data_hits("tel. (022) 555-12-34-56"))
        self.assertIn("iban", screen.personal_data_hits("PL61 1090 1014 0000 0712 1981 2874"))
        self.assertIn("payment-card", screen.personal_data_hits("card 4111 1111 1111 1111"))
        self.assertEqual(screen.personal_data_hits("sha 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"), [])
        self.assertEqual(screen.personal_data_hits("on 2026-11-24 at 10:41, v1.2.3, 42 tests"), [])

    def test_media_sniff(self):
        self.assertTrue(screen.is_image_or_pdf("image/png", b"x"))
        self.assertTrue(screen.is_image_or_pdf("application/pdf", b"x"))
        self.assertTrue(screen.is_image_or_pdf("text/plain", PNG))
        self.assertTrue(screen.is_image_or_pdf("text/plain", b"GIF89a...."))
        self.assertFalse(screen.is_image_or_pdf("text/plain", b"hello"))


@unittest.skipIf(h.real_redact_bin() is None, "Go is not installed: tools/redact-copy cannot be built here")
class RealRedactHelper(Base):
    """The vendored tools/redact-copy, built from source, is the helper the image ships."""

    @classmethod
    def setUpClass(cls):
        cls.redact = h.real_redact_bin()

    def test_real_helper_finds_a_github_token(self):
        body = request(claim("quote.in-source", {"quote": "token ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"}),
                       [obj_item("source", b"anything")])
        code, out = self.call(body)
        self.assertEqual((code, out["error"]), (422, "personal-data"))

    def test_real_helper_passes_clean_text(self):
        body = request(claim("quote.in-source", {"quote": "clean words"}), [obj_item("source", b"some clean words here")])
        code, out = self.call(body)
        self.assertEqual(code, 200, out)


if __name__ == "__main__":
    unittest.main()
