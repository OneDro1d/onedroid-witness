"""B2b (f): `match.screenshot`: OCR with Tesseract, canon/1, similarity thresholds T/F, `consistent` / `differs`;
`code_sha256` = the image digest from WITNESS_IMAGE_DIGEST; witness-verify reports "re-run skipped (needs image)". The real
Tesseract runs in the image; these tests use a stand-in binary with the same command line (and one test runs the real one
when it is installed)."""
import io
import json
import pathlib
import shutil
import tempfile
import unittest

from claim_witness import methods, ocr, verify
from tests_claim import helpers as h
from tests_claim.fakefetch import PNG, page, stack, url_item
from tests_claim.helpers import claim, obj_item, request

U = "https://shot.example/"
DIGEST = "sha256:" + "ab" * 32
PARAS = ["The harbour ferry now runs every forty minutes in summer.", "Tickets cost four euros and children travel free.",
         "The last boat leaves the island at ten in the evening.", "Bicycles are carried at no extra charge on every crossing."]
PAGE = ("<html><body><h1>Ferry timetable</h1>" + "".join(f"<p>{p}</p>" for p in PARAS) + "</body></html>").encode()


def fake_tesseract():
    d = pathlib.Path(tempfile.mkdtemp(prefix="cw-tess-"))
    p = d / "tesseract"
    p.write_text("#!/usr/bin/env python3\n"
                 "import sys\n"
                 "if '--version' in sys.argv:\n"
                 "    print('tesseract 5.3.0'); sys.exit(0)\n"
                 "assert sys.argv[1:3] == ['stdin', 'stdout'], sys.argv\n"
                 "data = sys.stdin.buffer.read()\n"
                 "if not data.startswith(b'\\x89PNG\\r\\n\\x1a\\nOCR:'):\n"
                 "    sys.exit(1)\n"
                 "body = data[12:]\n"
                 "conf = '96'\n"
                 "if body.startswith(b'[conf='):\n"          # a test image says how sure the stand-in is: [conf=NN]text
                 "    conf = body[6:body.index(b']')].decode()\n"
                 "    body = body[body.index(b']') + 1:]\n"
                 "if 'tsv' in sys.argv:\n"                   # the readability run: one TSV row per word, like Tesseract
                 "    print('level\\tpage_num\\tblock_num\\tpar_num\\tline_num\\tword_num\\tleft\\ttop\\twidth\\theight\\tconf\\ttext')\n"
                 "    print('1\\t1\\t0\\t0\\t0\\t0\\t0\\t0\\t800\\t600\\t-1\\t')\n"
                 "    for i, w in enumerate(body.decode('utf-8', 'replace').split()):\n"
                 "        print('5\\t1\\t1\\t1\\t1\\t%d\\t0\\t0\\t10\\t10\\t%s\\t%s' % (i + 1, conf, w))\n"
                 "    sys.exit(0)\n"
                 "sys.stdout.buffer.write(body)\n")
    p.chmod(0o755)
    return str(p)


def image(text):
    return PNG + b"OCR:" + text.encode("utf-8")


class Base(unittest.TestCase):
    overrides = None

    def setUp(self):
        o = {"tesseract_bin": fake_tesseract(), "image_digest": DIGEST}
        o.update(self.overrides or {})
        self.s, self.ff, _ = stack(**o)
        self.ff.set(U, page(PAGE))

    def tearDown(self):
        self.s.close()
        self.ff.close()

    def body(self, img, visibility="private", assertion=True):
        return request(claim("match.screenshot", {}, assertion), [obj_item("submitted", img, "image/png", "shot.png"), url_item(U)],
                       visibility)

    def check(self, img, **kw):
        code, out, _ = self.s.witness_call(self.body(img, **kw))
        self.assertEqual(code, 200, out)
        return out, out["disclosure"]["body"] if "disclosure" in out else h.payload_of(out["envelope"])["predicate"]


class Screenshot(Base):
    def test_consistent_with_image_digest_as_code(self):
        out, p = self.check(image("Ferry timetable\n" + "\n".join(PARAS)))
        self.assertEqual((p["finding"], p["outcome"]), ("consistent", "SUPPORTED"))
        self.assertEqual(p["method"]["code_sha256"], "ab" * 32)
        self.assertIn("tesseract", p["method"]["runtime"])
        sha = h.sha(image("Ferry timetable\n" + "\n".join(PARAS)))
        self.assertEqual(p["statement"], f"The submitted image {sha} shows text consistent with {U} observed at {h.iso(self.s.clock())}.")
        self.assertEqual(p["limits"], "Compared the text read from the image. The pixels were not proven; an image can be edited.")
        self.assertIsInstance(p["detail"]["similarity_bp"], int)

    def test_a_viewport_shot_of_part_of_the_page_is_consistent(self):
        out, p = self.check(image("\n".join(PARAS[1:3])))
        self.assertEqual(p["finding"], "consistent")

    def test_edited_text_differs(self):
        out, p = self.check(image("Ferry timetable\nThe ferry has been cancelled for the whole summer season this year.\n"
                                  "Refunds will be paid to every passenger who booked online before the change."))
        # BD19 addendum (decision 158): F is 8700 again, so the edit (1764 bp) and the cat sentence (1875 bp) differ as they did
        # before decision 157 (F 1200 had made them no finding); a text that shares no word with the page (0 bp) differs too.
        self.assertEqual((p["finding"], p["outcome"]), ("differs", "NOT_SUPPORTED"))
        out, p = self.check(image("Nothing at all like the page, a picture of a cat sleeping on a warm sofa."), assertion=False)
        self.assertEqual((p["finding"], p["outcome"]), ("differs", "SUPPORTED"))
        words = "Quokkas juggle violet marmots beyond frozen glaciers whenever nobody watches."
        out, p = self.check(image(words))
        self.assertEqual((p["finding"], p["outcome"], p["detail"]["similarity_bp"]), ("differs", "NOT_SUPPORTED", 0))
        out, p = self.check(image(words), assertion=False)
        self.assertEqual((p["finding"], p["outcome"]), ("differs", "SUPPORTED"))

    def test_no_text_read_is_unreadable(self):
        out, p = self.check(image("   "))
        self.assertEqual((p["finding"], p["reason"]), (None, "unreadable"))

    def test_tesseract_failure_is_unreadable(self):
        out, p = self.check(b"\x89PNG\r\n\x1a\nnot an ocr fixture")
        self.assertEqual((p["finding"], p["reason"]), (None, "unreadable"))

    def test_public_claim_with_an_image_is_refused(self):
        code, out, _ = self.s.witness_call(self.body(image("x"), visibility="public"))
        self.assertEqual((code, out["error"]), (422, "media-not-allowed"))

    def test_registry_reports_the_image_digest_and_thresholds(self):
        code, reg, _ = self.s.call("GET", "/v1/methods", key=None)
        m = [x for x in reg["methods"] if x["id"] == "match.screenshot"][0]
        self.assertEqual(m["code_sha256"], "ab" * 32)
        self.assertEqual(set(m["thresholds"]), {"T_bp", "F_bp"})
        self.assertLess(m["thresholds"]["F_bp"], m["thresholds"]["T_bp"])
        self.assertFalse(m["pure"])

    def test_witness_verify_skips_the_rerun_and_passes(self):
        out, p = self.check(image("Ferry timetable\n" + "\n".join(PARAS)))
        d = pathlib.Path(tempfile.mkdtemp())
        (d / "a.json").write_text(json.dumps(out))
        code, wk, _ = self.s.call("GET", "/.well-known/witness.json", key=None)
        (d / "keys.json").write_text(json.dumps(wk["key_list"]))
        from claim_witness import tarball
        (d / "m.tar.gz").write_bytes(tarball.build_methods_tarball())
        buf = io.StringIO()
        rc = verify.main(["--envelope", str(d / "a.json"), "--keys", str(d / "keys.json"), "--methods", str(d / "m.tar.gz")], out=buf)
        self.assertEqual(rc, 0, buf.getvalue())
        self.assertIn("SKIP method-rerun: re-run skipped (needs image)", buf.getvalue())
        self.assertNotIn("FAIL", buf.getvalue())


class NotConfigured(Base):
    overrides = {"image_digest": None}

    def test_no_image_digest_is_503_and_nothing_signed(self):
        n = self.s.log_count()
        code, out, _ = self.s.witness_call(self.body(image("x")))
        self.assertEqual((code, out["error"]), (503, "ocr-unavailable"))
        self.assertEqual(self.s.log_count(), n)

    def test_no_tesseract_is_503(self):
        self.s.witness.cfg.image_digest = "ab" * 32
        self.s.witness.cfg.tesseract_bin = "/nonexistent/tesseract"
        code, out, _ = self.s.witness_call(self.body(image("x")))
        self.assertEqual((code, out["error"]), (503, "ocr-unavailable"))


class Pure(unittest.TestCase):
    def test_method_over_ocr_text(self):
        from tests_claim.test_match_text import obs_ev
        ev = {"submitted": {"slot": "submitted", "kind": "object", "sha256": "1" * 64, "media_type": "image/png", "name": "s",
                            "data": b"", "ocr_text": "Title One two three four five."}, "page": obs_ev()}
        r = methods.run("match.screenshot", {}, ev)
        self.assertEqual(r.finding, "consistent")
        self.assertFalse(methods.get("match.screenshot").pure)

    def test_image_digest_parsing(self):
        self.assertEqual(ocr.parse_digest("sha256:" + "Ab" * 32), "ab" * 32)
        self.assertEqual(ocr.parse_digest("ab" * 32), "ab" * 32)
        for bad in (None, "", "sha256:xyz", "IMAGE_DIGEST_PLACEHOLDER"):
            self.assertIsNone(ocr.parse_digest(bad))

    @unittest.skipIf(shutil.which("tesseract") is None, "tesseract is not installed here (it is in Dockerfile.claim)")
    def test_real_tesseract_reads_text(self):
        o = ocr.Ocr(shutil.which("tesseract"))
        self.assertTrue(o.available())


if __name__ == "__main__":
    unittest.main()
