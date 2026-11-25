"""witness-verify re-runs page.live and match.text (and any pure method over observations) from the observation files inside
the bundle (SPEC VR-13, §6 step 6, TS-12): `--bundle DIR` reads `observations/<id>/{envelope.json, seal.json, files/<name>}`,
verifies each observation as it verifies any (signature, id, manifest, files against the manifest, text.canonical recompute),
and only then hands its files to the method from the tarball pinned by code_sha256, comparing the finding with the record.

The bundles here are the real ones: a kept record through the API, GET /v1/records/{id}/bundle unpacked into a folder."""
import base64
import io
import json
import pathlib
import tarfile
import tempfile
import unittest
import urllib.error
import urllib.request

from claim_witness import verify
from tests_claim import helpers as h
from tests_claim.fake_seal import FakeNotary
from tests_claim.fakefetch import page, stack, url_item
from tests_claim.helpers import claim, obj_item, request

OWNER = "dev-key-a-0123456789abcdef"
U = "https://obs.example/a"
SERVER_HTML = b"<html><body><h1>Release notes</h1><p>Version 2 ships today with faster search and a new export button.</p></body></html>"
RENDERED = b"<html><body><nav data-witness-hidden='1'>Menu</nav><h1>Release notes</h1><p>Version 2 ships today with faster search and a new export button.</p></body></html>"


class Base(unittest.TestCase):
    def setUp(self):
        self.clock = h.Clock()
        self.notary = FakeNotary(self.clock)
        self.s, self.ff, self.sleeper = stack(clock=self.clock, notary=self.notary, batch_interval_s=3600)

    def tearDown(self):
        self.s.close()
        self.ff.close()

    def raw_get(self, path, key=None):
        hd = {"Authorization": f"Bearer {key}"} if key else {}
        try:
            with urllib.request.urlopen(urllib.request.Request(self.s.url(path), headers=hd), timeout=30) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()

    def witness(self, body):
        code, out, _ = self.s.witness_call(body)
        self.assertEqual(code, 200, out)
        return out

    def bundle(self, out, evidence=()):
        """Keep the record, seal, fetch GET /v1/records/{id}/bundle and unpack it: (folder, names)."""
        body = {"envelope": out["envelope"]}
        if evidence:
            body.update(keep_evidence_days=30, evidence=[{"sha256": h.sha(d), "content_b64": h.b64(d)} for d in evidence])
        code, k, _ = self.s.call("POST", f"/v1/records/{out['record_id']}/keep", body, key=OWNER)
        self.assertEqual(code, 200, k)
        self.clock.advance(3601)
        self.s.witness.sealer.tick()
        code, data = self.raw_get(f"/v1/records/{out['record_id']}/bundle")
        self.assertEqual(code, 200, data[:200])
        d = pathlib.Path(tempfile.mkdtemp(prefix="cw-vobs-bundle-"))
        names = []
        with tarfile.open(fileobj=io.BytesIO(data)) as tf:
            for m in tf.getmembers():
                self.assertFalse(m.name.startswith("/") or ".." in m.name)
                if m.isfile():
                    names.append(m.name)
                    p = d / m.name
                    p.parent.mkdir(parents=True, exist_ok=True)
                    p.write_bytes(tf.extractfile(m).read())
        return d, names

    def verify(self, *args):
        buf = io.StringIO()
        code = verify.main([str(a) for a in args], out=buf)
        return code, buf.getvalue()

    def flip(self, path):
        data = bytearray(path.read_bytes())
        data[len(data) // 2] ^= 1
        path.write_bytes(bytes(data))

    def obs_dir(self, d, names):
        ids = sorted({n.split("/")[1] for n in names if n.startswith("observations/")})
        return [d / "observations" / i for i in ids]


class PageLive(Base):
    def live_bundle(self):
        self.ff.set(U, page(SERVER_HTML, rendered=RENDERED))
        out = self.witness(request(claim("page.live", {"url": U}), [url_item(U)], "public"))
        return (out,) + self.bundle(out)

    def test_the_bundle_carries_the_observation_files(self):
        out, d, names = self.live_bundle()
        for n in ("envelope.json", "seal.json", "files/rendered.html", "files/text.canonical.txt", "files/response.body"):
            self.assertTrue(any(x.endswith(n) for x in names), n)

    def test_live_record_reruns_from_the_observation_in_the_bundle(self):
        out, d, names = self.live_bundle()
        code, text = self.verify("--bundle", d)
        self.assertEqual(code, 0, text)
        self.assertIn("PASS method-rerun: page.live", text)
        self.assertNotIn("SKIP method-rerun", text)
        self.assertIn("PASS observation-files", text)
        self.assertIn("PASS text-canonical", text)

    def test_pure_python_ed25519_gives_the_same_pass(self):
        import os
        out, d, names = self.live_bundle()
        os.environ["WITNESS_VERIFY_PURE"] = "1"
        try:
            code, text = self.verify("--bundle", d)
        finally:
            del os.environ["WITNESS_VERIFY_PURE"]
        self.assertEqual(code, 0, text)
        self.assertIn("ed25519: pure-python", text)
        self.assertIn("PASS method-rerun: page.live", text)

    def test_one_byte_of_text_canonical_fails_by_name(self):
        out, d, names = self.live_bundle()
        (o,) = self.obs_dir(d, names)
        self.flip(o / "files" / "text.canonical.txt")
        code, text = self.verify("--bundle", d)
        self.assertEqual(code, 1, text)
        self.assertIn("FAIL observation-files", text)
        self.assertIn("FAIL method-rerun", text)
        self.assertNotIn("PASS method-rerun", text)

    def test_one_byte_of_rendered_html_fails_by_name(self):
        out, d, names = self.live_bundle()
        (o,) = self.obs_dir(d, names)
        self.flip(o / "files" / "rendered.html")
        code, text = self.verify("--bundle", d)
        self.assertEqual(code, 1, text)
        self.assertIn("FAIL observation-files", text)
        self.assertIn("FAIL method-rerun", text)
        self.assertNotIn("PASS method-rerun", text)

    def test_an_observation_signature_that_does_not_verify_fails_the_rerun(self):
        out, d, names = self.live_bundle()
        (o,) = self.obs_dir(d, names)
        env = json.loads((o / "envelope.json").read_text())
        sig = bytearray(base64.b64decode(env["signatures"][0]["sig"]))
        sig[0] ^= 1
        env["signatures"][0]["sig"] = base64.b64encode(bytes(sig)).decode()
        (o / "envelope.json").write_text(json.dumps(env))
        code, text = self.verify("--bundle", d)
        self.assertEqual(code, 1, text)
        self.assertIn("FAIL signature", text)
        self.assertIn("FAIL method-rerun", text)
        self.assertNotIn("PASS method-rerun", text)

    def test_an_observation_folder_under_another_id_fails(self):
        out, d, names = self.live_bundle()
        (o,) = self.obs_dir(d, names)
        o.rename(o.parent / ("0" * 64))
        code, text = self.verify("--bundle", d)
        self.assertEqual(code, 1, text)
        self.assertNotIn("PASS method-rerun", text)

    def test_a_missing_observation_is_a_skip_naming_its_id(self):
        out, d, names = self.live_bundle()
        (o,) = self.obs_dir(d, names)
        oid = o.name
        for p in sorted(o.rglob("*"), reverse=True):
            p.unlink() if p.is_file() else p.rmdir()
        o.rmdir()
        code, text = self.verify("--bundle", d)
        self.assertEqual(code, 0, text)
        self.assertIn("SKIP method-rerun", text)
        self.assertIn(oid, text)

    def test_a_missing_file_the_method_reads_is_a_skip_naming_it(self):
        out, d, names = self.live_bundle()
        (o,) = self.obs_dir(d, names)
        (o / "files" / "rendered.html").unlink()
        code, text = self.verify("--bundle", d)
        self.assertIn("SKIP method-rerun", text)
        self.assertIn("rendered.html", text)
        self.assertNotIn("PASS method-rerun", text)

    def test_the_observation_flag_gives_the_same_pass(self):
        out, d, names = self.live_bundle()
        (o,) = self.obs_dir(d, names)
        tar = next(d.glob("witness-methods-*.tar.gz"))
        code, text = self.verify("--envelope", d / "envelope.json", "--keys", d / "keys.json", "--methods", tar, "--observation", o)
        self.assertEqual(code, 0, text)
        self.assertIn("PASS method-rerun: page.live", text)

    def test_not_live_reruns_from_both_observations(self):
        self.ff.set(U, page(b"<h1>Not found</h1>", status=404))
        out = self.witness(request(claim("page.live", {"url": U}), [url_item(U)], "public", wait=30))
        d, names = self.bundle(out)
        self.assertEqual(len(self.obs_dir(d, names)), 2)
        code, text = self.verify("--bundle", d)
        self.assertEqual(code, 0, text)
        self.assertIn("PASS method-rerun: page.live", text)
        self.assertIn("not-live", text)

    def test_not_live_with_one_observation_missing_is_a_skip_not_a_fail(self):
        self.ff.set(U, page(b"<h1>Not found</h1>", status=404))
        out = self.witness(request(claim("page.live", {"url": U}), [url_item(U)], "public", wait=30))
        d, names = self.bundle(out)
        first = self.obs_dir(d, names)[0]
        for p in sorted(first.rglob("*"), reverse=True):
            p.unlink() if p.is_file() else p.rmdir()
        first.rmdir()
        code, text = self.verify("--bundle", d)
        self.assertEqual(code, 0, text)
        self.assertIn("SKIP method-rerun", text)
        self.assertIn(first.name, text)

    def test_a_confirmation_that_left_no_observation_is_a_skip(self):
        from tests_claim.fakefetch import error
        self.ff.set(U, page(b"<h1>Not found</h1>", status=404), error("timeout", "slow"))
        out = self.witness(request(claim("page.live", {"url": U}), [url_item(U)], "public", wait=30))
        d, names = self.bundle(out)
        self.assertEqual(len(self.obs_dir(d, names)), 1)
        code, text = self.verify("--bundle", d)
        self.assertEqual(code, 0, text)
        self.assertIn("SKIP method-rerun", text)
        self.assertNotIn("FAIL", text)

    def test_a_failed_fetch_leaves_nothing_to_rerun(self):
        from tests_claim.fakefetch import error
        self.ff.set(U, error("timeout", "slow"))
        out = self.witness(request(claim("page.live", {"url": U}), [url_item(U)], "public"))
        d, names = self.bundle(out)
        code, text = self.verify("--bundle", d)
        self.assertEqual(code, 0, text)
        self.assertIn("SKIP method-rerun", text)


class MatchText(Base):
    def match_bundle(self, page_item=None, assertion=True, submitted=SERVER_HTML):
        body = request(claim("match.text", {}, assertion), [obj_item("submitted", submitted, "text/html", "copy.html"),
                                                             page_item or url_item(U)], "public")
        out = self.witness(body)
        return (out,) + self.bundle(out, evidence=[submitted])

    def test_match_reruns_from_the_submitted_object_and_the_observation(self):
        self.ff.set(U, page(SERVER_HTML, rendered=RENDERED))
        out, d, names = self.match_bundle()
        code, text = self.verify("--bundle", d)
        self.assertEqual(code, 0, text)
        self.assertIn("PASS method-rerun: match.text", text)
        self.assertNotIn("SKIP method-rerun", text)

    def test_differs_reruns_to_the_same_finding(self):
        self.ff.set(U, page(SERVER_HTML.replace(b"faster search", b"slower search"), rendered=RENDERED.replace(b"faster search", b"slower search")))
        out, d, names = self.match_bundle(submitted=SERVER_HTML.replace(b"Version 2 ships today", b"Version 3 is cancelled"))
        self.assertEqual(h.payload_of(out["envelope"])["predicate"]["finding"], "differs")
        code, text = self.verify("--bundle", d)
        self.assertEqual(code, 0, text)
        self.assertIn("PASS method-rerun: match.text", text)

    def test_observation_evidence_by_id_reruns_too(self):
        self.ff.set(U, page(SERVER_HTML, rendered=RENDERED))
        code, obs, _ = self.s.call("POST", "/v1/observe", {"url": U, "visibility": "public"})
        self.assertEqual(code, 200, obs)
        out, d, names = self.match_bundle(page_item={"slot": "page", "kind": "observation", "id": obs["observation_id"]})
        code, text = self.verify("--bundle", d)
        self.assertEqual(code, 0, text)
        self.assertIn("PASS method-rerun: match.text", text)

    def test_one_byte_of_the_response_body_fails_by_name(self):
        self.ff.set(U, page(SERVER_HTML, rendered=RENDERED))
        out, d, names = self.match_bundle()
        (o,) = self.obs_dir(d, names)
        self.flip(o / "files" / "response.body")
        code, text = self.verify("--bundle", d)
        self.assertEqual(code, 1, text)
        self.assertIn("FAIL observation-files", text)
        self.assertIn("FAIL method-rerun", text)
        self.assertNotIn("PASS method-rerun", text)

    def test_one_byte_of_text_canonical_fails_by_name(self):
        self.ff.set(U, page(SERVER_HTML, rendered=RENDERED))
        out, d, names = self.match_bundle()
        (o,) = self.obs_dir(d, names)
        self.flip(o / "files" / "text.canonical.txt")
        code, text = self.verify("--bundle", d)
        self.assertEqual(code, 1, text)
        self.assertIn("FAIL method-rerun", text)
        self.assertNotIn("PASS method-rerun", text)

    def test_the_submitted_bytes_are_still_needed(self):
        self.ff.set(U, page(SERVER_HTML, rendered=RENDERED))
        out, d, names = self.match_bundle()
        for p in (d / "evidence").iterdir():
            p.unlink()
        code, text = self.verify("--bundle", d)
        self.assertIn("SKIP method-rerun", text)
        self.assertNotIn("PASS method-rerun", text)


class Screenshot(unittest.TestCase):
    def test_match_screenshot_stays_skipped_for_image(self):
        r = verify.Report(io.StringIO())
        view = {"method": {"id": "match.screenshot"}, "claim": {}, "evidence": [{"kind": "object"}, {"kind": "observation", "id": "x"}]}
        verify.rerun(r, view, [], None, None, {})
        self.assertIn("SKIP method-rerun: re-run skipped (needs image)", r.out.getvalue())


if __name__ == "__main__":
    unittest.main()
