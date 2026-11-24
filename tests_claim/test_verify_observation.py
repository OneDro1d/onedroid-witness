"""witness-verify on an observation envelope (SPEC §2.3, §6): signature, payload canonical, observation id, manifest digest
(the subject is H(canonical manifest)), key validity at fetched_at, each given file against its fingerprint, and
text.canonical.txt recomputed from rendered.html with the tarball's canon/1."""
import base64
import io
import json
import pathlib
import tempfile
import unittest

from claim_witness import tarball, verify
from tests_claim import helpers as h
from tests_claim.fakefetch import page, stack

U = "https://verify.example/"
RENDERED = b"<html><body><nav data-witness-hidden='1'>Menu</nav><p>Shown words.</p></body></html>"


class ObservationVerify(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.s, cls.ff, _ = stack()
        cls.ff.set(U, page(b"<p>server</p>", rendered=RENDERED))
        code, cls.obs, _ = cls.s.call("POST", "/v1/observe", {"url": U, "visibility": "public"})
        assert code == 200, cls.obs
        cls.dir = pathlib.Path(tempfile.mkdtemp(prefix="cw-vobs-"))
        (cls.dir / "obs.json").write_text(json.dumps(cls.obs))
        code, wk, _ = cls.s.call("GET", "/.well-known/witness.json", key=None)
        (cls.dir / "keys.json").write_text(json.dumps(wk["key_list"]))
        cls.files = cls.s.storage.get_observation_files(cls.obs["observation_id"])
        for n, b in cls.files.items():
            (cls.dir / n).write_bytes(b)
        (cls.dir / "m.tar.gz").write_bytes(tarball.build_methods_tarball())

    @classmethod
    def tearDownClass(cls):
        cls.s.close()
        cls.ff.close()

    def run_verify(self, *args):
        buf = io.StringIO()
        return verify.main([str(a) for a in args], out=buf), buf.getvalue()

    def test_observation_with_its_files_passes(self):
        args = ["--envelope", self.dir / "obs.json", "--keys", self.dir / "keys.json", "--methods", self.dir / "m.tar.gz"]
        for n in self.files:
            args += ["--evidence", self.dir / n]
        code, out = self.run_verify(*args)
        self.assertEqual(code, 0, out)
        for name in ("signature", "payload-canonical", "record-id", "manifest-digest", "key-validity", "observation-files",
                     "text-canonical"):
            self.assertIn(f"PASS {name}", out)
        self.assertIn(f"observation id: {self.obs['observation_id']}", out)

    def test_a_changed_file_fails(self):
        bad = self.dir / "bad.txt"
        bad.write_bytes(self.files["text.canonical.txt"] + b"x")
        code, out = self.run_verify("--envelope", self.dir / "obs.json", "--keys", self.dir / "keys.json", "--evidence", bad)
        self.assertEqual(code, 1, out)
        self.assertIn("FAIL observation-files", out)

    def test_a_flipped_payload_byte_fails(self):
        env = json.loads(json.dumps(self.obs["envelope"]))
        raw = bytearray(base64.b64decode(env["payload"]))
        raw[-5] ^= 1
        env["payload"] = base64.b64encode(bytes(raw)).decode()
        (self.dir / "flip.json").write_text(json.dumps(env))
        code, out = self.run_verify("--envelope", self.dir / "flip.json", "--keys", self.dir / "keys.json")
        self.assertEqual(code, 1)
        self.assertIn("FAIL", out)


if __name__ == "__main__":
    unittest.main()
