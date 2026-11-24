"""TS-23: the test vectors in claim_witness/vectors/ reproduce in the witness and in witness-verify; §9.4: the methods tarball is
reproducible and /v1/methods reports its digest."""
import gzip
import hashlib
import io
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

from claim_witness import tarball
from tests_claim import helpers as h

VECTORS = h.ROOT / "claim_witness" / "vectors" / "vectors.json"


class Vectors(unittest.TestCase):
    def test_check_passes(self):
        r = subprocess.run([sys.executable, "-m", "claim_witness.vectors", "--check"], cwd=str(h.ROOT), capture_output=True,
                           text=True, timeout=300)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("all vectors reproduce", r.stdout)

    def test_check_passes_with_pure_ed25519(self):
        env = dict(os.environ, WITNESS_VERIFY_PURE="1")
        r = subprocess.run([sys.executable, "-m", "claim_witness.vectors", "--check"], cwd=str(h.ROOT), capture_output=True,
                           text=True, timeout=300, env=env)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_vectors_cover_every_kind(self):
        doc = json.loads(VECTORS.read_text())
        for kind in ("jcs", "canon1", "claim_id", "record_id", "commitments", "templates", "envelope"):
            self.assertTrue(doc.get(kind), kind)
        methods = {t["method"] for t in doc["templates"]}
        self.assertEqual(methods, {"match.exact", "quote.in-source", "tests.pass"})
        self.assertEqual({t["assertion"] for t in doc["templates"]}, {True, False})

    def test_a_changed_vector_fails_the_check(self):
        doc = json.loads(VECTORS.read_text())
        doc["claim_id"][0]["claim_id"] = "0" * 64
        d = pathlib.Path(tempfile.mkdtemp(prefix="cw-vec-"))
        p = d / "vectors.json"
        p.write_text(json.dumps(doc))
        r = subprocess.run([sys.executable, "-m", "claim_witness.vectors", "--check", "--file", str(p)], cwd=str(h.ROOT),
                           capture_output=True, text=True, timeout=300)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("FAIL", r.stdout)


class Tarball(unittest.TestCase):
    def test_reproducible_bytes(self):
        a = tarball.build_methods_tarball()
        b = tarball.build_methods_tarball()
        self.assertEqual(a, b)
        self.assertEqual(tarball.methods_code_sha256(), hashlib.sha256(a).hexdigest())

    def test_members_sorted_mtime_zero_root_owned(self):
        data = tarball.build_methods_tarball()
        self.assertEqual(data[4:8], b"\x00\x00\x00\x00", "gzip mtime must be 0")
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
            members = tf.getmembers()
        names = [m.name for m in members]
        self.assertEqual(names, sorted(names))
        self.assertIn("witness_methods/__init__.py", names)
        self.assertIn("witness_methods/canon.py", names)
        for m in members:
            self.assertEqual((m.mtime, m.uid, m.gid, m.uname, m.gname), (0, 0, 0, "", ""))
            self.assertNotIn("__pycache__", m.name)

    def test_tool_writes_the_same_digest(self):
        out = pathlib.Path(tempfile.mkdtemp(prefix="cw-tar-"))
        r = subprocess.run([sys.executable, str(h.ROOT / "tools" / "build_methods_tarball.py"), "--out", str(out)],
                           capture_output=True, text=True, timeout=120)
        self.assertEqual(r.returncode, 0, r.stderr)
        files = list(out.glob("witness-methods-*.tar.gz"))
        self.assertEqual(len(files), 1)
        self.assertEqual(files[0].name, f"witness-methods-{tarball.library_version()}.tar.gz")
        digest = hashlib.sha256(files[0].read_bytes()).hexdigest()
        self.assertEqual(digest, tarball.methods_code_sha256())
        self.assertIn(digest, r.stdout)

    def test_tarball_code_is_the_code_the_witness_runs(self):
        data = tarball.build_methods_tarball()
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
            for m in tf.getmembers():
                if m.isfile():
                    src = h.ROOT / "claim_witness" / "methods" / m.name.split("/", 1)[1]
                    self.assertEqual(tf.extractfile(m).read(), src.read_bytes(), m.name)


if __name__ == "__main__":
    unittest.main()
