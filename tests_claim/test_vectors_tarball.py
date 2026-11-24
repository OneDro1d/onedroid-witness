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
        self.assertEqual(methods, {"match.exact", "quote.in-source", "tests.pass", "page.live", "match.text", "match.screenshot"})
        self.assertEqual({t["assertion"] for t in doc["templates"]}, {True, False})
        for mid in ("page.live", "match.text", "match.screenshot"):
            self.assertEqual({t["assertion"] for t in doc["templates"] if t["method"] == mid}, {True, False}, mid)

    def test_vectors_carry_thresholds_and_an_observation(self):
        doc = json.loads(VECTORS.read_text())
        self.assertEqual(doc["thresholds"]["match.text"], {"T_bp": 9700, "F_bp": 9600})
        self.assertEqual(set(doc["thresholds"]["match.screenshot"]), {"T_bp", "F_bp"})
        self.assertTrue(doc["observation"])
        findings = {(t["method"], t["finding"], t["reason"]) for t in doc["templates"]}
        for want in (("match.text", "match", "match"), ("match.text", "differs", "differs"), ("match.text", None, "undecided"),
                     ("page.live", "live", "live"), ("page.live", "not-live", "not-live"),
                     ("match.screenshot", "consistent", "consistent"), ("match.screenshot", "differs", "differs")):
            self.assertIn(want, findings)

    def test_vectors_cover_judge_supports(self):
        """B6: judge.supports templates (with the "Asserted false: " prefix), the prompt's sha256, the model input and the
        decision over fixed model outputs, each reproduced by the witness and by the tarball."""
        doc = json.loads(VECTORS.read_text())
        j = doc.get("judge")
        self.assertTrue(j)
        from claim_witness.methods import judge_supports
        self.assertEqual(j["prompt_sha256"], judge_supports.prompt_sha256())
        self.assertEqual({t["assertion"] for t in j["templates"]}, {True, False})
        self.assertTrue(any(t["statement"].startswith("Asserted false: ") for t in j["templates"]))
        reasons = {c["reason"] for c in j["decide"]}
        for r in ("judged-supports", "judged-contradicted", "judged-silent", "undecided", "possible-injection", "judges-disagree"):
            self.assertIn(r, reasons)
        for c in j["decide"]:
            self.assertRegex(c["input_sha256"], r"^[0-9a-f]{64}$")

    def test_vectors_replay_bd13_quotes_verified_by_text(self):
        """BD13: the vectors replay the B6-31 answer (end one past, the right text) as a contradiction recorded with the
        witness's offsets, a datamarked text that verifies, and a text found only in a hidden node that does not."""
        from claim_witness.methods import judge_supports
        cases = json.loads(VECTORS.read_text())["judge"]["decide"]

        def quotes_of(c):
            objs = [judge_supports.first_object(o) for o in c["outputs"] if o]
            return [q for o in objs if o for q in (o.get("quotes") or []) if isinstance(q, dict)]

        off = [c for c in cases if any(q.get("text") == "city library is closed on Sundays" and q.get("end") == 38
                                       for q in quotes_of(c))]
        self.assertTrue(off, "no B6-31 off-by-one vector")
        self.assertEqual((off[0]["finding"], off[0]["outcome"]), ("judged-contradicted", "NOT_SUPPORTED"))
        self.assertEqual(off[0]["runs"][0]["quotes"], [{"source": 0, "start": 4, "end": 37}])
        marked = [c for c in cases if any("ˆ" in (q.get("text") or "") for q in quotes_of(c))]
        self.assertTrue(marked, "no datamarked-text vector")
        self.assertIsNotNone(marked[0]["finding"])
        hidden = [c for c in cases if c["items"][0]["hidden"] and any(
            q.get("text") and q["text"] in c["items"][0]["hidden"][0] and q["text"] not in c["items"][0]["visible"]
            for q in quotes_of(c))]
        self.assertTrue(hidden, "no hidden-only-text vector")
        self.assertEqual((hidden[0]["finding"], hidden[0]["reason"]), (None, "undecided"))

    def test_a_changed_judge_vector_fails_the_check(self):
        doc = json.loads(VECTORS.read_text())
        doc["judge"]["decide"][0]["reason"] = "judged-silent" if doc["judge"]["decide"][0]["reason"] != "judged-silent" else "undecided"
        d = pathlib.Path(tempfile.mkdtemp(prefix="cw-vec-"))
        p = d / "vectors.json"
        p.write_text(json.dumps(doc))
        r = subprocess.run([sys.executable, "-m", "claim_witness.vectors", "--check", "--file", str(p)], cwd=str(h.ROOT),
                           capture_output=True, text=True, timeout=300)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("FAIL judge", r.stdout)

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
