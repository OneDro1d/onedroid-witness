"""The bundle carries the methods tarball the RECORD names (method.code_sha256), not today's (README_CLAIM decision 161).

Measured on 25 Nov: public record b0973af4... (quote.in-source, signed under methods library 1.5.0, code_sha256 0d691773...)
had a bundle holding the 1.7.0 tarball (1d8b3e75...), so `witness-verify --bundle` printed FAIL methods-tarball. Every record
signed before a methods change is hit, and every record signed today is hit at the next change.

- the archive claim_witness/methods_archive/: one `<sha256>.tar.gz` per distinct tarball the witness could have signed with,
  plus index.json {entries: [{sha256, library_version, commit, first_commit_date}]}; each file is the sha256 it is named by, is the
  library version the index says, and is rebuilt byte-identical from its commit by tools/archive_methods_tarball.py;
- the current build must be in the archive (a methods change without `archive_methods_tarball.py add` fails here);
- the bundle of a record picks the archived tarball by the record's code_sha256 and names it `witness-methods-<library
  version>.tar.gz`; a sha256 the archive cannot supply gives no tarball at all (never a wrong one), so witness-verify says SKIP
  method-rerun, never FAIL methods-tarball and never PASS; a non-tarball code_sha256 (match.screenshot's image digest) keeps
  today's behaviour (the current tarball);
- the image carries the archive (Dockerfile.claim copies claim_witness/ whole and .dockerignore does not exclude it)."""
import base64
import copy
import hashlib
import io
import json
import pathlib
import re
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

from claim_witness import tarball, verify
from tests_claim import helpers as h
from tests_claim import test_keep_api as k

ARCHIVE = h.ROOT / "claim_witness" / "methods_archive"
OWNER = k.OWNER

# every distinct tarball on the first-parent history of v1/claim-seal-chain (f99a04e) since the tarball existed:
# (sha256, library version, the commit it is rebuilt from)
SIGNED_WITH = (
    ("0a785425a1930097bfcbd32101670396675f7887d34e3efcf8e0144e429fe112", "1.0.0", "f3432fbb7733cd1323f980fdfc41060c7c438a17"),
    ("3be873a4413a116733dbf86a106ad8916e38cf87ad1b8ec5c596ca65481eede1", "1.1.0", "1a5bd707878bdb34d28be0c42ffdf691afc29bc6"),
    ("186448155c4baff313a3a7cb7bbb36c5f2df63c37ada611cf0575a5ac8f0c1e4", "1.2.0", "cb769922dad1230c8f2756ce2a13700499e1c448"),
    ("1d30489e8988f6f2a8d6ae66b0ddc28e5880e64f9ea13ee746101c1bcd2cefe0", "1.3.0", "8ca79b4aba3d700b6785f7bce0948d888e7ece3c"),
    ("a190fce150c0bcfb9f9a817ae1b7e2a8bd3a6be8aefb5c061c9f311869b218b1", "1.4.0", "678e1421fbca9afef636a8f4d110a9daac3417c2"),
    ("7f39d3940d39fd3f68e2b63879000e016165b37aaf2083b2db47dadad2b63e78", "1.4.0", "65cf3805e3ea5b7f003b509d039a734d768a196c"),
    ("0d691773a2c012b34ab5f22d2757b887761dcd6e09c29c5a2d05547dc21c69db", "1.5.0", "45cace90b13f666b7dd89d8e78dc3e73aff7aea1"),
    ("a36007123a4935d077cd702b3ee5620174f53a3d6a27499e0edd1f38e1a08aaf", "1.6.0", "270fdc301805d96d57d60c1a7ce3bf0619f6a39b"),
    ("0226f2dec1acd3e7f09c92ec7bd152768075a57ea46ddd6c2851172f4ccdbc0c", "1.7.0", "007168c2b7c397cc9f6ba249cb7db908fe30248b"),
    ("575885ea0967f6a421d50c61092a5dac2334f32cc46960c0e4140921fe4b0f27", "1.7.0", "58940cf961783f68dbcb592ecd82bbb0c677596e"),
    ("1d8b3e75f9815122d220227091d28f787a13b296918c15eb8dbe930f4d2b4237", "1.7.0", "24fb2a81ccaf68a4647b4a8f62910182dfba8e82"),
)
NOT_ARCHIVED = "ab" * 32


def index():
    return json.loads((ARCHIVE / "index.json").read_text())


class Archive(unittest.TestCase):
    def test_the_archive_has_an_index_of_files_named_by_their_sha256(self):
        self.assertTrue((ARCHIVE / "index.json").is_file(), "claim_witness/methods_archive/index.json is missing")
        entries = index()["entries"]
        self.assertTrue(entries)
        for e in entries:
            self.assertRegex(e["sha256"], r"^[0-9a-f]{64}$")
            self.assertRegex(e["library_version"], r"^\d+\.\d+\.\d+$")
            self.assertRegex(e["commit"], r"^[0-9a-f]{40}$")
            self.assertTrue((ARCHIVE / f"{e['sha256']}.tar.gz").is_file(), e)
        self.assertEqual(len({e["sha256"] for e in entries}), len(entries), "a sha256 is archived once")

    def test_every_file_is_the_sha256_it_is_named_by_and_the_version_the_index_says(self):
        self.assertTrue((ARCHIVE / "index.json").is_file(), "claim_witness/methods_archive/index.json is missing")
        for e in index()["entries"]:
            data = (ARCHIVE / f"{e['sha256']}.tar.gz").read_bytes()
            self.assertEqual(hashlib.sha256(data).hexdigest(), e["sha256"])
            with tarfile.open(fileobj=io.BytesIO(data)) as tf:
                init = tf.extractfile("witness_methods/__init__.py").read().decode()
            self.assertEqual(re.search(r'(?m)^LIBRARY_VERSION = "([^"]+)"', init).group(1), e["library_version"], e["sha256"])

    def test_no_file_in_the_archive_is_outside_the_index(self):
        self.assertTrue((ARCHIVE / "index.json").is_file(), "claim_witness/methods_archive/index.json is missing")
        named = {f"{e['sha256']}.tar.gz" for e in index()["entries"]} | {"index.json"}
        self.assertEqual({p.name for p in ARCHIVE.iterdir()}, named)

    def test_every_tarball_the_witness_signed_with_is_archived(self):
        self.assertTrue((ARCHIVE / "index.json").is_file(), "claim_witness/methods_archive/index.json is missing")
        have = {e["sha256"]: (e["library_version"], e["commit"]) for e in index()["entries"]}
        for sha, version, commit in SIGNED_WITH:
            self.assertEqual(have.get(sha), (version, commit), sha)

    def test_the_current_build_is_archived(self):
        """A methods change without `tools/archive_methods_tarball.py add` fails here, before it can be deployed."""
        self.assertTrue((ARCHIVE / "index.json").is_file(), "claim_witness/methods_archive/index.json is missing")
        cur = tarball.methods_code_sha256()
        self.assertIn(cur, {e["sha256"] for e in index()["entries"]},
                      f"the current methods tarball {cur} is not archived: run tools/archive_methods_tarball.py add")
        self.assertEqual((ARCHIVE / f"{cur}.tar.gz").read_bytes(), tarball.build_methods_tarball())

    def test_every_entry_is_rebuilt_byte_identical_from_its_commit_by_the_repo_builder(self):
        self.assertTrue((ARCHIVE / "index.json").is_file(), "claim_witness/methods_archive/index.json is missing")
        tool = h.ROOT / "tools" / "archive_methods_tarball.py"
        self.assertTrue(tool.is_file())
        for e in index()["entries"]:
            if subprocess.run(["git", "-C", str(h.ROOT), "cat-file", "-e", e["commit"] + "^{commit}"], capture_output=True).returncode:
                self.skipTest(f"commit {e['commit']} is not in this clone (shallow?): the rebuild cannot be checked here")
            with tempfile.TemporaryDirectory(prefix="cw-rebuild-") as d:
                out = pathlib.Path(d) / "t.tar.gz"
                r = subprocess.run([sys.executable, str(tool), "rebuild", e["commit"], "--out", str(out)], capture_output=True, text=True)
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertEqual(hashlib.sha256(out.read_bytes()).hexdigest(), e["sha256"], e)
                self.assertEqual(out.read_bytes(), (ARCHIVE / f"{e['sha256']}.tar.gz").read_bytes())

    def test_the_image_carries_the_archive(self):
        dockerfile = (h.ROOT / "Dockerfile.claim").read_text()
        self.assertIn("COPY --chmod=0755 claim_witness/ ./claim_witness/", dockerfile)  # the whole package, the archive inside
        self.assertTrue(ARCHIVE.is_dir() and ARCHIVE.is_relative_to(h.ROOT / "claim_witness"))
        ignored = (h.ROOT / ".dockerignore").read_text().split()
        for pattern in ignored:
            self.assertNotIn("tar", pattern)
            self.assertNotIn("methods_archive", pattern)

    def test_the_archive_is_not_part_of_the_current_tarball(self):
        with tarfile.open(fileobj=io.BytesIO(tarball.build_methods_tarball())) as tf:
            self.assertFalse([n for n in tf.getnames() if "archive" in n or n.endswith(".gz")])


class BundleTarball(k.Base, unittest.TestCase):
    """The bundle of a record signed under library X holds library X's tarball."""

    def signed_with(self, sha, private=False):
        """A kept, sealed record whose method.code_sha256 is `sha` (the witness is made to report it while signing)."""
        with mock.patch.object(tarball, "methods_code_sha256", return_value=sha):
            # the source differs per sha: an identical request is answered from the attempt log (same record, same code_sha256)
            out = self.private_check() if private else self.check(source=k.SOURCE + b" " + sha[:12].encode())
        self.assertEqual(h.payload_of(out["envelope"])["predicate"]["method"]["code_sha256"], sha)
        self.keep(out)
        self.seal_all()
        return out

    def bundle(self, out, key=None):
        code, data = self.raw_get(f"/v1/records/{out['record_id']}/bundle", key=key)
        self.assertEqual(code, 200, data[:200])
        d = pathlib.Path(tempfile.mkdtemp(prefix="cw-bt-"))
        with tarfile.open(fileobj=io.BytesIO(data)) as tf:
            names = tf.getnames()
            for m in tf.getmembers():
                if m.isfile():
                    p = d / m.name
                    p.parent.mkdir(parents=True, exist_ok=True)
                    p.write_bytes(tf.extractfile(m).read())
        return d, names

    def verify(self, d, *extra):
        buf = io.StringIO()
        code = verify.main(["--bundle", str(d), *extra], out=buf)
        return code, buf.getvalue()

    def tarballs(self, names):
        return [n for n in names if n.startswith("witness-methods-") and n.endswith(".tar.gz")]

    def test_each_library_the_witness_signed_with_gets_its_own_tarball_in_the_bundle(self):
        for sha, version, commit in SIGNED_WITH:
            with self.subTest(library=version, sha=sha[:12]):
                out = self.signed_with(sha)
                d, names = self.bundle(out)
                self.assertEqual(self.tarballs(names), [f"witness-methods-{version}.tar.gz"])
                self.assertEqual(hashlib.sha256((d / f"witness-methods-{version}.tar.gz").read_bytes()).hexdigest(), sha)
                code, text = self.verify(d)
                self.assertIn("PASS methods-tarball", text)
                self.assertNotIn("FAIL methods-tarball", text)

    def test_the_old_record_of_25_nov_names_1_5_0_and_its_bundle_passes_methods_tarball(self):
        sha = "0d691773a2c012b34ab5f22d2757b887761dcd6e09c29c5a2d05547dc21c69db"
        out = self.signed_with(sha)
        d, names = self.bundle(out)
        self.assertEqual(self.tarballs(names), ["witness-methods-1.5.0.tar.gz"])
        self.assertNotIn(tarball.tarball_name(), names)
        code, text = self.verify(d)
        self.assertIn("PASS methods-tarball", text)
        self.assertIn("PASS method-rerun", text)
        self.assertEqual(code, 0, text)

    def test_a_record_signed_now_still_gets_the_current_tarball(self):
        out = self.check()
        self.keep(out)
        self.seal_all()
        d, names = self.bundle(out)
        self.assertEqual(self.tarballs(names), [tarball.tarball_name()])
        self.assertEqual((d / tarball.tarball_name()).read_bytes(), tarball.build_methods_tarball())
        code, text = self.verify(d)
        self.assertEqual(code, 0, text)
        self.assertIn("PASS methods-tarball", text)

    def test_the_owner_bundle_of_a_private_record_gets_the_records_tarball_too(self):
        sha = "a36007123a4935d077cd702b3ee5620174f53a3d6a27499e0edd1f38e1a08aaf"
        out = self.signed_with(sha, private=True)
        d, names = self.bundle(out, key=OWNER)
        self.assertEqual(self.tarballs(names), ["witness-methods-1.6.0.tar.gz"])
        self.assertEqual(hashlib.sha256((d / "witness-methods-1.6.0.tar.gz").read_bytes()).hexdigest(), sha)

    def test_a_code_sha256_the_archive_cannot_supply_gives_no_tarball_and_a_skip_not_a_fail(self):
        out = self.signed_with(NOT_ARCHIVED)
        d, names = self.bundle(out)
        self.assertEqual(self.tarballs(names), [], "a wrong tarball must not be carried")
        code, text = self.verify(d)
        self.assertNotIn("FAIL methods-tarball", text)
        self.assertNotIn("PASS methods-tarball", text)
        self.assertNotIn("PASS method-rerun", text)
        self.assertIn("SKIP method-rerun", text)
        self.assertEqual(code, 0, text)
        notes = [n for n in names if n.startswith("witness-methods-") and not n.endswith(".tar.gz")]
        self.assertEqual(notes, ["witness-methods-missing.txt"])
        self.assertIn(NOT_ARCHIVED, (d / "witness-methods-missing.txt").read_text())

    def test_a_non_tarball_code_sha256_keeps_todays_behaviour(self):
        """match.screenshot's code_sha256 is the image digest: not a methods tarball, so the bundle is what it was."""
        out = self.check()
        self.keep(out)
        row = self.s.storage.get_kept(out["record_id"])
        env = copy.deepcopy(row["envelope"])
        payload = json.loads(base64.b64decode(env["payload"]))
        payload["predicate"]["method"] = {"id": "match.screenshot", "version": "1.0.0", "runtime": "python3.12+tesseract-5.3.0",
                                          "code_sha256": "sha256:" + "cd" * 32}
        env["payload"] = base64.b64encode(json.dumps(payload).encode()).decode()
        self.s.storage.update_kept(out["record_id"], envelope=env)
        d, names = self.bundle(out)
        self.assertEqual(self.tarballs(names), [tarball.tarball_name()])
        self.assertEqual((d / tarball.tarball_name()).read_bytes(), tarball.build_methods_tarball())
        self.assertNotIn("witness-methods-missing.txt", names)

    def test_get_methods_still_reports_the_current_library_only(self):
        code, reg, _ = self.s.call("GET", "/v1/methods", key=None)
        self.assertEqual(code, 200)
        self.assertEqual(reg["library"]["tarball"], tarball.tarball_name())
        self.assertEqual(reg["library"]["code_sha256"], tarball.methods_code_sha256())
        self.assertNotIn("archive", json.dumps(reg["library"]).lower())


if __name__ == "__main__":
    unittest.main()
