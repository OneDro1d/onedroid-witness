"""B3 (h) and the vectors: k8s/claim-dev.yaml names the sealer, notary and armarium settings (names only, optional volumes,
never in the signer container); README_CLAIM.md has the B3 sections and keeps the wording rule; vectors.json carries a sealed
record (leaf, path, batch header, notary over) that reproduces in the witness and in witness-verify (also pure-Python)."""
import os
import re
import subprocess
import sys
import unittest

from tests_claim import helpers as h
from tests_claim.test_deploy_files import docs, kind_of


class Manifest(unittest.TestCase):
    def setUp(self):
        self.text = (h.ROOT / "k8s" / "claim-dev.yaml").read_text()
        dep = [d for d in docs(self.text) if kind_of(d) == "Deployment" and "name: claim-witness" in d][0]
        self.api, rest = dep.split('args: ["signer", "serve"]')
        self.signer = rest.split("      volumes:")[0]
        self.volumes = rest.split("      volumes:")[1]

    def test_api_names_sealer_notary_and_armarium(self):
        for name in ("WITNESS_BATCH_INTERVAL_S", "WITNESS_BATCH_MAX_LEAVES", "WITNESS_SEALER", "WITNESS_NOTARY_URL",
                     "WITNESS_NOTARY_TOKEN_FILE", "WITNESS_NOTARY_CA_FILE", "ARMARIUM_URL", "ARMARIUM_TOKEN_FILE",
                     "ARMARIUM_CA_FILE", "ARMARIUM_CHAIN", "NDIM_STORE_EVIDENCE", "WITNESS_LINK_BASE"):
            self.assertIn(name, self.api, name)
            self.assertNotIn(name, self.signer, name)
        self.assertRegex(self.api, r'WITNESS_BATCH_INTERVAL_S, value: "3600"')
        self.assertRegex(self.api, r'NDIM_STORE_EVIDENCE, value: "0"')

    def test_optional_volumes_names_only(self):
        for name in ("claim-witness-notary-token", "claim-witness-armarium-token", "armarium-ca"):
            self.assertIn(name, self.volumes, name)
        for block in re.findall(r"(?s)- name: (?:notary-token|armarium-token|armarium-ca)\n.*?optional: true", self.volumes):
            self.assertIn("optional: true", block)
        self.assertEqual(len(re.findall(r"(?s)- name: (?:notary-token|armarium-token|armarium-ca)\n.*?optional: true", self.volumes)), 3)
        self.assertEqual([d for d in docs(self.text) if kind_of(d) in ("Secret", "ConfigMap")], [])


class Readme(unittest.TestCase):
    def setUp(self):
        self.text = (h.ROOT / "README_CLAIM.md").read_text()

    def test_b3_sections(self):
        for heading in ("## Keep", "## Private store", "## Delete", "## Sealer", "## n-dim", "### Builder decisions, B3"):
            self.assertIn(heading, self.text, heading)
        for name in ("leaf", "RFC 9162", "0x01", "over", "NDIM_STORE_EVIDENCE", "not-configured", "evidence_key"):
            self.assertIn(name, self.text)

    def test_wording_rule(self):
        delete = self.text.split("## Delete", 1)[1].split("\n## ", 1)[0]
        self.assertIn("the key is deleted; the encrypted bytes stay on the chain", delete)
        body = delete.split("Wording rule", 1)[-1] if "Wording rule" in delete else delete
        for w in ("erased", "permanently removed"):
            self.assertNotIn(w, delete.replace('"erased"', "").replace('"permanently removed"', "").lower())


class Vectors(unittest.TestCase):
    def test_vectors_have_a_sealed_record(self):
        import json
        doc = json.loads((h.ROOT / "claim_witness" / "vectors" / "vectors.json").read_text())
        s = doc["seal"]
        for k in ("leaves", "root", "paths", "batch_header", "over", "notary", "seals"):
            self.assertIn(k, s)
        self.assertEqual(s["notary"]["over"], s["over"])

    def test_check_passes_with_both_ed25519_backends(self):
        for pure in ("0", "1"):
            env = dict(os.environ, WITNESS_VERIFY_PURE=pure)
            done = subprocess.run([sys.executable, "-m", "claim_witness.vectors", "--check"], cwd=str(h.ROOT), env=env,
                                  capture_output=True, text=True, timeout=600)
            self.assertEqual(done.returncode, 0, done.stdout[-2000:] + done.stderr[-2000:])
            self.assertIn("seal", done.stdout)
            self.assertIn("all vectors reproduce", done.stdout)


if __name__ == "__main__":
    unittest.main()
