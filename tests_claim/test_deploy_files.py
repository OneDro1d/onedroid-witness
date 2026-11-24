"""(h) Dockerfile.claim and k8s/claim-dev.yaml: one image for the API and the signer, redact-copy built in, Postgres StatefulSet
with a PVC, the signer as a sidecar on a shared emptyDir socket, a Service exposing only the API port, IMAGE_PLACEHOLDER,
Secret names only. (i) README_CLAIM.md. Text checks only: no YAML library in the standard library."""
import re
import unittest

from tests_claim import helpers as h

SECRETS = ("claim-witness-signing-key", "claim-witness-master-key", "claim-witness-attempt-key", "claim-witness-dev-keys",
           "claim-pg-credentials")


def docs(text):
    return [d for d in re.split(r"(?m)^---\s*$", text) if d.strip()]


def kind_of(doc):
    m = re.search(r"(?m)^kind:\s*(\S+)", doc)
    return m.group(1) if m else None


class Dockerfile(unittest.TestCase):
    def setUp(self):
        self.text = (h.ROOT / "Dockerfile.claim").read_text()

    def test_builds_redact_copy_from_vendored_tree(self):
        self.assertIn("COPY tools/redact-copy/", self.text)
        self.assertIn("-mod=vendor", self.text)
        self.assertIn("/app/bin/redact-copy", self.text)
        self.assertIn("WITNESS_REDACT_BIN=/app/bin/redact-copy", self.text)

    def test_one_image_api_or_signer_by_command(self):
        self.assertRegex(self.text, r'ENTRYPOINT \["python3", "-m", "claim_witness"\]')
        self.assertRegex(self.text, r'CMD \["api"\]')
        self.assertIn("COPY --chmod=0755 claim_witness/ ./claim_witness/", self.text)
        self.assertRegex(self.text, r"USER 10001")
        self.assertNotIn("onedroid_witness", self.text)

    def test_vendored_redact_copy_present(self):
        for f in ("main.go", "go.mod", "go.sum", "vendor/modules.txt",
                  "vendor/github.com/OneDro1d/onedroid-indie/redact/redact.go"):
            self.assertTrue((h.ROOT / "tools" / "redact-copy" / f).is_file(), f)


class Manifest(unittest.TestCase):
    def setUp(self):
        self.text = (h.ROOT / "k8s" / "claim-dev.yaml").read_text()
        self.docs = docs(self.text)

    def by_kind(self, kind):
        return [d for d in self.docs if kind_of(d) == kind]

    def test_namespace_everywhere(self):
        for d in self.docs:
            self.assertRegex(d, r"(?m)^\s+namespace: witness-dev\s*$", kind_of(d))

    def test_postgres_statefulset_with_pvc(self):
        ss = self.by_kind("StatefulSet")
        self.assertEqual(len(ss), 1)
        self.assertIn("name: claim-pg", ss[0])
        self.assertIn("image: pgvector/pgvector:pg16", ss[0])
        self.assertIn("volumeClaimTemplates:", ss[0])
        self.assertIn("claim-pg-credentials", ss[0])

    def test_deployment_api_plus_signer_sidecar_on_shared_emptydir(self):
        deps = [d for d in self.by_kind("Deployment") if "name: claim-witness" in d]
        self.assertEqual(len(deps), 1)
        d = deps[0]
        self.assertEqual(d.count("image: IMAGE_PLACEHOLDER"), 2)
        self.assertRegex(d, r'args: \["api"\]')
        self.assertRegex(d, r'args: \["signer", "serve"\]')
        self.assertIn("emptyDir:", d)
        self.assertGreaterEqual(d.count("mountPath: /run/claim-witness"), 2)
        self.assertIn("WITNESS_SIGNER_SOCKET", d)
        # the signing key is mounted into the signer container only
        api_part, signer_part = d.split('args: ["signer", "serve"]')[0], d.split('args: ["signer", "serve"]')[1]
        self.assertIn("claim-witness-signing-key", signer_part)
        self.assertNotIn("claim-witness-signing-key", api_part)

    def test_service_exposes_only_the_api_port(self):
        svcs = self.by_kind("Service")
        self.assertTrue(svcs)
        api = [s for s in svcs if "name: claim-witness" in s]
        self.assertEqual(len(api), 1)
        self.assertEqual(re.findall(r"targetPort:\s*(\S+)", api[0]), ["8080"])
        self.assertNotIn("signer", api[0].split("spec:", 1)[1])

    def test_secret_names_only_never_values(self):
        for name in SECRETS:
            self.assertIn(name, self.text)
        self.assertEqual(self.by_kind("Secret"), [])
        self.assertNotRegex(self.text, r"(?m)^\s*(data|stringData):")


class B2b(unittest.TestCase):
    """(i) the fetcher wiring and the image digest in the manifest, names only; (f) Tesseract in the image."""

    def setUp(self):
        self.manifest = (h.ROOT / "k8s" / "claim-dev.yaml").read_text()
        self.api = self.manifest.split('args: ["signer", "serve"]')[0]

    def test_fetcher_env_in_the_api_container(self):
        self.assertRegex(self.api, r"FETCHER_URL, value: \"?http://claim-fetcher\.witness-dev\.svc\.cluster\.local\"?")
        self.assertIn("FETCHER_SECRET_FILE", self.api)
        self.assertIn("claim-fetcher-secret", self.api)
        self.assertRegex(self.manifest, r"secretName: claim-fetcher-secret[\s\S]{0,120}key: secret")
        self.assertIn("WITNESS_IMAGE_DIGEST", self.api)
        self.assertIn("IMAGE_DIGEST_PLACEHOLDER", self.api)
        self.assertNotIn("claim-fetcher-secret", self.manifest.split('args: ["signer", "serve"]')[1].split("volumes:")[0])

    def test_dockerfile_installs_tesseract(self):
        text = (h.ROOT / "Dockerfile.claim").read_text()
        self.assertIn("tesseract-ocr", text)
        self.assertIn("tesseract-ocr-eng", text)
        self.assertIn("WITNESS_TESSERACT_BIN", text)

    def test_readme_has_a_section_per_method(self):
        text = (h.ROOT / "README_CLAIM.md").read_text()
        for heading in ("### page.live", "### match.text", "### match.screenshot", "### Observations", "claim-fetcher-secret"):
            self.assertIn(heading, text)


class Readme(unittest.TestCase):
    def test_readme_sections(self):
        text = (h.ROOT / "README_CLAIM.md").read_text()
        for heading in ("Builder decisions", "Running the tests", "Running it locally", "Secrets"):
            self.assertIn(heading, text)
        for name in SECRETS:
            self.assertIn(name, text)


if __name__ == "__main__":
    unittest.main()
