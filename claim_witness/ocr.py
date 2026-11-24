"""OCR for match.screenshot: Tesseract (installed in Dockerfile.claim, named by WITNESS_TESSERACT_BIN), run as
`tesseract stdin stdout -l eng --psm 3` with the image on stdin and no network or shell. The image digest that becomes
match.screenshot's code_sha256 comes from WITNESS_IMAGE_DIGEST (`sha256:<hex>` or `<hex>`), set by the orchestrator at deploy.
"""
import os
import re
import subprocess

TIMEOUT = 60
DIGEST = re.compile(r"^(?:sha256:)?([0-9a-fA-F]{64})$")


def parse_digest(value):
    """The lowercase hex of an image digest, or None when it is missing or not a sha256 digest (e.g. a placeholder)."""
    m = DIGEST.match((value or "").strip())
    return m.group(1).lower() if m else None


class Ocr:
    def __init__(self, binary):
        self.binary = binary
        self._version = None

    def available(self):
        return bool(self.binary) and os.path.isfile(self.binary) and os.access(self.binary, os.X_OK) and self.version() is not None

    def version(self):
        """'5.3.0' from `tesseract --version`, or None."""
        if self._version is None:
            try:
                done = subprocess.run([self.binary, "--version"], capture_output=True, timeout=20, check=False,
                                      env={"PATH": "/usr/bin:/bin", "LC_ALL": "C.UTF-8"})
            except (OSError, subprocess.SubprocessError):
                return None
            m = re.search(rb"tesseract\s+v?([0-9][0-9A-Za-z.\-]*)", done.stdout + done.stderr)
            self._version = m.group(1).decode()[:20] if m else None
        return self._version

    def text(self, image):
        """The text Tesseract reads, or None when it fails."""
        try:
            done = subprocess.run([self.binary, "stdin", "stdout", "-l", "eng", "--psm", "3"], input=image, capture_output=True,
                                  timeout=TIMEOUT, check=False, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C.UTF-8", "OMP_THREAD_LIMIT": "1"})
        except (OSError, subprocess.SubprocessError):
            return None
        if done.returncode != 0:
            return None
        return done.stdout.decode("utf-8", "replace")
