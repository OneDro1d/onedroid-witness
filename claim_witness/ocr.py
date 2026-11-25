"""OCR for match.screenshot: Tesseract (installed in Dockerfile.claim, named by WITNESS_TESSERACT_BIN), run as
`tesseract stdin stdout -l eng --psm 3` with the image on stdin and no network or shell. A second run of the same command
with the `tsv` config gives the word confidences, and their mean is the image's readability (BD19 addendum, see
match_screenshot). The image digest that becomes
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

    def readability(self, image):
        """How well Tesseract reads the image, from its own word confidences: the mean confidence of the words it returns,
        x100 as an integer (9150 = 91.5), or None when it fails or finds no word. A second run of the same command line as
        `text` with the `tsv` config appended (one row per word, with its confidence); it depends on the image only. The text
        path is not touched: `text` still runs the plain command and returns what it always returned."""
        try:
            done = subprocess.run([self.binary, "stdin", "stdout", "-l", "eng", "--psm", "3", "tsv"], input=image,
                                  capture_output=True, timeout=TIMEOUT, check=False,
                                  env={"PATH": "/usr/bin:/bin", "LC_ALL": "C.UTF-8", "OMP_THREAD_LIMIT": "1"})
        except (OSError, subprocess.SubprocessError):
            return None
        if done.returncode != 0:
            return None
        return mean_confidence_x100(done.stdout.decode("utf-8", "replace"))


def mean_confidence_x100(tsv):
    """The mean word confidence of Tesseract's TSV output, x100 rounded to an integer, or None when it has no word. A word is a
    level-5 row with non-blank text and a confidence of 0 or more (-1 marks rows that are not words)."""
    total, n = 0.0, 0
    for line in tsv.splitlines()[1:]:
        f = line.split("\t")
        if len(f) < 12 or f[0] != "5" or not f[11].strip():
            continue
        try:
            conf = float(f[10])
        except ValueError:
            continue
        if conf >= 0:
            total, n = total + conf, n + 1
    return int(round(100 * total / n)) if n else None
