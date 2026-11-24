"""canon/1 (SPEC §9.1). The implementation lives in the method library (claim_witness/methods/canon.py) so that it ships in
the methods tarball the verifier re-runs; this module re-exports it."""
from .methods.canon import CANON_ID, canon1, decode, html_text, is_html, normalise  # noqa: F401
