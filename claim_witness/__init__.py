"""claim_witness: the single-claim witness (SPEC Draft 3 plus DECISIONS BD1-BD12), slice B1.

Modules: jcs (RFC 8785, integers only), ids (ids and commitments), methods (the method library and canon/1), record (the
record builder), dsse, crypto, schemas, signer (the sidecar), storage and pg (BD7), screen (public screening), reqauth
(onedroid-req/1 and agent signatures), service (the witness), api (HTTP), verify (witness-verify, standard library only),
vectors (test vectors), tarball (the reproducible methods tarball).
"""
__version__ = "0.1.0"
SERVICE = "claim-witness"
