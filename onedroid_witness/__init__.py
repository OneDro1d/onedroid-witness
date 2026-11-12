"""onedroid-witness: the witness service of the claims-snapshot format (SPEC.md section 14; contract draft v6).

A service that takes an auditor part and answers claim by claim from N model witnesses (chat models through OpenRouter's chat
endpoint, decision models through its Decisions API), one signed witness file per model identity, in the shape add_witness.py
inserts and check.py verifies. Standard library only, so a stranger can read it and a container needs nothing but Python and
ssh-keygen.

Built by trilix-onedroid-business for mission M-20261112-EVIDENCE-STEP1 (Michal's go of 12 Nov 2026 21:5xZ). The builder never
gates its own build: the gate is the claims session's, from a fresh clone, with withheld audit parts (draft v6 section 9).
"""

__version__ = "0.1.0-dev"
