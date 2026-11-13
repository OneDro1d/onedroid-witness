"""onedroid-witness: the witness service of the claims-snapshot format (SPEC.md section 14; contract draft v6).

A service that takes an auditor part and answers claim by claim from N model witnesses (chat models through OpenRouter's chat
endpoint, decision models through its Decisions API), one signed witness file per model identity, in the shape add_witness.py
inserts and check.py verifies. Standard library only, so a stranger can read it and a container needs nothing but Python and
ssh-keygen.

Built by trilix-onedroid-business for mission M-20261112-EVIDENCE-STEP1 (Michal's go of 12 Nov 2026 21:5xZ). The builder never
gates its own build: the gate is the claims session's, from a fresh clone, with withheld audit parts (draft v6 section 9).
"""

__version__ = "0.1.6-dev"  # 0.1.1: the S1 gate's eleven defects fixed; 0.1.2: the re-gate's N1 to N3; 0.1.3: the second re-gate's P1 (one try around the whole request path, manifest shape checked), N1 (publisher-surfaces out of scope), check.py repinned to the K2 cut; 0.1.4: the third re-gate's F2 (the witness signed line is the checker's prescribed line, so 0.5 and 0.6 folders take the witness), F3 (the length read and the body parse answer 400), F1 (agent-work and test-run out of scope until their evidence is carried); 0.1.5: service item S-1 (a request carries the files the manifest names under sources/ and sessions/, hash-checked; every pointer of an agent-work or test-run row is resolved from them and rendered, an unreadable pointer is said so by name and never carries a verdict; `on` indexes the evidence list; the three profiles served again), S-2 (a test-run auditor part has exactly C-001..C-003), the fourth re-gate's G1 (a JSON `models` that is a number answers 400 by name; a non-finite max_cost_usd answers 400); 0.1.6: the fifth re-gate's H1 (public mode binds the manifest to the published snapshot, every answer records the manifest and carried-file hashes) and H2 (inline fence runs broken), the S-2 message names the ids (13 Nov 2026)
