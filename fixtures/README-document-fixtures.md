# The claims-snapshot 0.9 "document" fixtures (R4c)

`document-in-document-proof-2026-11-22/` and `document-external-proof-2026-11-22/` are the format's two examples of the document profile
(SPEC.md section 17) at OneDro1d/onedroid-claims commit a5ce04078a8f6908adf8a82dc76b3a46f9541b7f (PR #35 head), exported with
`git archive a5ce040` and passed through `tests/document_fixtures.py` `strip_witnesses()`: the folder as its auditor published it, before
any witness was added (the pre-witness stage, SPEC 14). What the function removed, and nothing else:

- `witness/` (the example's `quote-check` script witness and `model-reader` model witness) and the example's `README.md`;
- the two entries of `grading.witnesses` and the two `files` entries naming the witness files (`manifest.json` rewritten, indent 1);
- the two `witness` entries of `signatures.json` and the two witness principals' lines of `allowed_signers`.

`audit.jsonl`, `audit.jsonl.sig`, `page.md`, `sources/001.txt`, `keys/model-keys.jsonl`, `anchors.json` and `manifest.sources.sig` are
byte-identical to a5ce040: the auditor's `sources` signature is over the five bound manifest sections, which a witness never changes. The
vendored checker (ff304606...) passes both folders with 0 failed.

The content is invented by the format's owner (an example document about an example product at example.org); the keys are throwaway
keys made for the examples and discarded. Variants (a restatement-only claim, EVIDENCED on a restatement, every claim settled by rule, a
row marked on request or withdrawn) are made from these folders in a temp dir by `document_fixtures.edit_audit()`, re-signed with a fresh
throwaway key there, never committed.

`recordings-document/` and `recordings-document-restatement/` are recorded model answers in the FakeClient's format (`raw-<model slug>.jsonl`,
one row per claim id), written for these fixtures in the shape the live providers return. The rows for C-002 answer EVIDENCED on purpose:
C-002 has no artefact proof and no counter, so a service that keeps R4c-3 never asks a model about it, and one that did would show it.
