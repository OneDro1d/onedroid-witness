# onedroid-witness

The witness service of the [claims-snapshot format](https://github.com/OneDro1d/onedroid-claims) (SPEC.md section 14). It takes an
**auditor part** (the claims of a published page or an agent's work, each with the candidate evidence an auditor gathered, and no verdicts)
and answers claim by claim from N **model witnesses**: chat models through OpenRouter's chat endpoint, decision models through its Decisions
API. Each model's answers become one **witness file** in the format's own words (EVIDENCED, CONTRADICTED, NO EVIDENCE PUBLISHED, UNDECIDED
with a note), signed with a key the service holds for that model identity. The answer is the folder `add_witness.py` inserts and `check.py`
verifies, offline, with no call back to the service.

Standard-library Python plus `ssh-keygen`. No framework, no dependency, so a stranger can read every line.

## What it does, and does not
- A witness reads what it is sent. It fetches nothing, runs nothing, and never changes the auditor part.
- A router, an alias or a free tier is never a model identity: the witness file names the model that answered, as the provider spelled it, version included.
- An answer the service cannot read is an UNDECIDED row whose note says why (not parseable; no content returned; a verdict word outside the
  vocabulary; a wrong shape key; a candidate index that does not exist). Nothing is retried with another prompt; nothing is normalised from a near-miss.
- A decision model returns probabilities and no text; the service writes the note from the probabilities, names the best-scoring candidate, and says so in the header.
- The prompts and the decision questions are part of the contract: their sha256 is in every witness header and in `service.json`.
- A daily spend cap and a per-request estimate bound the cost; a request whose estimate crosses the bound is refused before any model is called; a partial run names the models it skipped and why.
- The public service takes published parts only (a catalogue record, or a public https URL whose `audit.jsonl` matches byte for byte, fetched under SSRF rules). Private mode is the same code run by the caller with the caller's own key.
- The signature proves "the service says model X answered", never that a model signed. `GET /keys` lists every key the service has ever used with its validity window and never deletes one.

## Run it
```
python3 -m unittest discover -s tests            # 42 tests, offline, recorded answers; needs ssh-keygen
python3 -m onedroid_witness.cli run --config config.json <snapshot folder> <answer folder>   # private mode, one shot
python3 -m onedroid_witness.cli serve --config config.json                                   # the service
```
Configuration: `{"models": [{"id", "kind": "chat|decision", "max_tokens"}], "daily_cap_usd", "keys_dir", "jobs_dir", "ledger_path",
"check_py", "openrouter_key_file" (or `OPENROUTER_API_KEY`), "private_mode", "host", "port"}`. `vendor/check.py` is the public checker at
the hash the service pins (`onedroid_witness/checkpin.py`); the service refuses to start on any other.

## HTTP surface
`POST /witness` (multipart or JSON: `manifest.json`, `audit.jsonl`, `audit.jsonl.sig`, `allowed_signers`, `signatures.json`, the audited
text; fields `models`, `max_cost_usd`, `published_url`) answers `202 {job_id, estimate_usd}` or a refusal; `GET /witness/{job_id}` the status;
`GET /witness/{job_id}/answer.tar` the answer with its sha256 in `X-Answer-SHA256`; `GET /models`, `GET /keys`, `GET /healthz`.

## Where it comes from
Contract: the witness-service contract draft v6 and the measurements of 12 Nov 2026 (two probes, 36 models over a 74-claim snapshot), in the
OneDroid business notepad. Built by the trilix-onedroid-business session for mission M-20261112-EVIDENCE-STEP1; gated by another session
from a fresh clone with withheld audit parts, never by its builder. Licence: Apache-2.0.
