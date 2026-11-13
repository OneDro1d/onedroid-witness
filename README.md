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
"check_py", "openrouter_key_file" (or `OPENROUTER_API_KEY`), "private_mode", "host", "port", "profiles_served", "models_not_served"}`. `vendor/check.py` is the
public checker at the hash the service pins (`onedroid_witness/checkpin.py`); the service refuses to start on any other. `profiles_served`
defaults to cited-sources, agent-work and test-run: publisher-surfaces is refused by name until the format carries a candidate kind
(restatement or artefact) from the auditor and a gate passes on it (NEXT-REVISION 23 of the format). For an agent-work or test-run claim the
request carries the files the manifest names under `sources/` and `sessions/` (each hash-checked against its manifest entry, a part no entry
names refused by name); every pointer of the claim's `evidence` list is resolved from them the way `check.py` resolves it (the pointed file
line with its neighbours, the handed-in output, each artefact by name and hash, the session record row) and rendered to the models, a pointer
that cannot be read here (not sent, held by hash, not listed) is said so by name and never carries a verdict, and the models' `on` indexes
the evidence list. A test-run auditor part has exactly the three rows C-001, C-002, C-003 (SPEC 13). In public mode the request's manifest is
bound to the published snapshot: `manifest.json` is fetched beside the published `audit.jsonl` (the same rules as the audit fetch) and the
request is refused by name when its `subject`, `sources`, `pages`, `grading.profile` or `grading.sessions` differ from the published ones, so a
carried file can only be one the published record lists at that hash. The audited page is a carried file too (0.1.7): `page.txt` is
hash-checked against the manifest's `pages` entry and refused by name when it differs or when no entry names it. Every answer records what
the models read: `service.json` and every witness header carry `manifest_sha256` and `carried` (each carried file's path and sha256,
`page.txt` included) and, since 0.1.8, `bound` (the sha256 of each bound manifest section in canonical JSON, because `carried` binds bytes
and not which source entry a pointer resolved through: the claims session's seventh re-gate re-aimed a `prod/config.yaml` entry at the
genuine `dev/config.yaml` file and every carried hash stayed genuine); the public checker at the pinned hash (the bound cut, af216591…)
fails a witness whose `carried` or `bound` differs from the snapshot's manifest and a decision that rests on a file the witness did not
carry, as `add_witness.py` refuses a mismatch before writing. Inside any text a model sees, a run of eight or more
fence-like characters is broken with a visible mark, so a planted "fence" inside a carried line is never one; a planted instruction needs
no fence, though, so a model that follows one (gpt-4.1-nano answered EVIDENCED on 21 of 21 planted rows in the claims session's sixth
re-gate, 13 Nov 2026) is named in the configuration's `models_not_served` with the reason and refused by name. Since 0.1.8 two rules stand above
any model's answer (the seventh re-gate's fresh plants swayed served models: a plain-English and a German note, a planted JSON verdict
object): evidence text that names a verdict addresses the witness, so a row whose readable pointer text or candidate quote holds
EVIDENCED, CONTRADICTED, UNDECIDED or NO EVIDENCE PUBLISHED (upper case, whole words; the claim text and the page context are not
scanned) is UNDECIDED by rule for every model with no model call, the note naming the pointer and the word; and a chat model's EVIDENCED
stands only where a decision model that ran in the same job answered EVIDENCED on the row, so a request must name a decision model
(400 otherwise). Each served model's configuration carries its `plant_regression` record (fixture, date, result), shown on `/models` and
in `service.json`. A `published_url` on a
gist needs the gist's revision URL (`raw/<revision>/audit.jsonl`): a raw gist URL names one blob under any file name, and the refusal
says so. `GET /healthz` lists the profiles served and, for each not served, why, and the models not served with the reason.

## HTTP surface
`POST /witness` (multipart or JSON: `manifest.json`, `audit.jsonl`, `audit.jsonl.sig`, `allowed_signers`, `signatures.json`, the audited
text, and any file the manifest names under `sources/` or `sessions/` as a part named by that path; fields `models` (a comma-separated
string or a list of ids), `max_cost_usd` (a finite number), `published_url`) answers `202 {job_id, estimate_usd}` or a refusal; `GET /witness/{job_id}` the status;
`GET /witness/{job_id}/answer.tar` the answer with its sha256 in `X-Answer-SHA256`; `GET /models`, `GET /keys`, `GET /healthz`.
A sources-signed publisher (the format's `sign.py --role sources`) leaves `manifest.sources.sig` out of the request: `signatures.json` carries
the entry, and the service refuses that file by name (0.1.10, the ninth re-gate's S15).

## Where it comes from
Contract: the witness-service contract draft v6 and the measurements of 12 Nov 2026 (two probes, 36 models over a 74-claim snapshot), in the
OneDroid business notepad. Built by the trilix-onedroid-business session for mission M-20261112-EVIDENCE-STEP1; gated by another session
from a fresh clone with withheld audit parts, never by its builder. Licence: Apache-2.0.
