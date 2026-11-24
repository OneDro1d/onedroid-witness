# claim-witness, slices B1 and B6

The single-claim witness (SPEC Draft 3, `.df/missions/M-20261124-CLAIM-WITNESS/SPEC.md` in the claims notepad, plus
`M-20261124-WITNESS-BUILD/DECISIONS.md` BD1-BD12, which wins where they differ). One claim in, one signed record out. The old
`onedroid_witness/` package is untouched and keeps running until cut-over (B8).

## What B1 does

- **Records.** in-toto Statement v1 in a DSSE envelope, Ed25519, payload = RFC 8785 canonical JSON with integers only (BD9).
  Record id = H(payload), claim id = H(canonical claim), leaf = H(0x00 || payload) (SPEC §2.0). `claim_witness/jcs.py`,
  `ids.py`, `dsse.py`, `record.py`.
- **Private records** (the default visibility): the payload holds only the §2.6 allow-list (`visibility, body_commitment,
  finding, outcome, reason, method, limits, detail, attempt, options_used, witnessed_at, witness`); the subject is the claim
  commitment. The answer carries `disclosure: {salt (base64url), body}` once.
- **Methods** (`claim_witness/methods/`, standard library only): `match.exact`, `quote.in-source`, `tests.pass` (parsers: Jest
  JSON, `go test -json`, JUnit XML including pytest `--junitxml`, the pytest `-rA` summary). Each has its slots, its T and F
  templates, its findings with their classes, and its fixed `limits`. canon/1 (§9.1) is `methods/canon.py`. The outcome table
  (§2.4) is `record.outcome_for`.
- **Attempts** (§7.3): HMAC-SHA256 tags under the attempt key, kept 30 days, scope `account`, counted for private and public
  checks alike.
- **Public screening** (§3, VR-21, BD11): image and PDF objects are refused (`media-not-allowed`); the signed text fields go
  through `tools/redact-copy` (vendored, built into the image at `/app/bin/redact-copy`, named by `WITNESS_REDACT_BIN`) and
  through personal-data rules (email, phone, IBAN, payment card, US SSN shape). A hit is 422 `personal-data`.
- **The signer sidecar** (`claim_witness/signer.py`): Unix socket only (path from `WITNESS_SIGNER_SOCKET`), requests
  `{predicateType, payload}`, schema checks for claim, observation and batch-header payloads, DSSE Ed25519, one signing-log
  row per signature. Key lists are signed only by the operator command, with the outgoing and the incoming key (§7.4).
- **The HTTP API** (`claim_witness/api.py`, `service.py`): `POST /v1/witness` (200 within `wait` s, else 202 and
  `GET /v1/jobs/{id}`), `POST /v1/agent-keys`, `GET /v1/methods`, `GET /.well-known/witness.json`, `GET /v1/key-lists/{seq}`,
  `GET /healthz`. Auth: dev keys from `WITNESS_DEV_KEYS_FILE`, or the BFF's `onedroid-req/1` signature plus `X-Witness-Account`
  (BD8). Agent content signatures with the nonce (24 h) and time (300 s) checks (VR-22). `Idempotency-Key`, and the
  object-only idempotency rule.
- **Storage** (BD7): one interface (`storage.py`), in memory for unit tests and Postgres 16 with psycopg 3 for the cluster
  (`pg.py`, plain SQL migrations in `claim_witness/migrations/`). Jobs are kept 24 h with their answer encrypted (AES-256-GCM
  under a key derived from the master key, BD1).
- **witness-verify** (`claim_witness/verify.py`, standard library only; `cryptography` when importable, else a pure RFC 8032
  Ed25519, BD10): §6 steps 1 (key list), 2 (signature), 3 (payload canonical, record id, claim id or both commitments), 5 (key
  validity, unsealed), 6 (files and a re-run of the method from the tarball), 7 (agent signature). Step 4 (the seal) prints
  SKIP until S3. Every check prints `PASS`, `FAIL` or `SKIP` with its name; any FAIL exits 1.
- **Test vectors** (`claim_witness/vectors/vectors.json`): RFC 8785, canon/1, claim ids, record ids and leaves, commitments,
  attempt tags, templates for every method and both assertions, and a signed public and private record with their key list.
  `python3 -m claim_witness.vectors --check` reproduces each one in the witness and in witness-verify.
- **The methods tarball** (§9.4): `tools/build_methods_tarball.py --out DIR` writes `witness-methods-<version>.tar.gz` (files
  sorted, mtime 0, uid/gid 0, no names, gzip mtime 0) and prints its sha256, which is every record's `method.code_sha256` and
  what `GET /v1/methods` reports.

## judge.supports

Slice B6 (SPEC §4 and §5, DECISIONS BD2 and BD3). A statement in the submitter's own words and 1 to 5 evidence items, judged by
one to three language models. `claim_witness/methods/judge_supports.py` holds everything that decides, standard library only,
and ships in the methods tarball. `claim_witness/judge.py` makes the model calls and computes the price.

- **The claim.** `{"method": "judge.supports", "method_major": 1, "params": {}, "assertion": true|false, "statement": "..."}`.
  The statement is required: 1 to 4,000 characters of NFC text. The record's `statement` is that text, prefixed
  `Asserted false: ` when the assertion is false. Findings are `judged-supports` (+), `judged-contradicted` (−) and
  `judged-silent` (○), and the outcome follows the §2.4 table.
- **Evidence.** One slot, `evidence`, takes 1 to 5 items. The method's schema accepts `object` and `observation`, but this
  witness serves `object` only: an `observation` item is 422 `wrong-evidence-slots` until B2b. `url` and `record` evidence is
  also 422 `wrong-evidence-slots`. Each item's visible text is its canon/1 text. For an HTML object, the elements canon/1 drops
  for being hidden are kept apart as hidden nodes and never sent to a model. `item_from_observation` reads an observation's
  `text.canonical.txt` and the excerpts in its `hidden-nodes.json`, so observations plug in when B2b serves them.
- **What runs, in order.** These steps run before any model is called:
  1. evidence that is not UTF-8 text gives `unreadable`;
  2. an input over 200,000 tokens gives `too-large` (the estimate is ceil(characters / 4) of the prompt plus the input);
  3. the injection rules run, and any hard flag gives `possible-injection`;
  4. an item with no visible text gives `unreadable`.

  Then each model gets the fixed prompt (`claim_witness/methods/prompts/judge.supports-1.0.0.txt`, whose sha256 is the
  record's `prompt_sha256`) and the input. The input holds the statement and the assertion, then each item, between marker
  lines whose nonce comes from the content, with every space written as U+02C6. The marking keeps lengths, so offsets hold.
  Every quote is verified, and a model run is then decided. Last, the runs are combined.
- **The model's answer.** The witness reads the first JSON object in the text and strips a Markdown code fence:
  `{"finding": ..., "quotes": [{"source": i, "start": s, "end": e, "text": "..."}]}`. A quote verifies when the source is an
  item, `0 <= start < end <=` the length of that item's visible text, the span holds at least 2 non-space characters, and
  `text`, when given, equals the span. A positive or negative finding with no verified quote is no finding (`undecided`, run
  note `no-verified-quote`). A finding word outside the vocabulary is its own note (`finding-not-in-vocabulary`). Garbage,
  the wrong shape, an HTTP error, a dead endpoint and a timeout are each a note on that run, never a 5xx.
- **Injection rules (§5.5).** Hard flags are checked in the visible text and in the hidden nodes:
  - `instruction-override` ("ignore previous instructions");
  - `role-marker` (`system:`, `assistant:` or `developer:` at the start of a line);
  - `chat-token` (`<|im_start|>`, `[INST]`, `<<SYS>>`);
  - `addressed-to-model` ("Dear AI assistant,", "You are now an AI judge");
  - `verdict-instruction` ("answer SUPPORTED");
  - `new-instructions`;
  - `statement-in-hidden`: the statement word for word in a hidden node, or at least 90% of its content words when it has
    four or more.

  The soft signal is `verdict-word` (SUPPORTED, NOT_SUPPORTED, EVIDENCED, judged-supports and the like). It is recorded and
  does not block. Flags hold names, item indices and offsets only.
- **The model setup (BD2).** `options.models: {"count": 1|2|3, "require": n}`, with `require <= count` and a default `require`
  equal to `count`, strict integers. The legacy `panel: n` means `{count: n, require: n}`, and a `panel` that disagrees with
  `models.count` is 422. Models are picked one per vendor in list order while vendors last, then the rest of the list. A
  finding needs `require` runs agreeing and no other finding as large. Two findings with no winner give `judges-disagree`.
  Otherwise the runs' failure decides: `undecided`, `timeout` or `model-unavailable`. `options_used` is
  `{accept_untrusted, allow_provider, models: {count, require}}`.
- **The record.** `judgment` holds:
  - `models`: `{id, provider, version}`, where `version` is the dated model id the endpoint answered with;
  - `prompt_sha256`, `rubric_version` and `sampling`;
  - `runs`: `{model, raw_output_sha256, finding, quotes, note, rejected}`;
  - `agreement`, `injection_flags` and `input_sha256`.

  `detail` holds counts only: `evidence_items`, `visible_chars`, `input_tokens_est`, `injection_hard`, `injection_soft`,
  `models`, `require`, `models_run` and `agreeing`. A private record carries the judgment in the body only (§2.6).
- **Private claims (§5.7).** A private claim is 422 `provider-not-allowed` unless `options.allow_provider` is true, which
  `options_used` records. Raw model outputs of a private record are discarded. The body has each one's sha256, and nothing is
  stored in the clear. A public record's raw outputs go to `judge_outputs` (migration `002_judge.sql`) with an `expires_at`
  24 h on, and the purge removes them.
- **Attempts (§7.3).** Every judge run counts in the attempt table. That includes private runs with fresh salts (TS-21p),
  because the tag is computed on the plaintext claim. A judge claim is never answered from the object-only idempotency cache.
- **Price (BD3).** Every answer, mechanical ones included, carries `price: {credits, lines}` beside the envelope. The price is
  1 credit for the check, plus `ceil(10 × price_factor)` for each model run made. A run that timed out or failed was still
  made, so it counts. `possible-injection`, `too-large` and `unreadable` make no run. `GET /v1/price` and `GET /v1/methods`
  publish the list: check 1, observation 5, model run 10, kept evidence 1 per MB-month, and each model's `credits_per_run`.
  `WITNESS_PRICE_LIST_FILE` can override it. There is no balance logic here: the BFF holds the credits.
- **The backend.** Any OpenAI-compatible `POST <base>/chat/completions`, configured by env only:
  - `WITNESS_JUDGE_BASE_URL`, for example `https://openrouter.ai/api/v1`, or the host's vLLM in standalone;
  - `WITNESS_JUDGE_API_KEY_FILE`, a key file and never an env value;
  - `WITNESS_JUDGE_MODELS_FILE`, `[{"id", "vendor", "price_factor", "timeout"}]`;
  - optionally `WITNESS_JUDGE_MAX_TOKENS`, which defaults to 1024.

  The request is the model id, the two messages, `temperature: 0` and `max_tokens`: no tools, no functions and no user field.
  It never carries the account, the agent, key ids, the options or the label. Each call is held to its model's `timeout`
  seconds. A router, an alias or a variant (`openrouter/auto`, `~...`, `...-latest`, `...:free`) is refused when the list is
  loaded. If any of the three settings is unset, or a mounted file is absent, `judge.supports` answers 503
  `judge-not-configured` and nothing is signed.
- **On dev** (`k8s/claim-dev.yaml`), the api container names the backend. The key comes from Secret
  `onedroid-witness-openrouter` (key `key`) at `/etc/claim-witness/judge-key/key`. The model list comes from ConfigMap
  `claim-witness-judge-models` (key `models.json`) at `/etc/claim-witness/judge-models/models.json`. Both are optional
  volumes, so the pod starts without them. Only names are in the manifest. For example:

  ```
  kubectl -n witness-dev create configmap claim-witness-judge-models --from-file=models.json=models.json
  # models.json: [{"id": "<provider>/<dated model id>", "vendor": "<vendor>", "price_factor": 1, "timeout": 60}, ...]
  ```

The tests never call a model. `tests_claim/fake_models.py` is a local OpenAI-compatible server on 127.0.0.1, which
`test_judge_unit.py`, `test_judge_api.py` and the Postgres end-to-end test in `test_storage.py` use.

## Running the tests

```
python3 -m venv .venv                       # once; .venv/ is gitignored
.venv/bin/pip install cryptography psycopg[binary] pgserver
.venv/bin/python tools/run_claim_tests.py               # everything
.venv/bin/python tools/run_claim_tests.py test_verify   # one module
```

`tests_claim/test_storage.py` runs the storage contract against real Postgres 16: a throwaway cluster from `initdb` and
`pg_ctl` on PATH, from `WITNESS_TEST_PG_BIN`, or from the `pgserver` wheel's binaries; it is skipped only when none exists.
`tests_claim/test_screen.py` builds the real `tools/redact-copy` with Go when Go is installed. Nothing in the suite uses the
network.

## Running it locally

One process, API and signer together, memory storage and throwaway keys (never for a cluster):

```
echo '{"dev-key-local-0123456789": "acct_local"}' > /tmp/dev-keys.json
WITNESS_DEV_KEYS_FILE=/tmp/dev-keys.json WITNESS_REDACT_BIN=/path/to/redact-copy WITNESS_PORT=8080 \
  .venv/bin/python -m claim_witness dev
curl -s -H 'Authorization: Bearer dev-key-local-0123456789' -H 'Content-Type: application/json' localhost:8080/v1/witness \
  -d '{"claim": {"method": "match.exact", "method_major": 1, "params": {}, "assertion": true, "statement": null},
       "evidence": [{"slot": "submitted", "kind": "object", "sha256": "<sha256 of the bytes>", "media_type": "text/plain",
                     "name": "a.txt", "content_b64": "<base64>"}, {"slot": "target", ...}],
       "options": {"visibility": "public"}}'
```

Build `redact-copy` with `CGO_ENABLED=0 go build -mod=vendor -trimpath -o /tmp/redact-copy ./tools/redact-copy` (from the
repository root); without it public claims answer 503 and private ones work. The cluster layout (two processes on Postgres)
is the same commands as the manifest: `python3 -m claim_witness signer serve` with `WITNESS_SIGNER_SOCKET`,
`WITNESS_SIGNING_KEY_FILE`, `WITNESS_KEY_ID`, `WITNESS_DATABASE_URL`, and `python3 -m claim_witness api` with
`WITNESS_SIGNER_SOCKET`, `WITNESS_DATABASE_URL`, `WITNESS_ATTEMPT_KEY_FILE`, `WITNESS_MASTER_KEY_FILE`, `WITNESS_REDACT_BIN`,
`WITNESS_DEV_KEYS_FILE`, optionally `WITNESS_CALLER_KEYS_URL`.

Verify an answer offline: `python3 -m claim_witness.verify --envelope answer.json --keys keys.json` (keys.json = the
`key_list` of `/.well-known/witness.json`), with `--disclosure`, `--agent-key`, `--methods witness-methods-1.1.0.tar.gz` and
`--evidence FILE` as needed, or `--bundle DIR`.

## Deploying on dev

`k8s/claim-dev.yaml`, namespace witness-dev: StatefulSet `claim-pg` (`pgvector/pgvector:pg16`, PVC from
`volumeClaimTemplates`), Deployment `claim-witness` (container `api`, args `["api"]`, and container `signer`, args
`["signer", "serve"]`, sharing an in-memory emptyDir at `/run/claim-witness` for the socket), Service `claim-witness`
(port 80 to 8080 only). Replace `IMAGE_PLACEHOLDER` with the image built from `Dockerfile.claim`.

## Secrets

Names only in the manifest. Create each in witness-dev from files made off-cluster, never echoed to a terminal or a log, and
delete the files afterwards. Values on hosted come from Key Vault `kv-pww-poland-central` later.

| Secret | key(s) | mounted into | what |
|---|---|---|---|
| `claim-witness-signing-key` | `key` | signer only, `/etc/claim-witness/signing/key` | standard base64 of the 32-byte Ed25519 seed |
| `claim-witness-attempt-key` | `key` | api, `/etc/claim-witness/attempt/key` | base64 of 32 random bytes, the HMAC key of the attempt table |
| `claim-witness-master-key` | `key` | api, `/etc/claim-witness/master/key` | base64 of 32 random bytes, wraps stored job answers (BD1) |
| `claim-witness-dev-keys` | `dev-keys.json` | api, `/etc/claim-witness/dev-keys/` | `{"<api key, 16+ chars>": "<account id>", ...}` (dev only, BD8) |
| `claim-pg-credentials` | `username`, `password`, `database`, `url` | claim-pg (first three), api and signer (`url`) | `url` = `postgresql://<username>:<password>@claim-pg.witness-dev.svc.cluster.local:5432/<database>` |

```
umask 077
python3 -c "import os,base64; print(base64.b64encode(os.urandom(32)).decode())" > signing.key
python3 -c "import os,base64; print(base64.b64encode(os.urandom(32)).decode())" > attempt.key
python3 -c "import os,base64; print(base64.b64encode(os.urandom(32)).decode())" > master.key
python3 -c "import os,base64; print(base64.urlsafe_b64encode(os.urandom(24)).decode())" > pg.password
kubectl -n witness-dev create secret generic claim-witness-signing-key --from-file=key=signing.key
kubectl -n witness-dev create secret generic claim-witness-attempt-key --from-file=key=attempt.key
kubectl -n witness-dev create secret generic claim-witness-master-key --from-file=key=master.key
kubectl -n witness-dev create secret generic claim-witness-dev-keys --from-file=dev-keys.json=dev-keys.json
# url.txt holds the url line above, written with the password from pg.password
kubectl -n witness-dev create secret generic claim-pg-credentials --from-literal=username=witness \
  --from-literal=database=claim_witness --from-file=password=pg.password --from-file=url=url.txt
shred -u signing.key attempt.key master.key pg.password url.txt dev-keys.json
```

On its first start, with no key list in the database, the signer signs key list 1 itself (`WITNESS_SIGNER_BOOTSTRAP=1`, dev
only). Otherwise run `kubectl exec ... -c signer -- python3 -m claim_witness signer keylist init --key-file <seed file>
--key-id <id>`.

### Rotating the key

Put the incoming seed in a file inside the signer container (never on the command line), then

```
python3 -m claim_witness signer keylist rotate --outgoing-key-file /etc/claim-witness/signing/key \
  --outgoing-key-id witness:onedroid-dev:2026a --incoming-key-file /path/new.key --incoming-key-id witness:onedroid-dev:2026b \
  [--revoke "reason"]
```

The new list is signed by both keys, logged, and served at `/v1/key-lists/{seq}`. Then replace the Secret with the new seed,
set `WITNESS_KEY_ID` to the new id, and restart the pod: the signer refuses to sign with a key that is no longer current.

## Builder decisions

Where SPEC and DECISIONS left a choice, these are the simplest readings taken. Each one is reversible.

1. **Two RED test fixes**, in their own commits after the RED commit (no test removed): two auth tests asserted an empty
   signing log after setup, but the bootstrap key list is itself a log row (§7.1, and `test_signer` requires it); one screen
   test unpacked a 3-tuple into two names.
2. **The claim object carries all five fields**, `statement` included (null for every B1 method). A missing field is 422
   `invalid-claim`: the claim id is computed over exactly what the record signs, so the witness does not fill fields in.
3. **Request parsing is strict**: JSON with integers only and no duplicate keys, anywhere in the body (BD9); a float is 400
   `malformed`. Unknown fields in the request, the claim, an evidence item, the options or the agent block are refused.
4. **Order of checks in POST /v1/witness**: validation (422, then the bytes: 400 `missing-object` / `hash-mismatch`, 413), then
   the `Idempotency-Key` lookup, then public screening, then the agent block (key of this account, else 403; agent_time, else
   401; signature, else 401; nonce consumed last, else 401), then the object-only idempotency lookup, then the job. So a
   retry with the same `Idempotency-Key` and nonce gets the first answer, a replayed nonce without the key is 401 even when
   the record exists, and a screening refusal does not burn the nonce.
5. **The object-only idempotency fingerprint** is H(account, claim id, method id and version, the evidence slots with their
   sha256, media type and name, visibility, label, agent key id). Visibility is in it because the VR-19 test checks a private
   and then a public check of one claim as two records; the agent key id so that a returned record's submitter is the caller's.
6. **`options_used`** in B1 records is `{accept_untrusted, allow_provider, panel}`, the SPEC §2.4 example's fields with the
   request's values. BD2's `models: {count, require}` is accepted and validated (count 1-3, require ≤ count) but not recorded:
   no B1 method runs a model.
7. **Not served in B1**, each a 422 so nothing is signed: `keep: true` or `keep_evidence_days > 0` (`keep-not-served`, S3);
   `url`, `observation` and `record` evidence (`wrong-evidence-slots`: every B1 slot takes `object` only; observations come
   with S4, the Argus-signed run record for `tests.pass` with S3). The Argus run JSON parser is not in B1.
8. **Screening covers** every string in `params` (keys too), the claim's `statement`, the rendered template, and each evidence
   `name`. The `label` is never signed and, with no store in B1, a public record's label is dropped (a private one's is in
   the body). Image and PDF are recognised by declared media type or by magic bytes (PNG, JPEG, GIF, PDF, BMP, TIFF, WebP,
   HEIC/AVIF). With the helper missing, a public claim is 503 `screening-unavailable`; private claims are never screened.
9. **Job answers are stored encrypted for 24 h, disclosure included** (AES-256-GCM, key = HKDF-SHA256(master key, job id)),
   so a retry can return the first answer. That means the witness holds a private record's salt, encrypted, for 24 h: BD1's
   custody model supersedes §2.6's "the witness does not store the salt".
10. **Agent key ids** are derived: `ak_` + 32 hex of H(account, public key), `agt_` + 24 hex of another such hash. Registering
    the same key again returns the same ids; the same key under another account is another registration.
11. **Key lists** are statements of predicateType `https://onedroid.ai/witness/key-list/v1`, subject
    `{"name": "key-list", "digest": H(canonical predicate)}`, kept in storage by seq and logged. Seq 1 is signed by its one key,
    every later list by the outgoing and the incoming key; the verifier asks for two signatures from seq 2 on. A rotation sets
    the outgoing key's `valid_to`; `--revoke` also sets `revoked_at` and `revoke_reason`.
12. **Key validity for an unsealed record** (§6 step 5 without an anchor): a revoked key fails, because the record cannot
    prove it was signed before the revocation; otherwise `witnessed_at` must lie in `valid_from..valid_to`.
13. **The signer** also refuses a claim or observation payload whose time is more than 300 s from its clock, or that names
    another witness id, key id or key list seq. A batch header is signed as PAE(`application/vnd.onedroid.witness.batch-header+json`,
    canonical header) and answered `{keyid, sig, payload_id, log_seq}`; no sealer calls it yet (S3).
14. **`tests.pass`**: the commit rules come before pass or fail (a named commit that differs from `expect_commit` is
    `commit-mismatch` even when tests failed). A log names a commit through a JUnit property or a `commit: <hex>` /
    `git_commit=<hex>` style line; a prefix match in either direction counts as the same commit. Zero tests is `tests-failed`.
15. **Rate**: an in-process ceiling of 60 checks a minute per account (BD3), 429 with `Retry-After`. Credits and prices stay
    with the BFF (BD3) and are not in B1.
16. **Dev witness id** is `witness:onedroid-dev`, key id `witness:onedroid-dev:2026a`. The signer signs key list 1 on its first
    start on dev (`WITNESS_SIGNER_BOOTSTRAP=1`).
17. **Postgres migrations** run in one transaction under an advisory lock, because the API and the signer both migrate on start.
18. **`/healthz`** answers 503 when the signer socket does not answer, so the pod is not ready without its signer.
19. **`wait`** above 60 s is served as 60 s (not refused); a negative or non-integer `wait` is 422. A body that is neither
    JSON nor multipart is 400 `malformed` (SPEC §3 lists no 415).
20. **The rate ceiling** is `WITNESS_RATE_PER_MINUTE` (default 60), so a holdout run from one account can be given room
    without a code change.

### Builder decisions, B6 (judge.supports)

21. **Two test fixes after the RED commit**, each in its own commit, with no test removed and no assertion changed. The fake
    server's `status()` answered with the request body: its lambda argument shadowed the default. One test passed `label` as
    an option. The manifest test read the pod's `volumes` list as part of the signer container. One B1 test changed by one
    line: `test_methods_registry_with_tarball_digest` asserted the registry holds exactly the three B1 methods, and it now
    names `judge.supports` too.
22. **The methods library is 1.1.0** (`witness-methods-1.1.0.tar.gz`). The library gained a method and its prompt file, so
    its tarball, and therefore every record's `code_sha256`, changed. The B1 methods keep version 1.0.0. The tarball now ships
    `.py` and `.txt` files, sorted by path. `vectors.json` was regenerated: the B1 vectors' envelopes name the new
    `code_sha256`, and a `judge` section was added.
23. **Templates**: T is `{statement}` and F is `Asserted false: {statement}`, through the same renderer as every method.
24. **Slots with counts**: `Method.slot_counts` is `(min, max)` per slot, `(1, 1)` for every mechanical slot and `(1, 5)` for
    `judge.supports`. `GET /v1/methods` shows it. `observation` evidence is in the schema, and the service answers 422
    `wrong-evidence-slots` for it until B2b.
25. **Order of the judge steps**: unreadable bytes, then too-large, then the injection rules, then empty visible text, then
    the models. A hard flag stops the run before any model call, so no provider sees a page that tries to steer it, and the run
    costs no model credits.
26. **The token estimate** is ceil(characters / 4) of the prompt plus the input. It is not a real tokenizer: a model-specific
    tokenizer would make `too-large` depend on the model.
27. **The assertion is sent** (the `ASSERTION:` line) because SPEC §5.2 lists it. The prompt says the finding is always
    about the statement as written.
28. **Quotes**: `text` is optional. Without it, a quote is checked by its offsets alone: a non-blank span of at least 2
    characters inside the item. With it, `text` must equal the span exactly, as plain text or datamarked. Offsets that are
    wrong are never moved to where the text sits. At most 10 quotes per run are read. Verified quotes go into the record;
    rejected ones are only counted in `rejected`.
29. **Hidden-node rules** apply to HTML objects as well as observations. The elements canon/1 drops for being hidden are the
    hidden nodes. Hard-flag patterns are matched in them too. A short statement, under four content words, flags only word
    for word, so a hidden menu that shares a word is not a flag.
30. **Agreement with failures**: failed runs count for no finding. If the runs that answered agree but are fewer than
    `require`, the failures decide the reason, in this order: undecided, then timeout, then model-unavailable. A tie is
    `judges-disagree`, even with `require` 1.
31. **Errors before anything is signed**: no backend is 503 `judge-not-configured`. More models than configured is 422
    `invalid-options`. A private claim without `allow_provider` is 422 `provider-not-allowed`. These checks run in
    validation, so neither the nonce nor an attempt is used.
32. **`allow_provider` is required for every private judge claim**, whatever the backend. Standalone vLLM could later be
    exempt by configuration.
33. **No response_format is sent.** Some OpenAI-compatible backends refuse it, and the parse rule copes with prose and fences.
34. **Raw outputs** are the model's message content only, kept 24 h (`judge_output_ttl`) for public records. A private
    record's raw outputs are discarded rather than put in the body, because the body would publish them on a later
    `record.disclose`. There is no route to read raw outputs yet.
35. **Price**: integer credits, with the factor applied in decimal arithmetic and rounded up. The base for a judge claim is
    `check` (1): BD3's base for a check over objects. Every answer reports a price, mechanical ones included.
36. **`witness-verify`** skips the re-run of `judge.supports` ("not a pure-Python method"). The vectors replay the decision
    from fixed model outputs in the witness and from the tarball, which is the reproducible part.
