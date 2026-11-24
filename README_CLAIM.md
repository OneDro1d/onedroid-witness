# claim-witness, slices B1 and B2b

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

## What B2b adds (branch v1/claim-observe)

Observations of web pages through the fetcher (`claim_fetcher`, branch v1/claim-fetcher, `README_FETCHER.md`), `url` and
`observation` evidence, and three methods: `page.live`, `match.text`, `match.screenshot`. Also the Postgres start-up retry.

- **Fetcher client** (`claim_witness/fetcher.py`): `POST $FETCHER_URL/v1/capture` with `X-Fetcher-Secret` (from
  `FETCHER_SECRET_FILE`); reads the tar (`manifest.json` first, every file checked against the manifest). Error codes map to
  the SPEC reasons: `blocked` (also `scheme`, `port`, `bad-request`), `robots-disallowed`, `timeout`, `too-large`,
  `unreachable`. The optional partial `manifest` of an error answer is read when present. Fetcher-side failures (busy after
  two retries, unauthorized, internal, no answer, an answer that does not check out) are `unreachable` with
  `detail.fetch_error = "fetcher-unavailable"`. A fetch failure is always a signed CANNOT_WITNESS, never a 5xx.
- **DNS** (`claim_witness/dns.py`): a standard-library UDP client for page.live's "NXDOMAIN from two resolvers"
  (`WITNESS_RESOLVERS`, default `1.1.1.1,8.8.8.8`).
- **Storage**: migration `002_observations.sql` (observations, their files, the per-account daily count of fresh
  observations), the same contract in memory and on Postgres.
- **Start-up**: `storage.from_env` retries the first Postgres connection with doubling waits (1 s up to 15 s) for at most
  `WITNESS_DB_START_TIMEOUT_S` (120) seconds, one log line per attempt (never the DSN), then exits. The API and the signer
  both start through it.

### Observations

`claim_witness/observation.py`, SPEC §2.3 and §2.6.

- The witness computes `text.canonical.txt` itself: canon/1 of `rendered.html` at the rendered layer, so every element the
  fetcher marked `data-witness-hidden` is left out with its text. A page with no `rendered.html` (not HTML) takes its text
  from `response.body`. `hidden-nodes.json` is kept as the fetcher wrote it.
- The manifest is the §2.3 predicate with exactly its fields. `fetcher` is `{id, version, browser, viewport}`. `files` lists
  `capture.wacz`, `response.body`, `screenshot.png`, `rendered.html`, `hidden-nodes.json` and `text.canonical.txt`, each with
  `sha256`, `size` and `media_type`. `canonicaliser` is `canon/1`, `platform` is null.
- Public: subject `[{name: final URL, digest: H(canonical manifest)}]` (the signer refuses any other digest). Private (made for
  a private claim, or `POST /v1/observe` with `visibility: private`, the default): the payload is `{visibility,
  body_commitment, fetched_at, fetcher: {id, version}}` and the subject is `observation` with the body commitment.
- Signed by the signer sidecar as `https://onedroid.ai/witness/observation/v1`; one signing-log row each.
- Stored in Postgres with its files for 24 h (`observation_ttl`), unless a kept record uses them (S3). A private
  observation's body and files are sealed (AES-256-GCM under keys derived from the master key, BD1). The reuse lookup is a
  keyed tag, never the URL in the clear.
- `POST /v1/observe {url, capture: "page", visibility?, max_age?, wait?}` answers `{observation_id, envelope, seal, reused,
  price, disclosure?}`; a failed fetch is 422 with the reason as `error`, and nothing is signed.
  `GET /v1/observations/{id}` (and `/files/{name}`) serves a public observation to anyone and a private one to its account.
- **`url` evidence**: `{slot, kind: "url", url, capture: "page", max_age?}`. `max_age` (seconds, default 0 = fresh) reuses the
  newest observation of that URL the reader may see: public ones and, for a private claim, the account's own private ones.
  A public claim never rests on a private observation. Reuse is free; `max_age` is not in the claim id.
  In the record the item becomes `{slot, kind: "url", url, capture, observations: [ids]}`, and `relied_on` lists each
  observation with its signer and `trusted`.
- **`observation` evidence**: `{slot, kind: "observation", id}` loads one from this witness (same visibility rule, else 422
  `observation-not-found`), or `{..., envelope, key_list?, files?}` checks it under the Evidence-trust rule: a bad signature,
  an unknown signer, an id that is not the payload's hash, a bad manifest digest or a file that does not match the manifest
  gives `evidence-untrusted`, and nothing is fetched. A valid observation from another witness (its key list sent with it) is
  outside the trust list: used only with `options.accept_untrusted: true`, recorded in `options_used`, `trusted: false`.
- **Price** (BD3): beside the envelope, never signed: `price: {credits, fresh_observations, reused_observations,
  free_left_today}`. Each account has 50 free fresh observations per UTC day (`WITNESS_FREE_OBSERVATIONS_PER_DAY`), then 5
  credits each (`WITNESS_OBSERVATION_PRICE`); a reused observation is free. `/v1/methods` publishes both numbers.

### page.live

Params `{url}`, slot `page` (`url`, capture `page`; its url is `params.url`). T: "{url} was live when observed at
{fetched_at}." F: "{url} was not live when observed at {fetched_at}."

- `live` (+): a 2xx answer with at least one visible character of `text.canonical.txt`. detail `{status, text_chars}`.
- `not-live` (−): 404 or 410 on the exact URL (no redirects), or NXDOMAIN (the fetcher's `host-not-found`) from both
  resolvers, each confirmed by a second fetch at least `WITNESS_CONFIRM_DELAY_S` (60) seconds after the first. The job sleeps
  meanwhile, so the caller has a 202 and polls `GET /v1/jobs/{id}`. detail `{status | dns: "nxdomain", resolvers,
  confirm_after_s}`.
- No finding: 401, 403, 407, 429, 451 and challenge pages (`blocked`); 5xx, other statuses, a 404 after a redirect and a
  resolver that finds the name (`unreachable`); a fetcher refusal (its reason, with `detail.fetch_error`, and
  `detail.redirects` / `detail.robots` from a partial manifest); a 2xx with no visible text (`unreadable`); a first answer the
  second fetch does not confirm (`undecided`, with `detail.confirm_status`).

### match.text

Slots `submitted` (object) and `page` (url or observation). SPEC §9.3, `claim_witness/methods/match_text.py`.

- A `text/html` submission is compared first with the response layer (canon/1 of `response.body`, no render marks), then, if
  that does not match, with the rendered layer (`text.canonical.txt`). Other text is compared with the rendered layer only.
- Rungs: `exact` (sha256 equal to `response.body`, resp. `text.canonical.txt` or `rendered.html`), `canonical`, `similar`
  (≥ T), `differs` (< F, `detail.first_diff_token`), `undecided` (between). detail: `layer`, `rung`, `similarity_bp`,
  `submitted_tokens`, `page_tokens`, `T_bp`, `F_bp`. Over 50,000 tokens: `too-large`.
- **T = 9700, F = 9600** basis points for 1.0.0, from the calibration set `tests_claim/fixtures/calibration/` (`build.py`
  writes `cases.json`): 20 honest copies (script-rendered pages, CSS-hidden menus, saved HTML, static text with typographic
  changes) scored 9765 to 9967 at the deciding layer; 20 one-paragraph forgeries scored 6666 to 9387. T sits under the lowest
  honest copy and F above the highest forgery. Published in `/v1/methods` (`thresholds`) and in the vectors.
- A page that did not answer 2xx, or a challenge page, gives no finding (`unreachable` / `blocked`).

### match.screenshot

Slots `submitted` (an image object, so private claims only: VR-21 refuses images on public claims) and `page`.

- OCR: `tesseract stdin stdout -l eng --psm 3` (`tesseract-ocr` and `tesseract-ocr-eng` in `Dockerfile.claim`,
  `WITNESS_TESSERACT_BIN`), then canon/1. The OCR tokens are compared with the span of the page's tokens they line up with
  (a screenshot shows part of a page): `consistent` (≥ T = 8500), `differs` (< F = 6500), else `undecided`; no text read is
  `unreadable`.
- `method.code_sha256` is the image digest from `WITNESS_IMAGE_DIGEST` (`sha256:<hex>`; the orchestrator sets it at
  rollout, `IMAGE_DIGEST_PLACEHOLDER` in the manifest), `runtime` is `python3.12+tesseract-<version>`. Without the digest or
  Tesseract the method answers 503 `ocr-unavailable` and signs nothing. witness-verify prints `SKIP method-rerun: re-run
  skipped (needs image)`.

### Running B2b locally with the real fetcher

```
git -C <repo> archive --format=tar -o /tmp/f.tar v1/claim-fetcher      # read-only export
mkdir /tmp/f; tar -xf /tmp/f.tar -C /tmp/f
uv venv --python 3.12 /tmp/f-venv; uv pip install --python /tmp/f-venv/bin/python -r /tmp/f/requirements-fetcher.txt
/tmp/f-venv/bin/python -m playwright install chromium
FETCHER_SECRET_FILE=/tmp/fsecret FETCHER_PORT=8090 PYTHONPATH=/tmp/f /tmp/f-venv/bin/python -m claim_fetcher
FETCHER_URL=http://127.0.0.1:8090 FETCHER_SECRET_FILE=/tmp/fsecret WITNESS_DEV_KEYS_FILE=/tmp/dev-keys.json \
  WITNESS_REDACT_BIN=/tmp/redact-copy .venv/bin/python -m claim_witness dev
```

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
network: `tests_claim/fakefetch.py` is a local HTTP server speaking the fetcher API (prepared tars), and the end-to-end
tests run through the real witness API against it, on memory and on Postgres.

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
`key_list` of `/.well-known/witness.json`), with `--disclosure`, `--agent-key`, `--methods witness-methods-1.0.0.tar.gz` and
`--evidence FILE` as needed, or `--bundle DIR`.

## Deploying on dev

`k8s/claim-dev.yaml`, namespace witness-dev: StatefulSet `claim-pg` (`pgvector/pgvector:pg16`, PVC from
`volumeClaimTemplates`), Deployment `claim-witness` (container `api`, args `["api"]`, and container `signer`, args
`["signer", "serve"]`, sharing an in-memory emptyDir at `/run/claim-witness` for the socket), Service `claim-witness`
(port 80 to 8080 only). Replace `IMAGE_PLACEHOLDER` with the image built from `Dockerfile.claim` and
`IMAGE_DIGEST_PLACEHOLDER` with that image's digest (`sha256:...`, match.screenshot's `code_sha256`). The api container
reaches the fetcher at `FETCHER_URL=http://claim-fetcher.witness-dev.svc.cluster.local`.

## Secrets

Names only in the manifest. Create each in witness-dev from files made off-cluster, never echoed to a terminal or a log, and
delete the files afterwards. Values on hosted come from Key Vault `kv-pww-poland-central` later.

| Secret | key(s) | mounted into | what |
|---|---|---|---|
| `claim-witness-signing-key` | `key` | signer only, `/etc/claim-witness/signing/key` | standard base64 of the 32-byte Ed25519 seed |
| `claim-witness-attempt-key` | `key` | api, `/etc/claim-witness/attempt/key` | base64 of 32 random bytes, the HMAC key of the attempt table |
| `claim-witness-master-key` | `key` | api, `/etc/claim-witness/master/key` | base64 of 32 random bytes, wraps stored job answers (BD1) |
| `claim-witness-dev-keys` | `dev-keys.json` | api, `/etc/claim-witness/dev-keys/` | `{"<api key, 16+ chars>": "<account id>", ...}` (dev only, BD8) |
| `claim-fetcher-secret` | `secret` | api, `/etc/claim-witness/fetcher/secret` (and the claim-fetcher Deployment) | the fetcher's shared secret (B2a creates it) |
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

### B2b builder decisions

21. **One RED test fix**, in its own commit (no test removed): B1's `test_methods_registry_with_tarball_digest` pinned the
    registry to exactly the three B1 methods; it now asks for those three among the methods.
22. **Fetcher failures are records.** Every fetcher error code maps to a SPEC reason (`scheme`, `port` and `bad-request` are
    `blocked`); the fetcher's own failures (busy after two retries, 401, 500, no answer, a tar whose files do not match its
    manifest) are `unreachable` with `detail.fetch_error = "fetcher-unavailable"`, and an HTTP timeout talking to the fetcher
    is `timeout`. The one 5xx is a witness with no `FETCHER_URL` at all: 503 `fetcher-not-configured`, nothing signed (a
    configuration error, not a fetch failure).
23. **The partial manifest** of an error answer goes into the record as counts and enums only: `detail.redirects` (how many)
    and `detail.robots`. Its URLs and addresses are never signed (`detail` holds no evidence text).
24. **URL validation** (422 `invalid-params` / `invalid-evidence`): an absolute http(s) URL with a host, at most 4,096
    characters, NFC, no spaces. Ports, credentials and private addresses are the fetcher's to refuse, which gives a signed
    `blocked`.
25. **The signed manifest** keeps the §2.3 fields only (the fetcher's `user_agent` and `isolation` are dropped). It lists
    `rendered.html` too, so `text.canonical.txt` can be recomputed by anyone. No `phash` is computed for the screenshot yet.
26. **Record evidence for a url item** is `{slot, kind: "url", url, capture, observations: [ids]}`: the requested URL stays,
    because the agent signature and the attempt tag are over requested URLs (§2.4, §7.3). `observations` holds one id, two
    for a confirmed page.live, none when every fetch failed. `max_age` is not recorded.
27. **Agent signature and attempt tag** cover object sha256s, requested URLs and the ids of observation evidence (sorted);
    witness-verify computes the same.
28. **Visibility of observations.** A public claim reuses or names public observations only; a private claim also the
    account's own private ones. Anything else by id is 422 `observation-not-found`. Reuse needs the files (24 h), re-checks
    the stored envelope's signature, and is free. An identical payload (the same capture in the same second) is stored once.
29. **Private observations** made inside a private claim are not disclosed separately: the owner reads them with
    `GET /v1/observations/{id}` (the witness holds the body sealed, BD1). `POST /v1/observe` returns `disclosure` once.
30. **page.live details**: not-live needs the exact URL (no redirects); a 404 after a redirect is `unreachable`. A first
    "gone" that the second fetch does not confirm is `undecided`. The second fetch never reuses. The wait runs inside the
    job thread (a restart loses that job; it stays `running` until purged). The configured delay is passed to the method as
    the minimum, so tests can run it at 5 s. 401/403/407/429/451 and challenge markers (Cloudflare, Incapsula,
    PerimeterX, DataDome, "please verify you are a human") are `blocked`; a 2xx with no visible text is `unreadable`.
31. **NXDOMAIN** comes from the fetcher's `host-not-found` detail and is confirmed by asking every configured resolver
    (default two) on both attempts; all must say NXDOMAIN. No observation exists for it (the fetcher captured nothing).
32. **match.text** compares the submission's canon/1 text at the response layer (no render marks) with each layer. A
    too-large response layer moves on to the rendered layer. `detail` carries `T_bp` and `F_bp` so a record reads alone.
    Global similarity cannot see a small edit in a very long page; T and F were set so that the calibration forgeries
    differ and the honest copies match, with a narrow undecided band.
33. **match.screenshot** compares OCR tokens with the aligned window of the page's tokens. T = 8500 and F = 6500 are
    provisional: Tesseract was not installed where B2b was built, so OCR noise was not measured (the tests use a stand-in
    binary with the same command line). Recalibrate in the image before relying on it.
34. **Evidence trust.** This witness's keys come from its own key lists only. A key list sent with a foreign envelope must
    verify (its own signatures, its subject digest) and must name another witness; its observations are valid but untrusted
    (the trust list holds witness ids, no pinned keys yet), so they count only with `accept_untrusted`. A foreign private
    observation is `unreadable`; so is a trusted observation whose files are gone.
35. **Price** is reported beside the envelope when the evidence includes a url or an observation: observation credits only.
    Every fresh fetch that produced a signed observation counts, the page.live confirmation included; failed fetches and
    reuse are free. BD3's 1 credit per mechanical check is left to the BFF (B4), which knows the method.
36. **Host limit**: at most `WITNESS_HOST_FETCHES_PER_MINUTE` (6) fetches a minute per target host; a job over it waits.
    SPEC §8's 20 fresh observations a minute per account is not enforced yet (the 60 checks a minute ceiling is).
37. **witness-verify** also verifies observation envelopes (id, manifest digest, key validity at `fetched_at`, files,
    `text.canonical.txt` recomputed with the tarball's canon/1). It does not re-run a record whose evidence is an observation
    (the bundle with the observations comes in S3), and never match.screenshot: "re-run skipped (needs image)".
38. **`methods/__init__.py` imports `canon` itself**, so the tarball package exposes it even when loaded twice in one process.
