# claim-witness, slice B1

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
`key_list` of `/.well-known/witness.json`), with `--disclosure`, `--agent-key`, `--methods witness-methods-1.0.0.tar.gz` and
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
