# claim-witness, slices B1, B6, B2b, B5a (post.by-author) and B3 (keep, store, sealer), integrated

The single-claim witness (SPEC Draft 3, `.df/missions/M-20261124-CLAIM-WITNESS/SPEC.md` in the claims notepad, plus
`M-20261124-WITNESS-BUILD/DECISIONS.md` BD1-BD14, which wins where they differ). Branch `v1/claim-keep` adds B3 on
`v1/claim-integrate`: keep, the private store, delete and takedown, the sealer and n-dim ("Keep" to "n-dim" below). One claim in, one signed record out. The old
`onedroid_witness/` package is untouched and keeps running until cut-over (B8).

Branch `v1/claim-integrate` joins two separately verified slices on the B1 core (`v1/claim-witness`): B6, `judge.supports`
(`v1/claim-judge`), and B2b, observations with `url` and `observation` evidence and three methods (`v1/claim-observe`). The
sections below describe the joined witness; "Integration" says what joining them decided, and the builder decisions keep each
slice's own list, renumbered so that no two share a number.

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
  validity), 6 (files and a re-run of the method from the tarball), 7 (agent signature). Step 4 (the seal) came with B3:
  see "Sealer". Every check prints `PASS`, `FAIL` or `SKIP` with its name; any FAIL exits 1.
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
- **Evidence.** One slot, `evidence`, takes 1 to 5 items, each an `object` or an `observation` (SPEC §2.2). `url` and
  `record` evidence is 422 `wrong-evidence-slots`: a page is judged from an observation made first (`POST /v1/observe`, or
  the observation of another check). An observation item is `{slot, kind: "observation", id}` or `{..., envelope, key_list?,
  files?}` and goes through the Evidence-trust rule of "Observations" below before any model is called: untrusted gives no
  finding (`evidence-untrusted`) unless `options.accept_untrusted` is true, unreadable gives `unreadable`. An object's
  visible text is its canon/1 text. For an HTML object, the elements canon/1 drops for being hidden are kept apart as hidden
  nodes and never sent to a model. `item_from_observation` reads an observation's
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
  `{"finding": ..., "quotes": [{"source": i, "start": s, "end": e, "text": "..."}]}`. The source must be an item. A quote
  with `text` is verified by its text, not by the model's offsets (BD13, decision 63): U+02C6 is mapped back to a space,
  canon/1 is applied as in `quote.in-source` (a line break in the visible text counts as a space), and the text must occur
  in that item's visible text. Hidden nodes are never searched. With several occurrences, the one whose start is nearest the
  model's `start` is taken (ties: the earliest). The record's offsets are the witness's, from that occurrence, never the
  model's. A quote without `text` is verified by its offsets: `0 <= start < end <=` the length of that item's visible text.
  Either way the span holds at least 2 non-space characters. A positive or negative finding with no verified quote is no
  finding (`undecided`, run note `no-verified-quote`). A finding word outside the vocabulary is its own note (`finding-not-in-vocabulary`). Garbage,
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
- **Price (BD3).** A judge answer's `price` has a `check` line (1 credit) and a `model-run` line of `ceil(10 × price_factor)`
  for each model run made. A run that timed out or failed was still made, so it counts. `possible-injection`, `too-large`,
  `unreadable` and `evidence-untrusted` make no run. The whole price object, for every method, is in "Price" below.
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
- **Storage**: migration `003_observations.sql` (observations, their files, the per-account daily count of fresh
  observations; `002_observations.sql` on the B2b branch, renumbered when joined), the same contract in memory and on
  Postgres.
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
- **Price** (BD3): each account has 50 free fresh observations per UTC day (`WITNESS_FREE_OBSERVATIONS_PER_DAY`), then 5
  credits each (`WITNESS_OBSERVATION_PRICE`, else the price list's `observation`); a reused observation is free. Answers
  over observations carry `fresh_observations`, `reused_observations` and `free_left_today` in their `price` ("Price" below).
  `/v1/methods` publishes both numbers under `observations`.

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
  (a screenshot shows part of a page): `consistent` (≥ T = 9500), `differs` (< F = 9300), else `undecided`; no text read is
  `unreadable`.
- **T = 9500, F = 9300** basis points (decision 64), from the screenshot calibration set
  `tests_claim/fixtures/calibration/screenshots/` (`build.py` makes the screenshots with Chromium, `measure.py` measured them
  inside the claim-witness image `dev-8ca79b4@sha256:829dae31…`, Tesseract 5.5.0, and wrote `measured.json`; `pod.log` and
  `pod.yaml` beside it): 32 honest screenshots (widths 1280 and 390, two fonts, full page and a crop, PNG and JPEG) scored
  9655 to 10000; 32 forgeries (one sentence replaced) scored 6486 to 9134; 8 screenshots of another page 714 to 4745. T sits
  155 under the lowest honest screenshot and F 166 above the highest forgery, with an undecided band of 200 between.
- Limits of that set: Tesseract read every word of these clean renders, so the honest loss came only from canon/1 joining
  inline links spaced by CSS (a navigation bar). Phone and browser chrome (status bar, address bar, tabs), cookie banners,
  dark mode, re-compressed or rescaled images were not in it. Pages were 116 to 165 tokens: on a much longer page one replaced
  sentence moves a full-page screenshot less than the gap, so a full-page shot of a long page with one sentence changed can
  be `consistent` (as with match.text, decision 48). A crop of the changed part is what this method can tell apart.
- `method.code_sha256` is the image digest from `WITNESS_IMAGE_DIGEST` (`sha256:<hex>`; the orchestrator sets it at
  rollout, `IMAGE_DIGEST_PLACEHOLDER` in the manifest), `runtime` is `python3.12+tesseract-<version>`. Without the digest or
  Tesseract the method answers 503 `ocr-unavailable` and signs nothing. witness-verify prints `SKIP method-rerun: re-run
  skipped (needs image)`.

## What B5a adds (branch v1/claim-post): post.by-author for Bluesky

`claim_witness/methods/post_by_author.py`, SPEC §4 and TS-5, over the fetcher's `capture: post` (`README_FETCHER.md` on
v1/claim-fetcher, "capture: post"), which proves the post from AT Protocol and resolves the claimed handle both ways.

- **Claim**: `{"method": "post.by-author", "method_major": 1, "params": {"handle": "bsky.app"}, "assertion": true,
  "statement": null}`. `handle` is an AT Protocol handle (a DNS name, two or more labels, the last not starting with a
  digit, no `@`), compared case-insensitively; the template keeps it as written.
- **Slot `post`**: `{slot: "post", kind: "url", url, capture: "post", max_age?}` (capture defaults to `post` here, and
  `page` is 422), or `{slot: "post", kind: "observation", id | envelope}`. The witness sends the fetcher
  `{"url", "capture": "post", "handle": <the claimed handle, lower case>}`.
- **No fetch for other platforms**: a url that is not `https://bsky.app/profile/<handle or DID>/post/<rkey>` (X, LinkedIn,
  TikTok, any other site, an http or profile URL) is never sent to the fetcher. The record is a signed CANNOT_WITNESS
  with reason `method-not-applicable` and `detail.platform` `x`, `linkedin`, `tiktok` or `other`; it costs nothing.
- **T**: "The post at {url} was published by the account {handle}." **F**: "The post at {url} was not published by the
  account {handle}." **Limits**: "Proves which account key or platform account published the post, not who controls the
  account. The post time is the author's own claim."
- **Findings**, in this order, from the observation's `platform` (§2.3):

  | when | finding | class |
  |---|---|---|
  | no Bluesky `platform` in the observation (a page capture, another platform) | none, `method-not-applicable` | |
  | the capture failed | none, its reason (`timeout`, `blocked`, `unreachable`, ...) | |
  | the observation's `handle` is not the claimed one, or `handle_resolution.bidirectional` is false | `handle-unresolved` | ○ |
  | `signature` is `failed` or `not-available` | `signature-unverifiable` | ○ |
  | the handle's verified DID is the post's `author_did` | `author-verified` | + |
  | the handle's verified DID is another DID | `author-differs` | − |

  `author-platform` (+) is registered for YouTube and Meta but nothing produces it yet.
- **detail**: `{platform, signature, resolution (dns-txt | well-known | none), bidirectional, handle_match, same_did}`, enums
  only (`yes`/`no`).
- **Observation**: the manifest predicate's `platform` is exactly the §2.3 fields (`observation.platform_of`: strings or
  null, `bidirectional` a boolean, `signature` one of its three values); the files add `platform.json`, `post.car`,
  `did-document.json` (and `handle-did-document.json`) as the fetcher wrote them, each fingerprinted in `files`.
- **Reuse** with `max_age` works as for pages, but a post observation answers only for the handle it resolved: the
  lookup tag includes the handle, so another handle is a fresh capture. A private claim makes a private observation
  (§2.6): its payload holds only `{visibility, body_commitment, fetched_at, fetcher}`.
- **`POST /v1/observe`** takes `capture: "post"` with an optional `handle` (a bsky.app post URL only; `handle` with
  `capture: page` is 422).
- **Price**: one fresh observation (BD3: 5 credits after the free 50 a day), nothing for `method-not-applicable`.
- **witness-verify** checks the record (signature, ids, key validity; the re-run is skipped because the evidence is an
  observation) and the observation with its files (`platform.json` among them).

## Price

Every answer of `POST /v1/witness` and `POST /v1/observe` carries one `price` object beside the envelope. It is never signed,
and the witness holds no balance: the BFF holds and settles the credits (BD3).

```
price: {credits, lines: [{item, credits, model?}, ...], fresh_observations?, reused_observations?, free_left_today?}
```

- `lines` has a `check` line (1) for a mechanical check over objects and for every `judge.supports` claim; a `model-run` line
  (with `model`) for each model run made, `ceil(10 × price_factor)`; and an `observation` line (5) for each fresh observation
  past the free 50 of the day. `credits` is the sum of the lines.
- A mechanical check whose evidence includes a `url` or an `observation` has no `check` line: BD3 prices a check over objects
  at 1 and a fresh observation at 5, and a check over observations pays for its fresh observations only. So a `page.live`
  with one free fresh observation costs 0, and the 51st fresh observation of the day costs 5.
- When the evidence includes a `url` or an `observation` (and for `POST /v1/observe`), the object also has
  `fresh_observations`, `reused_observations` and `free_left_today`.

Examples: `match.exact` over two objects `{credits: 1, lines: [{item: check, credits: 1}]}`; `judge.supports` with two models
of factors 1 and 2 `{credits: 31, lines: [check 1, model-run 10, model-run 20]}`; a `page.live` past the free quota
`{credits: 5, lines: [{item: observation, credits: 5}], fresh_observations: 1, reused_observations: 0, free_left_today: 0}`.

`GET /v1/price` and `GET /v1/methods` publish the list: check 1, observation 5, model run 10, kept evidence 1 per MB-month,
each model's `credits_per_run`, and the free fresh observations a day. `WITNESS_PRICE_LIST_FILE` overrides the list;
`WITNESS_OBSERVATION_PRICE`, when set, overrides its `observation`, so the two numbers never differ.

## Integration (v1/claim-integrate)

- **Migrations** are one ordered sequence: `001_init.sql`, `002_judge.sql` (B6), `003_observations.sql` (B2b). The runner
  (`pg.PostgresStorage.migrate`) applies, in file-name order, every file not named in `schema_migrations`, in one transaction
  under an advisory lock, and records each name. The dev database, on B6 now, holds `001` and `002_judge`, so it gains
  `003_observations` alone; a fresh database gets all three. Every statement is `CREATE ... IF NOT EXISTS`, so a database
  that ran B2b's `002_observations.sql` also upgrades cleanly (it then records both names). `test_migrations_upgrade.py`
  checks these paths on real Postgres.
- **judge.supports over observations**: see "judge.supports", Evidence. The observation's visible text is its
  `text.canonical.txt` and its hidden nodes are the excerpts of its `hidden-nodes.json` (§5.2, §5.5), so the hidden-node
  injection rules (`statement-in-hidden` and the hard patterns) read the fetcher's hidden nodes, and a quote is verified
  against the visible text only.
- **One methods library, 1.4.0** (1.2.0 until BD13, decision 63; 1.3.0 = BD13 alone, live on witness-dev 24 Nov; 1.4.0 = BD13 + B5a post.by-author, decision 71, + the screenshot calibration, decision 74) (`witness-methods-1.4.0.tar.gz`, `.py` and `.txt` files with the judge prompt), holding all
  eight methods. `vectors.json` was regenerated with both slices' sections (`judge`, `thresholds`, `observation`).
- **One price object**: "Price" above.

## Keep

Slice B3 (SPEC §2.6 as changed by DECISIONS BD1, §3, TS-13). `claim_witness/records.py`.

`POST /v1/records/{id}/keep` with `{envelope, disclosure? (private), keep_evidence_days?, evidence?: [{sha256, content_b64}]}`
as JSON, or multipart (a part `request` holding that JSON and one part per evidence object, named by its sha256).

- The request has no visibility field: the record's visibility is signed. Unknown fields are 422.
- The id is H(the envelope's payload) (else 422 `record-mismatch`). The envelope must be a claim record signed by this
  witness's key and present in its signing log (else 422 `not-witnessed-here`).
- A private record needs its disclosure, and both commitments are checked: the claim commitment against the subject, the
  body commitment against the predicate (else 422 `disclosure-required` / `disclosure-mismatch`). A public record has none.
- Only the account that made the record keeps it (`submitter.account`, from the payload or the disclosed body), else 403.
- `keep_evidence_days` (1 to 3,650) keeps evidence bytes: each must be one of the record's object evidence items (422
  `evidence-not-in-record`) and hash to its sha256 (400 `hash-mismatch`). The answer carries `evidence_key` once.
- Keeping twice is idempotent: the second answer is the first keep's state with `already_kept: true` and no `evidence_key`.
  A record whose owner deleted it is 410.
- TS-13: a record kept after its batch closed is already sealed; the answer's `seal` says so.
- The answer: `{record_id, visibility, link, kept_at, already_kept, seal, ndim, evidence?: {expires_at}, evidence_key?}`, with
  `link` = `{WITNESS_LINK_BASE}/r/{id}` (default `https://evidence.onedroid.ai`).
- Observations the record relied on are marked kept, so their files stay beyond 24 h (SPEC §8).
- `options.keep` on `POST /v1/witness` stays 422 `keep-not-served`, pointing to this route.

## Private store

BD1 custody. The witness holds, for each kept record:

- a random 32-byte **data key**, stored only wrapped by the master key (AES-256-GCM under HKDF-SHA256(master key,
  `claim-witness/kek/1`), the record id as associated data);
- for a private record, the disclosure `{salt, body}` encrypted under the data key;
- with kept evidence, a random **evidence key** encrypted under the data key, and each evidence file encrypted under the
  evidence key, with its media type and name inside the ciphertext. `evidence_key` (base64url) is that key, returned once:
  with it the holder reads the evidence ciphertext wherever it is (also as an n-dim object), without this witness.

Reads, all under `GET /v1/records/{id}`:

- anyone: the envelope and the seal. A private envelope holds commitments only (TS-10: without a token, only fingerprints);
- the owner (API key) and a share-token holder: also `disclosure` and the kept evidence list;
- `GET /v1/records/{id}/evidence/{sha256}`: one kept file. A public record's (screened, public evidence) to anyone; a private
  record's to the owner and to holders of a token made with `evidence: true`.

**Share tokens** (capabilities, one record each): `POST /v1/records/{id}/shares {days?: 1-365 (30), evidence?: false}` answers
`{token_id, token, link, expires_at, evidence}` once; `GET .../shares` lists them without the token; `DELETE
.../shares/{token_id}` revokes. The token goes in `?token=` (the link) or the `X-Witness-Share-Token` header. The witness keeps
only its sha256; the request log never prints the query string. A revoked, expired or foreign token is 403.

**Owner search**: `GET /v1/records?q=&method=&outcome=&since=` lists the caller's own kept, undeleted private records, newest
first, with the statement and the label. It is plaintext and server-side: every word of `q` must be in the record's index,
then the phrase must occur in the opened body (statement, claim statement, params, label, evidence names and URLs). The index
rows are HMAC(HKDF(master key, `claim-witness/owner-index/1`), account || NUL || word): no word is stored, and only the owning
account's tokens can match. Other accounts and public reads never see these records or their count.

## Delete

Wording rule (Michal, armarium item 3): an answer never says private data is "gone", "erased" or "permanently removed". It
states exactly what the witness deleted and what stays. Where n-dim holds bytes it says "the key is deleted; the encrypted
bytes stay on the chain", and only when armarium reported the key deleted.

- **Owner delete**, `DELETE /v1/records/{id}`, private records only (a public record is 422 `use-takedown`). The witness
  deletes the wrapped data key, the encrypted body and salt, the kept evidence and the evidence key, the owner index rows,
  the share tokens, the stored job answers of that record, and the account's private observations the record relied on.
  It writes a tombstone version of the record's n-dim object. The answer lists each of these with counts (`deleted`), and
  what stays (`kept`): the signed envelope (commitments only) and its seal, still served and verifiable; the signing-log row
  and the batch leaf; the attempt tag (an HMAC, 30 days); copies readers already took and the owner's own disclosure. After
  it `GET /v1/records/{id}` answers the envelope and the seal with `deleted_at`. Deleting again gives the same `deleted_at`.
- **Evidence delete**, `DELETE /v1/records/{id}/evidence` (owner): the kept evidence files and the evidence key. The record
  and its seal stay valid. With `NDIM_STORE_EVIDENCE` the evidence object gets armarium's DELETED marker, and the answer
  repeats armarium's `dek`: "deleted" gives "the key is deleted; the encrypted bytes stay on the chain"; "on-chain" (a legacy
  chain) says the key was not deleted and the encrypted bytes stay on the chain. The `evidence_key` the owner was given
  still decrypts the chain's ciphertext wherever someone holds a copy of it.
- **Takedown**, `POST /v1/records/{id}/takedown {reason?}`: the owner, or an account in `WITNESS_OPERATOR_ACCOUNTS` after a
  subject's request. The record view and the bundle answer 410 to everyone but the owner; `/seal` is still served; the signed
  record stays valid wherever someone holds it. The reason is not stored.
- Kept evidence past its `keep_evidence_days` is deleted by the minute purge the same way (files and key).

## Sealer

SPEC §7.1, §7.2. `claim_witness/sealer.py`, `merkle.py`; a thread of the API process (`WITNESS_SEALER=0` turns it off).

- **Leaf**: every signing-log row stores `leaf = H(0x00 || payload)` when it is signed, where payload is the signed bytes:
  the canonical statement of a record, observation or key list, the canonical header of a batch header (migration
  `004_keep.sql`). Rows signed before B3 have no leaf and are never batched.
- **Tree**: RFC 9162 §2.1 over the batch's leaves in signing-log order. A leaf is its own subtree hash;
  `MTH(D[n]) = H(0x01 || MTH(D[0:k]) || MTH(D[k:n]))` with k the largest power of two below n. A path is RFC 9162's
  `PATH(m, D[n])`, bottom up, lowercase hex, and is checked by §2.1.3.2 (`merkle.root_from_path`,
  `verify.merkle_root_from_path`). The RFC 6962 reference roots are in `test_merkle.py`.
- **Closing**: a tick (`WITNESS_SEALER_POLL_S`, 30 s) closes a batch of the unbatched leaves when it holds
  `WITNESS_BATCH_MAX_LEAVES` (100,000) or its oldest leaf is `WITNESS_BATCH_INTERVAL_S` (3,600 s on dev) old. The headers
  signed during a tick wait for the next one.
- **Header**: `{witness, batch_id, root, size, opened_at, closed_at, interval_s, key_id}` with `batch_id = H(canonical
  {witness, first_seq, last_seq, root})`, `opened_at` the first leaf's time and `closed_at` the tick's. The signer signs it
  (predicateType `batch-header/v1`, PAE(`application/vnd.onedroid.witness.batch-header+json`, canonical header)); the seal
  carries it with its `sig`.
- **Notary** (`claim_witness/notary.py`, the onedroid-audit client): `POST /notary/v1/seals {"profile": "hash/1", "key":
  "<hex>", "payload": base64 of {"over": "sha256:<hex>"}}` with hex = H(canonical signed header). Settings
  `WITNESS_NOTARY_URL` (https), `WITNESS_NOTARY_TOKEN_FILE`, `WITNESS_NOTARY_CA_FILE`, `WITNESS_NOTARY_TIMEOUT_S`. A batch
  whose notary has not landed stays pending and is repeated each tick with the same key. Without a token file the batches
  close and their proofs are served, never anchored (`notary.status: off`).
- **Seal**: `GET /v1/records/{id}/seal`, open, for any record or observation id in the signing log, kept or not:
  `{"state": "pending"}` before the batch closes, then `{state: pending|anchored, leaf_index, path, batch_header, notary}`
  (the notary result copied as it answered: `status, profile, over, key, anchors[{chain, state, tx_hash, block, block_time,
  explorer_url, final}]`). `anchored` means every chain landed; `final` is the notary's word.
- **witness-verify step 4** (`seal`): the leaf and its path give the header's root; the header verifies under its key in the
  key list and names that witness; the notary's `over` is sha256 of the canonical signed header and every anchor landed.
  Then key validity is judged at the anchor time (the earliest landed `block_time`): a key revoked at or before it fails
  (TS-20, VR-16); `FLAG seal-delay` marks an anchor more than `interval_s` + 15 min after the payload's time. The anchor
  transaction itself is not read by the verifier (`SKIP seal-chain`; check it with armarium's `POST /notary/v1/verify`). Give
  the seal with `--seal`, inside the answer file, or as `seal.json` of a bundle.

## n-dim

BD4, SPEC §7.5. `claim_witness/ndim.py`: an `ArmariumClient` interface (create object, put version, delete = the DELETED
marker of a version, get) and `HttpArmarium` over armarium's `POST /chain/{name}/object` and `GET/PUT/DELETE
/chain/{name}/object/{id}?block=`. Settings `ARMARIUM_URL` (https), `ARMARIUM_TOKEN_FILE` (an object:write and object:read
token bound to the chain), `ARMARIUM_CA_FILE`, `ARMARIUM_CHAIN`. `ndim.chain_for(account, chain)` is the one place a per-owner
claimant chain (armarium's recommended model) would be picked; today every owner writes to `ARMARIUM_CHAIN`.

- The sealer writes each kept record's object once its batch has closed: `{kind: "claim-witness/record/1", record_id,
  envelope, seal}`. A private envelope holds commitments only.
- An owner delete puts a tombstone version `{kind: "claim-witness/record-tombstone/1", record_id, deleted_at}` after it; the
  earlier version stays on the chain and holds commitments only.
- `NDIM_STORE_EVIDENCE=1` (default 0, BD4 option C) also writes one evidence object per record with kept evidence:
  `{kind: "claim-witness/evidence/1", record_id, box_b64}`, the box being AES-256-GCM under the evidence key, so armarium
  sees ciphertext only (and encrypts it again). An evidence or owner delete sends the object's DELETE; see "Delete" for what
  the answer says.
- With `ARMARIUM_URL` unset (or its token file not mounted) nothing is written, and `GET /v1/records/{id}` says
  `ndim.state: "not-configured"`. The record view never claims a write that did not happen: `pending`, `written`,
  `tombstoned`, with the object id and the last error code of a failed attempt (retried each tick).
- armarium's facts (24 Nov): an object DELETE removes the version's key only on a claimant chain created with ARMARIUM_KMS
  (`dek: "deleted"`); on a legacy (service-owned) chain the key stays under the shared KEK (`dek: "on-chain"`).

## Running locally with the real fetcher

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
`key_list` of `/.well-known/witness.json`), with `--disclosure`, `--agent-key`, `--methods witness-methods-1.4.0.tar.gz` and
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
| `claim-witness-notary-token` | `token` | api, `/etc/claim-witness/notary/token` (optional) | armarium's notary token (`anchor:write`, profile `hash/1`), B3 |
| `claim-witness-armarium-token` | `token` | api, `/etc/claim-witness/armarium/token` (optional) | armarium object token (`object:write`, `object:read`, bound to `ARMARIUM_CHAIN`), B3 |
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

B3 (the orchestrator, when armarium mints the tokens; until then the pod runs with the notary off and n-dim not configured):
set `NOTARY_URL_PLACEHOLDER` and `ARMARIUM_URL_PLACEHOLDER` in the manifest, then
`kubectl -n witness-dev create secret generic claim-witness-notary-token --from-file=token=notary.token`, the same for
`claim-witness-armarium-token`, and ConfigMap `armarium-ca` (key `ca.crt`) for armarium's private CA.

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

### Builder decisions, B6 (judge.supports, 21-36)

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
    wrong are never moved to where the text sits. (The rule for a quote with `text` is superseded by decision 63, BD13.) At most 10 quotes per run are read. Verified quotes go into the record;
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
### Builder decisions, B2b (observations, 37-54; numbered 21-38 on v1/claim-observe)

37. **One RED test fix**, in its own commit (no test removed): B1's `test_methods_registry_with_tarball_digest` pinned the
    registry to exactly the three B1 methods; it now asks for those three among the methods.
38. **Fetcher failures are records.** Every fetcher error code maps to a SPEC reason (`scheme`, `port` and `bad-request` are
    `blocked`); the fetcher's own failures (busy after two retries, 401, 500, no answer, a tar whose files do not match its
    manifest) are `unreachable` with `detail.fetch_error = "fetcher-unavailable"`, and an HTTP timeout talking to the fetcher
    is `timeout`. The one 5xx is a witness with no `FETCHER_URL` at all: 503 `fetcher-not-configured`, nothing signed (a
    configuration error, not a fetch failure).
39. **The partial manifest** of an error answer goes into the record as counts and enums only: `detail.redirects` (how many)
    and `detail.robots`. Its URLs and addresses are never signed (`detail` holds no evidence text).
40. **URL validation** (422 `invalid-params` / `invalid-evidence`): an absolute http(s) URL with a host, at most 4,096
    characters, NFC, no spaces. Ports, credentials and private addresses are the fetcher's to refuse, which gives a signed
    `blocked`.
41. **The signed manifest** keeps the §2.3 fields only (the fetcher's `user_agent` and `isolation` are dropped). It lists
    `rendered.html` too, so `text.canonical.txt` can be recomputed by anyone. No `phash` is computed for the screenshot yet.
42. **Record evidence for a url item** is `{slot, kind: "url", url, capture, observations: [ids]}`: the requested URL stays,
    because the agent signature and the attempt tag are over requested URLs (§2.4, §7.3). `observations` holds one id, two
    for a confirmed page.live, none when every fetch failed. `max_age` is not recorded.
43. **Agent signature and attempt tag** cover object sha256s, requested URLs and the ids of observation evidence (sorted);
    witness-verify computes the same.
44. **Visibility of observations.** A public claim reuses or names public observations only; a private claim also the
    account's own private ones. Anything else by id is 422 `observation-not-found`. Reuse needs the files (24 h), re-checks
    the stored envelope's signature, and is free. An identical payload (the same capture in the same second) is stored once.
45. **Private observations** made inside a private claim are not disclosed separately: the owner reads them with
    `GET /v1/observations/{id}` (the witness holds the body sealed, BD1). `POST /v1/observe` returns `disclosure` once.
46. **page.live details**: not-live needs the exact URL (no redirects); a 404 after a redirect is `unreachable`. A first
    "gone" that the second fetch does not confirm is `undecided`. The second fetch never reuses. The wait runs inside the
    job thread (a restart loses that job; it stays `running` until purged). The configured delay is passed to the method as
    the minimum, so tests can run it at 5 s. 401/403/407/429/451 and challenge markers (Cloudflare, Incapsula,
    PerimeterX, DataDome, "please verify you are a human") are `blocked`; a 2xx with no visible text is `unreadable`.
47. **NXDOMAIN** comes from the fetcher's `host-not-found` detail and is confirmed by asking every configured resolver
    (default two) on both attempts; all must say NXDOMAIN. No observation exists for it (the fetcher captured nothing).
48. **match.text** compares the submission's canon/1 text at the response layer (no render marks) with each layer. A
    too-large response layer moves on to the rendered layer. `detail` carries `T_bp` and `F_bp` so a record reads alone.
    Global similarity cannot see a small edit in a very long page; T and F were set so that the calibration forgeries
    differ and the honest copies match, with a narrow undecided band.
49. **match.screenshot** compares OCR tokens with the aligned window of the page's tokens. T = 8500 and F = 6500 are
    provisional: Tesseract was not installed where B2b was built, so OCR noise was not measured (the tests use a stand-in
    binary with the same command line). Recalibrate in the image before relying on it. (Superseded by decision 64.)
50. **Evidence trust.** This witness's keys come from its own key lists only. A key list sent with a foreign envelope must
    verify (its own signatures, its subject digest) and must name another witness; its observations are valid but untrusted
    (the trust list holds witness ids, no pinned keys yet), so they count only with `accept_untrusted`. A foreign private
    observation is `unreadable`; so is a trusted observation whose files are gone.
51. **Price** is reported beside the envelope when the evidence includes a url or an observation: observation credits only.
    Every fresh fetch that produced a signed observation counts, the page.live confirmation included; failed fetches and
    reuse are free. BD3's 1 credit per mechanical check is left to the BFF (B4), which knows the method.
52. **Host limit**: at most `WITNESS_HOST_FETCHES_PER_MINUTE` (6) fetches a minute per target host; a job over it waits.
    SPEC §8's 20 fresh observations a minute per account is not enforced yet (the 60 checks a minute ceiling is).
53. **witness-verify** also verifies observation envelopes (id, manifest digest, key validity at `fetched_at`, files,
    `text.canonical.txt` recomputed with the tarball's canon/1). It does not re-run a record whose evidence is an observation
    (the bundle with the observations comes in S3), and never match.screenshot: "re-run skipped (needs image)".
54. **`methods/__init__.py` imports `canon` itself**, so the tarball package exposes it even when loaded twice in one process.

### Integration decisions (55-62)

55. **Migration order**: B6's `002_judge.sql` keeps its name, because dev already recorded it; B2b's file became
    `003_observations.sql`. Its statements were already `IF NOT EXISTS`, so no data step was needed.
56. **judge.supports takes observations** (supersedes B6 decision 24's refusal): by id or by envelope, under the same
    Evidence-trust and visibility rules as every other method. The trust check runs before the judge's pre-checks, so an
    untrusted or unreadable observation makes no model run and costs only the check. `url` evidence stays refused
    (`wrong-evidence-slots`, §2.2). The record's item is `{slot, kind: "observation", id}`, and `relied_on` lists it.
57. **Given observation files and rows are kept by item position**, not by slot, because `judge.supports` takes up to five
    items in one slot. B2b keyed them by slot, which holds one item for its methods.
58. **One price object** (supersedes B2b decision 51, kept in its words as 35 on its branch, and extends B6 decision 35): see
    "Price". A mechanical check over objects has a `check` line, a mechanical check over observations has none. B2b's tests
    (a free page.live costs 0) and B6's (a match.exact costs exactly `{credits: 1, lines: [check]}`) both hold unchanged.
59. **One observation price**: `WITNESS_OBSERVATION_PRICE` when set, else the price list's `observation`. `/v1/price`,
    `/v1/methods` and the answers use the same number.
60. **Methods library 1.2.0** (supersedes B6 decision 22's 1.1.0; B2b left the library at 1.0.0 although its tarball
    changed). Each method keeps its own version (1.0.0).
61. **`judge.supports` is `pure`** in B2b's sense: its `code_sha256` is the methods tarball, not an image digest.
    witness-verify still skips its re-run (B6 decision 36).
62. **Three tests changed**, no assertion loosened: B6's `test_observation_evidence_not_served_until_b2b` became
    `test_observation_evidence_by_unknown_id_is_observation_not_found` (the premise "until B2b" ended; an unknown id is now
    B2b's `observation-not-found`); B6's `test_library_version_bumped_for_the_new_method` pins 1.2.0 instead of 1.1.0; and
    B1's registry test in `test_api_auth.py` pins exactly the seven methods (B6 pinned four, B2b asked for a subset). New:
    `test_integration.py` (judge.supports over observations, trust, price, library) and `test_migrations_upgrade.py`.

### Decisions after the B6 holdout (63-)

63. **Quotes are verified by their text, not by the model's offsets** (BD13, from B6-31 with a live openai/gpt-4.1-mini;
    supersedes decision 28 for a quote with `text`). The model quoted "city library is closed on Sundays" with `end` 38 where
    the span is 4..37, and in another answer copied the datamark into `text`. The exact-offset rule made a correct
    contradiction `undecided`. Now a quote with `text` is found in the item's visible text (`judge_supports.find_quote`:
    U+02C6 back to a space, canon/1 as in `quote.in-source`, a line break counts as a space, the occurrence nearest the
    model's `start`, ties and a missing or non-integer `start` the earliest) and the record carries the witness's offsets.
    `end` is not read for such a quote. A quote without `text` keeps the offsets rule. The 2-character minimum, the hidden-node
    and injection rules, the order of checks, the agreement rule and the price are unchanged. Safety holds: every verified
    quote is verbatim visible text, and hidden nodes are never searched. The methods library is **1.3.0**
    (`witness-methods-1.3.0.tar.gz`) because the tarball's code changed, so every record's `code_sha256` changes and a
    verifier can tell which rule decided a record. `judge.supports` keeps method version 1.0.0 and its prompt file
    (`judge.supports-1.0.0.txt`, same sha256): the prompt and the model input are unchanged, and the method's output shape is
    the same. `vectors.json` was regenerated: four judge vectors were added (the B6-31 answer, a datamarked text, a text only
    in a hidden node, the nearest of two occurrences), the ten earlier ones decide as before, and the envelopes name the new
    `code_sha256`. One test changed ("test change for BD13", its own commit): in `test_fabricated_quotes_are_rejected` the
    case "offsets shifted" (start + 3 with the right text) is now asserted to verify with the witness's offsets, and the two
    library pins say 1.3.0.

### Builder decisions, B5a (post.by-author, 64-73)

64. **The witness never touches the network for a post.** The claimed handle goes to the fetcher with the capture
    (`handle`), and the fetcher resolves it both ways through its egress proxy and public resolvers. The method reads the
    signed observation only, so it is pure and re-runs from the tarball like the other observation methods.
65. **`handle-unresolved` before `signature-unverifiable`.** TS-5's "a handle whose DNS no longer points at the DID" must be
    `handle-unresolved`, and a URL written with that handle cannot even locate the repository (no signature then). A
    claimed handle that is not bidirectional therefore decides first; with it bidirectional, an unverified signature is
    `signature-unverifiable`; only a verified post gives `author-verified` or `author-differs`.
66. **`author-differs` needs both sides verified**: the post's commit signature verified against its author DID, and the
    claimed handle bidirectional to a different DID (the fetcher reads that DID's document too). A handle resolving to
    another DID that does not list it back is `handle-unresolved`, never `author-differs` (VR-6: NOT_SUPPORTED only from
    a real negative finding).
67. **An observation answers only for the handle it resolved.** Given an observation whose `platform.handle` is another
    handle than the claim's, the answer is `handle-unresolved` (`detail.handle_match: no`), and the reuse lookup tag of a
    post capture includes the handle, so `max_age` never reuses one handle's observation for another.
68. **method-not-applicable without a fetch**: only `https://bsky.app/profile/<actor>/post/<rkey>` is applicable (the one form
    the fetcher accepts). Every other URL, including X, LinkedIn and TikTok, gets a signed CANNOT_WITNESS with no fetcher
    call and no observation; `detail.platform` names x, linkedin, tiktok or other. An observation without Bluesky platform
    fields (a page capture) is `method-not-applicable` too, rather than 422, because an envelope given by value can only be
    read after the request is accepted.
69. **The post slot defaults to `capture: post`** and refuses `page` (422 `invalid-evidence`); `capture: post` on any other
    method stays 422 `capture-not-served`, as before.
70. **`platform` in the signed manifest is normalised** (`observation.platform_of`): exactly the nine §2.3 fields and the
    four `handle_resolution` fields, strings of at most 512 characters or null, `bidirectional` a boolean, `signature`
    forced to `failed` when it is not one of its three values. The fetcher's extra fields stay in `platform.json`, which
    is fingerprinted in `files`.
71. **Methods library 1.4.0** (B5a was built as 1.3.0 from 1.2.0; at the merge onto BD13, which had already published 1.3.0 live, it became 1.4.0 so that one version never names two tarballs); `post.by-author` itself is 1.0.0, determinism `observed`.
    The pins of the library version and of the exact method set in `test_integration.py`, `test_judge_unit.py`,
    `test_api_auth.py` and `test_vectors_tarball.py` were moved to 1.4.0 and to the eight methods (no assertion loosened).
72. **Vectors**: nine `post.by-author` template cases (both templates, every finding, method-not-applicable for X and
    LinkedIn); the author-verified pair decides over `claim_witness/vectors/platform-bsky.app.json`, the platform.json the
    real fetcher wrote for https://bsky.app/profile/bsky.app/post/3n2opitxdyc2j on 24 Nov 2026, byte for byte (also
    `tests_claim/fixtures/bsky/`).
73. **No k8s change**: the fetcher reaches plc.directory, the PDS hosts and the handles' well-known URLs on 443 and the
    public resolvers on 53, which the fetcher's manifest already allows; the witness needs nothing new.

### Builder decision, screenshot calibration (74)

74. **match.screenshot T = 9500, F = 9300, measured in the image** (supersedes decision 49's provisional 8500/6500). The
    calibration set `tests_claim/fixtures/calibration/screenshots/` holds 72 cases made by `build.py` (fixed seed 20261124,
    Playwright 1.49.1, Chromium 131.0.6778.33 headless, DejaVu Serif 18px and DejaVu Sans 14px; it rebuilds every file byte
    for byte, and the images are committed because a screenshot depends on the browser build and the fonts): 8 article
    pages, each in one layout (width 1280 at scale 1 or 390 at scale 2, one of the two fonts); per page 4 honest screenshots
    (full page and a two-paragraph crop, PNG and JPEG quality 80), 4 forgeries (the same page with exactly one sentence
    inside the crop replaced by a sentence within 3 words of its length, compared with the original page) and one
    unrelated case (another article's screenshot). The page side is the browser's DOM after load, made into an observation
    with `observation.from_capture`, so the comparison is with its `text.canonical.txt` as for a fetched page.
    `measure.py` ran inside pod `claim-screenshot-cal` in `witness-dev` from image
    `claim-witness:dev-8ca79b4@sha256:829dae31e192de5c1a724755c65c1eab7a52205b4f18ac54854649b0f2e48af7` (no Secrets, no
    service-account token, read-only root, user 10001; deleted after), through `ocr.Ocr.text` (`tesseract stdin stdout -l
    eng --psm 3`, Tesseract 5.5.0, `eng.traineddata` sha256 `7d4322bd…`) and `methods.run("match.screenshot")`, and wrote
    `measured.json` (similarity, token counts and the OCR text per case). Results: honest 9655 to 10000 (every crop
    10000, full pages 9655 to 9761), forgeries 6486 to 9134 (crops 6486 to 8527, full pages 8702 to 9134), unrelated 714 to
    4745; PNG and JPEG of the same screenshot scored the same except in two forgeries (by 167 and 68 bp). The gap is 521 bp. T and F split it in about thirds: T = 9500 is 155
    under the lowest honest case, F = 9300 is 166 above the highest forgery, and 9300 to 9499 is `undecided`, so a little
    more noise than measured makes an answer undecided before it makes it wrong. On the provisional values 18 of the 32
    forgeries were `consistent`. `test_match_screenshot_calibration.py` checks the table against the set and the image,
    re-computes every similarity from the recorded OCR text with the code here, and asserts the separation. The limits are
    in the match.screenshot section above (clean renders only; short pages). The thresholds are in
    `match_screenshot.py`, which is in the methods tarball, so the library is **1.4.0** (`witness-methods-1.4.0.tar.gz`,
    `methods_code_sha256` 1d30489e… → 540ea1a9… on the calibration branch alone; merged with B5a the 1.4.0 tarball is the one /v1/methods names, and no other 1.4.0 was ever served) and every pure method's `code_sha256` changes, no other method's behaviour.
    match.screenshot keeps method version 1.0.0 (its output shape is unchanged; `detail` carries `T_bp`/`F_bp`), and its
    `code_sha256` is the image digest, so the new thresholds take effect only with a new image. `vectors.json` was
    regenerated: the three match.screenshot vectors decide as before with the new `T_bp`/`F_bp` in their detail, and the
    envelopes name the new `code_sha256`. Two tests changed ("test change for match.screenshot calibration", its own
    commit): the two library pins say 1.4.0.

### Builder decisions, B3 (keep, private store, delete, sealer, n-dim: 75-104; built as 63-92, renumbered at the merge)

75. **One test fix after the RED commit**, in its own commit, no assertion changed: `test_share_tokens` made its second
    private record with the identical request, so the object-only idempotency rule answered the same record; it now differs
    by its label.
76. **Keeping is the route only.** `options.keep` / `keep_evidence_days` on `POST /v1/witness` stay 422 `keep-not-served`
    (B1's test unchanged), now pointing to `POST /v1/records/{id}/keep`, where the disclosure and the evidence bytes are given.
77. **The leaf is stored at signing time** (`signing_log.leaf`), because the log keeps no payloads. Rows signed before B3
    have none and are never sealed: their seal stays `pending` ("time not proven").
78. **Batches**: closed when full or when the oldest leaf is `batch_interval_s` old; a tick's own header leaves wait for the
    next tick (so a full batch does not chase its own headers). `batch_id = H(canonical {witness, first_seq, last_seq,
    root})`, `opened_at` the first leaf's time, `closed_at` the tick's time. Two sealers racing: the loser's write is a
    Conflict and its signed header is only a log row.
79. **over** is sha256 of the canonical header including `sig` (SPEC §2.5 "signed batch header"); the notary key is that
    hex, so a repeat is the same request. A failed or unanswered notary call leaves the batch pending (proofs served) and is
    repeated each tick; without a notary the state is `unanchored` and the seal's notary is `{status: off}`.
80. **Seal state** is `anchored` only when the notary result is `landed` (every chain with a transaction). `final` is
    copied as the notary answered; nothing waits for finality.
81. **witness-verify step 4 is one check, `seal`**, which fails by name for a wrong path hash, index, root, header signature
    or `over`. The anchor transaction is not read (`SKIP seal-chain`): the brief keeps the verifier offline and no Base
    Sepolia decoder vector is available to this builder. The anchor time is the earliest landed `block_time`.
82. **Key validity, sealed**: a key revoked at or before the anchor time fails; otherwise `witnessed_at` (or `fetched_at`)
    must lie in the key's validity, so a plain rotation after signing still passes. The batch header's key is held to the
    same rule at `closed_at`. `FLAG seal-delay` is a line, not a failure.
83. **The sealer is a thread of the API process** (one replica, `Recreate`), not a third container: it needs the signer
    socket, the storage and the notary, which the API already has. `WITNESS_SEALER=0` turns it off.
84. **Keep owner** is `submitter.account` of the public predicate or of the disclosed private body; the BFF account is the
    same id. A record whose owner deleted it cannot be kept again (410).
85. **Custody keys**: one data key per kept record, public records too (it wraps their evidence key). Associated data binds
    every ciphertext to its record id (and evidence sha256), so boxes cannot be swapped between records.
86. **`evidence_key` is returned once and also kept wrapped** under the data key: SPEC §2.6 returns it once, and BD1 has the
    owner read without holding anything. Its own use is to read the evidence ciphertext independently of this witness.
87. **Kept evidence** is limited to the record's own object evidence, hash checked. A public record's kept evidence is read
    by anyone (it was screened public evidence and lets TS-12 re-run the method from the bundle); a private one's by the
    owner and by tokens made with `evidence: true`. Expired evidence is deleted by the minute purge.
88. **Private reads without a token** give the envelope and the seal (TS-10: "without it, only fingerprints"), never the
    evidence list or the disclosure. After an owner delete the same holds, with `deleted_at` (BD1).
89. **Share tokens** are `wst_` + 32 random bytes, stored as sha256, id `tok_` + 16 hex, 1 to 365 days (30), private records
    only. A bad token is 403 rather than a silent fingerprints-only answer, so a broken link is visible.
90. **Links** are `{WITNESS_LINK_BASE}/r/{id}` and, for a share, `?token=`; BD1 drops the URL fragment scheme.
91. **Owner search** covers the caller's own kept private records (public records are left to S5's public search): all
    words through the HMAC index, then the phrase in the opened body. Evidence content is not searched (it is not part of
    the body).
92. **Owner delete is for private records**; a public record's content is public, so it is taken down instead. Jobs are
    found by a new `jobs.record_id` column. The account's private observations the record relied on are deleted too.
    Deleting twice answers the first `deleted_at`.
93. **Tombstones**: the record object gets a tombstone *version* (BD1), not armarium's DELETE, because its envelope holds
    commitments only and stays served. The evidence object gets armarium's DELETE, and the answer repeats armarium's `dek`.
94. **The record object is written after its batch closes**, so it carries the seal; failures keep the state and are
    retried each tick. It is written by the sealer only (keep does not call armarium); an owner delete writes its tombstone at
    once and leaves a failure to the sealer.
95. **NDIM_STORE_EVIDENCE** writes one evidence object per record, ciphertext under the evidence key with names and media
    types inside, so no evidence metadata reaches the chain in the clear.
96. **Takedown** is the owner's or an operator's (`WITNESS_OPERATOR_ACCOUNTS`); the reason is accepted but not stored
    (it may carry a subject's personal data). The owner still reads a taken-down record.
97. **The bundle's keys.json is the latest key list** (the one in force now), because it carries revocations made after the
    record; `keys-seal.json` is its own seal. Observations relied on are included when the reader may see them.
98. **Optional volumes**: a token or CA file that is not mounted means off (notary off, n-dim `not-configured`, system
    trust), not a crash. A placeholder URL with a mounted token fails the start, loudly.
99. **FileStorage** (the laptop CLI) does not persist the B3 tables; `dev` mode on memory or Postgres has them all.
100. **Not changed**: `claim_witness/judge.py` and `claim_witness/methods/` (so the methods tarball and every `code_sha256`
    are unchanged; `vectors.json` gained the `seal` section only, 150 lines added and none changed).
101. **An anchor before the payload's own time fails key validity** (beyond the signer's 300 s clock tolerance): a block
    cannot carry a hash that did not exist yet, so such a seal or clock is not consistent. Found by the local end-to-end
    run, whose first fake notary answered a fixed block time.
102. **The local end-to-end** is `tools/e2e_keep_seal.py [--postgres]`: the real API, the real notary and armarium HTTP
    clients against local HTTPS fakes (`tests_claim/fake_seal.py`), a check, keep, a batch close, the anchored seal, and
    witness-verify on the bundle passing `seal`, then failing it by name with one path hash changed.
103. **One existing test changed**, in its own commit: `test_migrations_upgrade.py` pinned the sequence to exactly three
    files; it pins the same exact lists with `004_keep.sql` added. `jobs.record_id` is written only when set, so a row can
    still be written to a database that has not run 004 yet (that test writes into the B6-era dev schema).
104. **Migration 004** is all `ADD COLUMN IF NOT EXISTS` / `CREATE ... IF NOT EXISTS`, so the dev database (001 to 003
    recorded) gains 004 alone and keeps its rows.
