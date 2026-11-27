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

  Then each model gets the fixed prompt (`claim_witness/methods/prompts/judge.supports-1.1.0.txt`, whose sha256 is the
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

  The soft signals are `verdict-word` (SUPPORTED, NOT_SUPPORTED, EVIDENCED, judged-supports and the like) and
  `reliance-request` (judge.supports 1.1.0: text addressed to a human reader that asks to be believed instead of showing the
  fact, such as "take my word for it", "no need to verify", "this counts as proof", "stands in for the output", "staging is a
  copy of production, so these results apply"; `judge_supports.RELIANCE`, case-insensitive). They are recorded and never
  block. Flags hold names, item indices and offsets only. `reliance-request` changes one thing (decision 190): a chat run's
  `judged-supports` whose every verified quote lies inside a reliance line (a line of the visible text holding a reliance
  request) is `judged-silent` with run note `reliance-only`. It never moves a finding toward `judged-supports`.
- **The model setup (BD2, M-20261127-WITNESS-MODELS WM-1, WM-3).** The model list is the ranking (at most 5, rank 1 first;
  `GET /v1/models`, public, lists it with `rank`, `kind`, `credits_per_run` and `rank_note`). `options.models` is exactly one of:
  - `{"count": 1..5, "require"?: 1..count}`: the top `count` models in rank order (the default `{count: 1}` is rank 1);
  - `{"ids": [1 to 5 distinct ids], "require"?: 1..len, "max_credits_per_run"?: 1..1000}`: those models, in the order given.
    An id in the list is listed; any other id must be a plain OpenRouter model id (`^[a-z0-9-]+/[a-z0-9._:-]+$`, no router,
    no `~` alias, no variant or free tier, no `openrouter/auto`) that OpenRouter's model catalogue lists with a price;
    it is a decision model when the catalogue gives it output modality `decisions`, else a chat model.

  `require` defaults to all, strict integers. Anything else is 422 `invalid-request` naming the two shapes; more models than
  listed is 422 `invalid-options`; an unlisted id OpenRouter does not list is 422 `unknown-model`; a catalogue that cannot be
  read is 503 `model-catalogue-unavailable`; none of these runs a model. The legacy `panel: n` means `{count: n, require: n}`,
  and a `panel` that disagrees with `models` is 422. A finding needs `require` runs agreeing and no other finding as large.
  Two findings with no winner give `judges-disagree`. Otherwise the runs' failure decides: `undecided`, `timeout` or
  `model-unavailable`. `options_used` is `{accept_untrusted, allow_provider, models}`, `models` naming the shape used and
  the resolved ids: `{shape: "count", count, require, ids}` or `{shape: "ids", ids, require, max_credits_per_run}`. A
  private record leaves the ids out there (its models are named in the body only) and keeps `count`.
- **Decision models (WM-2).** A model of kind `decision` is asked through OpenRouter's Decisions API (`POST
  https://openrouter.ai/api/alpha/decisions`, the same key) with body `{model, state, questions}` and nothing else: `state`
  is the same datamarked input a chat model gets, `questions` is one typed choice question (`judge_supports.
  decision_questions()`: supports | contradicts | silent). It writes no text and gives no quotes. Its run is the argmax option
  of `answers.verdict.probabilities`, kept only when `answers.verdict.confidence` (or, when absent, that option's
  probability) is at least 0.8; below it the run is `judged-silent` with note `below-confidence`. Another answer shape is
  `wrong-shape`. The injection gates run before any model of either kind, as before.
- **The record.** `judgment` holds:
  - `models`: `{id, provider, version}`, where `version` is the dated model id the endpoint answered with;
  - `prompt_sha256`, `rubric_version` and `sampling`;
  - `runs`: `{model, raw_output_sha256, finding, quotes, note, rejected}`;
  - `agreement`, `injection_flags` and `input_sha256`.

  A decision model's entries also carry `kind: "decision"`: in `models`, `{id, provider, version, kind}` (`version` is the
  response's `model`, the dated id that answered); in `runs`, `version`, `probabilities_bp` (each option in basis points,
  since a signed record holds integers only), `confidence_bp`, `threshold_bp` (8000) and `questions_sha256` (sha256 of the
  question set and the threshold, `judge_supports.decision_questions_sha256()`), which `judgment.questions_sha256` repeats.
  Its `raw_output_sha256` is the sha256 of its `answers` object as sorted compact JSON. A chat model's entries are unchanged.

  `detail` holds counts only: `evidence_items`, `visible_chars`, `input_tokens_est`, `injection_hard`, `injection_soft`,
  `reliance_requests`, `models`, `require`, `models_run` and `agreeing`. A private record carries the judgment in the body only (§2.6).
- **Private claims (§5.7).** A private claim is 422 `provider-not-allowed` unless `options.allow_provider` is true, which
  `options_used` records. Raw model outputs of a private record are discarded. The body has each one's sha256, and nothing is
  stored in the clear. A public record's raw outputs go to `judge_outputs` (migration `002_judge.sql`) with an `expires_at`
  24 h on, and the purge removes them.
- **Attempts (§7.3).** Every judge run counts in the attempt table. That includes private runs with fresh salts (TS-21p),
  because the tag is computed on the plaintext claim. A judge claim is never answered from the object-only idempotency cache.
- **Price (BD3, WM-4).** A judge answer's `price` has a `check` line (1 credit) and a `model-run` line of `ceil(10 × price_factor)`
  for each listed model run made; an unlisted run's line is `ceil(usage.cost / US$0.001) + 2`, never above
  `max_credits_per_run` (default 50), marked `unlisted: true` with its `cost_usd`. An unlisted model whose estimate (prompt
  tokens + `max_tokens` at its OpenRouter prices, + 2) is above the cap is 422 `model-over-cap` before any model is called. A run that timed out or failed was still made, so it counts. `possible-injection`, `too-large`,
  `unreadable` and `evidence-untrusted` make no run. The whole price object, for every method, is in "Price" below.
- **The backend.** Any OpenAI-compatible `POST <base>/chat/completions`, configured by env only:
  - `WITNESS_JUDGE_BASE_URL`, for example `https://openrouter.ai/api/v1`, or the host's vLLM in standalone;
  - `WITNESS_JUDGE_API_KEY_FILE`, a key file and never an env value;
  - `WITNESS_JUDGE_MODELS_FILE`, `[{"id", "vendor", "kind"?, "price_factor", "timeout", "rank_note"?, "reasoning"?}]`, at
    most 5, rank 1 first (`kind` defaults to `chat`, so the list shape before WM-1 still reads; `reasoning` is only ever
    `false`, on a chat entry, decision 193);
  - optionally `WITNESS_JUDGE_MAX_TOKENS`, which defaults to 1024;
  - optionally `WITNESS_JUDGE_DECISIONS_URL` (default: the base without `/v1`, plus `/alpha/decisions`) and
    `WITNESS_JUDGE_CATALOGUE_URL` (default: the base plus `/models`; read without a key, cached 1 h, for unlisted ids).

  The request is the model id, the two messages, `temperature: 0` and `max_tokens`: no tools, no functions and no user field.
  A model listed with `"reasoning": false` also gets `"reasoning": {"enabled": false}` on every chat call (decision 193).
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
  # models.json: [{"id": "<provider>/<model id>", "vendor": "<vendor>", "kind": "chat", "price_factor": 1, "timeout": 60,
  #                "rank_note": "<a short public sentence>"}, ...]   (the ranking, rank 1 first, at most 5)
  ```

  `k8s/claim-witness-judge-models.example.json` is an example in that shape: today's three chat models in today's order and
  one decision model (`typesafe/jev-1.14`). It is not a measured ranking: the ranking and the `rank_note`s come from the
  measurement of DESIGN M-20261127-WITNESS-MODELS.

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
  (a screenshot shows part of a page): `consistent` (≥ T = 9500), `differs` (< F = 8490), else `undecided`; no text read, or an
  image under the readability gate (next bullet), is `unreadable`.
- **Readability gate** (decision 158, DECISIONS BD19 addendum): the witness runs Tesseract a second time on the image with the
  same command line plus the `tsv` config (`ocr.Ocr.readability`; the plain-text run is unchanged, its text is byte-identical to
  before for all 157 measured images) and takes the mean confidence of the words it returns, x100 (`ocr.mean_confidence_x100`).
  Under `MIN_READABILITY_X100 = 8500` (85.0; 9150 under decision 158, moved by decision 159) the claim gets no finding, reason `unreadable`, whether the assertion is true or
  false; `detail` carries `readability_x100` (and `min_readability_x100` when gated). The gate looks at the image only, never at
  the page text, so it cannot be tuned per claim. Evidence without an `ocr_readability` field (a caller other than the witness) is
  not gated; `None` (the second run failed) is `unreadable`. Measured in pod `claim-screenshot-cal3` from the live image
  (`measure_gate.py`, `measured_gate.json` sha256 d513e5d5…, `pod_gate.log`; the shipped code re-measured as
  `measured_gate_prod.json`, `pod_gate_prod.log`): honest images that pass read 9177 to 9664, the 11 honest images the gate takes
  read 4903 to 9102 and are all resampled to 0.5 (8 of 12) or 0.75 (3 of 12); none is a full-size or crop image at scale 1 or 2.
  Its cost: the gate is tuned to this table (the gap between the highest gated honest image, 9102, and the lowest passing one,
  9177, is 75 points) and a forgery at 9164 passes it, so a real photograph or a phone screenshot at a different quality can land
  either side; those get `unreadable` or are judged by F, and F's margin is what protects the honest ones.
- **T = 9500, F = 8490** basis points (decision 159; F was 8700 under decision 158, 1200 under decision 157 and 9300 under decision 74, which signed
  `differs` over honest screenshots), from the widened calibration set `tests_claim/fixtures/calibration/screenshots2/` (`build.py` makes
  the screenshots with Chromium, `measure.py` measured them inside the live image `dev-0ce2a6f@sha256:4a091d1b…`, Tesseract
  5.5.0, in pod `claim-screenshot-cal2`, and wrote `measured.json`; `pod.log`, `pod.yaml`, `ocrvar.log` beside it): 72 honest
  screenshots (widths 1000, 1024, 1440, 1280 and 390, device scale 1 and 2, two fonts, 36 short pages of 64 to 102 tokens and 36
  long ones, a monospace id line, "—" and "·", full page, a crop, and the full page resampled by 0.75 and 0.5, PNG and JPEG)
  scored 1343 to 10000; 72 forgeries (one sentence replaced) 1343 to 9247; 12 screenshots of another page 468 to 6250. The rule
  is BD19's: **no honest screenshot that passes the readability gate is `differs`** (decision 158's F = 8700 was 255 bp under the lowest of them,
  8955, `b3-honest-full-jpg`; decision 159's F = 8490 is 250 bp under the lowest at G = 8500, 8740, `b3-honest-full-s75-png`) and **no forgery is `consistent`** (T is 253 bp over the highest forgery that passes the gate, 9247).
  Outcomes under G = 8500, F = 8490, T = 9500 (decision 159; readability and similarity from `measured_gate.json`): honest 42 `consistent`,
  23 `undecided`, 8 `unreadable`, 0 `differs`; forgeries 41 `differs`, 23 `undecided`, 8 `unreadable`, 0 `consistent` (under decision 158's
  G 9150, F 8700: honest 42 / 19 / 11 / 0, forgeries 42 `differs` / 20 `undecided` / 10 `unreadable`); other-page
  screenshots 12 `differs` (all pass the gate, highest 6250); the regression fixture 9111 bp, readability 9177: `undecided`
  (it was `differs` under decision 74's F). Under decision 157's F = 1200 all 72 forgeries and 9 of the 12 other-page screenshots
  had been `undecided`; the gate is what lets F rise: the honest minimum 1343 came from full pages resampled to half size (text
  7 to 9 px), which Tesseract barely reads, and with the gate those are `unreadable`, not low-similarity. Tesseract `--dpi 300`
  and `--dpi 150` do not help (`ocrvar.log`), and the image has no image library to rescale before OCR.
- The first set (`tests_claim/fixtures/calibration/screenshots/`, decision 74) is kept: widths 1280 and 390 only, 116 to 165
  tokens a page. Its measurements still hold; its F (9300) was the defect. The honest 1000 x 420 screenshot of a 45-token page that
  showed it (9111 bp, 45 OCR tokens) is `screenshots2/regression/`; it is `undecided` (readability 9177, it passes the gate).
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
- **witness-verify** checks the record (signature, ids, key validity; the re-run comes from the observation folders
  of a bundle, decision 153, and is a SKIP without them) and the observation with its files (`platform.json` among them).

## What B5b adds (branch v1/claim-b5b): record.valid and record.disclose

SPEC §4. Both are pure methods in the tarball (library 1.5.0: `methods/record_valid.py`, `record_disclose.py`, and `recordcheck.py`
that holds their shared checks), and both take the `record` evidence kind (§2.2): `{slot, kind: "record", id}`, nothing else. A
record is named by id and must be kept (POST /v1/records/{id}/keep): the witness reads its envelope and its seal from the store.
They never read a private record's plaintext.

**record.valid** (params `{}`; slots `record` and `key_list`, an object: the signer's key list envelope as JSON). It checks, under
that list only: the list itself (subject digest, key shapes, its signatures), the record's signature, the list's witness against
the record's, the id against the payload, the seal (leaf path, header signature, notary `over`, landed anchors) and the key's
validity at the anchor time (a key revoked at or before it fails). Findings: + `record-valid` (detail `{seal: anchored,
anchor_time}`); - `record-invalid` (detail `{failed: "signature,seal,..."}`, from `key-list, signature, key-list-witness,
record-id, seal, key-validity`). A record whose seal is not anchored yet gets **no finding**: reason `undecided`, detail
`{seal: pending}` (it cannot be called "sealed", and "NOT_SUPPORTED" would be a negative the witness did not find: VR-6). Bytes
that are no key list (or no record) give no finding, reason `unreadable`. The Evidence-trust rule does not apply (VR-9): an
invalid record is a `record-invalid` answer. The Ed25519 primitive is not in the tarball: the caller puts `ed25519_verify` in the
record evidence (the witness: `crypto.ed25519_verify`; witness-verify: its own, the pure-Python one under WITNESS_VERIFY_PURE=1).

**record.disclose** (params `{}`; slots `record` and `disclosure`, an object: the disclosure JSON `{salt, body}`). The request must
say `options.visibility: "public"`. Refused before anything is signed: an unknown or unkept id (422 `record-not-found`), a public
record (422 `public-record`), a record of another account (403 `not-owner`), a deleted or taken-down one (410), a disclosure that
fails either commitment (422 `disclosure-mismatch`), an original whose seal is not anchored (422 `record-not-anchored`: the
statement says when it was sealed), a false assertion (422 `assertion-not-allowed`), personal data or a credential anywhere in the
body (422 `personal-data`, the same screening as any public claim, run over every string of the body). Otherwise the record is
public, finding `disclosed`, and the disclosure evidence item carries the disclosure JSON in the clear as `content`, inside the
signed payload, so a reader checks both commitments from the new record alone. It names the original (`evidence[0].id` and the
statement), makes no new judgment (`judgment: null`, `relied_on: []`), and leaves the original private and unchanged.

witness-verify re-runs both from the tarball: `--record FILE` (repeatable) gives the checked record's envelope and seal (an answer
or a record view), a bundle carries `records/<id>/envelope.json` and `seal.json`, and the key list or the disclosure comes with
`--evidence` (or `evidence/<sha256>`). Without the record it prints `SKIP method-rerun`.

## Price

Every answer of `POST /v1/witness` and `POST /v1/observe` carries one `price` object beside the envelope. It is never signed,
and the witness holds no balance: the BFF holds and settles the credits (BD3).

```
price: {credits, lines: [{item, credits, model?}, ...], fresh_observations?, reused_observations?, free_left_today?}
```

- `lines` has a `check` line (1) for a mechanical check over objects and for every `judge.supports` claim; a `model-run` line
  (with `model`) for each model run made, `ceil(10 × price_factor)` for a listed model, and for an unlisted one (any other
  OpenRouter model, WM-4) `ceil(usage.cost / US$0.001) + 2` capped at `options.models.max_credits_per_run` (default 50),
  with `unlisted: true` and `cost_usd` (the `usage.cost` OpenRouter reported; a failed call costs the run fee 2; an answer
  without `usage.cost` costs the estimate, capped); and an `observation` line (5) for each fresh observation past the free
  50 of the day. `credits` is the sum of the lines. With billing own-key a listed run is 0 and an unlisted run is the run fee
  only, `{item: model-run, model, credits: 2, unlisted: true, paid_by: own-key}`.
- An answer from the object-only idempotency rule (item 5 under the order of checks) is a replay: `"replayed": true` beside
  the envelope and `price: {credits: 0, lines: []}`, since its record was already priced and the BFF charges a record once.
- A mechanical check whose evidence includes a `url` or an `observation` has no `check` line: BD3 prices a check over objects
  at 1 and a fresh observation at 5, and a check over observations pays for its fresh observations only. So a `page.live`
  with one free fresh observation costs 0, and the 51st fresh observation of the day costs 5.
- When the evidence includes a `url` or an `observation` (and for `POST /v1/observe`), the object also has
  `fresh_observations`, `reused_observations` and `free_left_today`.

Examples: `match.exact` over two objects `{credits: 1, lines: [{item: check, credits: 1}]}`; `judge.supports` with two models
of factors 1 and 2 `{credits: 31, lines: [check 1, model-run 10, model-run 20]}`; a `page.live` past the free quota
`{credits: 5, lines: [{item: observation, credits: 5}], fresh_observations: 1, reused_observations: 0, free_left_today: 0}`.

`GET /v1/price` and `GET /v1/methods` publish the list: check 1, observation 5, model run 10, kept evidence 1 per MB-month,
each model's `credits_per_run`, and the free fresh observations a day. `GET /v1/price` also states both model rules:
`listed_models.rule` and `unlisted_models` (`rule`, `run_fee` 2, `credit_usd` "0.001", `max_credits_per_run`
{default 50, min 1, max 1000}, `own_key`, `id_pattern`, `refused`). `GET /v1/models` (public) is the ranked list with the
same rules. `WITNESS_PRICE_LIST_FILE` overrides the list;
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
  record's to the owner and to holders of a token made with `evidence: true`;
- `GET /v1/records/{id}/bundle`: the proof file people hand on (envelope, seal, key list and its seal, a public record's agent
  key, the observations relied on and the kept evidence this reader may see, the methods tarball the record names, from the
  archive, decision 161: `witness-methods-<the record's library version>.tar.gz`, or no tarball and a
  `witness-methods-missing.txt` when the witness has no copy of it). It **never carries
  `disclosure.json`**, for any reader (BD17, decision 154): a private body travels only through a deliberate share link. The
  owner or token holder reads the disclosure from `GET /v1/records/{id}` and passes it with `witness-verify --bundle DIR
  --disclosure FILE`.

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
  It DELETEs every version of the record's n-dim object at armarium (one DELETE per version, B3W; no tombstone version is
  written). The answer lists each of these with counts (`deleted`), and
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
  transaction is read only with `--rpc URL` (decision 160): `PASS seal-chain` needs the transaction to exist, be to 0x0, carry
  the hash-mode datablock whose `payload.over` is the seal's `over`, sit in the anchor's block, in a block whose timestamp is the
  anchor's `block_time`; the PASS line names the chain, the transaction, the block and the sender. Without `--rpc` it is
  `SKIP seal-chain` (no network; the line names `--rpc`). The sender is checked against the key list's `sealers` for
  base-sepolia, or against `--sealer ADDRESS` (repeatable; replaces the list); with neither the line says the sender was not
  checked. lab-qbft and any other chain: a SKIP naming it as the operator's own chain. Give
  the seal with `--seal`, inside the answer file, or as `seal.json` of a bundle.
  `witness-verify --bundle DIR --rpc https://sepolia.base.org` is the whole check, with the one network call the verifier makes.

## n-dim

BD4, SPEC §7.5, wired to armarium's real object service in B3W. `claim_witness/ndim.py`: an `ArmariumClient` interface
(create claimant, create object, put version, delete one version's key, get) and `HttpArmarium` over armarium's
`POST /chain/{case}/claimant`, `POST /chain/{cid}/object` and `GET/PUT/DELETE /chain/{cid}/object/{id}`. Settings
`ARMARIUM_URL` (https), `ARMARIUM_TOKEN_FILE` (a token bound to the case: object:read, object:write, lifecycle), `ARMARIUM_CA_FILE`
(the object service's CA, not the notary's), `ARMARIUM_CASE` (the 32-hex case). Each owner has their own claimant chain under
the case; it is created in the background and stored in `ndim_chains` (migration 005). See "Builder decisions, B3W".

- The sealer writes each kept record's object once its batch has closed: `{kind: "claim-witness/record/1", record_id,
  envelope, seal}`. A private envelope holds commitments only.
- An owner delete sends armarium's DELETE for every version of the record's object, each with its own id and tail block; the
  encrypted bytes (commitments only) stay on the chain, each version's key is deleted. We write no tombstone version.
- `NDIM_STORE_EVIDENCE=1` (default 0, BD4 option C) also writes one evidence object per record with kept evidence:
  `{kind: "claim-witness/evidence/1", record_id, box_b64}`, the box being AES-256-GCM under the evidence key, so armarium
  sees ciphertext only (and encrypts it again). An evidence or owner delete sends the object's DELETE; see "Delete" for what
  the answer says.
- With `ARMARIUM_URL` unset (or its token file not mounted) nothing is written, and `GET /v1/records/{id}` says
  `ndim.state: "not-configured"`. The record view never claims a write that did not happen: `pending`, `written`, `deleted`
  (with armarium's `dek`), `not-written` (deleted before it was written) or `failed`, with the object id and the last error of a
  failed attempt (retried with backoff).
- armarium's facts (24 Nov): an object DELETE removes the version's key only on a claimant chain created with ARMARIUM_KMS
  (`dek: "deleted"`); on a legacy (service-owned) chain the key stays under the shared KEK (`dek: "on-chain"`).

## Own model key

DESIGN M-20261126-CLAIMS-DOCS-BYOK, C1 (the witness part) and C2: a check a user pays with their own OpenRouter key. The BFF
decides (credits first; own key only when the credits cannot cover the check and the account has saved a key) and the witness
does what it is told in the body the BFF signs. Name in code and APIs: **own key** (`own-key`, `own_key`).

- **Request** (`POST /v1/witness`, `POST /v1/observe`): `options.billing: "own-key"` (its only value; anything else is 422
  `invalid-options`) plus the key in header `X-Witness-Model-Key`. Billing own-key without the header (or with an empty or
  malformed one) is 422 `model-key-missing`; the header without billing own-key is ignored and never used. `/v1/observe` takes
  `options` with `billing` only.
- **Model calls**: an own-key `judge.supports` run calls the same base URL and the same configured models with the header key
  instead of `WITNESS_JUDGE_API_KEY_FILE`'s. The key lives in the request's memory only: never logged, never stored (not in the
  job row, not in the answer, not in the signing log or raw outputs), never echoed; every string from a provider answer is
  scrubbed of it before it is parsed, hashed or kept, and an error body is never read (its status only).
- **A refused key**: when every model run of the check is answered 401, 402 or 403, there is no record: 422
  `model-key-rejected`, detail `OpenRouter answered 401: the key is not valid` / `402: the key's OpenRouter account is out of
  credit` / `403: the key is disabled or not allowed to use this model`. Nothing is signed, nothing is counted.
- **Price**: `{"credits": 0, "billing": "own-key", "lines": [...]}`, every line `credits: 0`, model-run lines with
  `"paid_by": "own-key"`; an unlisted model's run (WM-4, decision 187) costs the run fee only, 2 credits, so `credits` is
  2 per unlisted run. Fresh observations stay free within the daily allowance (`WITNESS_FREE_OBSERVATIONS_PER_DAY`, 50);
  past it an own-key request is 402 `own-key-observation-limit` ("own-key checks include 50 fresh page observations a day"),
  refused before anything is fetched or signed.
- **Anchoring**: answers (`POST /v1/witness`, `GET /v1/jobs/{id}`, `POST /v1/observe`) and the record view (`GET
  /v1/records/{id}`) carry top-level `"anchoring": "own"` for what was signed while serving an own-key request, `"public"` for
  everything else. The signed record itself is the same record as a paid check's.
- **Tier** (migration `008_signing_log_tier.sql`): every signing-log row has `tier` `public` or `own`. Own: the record, every
  observation fetched for it (and by an own-key `/v1/observe`), and the header of a batch of own rows. Rows from before the
  migration are public. The tier goes to the signer sidecar in the sign request; the signer logs it and echoes it, and the API
  refuses an answer that does not echo it.
- **Sealer**: batches are formed per tier and never mix tiers. Every new header carries `"anchoring": "public" | "own"` (signed;
  a header without it is public, so every older seal still verifies). Public batches are unchanged (profile hash/1, lab-qbft +
  base-sepolia). Own batches go only to the own notary client: profile `WITNESS_NOTARY_OWN_PROFILE` (unset: `hash/1-own`;
  empty or `off`: none; `hash/1` is refused at start), token `WITNESS_NOTARY_OWN_TOKEN_FILE`, required (unset, empty or not
  mounted: no own client, never the public token); URL, CA and timeout are the notary's. Without an own client own batches close unanchored
  (`notary.status: off`) and are never sent with hash/1. An answer for an own batch that names any chain other than lab-qbft
  is a failed seal (state stays pending, reason names the chain, no anchor kept), asked again each tick with the own client.
- **witness-verify**: a header with `anchoring: own` prints `INFO anchoring: own chain only (a check paid with the user's own
  model key is not anchored on a public chain)`; with `--rpc` its lab-qbft anchor is `SKIP seal-chain` as before and the
  missing public anchor is never a FAIL. An own header whose seal carries a base-sepolia anchor is `FAIL seal` naming it; an
  `anchoring` other than public or own is `FAIL seal`. A public header (or none) behaves exactly as before.
- **Deploying**: armarium must serve the own profile (lab-qbft only) for the witness's token; until it does, own seals stay
  pending (the notary refuses the profile), and nothing own is ever sent with hash/1.

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
`--evidence FILE` and `--observation DIR` (an observation the record relied on: `envelope.json`, `files/<name>`; repeatable) as
needed, or `--bundle DIR`. A bundle's `observations/<id>/` folders make `page.live`, `match.text` and the other observation
methods re-run offline (decision 153).

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
| `armarium-claim-witness` | `token` | api, `/etc/claim-witness/notary/token` (optional) | armarium's notary token (`anchor:write` + read, profile `hash/1`, chains lab-qbft and base-sepolia), B3W; armarium renews it |
| `armarium-claim-witness-objects` | `token` | api, `/etc/claim-witness/armarium-objects/token` (optional) | armarium object token (object:read, object:write, lifecycle, read; bound to case `1e59334fee73fc758f793ce01c3cdd00`), B3W; armarium renews it |
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

B3W: armarium made the two token Secrets and the two CA ConfigMaps in `witness-dev` itself (`armarium-claim-witness`,
`armarium-claim-witness-objects`, `armarium-ca` for the notary, `armarium-objects-ca` for the object service); the manifest names
them and writes both URLs in (they are not secrets). All four volumes are optional: without a token file the notary is off and
n-dim says `not-configured`. Tokens expire 2026-12-24; armarium renews them.

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
   **The replay marker** (26 Nov): an answer from this rule is the existing record (the same `record_id`, envelope and, for a
   private record, disclosure) with `"replayed": true` and `price: {credits: 0, lines: []}` (plus `billing: "own-key"` for an
   own-key record), because the BFF charges a record once. Under an Idempotency-Key, that marked answer is what the key
   answers afterwards. A new `label` is a new record.
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
    or `over`. The anchor transaction is not read (`SKIP seal-chain`; superseded by decision 160: it is read with `--rpc`): the
    brief keeps the verifier offline and no Base Sepolia decoder vector is available to this builder. The anchor time is the earliest landed `block_time`.
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
93. **Tombstones** (superseded by B3W 111): B3 wrote a tombstone *version* on the record object (BD1) and used armarium's
    DELETE for the evidence object only. Armarium's real service says not to write our own tombstone; every version is DELETEd.
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
    trust), not a crash. (B3W: the manifest has no placeholder URLs any more.)
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

### Builder decisions, B3W

B3 was built against fakes; armarium's real notary and object service (24 Nov 2026, armarium PR #78, loom-armarium's record)
differ from what it assumed. Wired in branch v1/claim-wire. `claim_witness/methods/` is not touched, so every `code_sha256` is
unchanged.

105. **One claimant chain per owner** under the claim-witness case (`ARMARIUM_CASE`), as armarium recommends: the object
     service deletes keys only on claimant chains, and one chain per owner keeps an owner's data apart. ARMARIUM_CHAIN is gone.
     `ndim.ensure_chain` makes it with `POST /chain/{case}/claimant` and stores it durably in `ndim_chains` (migration 005,
     both storage backends), keyed by `owner_tag`.
106. **The create never blocks a request.** The first create can take 6 minutes (a disk and a node pod). `keep` writes the record
     with n-dim `pending` and calls armarium never. A second sealer thread, `ndim`, creates the chain and then writes the
     pending objects, so the notary and batch closing are not held up. `ndim_sync` (also run inline by an owner delete) never
     makes a chain: it waits for the thread.
107. **Retry, backoff and failure with a reason.** A transient failure (no answer, 5xx, 409) keeps its progress and backs off
     30 s doubling to 1 h; after 12 in a row the step is `failed` with the last reason. A 401 or 403 is a configuration error
     (`ArmariumConfigError`): `failed` at once, reason starting "configuration:", never retried. `failed` is cleared once when
     the sealer starts, so an operator who fixed the Secret restarts the pod. The record view says `failed` with `last_error`.
     A claimant create that timed out may have made a chain nobody records: an orphan, costing a disk until a person deletes it.
108. **from, to and ruleSet** are opaque to armarium for this use (it takes ids and addresses). Each is an HMAC-SHA256 of the
     account under a key derived from the master key (HKDF `claim-witness/ndim-owner/1`), with its own label per value, cut to 32
     or 40 hex. They are stable per owner, so a re-run derives the same request, and they carry no account: armarium cannot
     recover the account from them, and nothing ties the values to each other or to `owner_tag` (HMAC with its own label), which
     is the only thing stored. Rotating the master key would orphan the table, as it would the wrapped data keys.
109. **Real field names.** POST answers `correlation_id` and `block`; PUT answers `new_correlation_id`, `new_block` and
     `original_id` (a NEW version id per PUT); DELETE answers `dek`, `residual` and `message` with no block; the claimant create
     answers 201 with `id`, which can start with a digit. Reads, PUT and DELETE name a version by its own id. The record keeps a
     `versions` list `{id, block, dek, residual}` per object.
110. **DELETE per version** (`?block=<that version's tail>`): the key is per version, so an owner delete of a record with N
     versions is N DELETEs; each version's `dek` is stored as it answers, a 409 `incomplete` is retried (the same DELETE), and the
     record is `deleted` only when every version is. Its `dek` is `deleted` only when all are; the words "the key is deleted;
     the encrypted bytes stay on the chain" are used only then. A record deleted before it was written is `not-written` and
     nothing is sent. Deleting a whole claimant chain needs a person's token and stays a person-approved step.
111. **No tombstone version** (supersedes decision 93): armarium says not to write our own. The `tombstoned` state is now
     `deleted`.
112. **Notary body**: `{"profile": "hash/1", "key", "payload"}` with the payload the base64 of `{"label": "claim-witness/batch/1",
     "over": "sha256:<hex>"}` (`label` is optional in hash/1; its pattern is checked by the profile). The key is still the header
     hash. **`final: false`** (base-sepolia at write time) means landed but not yet final on that chain: the result stays
     `landed` (a transaction exists and verifies), the batch stays `pending`, and each tick sends the same request again until
     no anchor says false (`notary.all_final`; an anchor with no `final` field is not held back). So the seal view is
     `pending` with the anchors, then `anchored`.
113. **Two CAs.** The notary's is ConfigMap `armarium-ca` (homelab CA); the object service's is `armarium-objects-ca`
     (raptor-dev-internal-ca): two mounts, `WITNESS_NOTARY_CA_FILE` and `ARMARIUM_CA_FILE`. The Secrets are `armarium-claim-witness`
     (notary) and `armarium-claim-witness-objects`. Volumes stay optional; the placeholders are gone but `IMAGE_PLACEHOLDER` and
     `IMAGE_DIGEST_PLACEHOLDER`, which the orchestrator fills.
114. **Tests.** RED first (`tests_claim/test_wire_*.py` and `fake_armarium_real.py`, an HTTPS fake of the real answers: slow first
     create, a digit-first claimant id, 410 after DELETE, 401, 403, the notary's final:false). Changes to older tests are in their
     own commits named "test change for B3W". `tools/e2e_keep_seal.py` uses the real-shaped fakes. The Postgres variants of
     the keep suite and the migration-list test (now pinning `005_ndim_chains.sql`) skip where no Postgres is installed.
115. **Live smoke**: `tools/live_armarium_smoke.py`, run from a short-lived pod in witness-dev (the tokens are only there):
     1 claimant create for a throwaway owner, POST, PUT, GET, DELETE, GET (410), 1 notary seal (at most 2 requests) and its verify.
     It prints no token. The throwaway claimant chain stays.

### Builder decisions, B5b (record.valid, record.disclose: 116-)

116. **`record` evidence is by id only, and the id must be a kept record.** SPEC §2.2 gives the kind one field, `id`, so there is
     no envelope by value (unlike observations). The witness holds an envelope only for kept records (the job answer is purged
     after 24 h), so an unkept id is 422 `record-not-found` with the hint to keep it.
117. **record.valid on someone else's record is allowed** (it reads the envelope and seal, which GET /v1/records/{id} serves to
     anyone, and a private envelope holds commitments only). A record taken down is not found for anyone but its owner; a deleted
     private record still checks (its envelope and seal stay).
118. **An unanchored record: `undecided`, not `record-invalid`.** "Validly signed and sealed" cannot be said without an anchor, and
     a failure to be anchored yet is no negative finding (VR-6). Reason `undecided` is already in the closed list, so the signer's
     schema is unchanged. A bad signature, a bad path or a revoked key on a record not yet anchored is still `record-invalid`
     (those are real negatives; an unsealed record is judged at its own time, as witness-verify does).
119. **A key list that parses but does not verify is `record-invalid`** (check `key-list`: nothing can be validated under it); bytes
     that are not a key-list envelope at all are `unreadable`, no finding. A list for another witness is `record-invalid`
     (`key-list-witness`), like witness-verify's.
120. **The checks are restated in `methods/recordcheck.py`, not imported.** The tarball cannot import `verify.py` (standard library
     only, relative imports only), so the canonical JSON, merkle path, PAE, commitments and the seal and key-validity logic are
     restated, as verify.py itself restates jcs and ids. The vectors check the restatement both ways: every `record_methods`
     vector must give the same answer in the witness and the tarball, and for record.valid witness-verify's own run on the same
     inputs must print a FAIL exactly when the finding is `record-invalid`. Ed25519 is not restated: it is passed in by the caller (see the section above).
121. **record.disclose's statement carries `anchor_time`**, the earliest landed `block_time` of the original's seal. Whether that seal
     verifies is record.valid's question; disclose reads the witness's own stored seal and says it made no new check. The method
     has no F template (`templates.false` is null in GET /v1/methods) and a false assertion is 422.
122. **Publishing is deliberate.** record.disclose without `options.visibility: "public"` (default is private) is 422 `invalid-options`
     rather than being quietly made public.
123. **The body travels in the signed record.** The public record's schema has no body field, and `detail` takes enums only, so the
     disclosure JSON is the `content` of the disclosure evidence item (the schema only asks an evidence item for `slot` and `kind`).
     `sha256` stays the hash of the bytes the caller sent. The salt is published with the body: it is what lets a reader recompute
     the commitments, and a disclosed record has nothing left to hide with it.
124. **Screening runs over every string of the disclosed body** (`screen_public(..., extra_texts=)`), including its evidence names,
     label, statement and params. A hit is 422 `personal-data` before anything is signed and the answer names rules, not values.
125. **The agent's signature covers record ids** (`agent_message` in the witness and in verify.py), the same way it covers object
     hashes, URLs and observation ids. The attempt tag counts record ids too. Nobody signed over a `record` item before B5b.
126. **Price.** Both are one `check`; `observed` (the fresh/reused observation fields) is now only for `url` and `observation`
     evidence, so a record item does not drop the check line.
127. **No new route and no storage change.** Bundles of a record.valid or record.disclose record also carry the checked record
     (`records/<id>/envelope.json`, `seal.json`; the seal as it is when the bundle is built). The Postgres run of the same cases is
     `test_record_methods_pg.py`.
128. **Library 1.4.0 -> 1.5.0**, both methods 1.0.0. `methods_code_sha256` changes from 7f39d394... (every pure method's
     `code_sha256` moves with it); the existing tests that pin the library version are changed in their own commit,
     "test change for B5b".

## B7: the record graph and search

Branch `v1/claim-b7`, from `095e014`. `claim_witness/methods/` is not touched, so every `code_sha256` is unchanged. Migration
`007_graph_search.sql` (006 is left free for the parallel B5b branch). Code: `claim_witness/graph.py`, `claim_witness/search.py`;
storage methods on both backends (memory and Postgres); tests `tests_claim/test_graph_search.py` and `test_graph_search_pg.py`.

**Graph**, `GET /v1/records/{id}/graph?depth=2` (the id is a record's or an observation's; a key is optional, a share token via
`?token=` or `X-Witness-Share-Token`). Edges are W3C PROV-O, written when a record is signed:

| from | edge | to | when |
|---|---|---|---|
| record | `prov:used` | observation | every observation in `relied_on` |
| record | `prov:wasDerivedFrom` | record | evidence of kind `record` (the B5b hook; nothing writes such evidence yet) |
| record | `prov:wasAttributedTo` | witness | every record |
| record | `prov:wasAttributedTo` | agent `agt_...` | a public record signed for an agent (never the agent key id, key or account) |

The answer is `{model: "W3C PROV-O", root, depth, nodes: [{id, kind, prov, visibility, method?, outcome?, witnessed_at?}], edges:
[{from, to, rel, visibility}], truncated}`. `depth` is 0 to 5 (default 2; anything else is 422), the walk goes both ways, and
stops at 300 nodes with `truncated: true`. The witness and agent nodes are leaves (two records are not one hop apart because
the same witness signed both).

**Visibility.** An edge has the visibility of its most private end; each private end names its owner in an internal column and a
reader sees the edge only when every private end is theirs. A reader sees public nodes and edges plus their own private ones.
Another account's private node, edge, flag or count is never in the answer: an answer with and without another account's private
record over a shared public observation is byte-identical (TS-15), `truncated` is computed from visible nodes only, and no total
or "n hidden" exists. A private node the reader may not see answers like an unknown id (404). A taken-down public record is 410
to others and in nobody else's graph; its owner still sees it flagged `taken_down`. An owner-deleted private record loses its
edges and the private observations deleted with it lose theirs; its owner still gets the lone node flagged `deleted`. A share
token opens the private edges and nodes touching its one record, not the owner's other private records.

**Search**, `GET /v1/search?q=&mode=hybrid|keyword|semantic&outcome=&method=&since=&limit=&offset=` (key optional).
Public kept records are searched by Postgres full text (a `tsvector` with a GIN index, config `simple`); the reader's own live
private records are listed when there is no `q`, with no statement or label, and are never matched by a `q`. `limit` 1 to 100
(default 20), `offset` 0 to 10000, `next_offset` instead of a total. Bad `outcome`, `method`, `since`, `mode`, `limit`, `offset`,
a `q` over 500 characters or over 32 distinct words: 422.

**Without an embedder** (`WITNESS_EMBEDDER_URL` unset, as on dev): `mode=semantic` is `503 semantic-unavailable` with no
records, `mode=hybrid` (the default) answers the keyword results with `mode_used: "keyword"`, `degraded: true` and a `note`, and
`mode=keyword` is plain. Every answer carries both `mode` (asked) and `mode_used` (done). **With one**: records are embedded when
kept and by `embed_missing`; `hybrid` fuses the keyword and cosine rankings by reciprocal rank; if the embedder does not answer
at query time, semantic is `503 embedder-unavailable` and hybrid is degraded as above.

### Builder decisions, B7

140. **Edges are written when a record is signed, in the same request**, from the predicate the witness has just built (for a
     private record, the sealed body's predicate: the payload alone does not carry `relied_on`). A failure to write them is
     logged and never loses the answer; `graph.backfill()` writes them at the next start, idempotently (`ON CONFLICT DO
     NOTHING` on `(src, dst, rel)`).
141. **Backfill reads what is still held**: every kept record (a private one through its sealed body, unless its owner deleted
     it) and every stored job answer (24 h). A record that was neither kept nor in a job's 24 h is only in the signing log, so
     its edges cannot be recovered; such a record is simply absent from the graph. Observation nodes are created when an
     observation is signed and, for older ones, lazily when asked for.
142. **Two columns name the owner of a private end** (`src_account`, `dst_account`; null for a public end), instead of one
     edge account. A private record that relies on a disclosed private record of another account (B5b) then has an edge nobody
     but a share-token holder can see. A public node row holds no account at all. A record or observation whose owner is not
     known gets the owner `''`, which no account matches.
143. **Taken-down and deleted state is read from `kept_records`, not copied into the graph**, so it cannot go stale. A takedown
     also deletes the record's search row.
144. **Not found and not allowed answer alike (404)** for a private record or observation, so the graph is not an oracle for private
     ids. A taken-down public record is 410, as `GET /v1/records/{id}` already says.
145. **The `agt_` id is in the public graph, the agent key id and key are not.** The `agt_` id is already in every public record's
     `submitter`; it is a hash of the account and the key and names neither. A private record has no agent edge (its agent is
     inside the body).
146. **Search covers kept public records only.** A record that was signed and not kept has no stored envelope after 24 h, so it
     has no text to index. Indexing happens in `keep`; `search.backfill()` indexes the public records kept before this slice.
147. **The query parser is Python's, not Postgres's.** `q` is cut into `[^\W_]+` words (NFKC, casefolded), the words are
     joined by spaces and bound as one parameter of `plainto_tsquery('simple', ...)`, and the document is indexed from the same
     words. No tsquery operator, quote or SQL can come out of a query, and memory and Postgres storage agree on what matches.
     Every query is an AND of its words; there is no prefix, phrase or OR search.
148. **A `q` never matches or lists a private record, not even the owner's.** With a `q` the signed-in reader is told so
     (`private.searched: false`, pointing at `GET /v1/records?q=`); with no `q` their own live private records are listed with
     method, outcome and time only. Neither lists a deleted or taken-down record.
149. **Default mode is `hybrid`** (SPEC lists it first), which with no embedder is the keyword result flagged degraded. A
     semantic answer is never keyword results under the semantic name: 503.
150. **`embedding` is `real[]`, not `vector`.** The migration works on any Postgres 16 (the pgserver wheel the tests use has no
     pgvector) and the cosine is computed in Python over at most 1000 candidates; claim-pg runs `pgvector/pgvector:pg16`, so a
     later migration can add a `vector` column and an index when the corpus needs one. The embedder is any OpenAI-compatible
     `/v1/embeddings` URL (`WITNESS_EMBEDDER_URL`, optional `WITNESS_EMBEDDER_MODEL`, `WITNESS_EMBEDDER_KEY_FILE`); a private
     record is never sent to it. `embed_missing()` runs at start; there is no scheduled re-embed yet.
151. **Tests.** RED first (`e6de830`: 67 tests, all failing on 095e014). The migration-list test changed in its own commit
     named "test change for B7" (it pins exact lists; they gain `007_graph_search.sql`). One test class, `SearchBackfill`, was
     added in the GREEN commit. No existing assertion was loosened. `Storage.clear_graph()` exists for the backfill test and for
     an operator rebuild.
152. **The graph and search tables are not in the n-dim or bundle paths.** The bundle already includes the observations a record
     relied on; the graph is a derived index of the same facts and is not signed or sealed.

### Builder decisions, witness-verify observation re-run (branch v1/claim-verify-obs: 153-)

153. **`witness-verify --bundle` re-runs `page.live`, `match.text` and any other pure method whose evidence is an observation or
     a url** (SPEC VR-13, §6 step 6, TS-12). `verify.py` is the client, so the methods tarball and `methods_code_sha256` are
     unchanged. The bundle's `observations/<id>/{envelope.json, seal.json, disclosure.json?, files/<name>}` is read
     (`--observation DIR`, repeatable, takes the same folder for a single envelope). Each observation the record names (an
     `observation` item's `id`, a `url` item's `observations`, in the record's order) goes through the checks any observation
     gets (signature, id, manifest digest, files against the manifest, `text.canonical.txt` recomputed from `rendered.html`, seal,
     key validity) and only then are its manifest and its files, matched by name against the manifest, given to the method in the
     shape the server gives it: `{slot, kind: observation, id, manifest, files}`, and for `page.live` `{slot, kind: url, url,
     attempts: [{observation}, ...]}` (decision 42's `observations` list is the attempts). The finding is compared with the
     record by `_compare` (finding, reason, outcome, detail, statement, limits).
     - An observation that fails its own checks makes `method-rerun` FAIL, never PASS, beside the failing check by name
       (`observation-files`, `signature`, `record-id`, `text-canonical`, `manifest-digest`). A bundle folder is named by the id it
       claims, so a folder holding another observation fails `record-id`.
     - SKIP, naming what is missing: an observation the bundle lacks (its id); a file its manifest lists that the bundle lacks
       (`capture.wacz` and `screenshot.png` may be left out: no pure method reads them); a private observation without
       `disclosure.json` (the witness keeps the body, not the salt, so its bundle cannot carry one yet); a `url` item whose fetch
       failed (no observation exists); a `page.live` whose confirming second fetch failed (the record has one observation and the
       confirmation cannot be re-run); the object bytes of the record.
     - `match.screenshot` stays "re-run skipped (needs image)". `confirm_min_s` is `page.live`'s own default (60), not the
       server's configured delay: a record made on a witness configured with another delay is judged by the library's rule.
     - `verify.py` stays one module, standard library only, importing nothing from its package.

154. **A record bundle never carries the private disclosure** (BD17, from B3-23). SPEC §3 lists the bundle's contents (envelope,
     seal, key list and its seal, a public record's agent key, the observations relied on, capture files and kept evidence the
     reader may see) and no disclosure; B3 had added `disclosure.json` for the owner or a token holder, which put a private body
     in clear in the file people pass around as proof. `Records.bundle` now never writes it, for any reader. The body still
     selects, server-side, which observations and records this reader may see in the bundle. Kept evidence stays
     reader-dependent as SPEC says (a private record's kept evidence is in the owner's bundle, or a token holder's with
     `evidence: true`): that is a deliberate kept file, not the disclosure, and it is unchanged. Observation disclosures inside
     `observations/<id>/` were never served and still are not. `witness-verify` is unchanged in behaviour: `--disclosure FILE`
     (with `--bundle DIR` or `--envelope`) checks the claim and body commitments, a bundle without it verifies what it can
     (the disclosure-dependent checks are SKIP, none FAIL), and `--bundle` still picks up a `disclosure.json` a user puts in
     the folder themselves. The methods tarball and `methods_code_sha256` are unchanged. Tests: `tests_claim/test_keep_api.py`
     `Bundles` (memory and Postgres), with one existing assertion reversed in its own commit (the owner's bundle used to be
     asserted to hold `disclosure.json`). Reversible.
155. **Every signed statement fills the claim's params** (live defect on witness-dev, 25 Nov: a `post.by-author` claim whose
     observation evidence had one byte of `platform.json` changed got `evidence-untrusted` and the signed statement read "...
     was published by the account ." with the handle missing). The early CANNOT_WITNESS paths (`Untrusted`, several raised with
     no variables at all) rendered the template from the observation's variables alone. Every claim record is rendered at one
     place, `service._witness`, so the fix is one function, `service.fill_vars(method, assertion, params, vars)`: the claim's
     params are always template variables (taken from the claim when the method or an early path did not give them), and a
     mandatory variable that is still unknown is a fixed phrase, never an empty string. The phrases: `url` "an observation that
     could not be used" (as before), `fetched_at` and `anchor_time` "an unknown time" (as before for the time), any other name
     "an unknown <name>". Optional parts (`{ for commit {expect_commit}}`) are untouched. Only `_witness` signs a claim record (a
     finding, a method refusal, a failed capture, `method-not-applicable`, `evidence-untrusted`, `unreadable` and
     `judge.supports`' no-run answers all pass through it), and `POST /v1/observe` signs observations, which have no statement.
     The methods library is unchanged (1.5.0), so the tarball and `methods_code_sha256` are unchanged, and a finding's statement
     is byte for byte what it was. Tests: `tests_claim/test_statement_params.py`. Reversible.
156. **record.valid and witness-verify name key validity at the anchor time** (live defect on witness-dev, 25 Nov: a sealed, anchored
     record whose key list revoked the witness key before the anchor time was NOT_SUPPORTED `record-invalid` with detail
     `failed: ["seal"]` only. SPEC §4 record.valid, §6 step 5, VR-16, TS-20). The same key signs the batch header and the record,
     so `_seal_errors` counted the header key's revocation or validity as a seal error, and the record key's own check ran only
     when "seal" had not failed. Now `seal` is the structural checks (path, header key in the list, header signature, header
     witness, over, not-landed, block-time) and `key-validity` is the key's validity at the anchor time: the header key revoked at
     or before the anchor time or the batch closed outside its validity, and the record key as before. When the seal fails for a
     structural reason and an anchor time can still be read, the record key is still judged at it (`seal,key-validity`). With no
     readable anchor time the record key is not judged, as before. `CHECKS` order is unchanged. witness-verify: `check_seal`
     returns (failed, anchor). A revoked or out-of-validity header key is a `FAIL key-validity` of its own beside a `PASS seal`
     (or beside a `FAIL seal` when that fails too), and step 5 judges the record key whenever an anchor time was read. No finding,
     outcome or valid/invalid verdict changes: only which checks are named in `failed` and the verifier's lines. The methods
     library is **1.6.0** because `recordcheck.py` is in the tarball (`methods_code_sha256` 0d691773... -> a3600712...: every pure
     method's `code_sha256` moves). Both methods keep version 1.0.0 (output shape unchanged). Vectors regenerated (their own commit):
     "public, key revoked before the anchor" now says `key-validity`, two vectors added (bad seal with a revoked key, bad seal
     alone), the envelopes name the new `code_sha256`. Tests: `tests_claim/test_record_keyvalidity.py`. The library pins moved to
     1.6.0 in their own commit. Reversible.
157. **match.screenshot never signs `differs` over an honest screenshot: F 9300 -> 1200, T stays 9500** (DECISIONS BD19, live defect
     on witness-dev, 25 Nov: an honest 1000 x 420 Chromium screenshot of a 45-token page scored 9111 bp, 45 OCR tokens, and was
     signed NOT_SUPPORTED `differs`; reproduced exactly in the live image, `screenshots2/regression/pod_fixture.log`). Decision 74's
     calibration had honest cases at widths 1280 and 390 and forgeries up to 9134, so honest and forged overlapped. The widened set
     (`screenshots2/`, "match.screenshot" above) was measured in pod `claim-screenshot-cal2` from the live image
     `dev-0ce2a6f@sha256:4a091d1b…` (`measured.json` sha256 320b9b44…; the pod was deleted after): honest 1343..10000 (full size
     8955..10000), forgery 1343..9247, other page 468..6250. Rule (BD19): F below every honest screenshot, T above every forgery;
     a forgery between them gets no finding (SPEC: "Otherwise no finding"). F = 1200 (143 bp under 1343), T = 9500 (253 bp over
     9247). Effects on the 72 forgeries: 72 `differs` -> 72 `undecided`, 0 `consistent`; on the 72 honest: 42 `consistent`, 30
     `undecided`, 0 `differs` (before: 42, 7, 23); on the 12 other-page screenshots: 3 `differs`, 9 `undecided`. The regression
     fixture scores 9111 before and after (same OCR) and goes from `differs` to `undecided`. **No OCR change**: `--dpi 300` and
     `--dpi 150` lift nothing (`ocrvar.log`), a scaling step needs an image library the image does not have, so the image is not
     rebuilt for this (match.screenshot's `code_sha256` is unchanged: the image digest). The methods library is **1.7.0**
     because `match_screenshot.py` is in the tarball (`methods_code_sha256` a3600712... -> 0226f2de...: every pure method's
     `code_sha256` moves; match.screenshot stays method 1.0.0, output shape unchanged, `thresholds` in `/v1/methods` now F 1200).
     Vectors regenerated and the library pins moved in their own commits; BD16's "every forgery < F" is replaced by "every forgery
     < T" in `test_match_screenshot_calibration.py` (own commit). Tests: `tests_claim/test_match_screenshot_honest.py`. Open:
     the 0.5 resampled images (text 7 to 9 px) set F; without them F could be ~8600 and 49 of 72 forgeries stay `differs`; that is
     the operator's call. Reversible by recalibrating.
158. **match.screenshot readability gate: an image Tesseract cannot really read is `unreadable`, and F 1200 -> 8700** (DECISIONS BD19
     addendum; brief BRIEF-SC2.md). Decision 157's honest minimum, 1343, came only from full pages resampled to half size, which
     Tesseract barely reads; F 1200 made every one-sentence forgery and a "cat on a sofa" text no finding, which removes the method's
     main use (showing that a faked screenshot does not match the page). SPEC already says "an image Tesseract cannot read:
     unreadable", so those images are gated by a property of the IMAGE's OCR, not by the comparison with the page. Measures tried
     over the 157 images, measured in pod `claim-screenshot-cal3` from the live image (`measured_gate.json`): mean word confidence,
     share of words >= 60, words per megapixel; mean word confidence separates the half-size pages cleanly and is the simplest, so it
     is the one rule: `ocr.Ocr.readability` = mean confidence of Tesseract's `tsv` words x100, `MIN_READABILITY_X100 = 9150`. G scan
     (honest gated of 73 / lowest honest passing / highest F with 250 bp margin): G 0: 0 / 1343 / 1093; 7000: 4 / 7361 / 7111;
     8100: 8 / 8740 / 8490; 9150: 11 / 8955 / 8705 (the gated ones are 8 half-size and 3 three-quarter-size pages, none at scale 1
     or 2); 9400: 16 / 8955 / 8705 (also takes full-size pages and the regression fixture, 9177, so no better). **G = 9150, F =
     8700** (255 bp under 8955), **T = 9500** (253 bp over the highest forgery that passes, 9247; no forgery reaches it). The
     plain-text OCR path is untouched (all 157 texts byte-identical to `measured.json`'s); the second run costs one more Tesseract
     pass per screenshot. Gated: no finding, reason `unreadable`, `detail.readability_x100` and `min_readability_x100`, assertion
     true or false the same. Not gated, evidence without `ocr_readability` (a caller that is not the witness); `None` (the second
     run failed) is `unreadable`. Effects (G 9150, F 8700): honest 42 `consistent` / 19 `undecided` / 11 `unreadable` / 0 `differs`;
     forgeries 42 `differs` / 20 `undecided` / 10 `unreadable` / 0 `consistent` (decision 157: 72 `undecided`); other page 12
     `differs`; the regression fixture stays 9111 bp, readability 9177, `undecided`. Limits, said plainly: the gate is tuned to this
     table (75 points between the highest gated honest image, 9102, and the lowest passing one, 9177; a forgery at 9164 passes the
     gate) and the set is clean Chromium renders, so a real phone screenshot may land either side; F's margin and "no finding" are the
     protection. **The image must be rebuilt**: `ocr.py` and `service.py` are in the image, and match.screenshot's `code_sha256` is the
     image digest, so every change on this branch (including the F constant) needs a new image; the orchestrator builds it. The
     methods library stays **1.7.0** (not deployed anywhere yet, so there is no second tarball under that version):
     `match_screenshot.py` changed, `methods_code_sha256` 0226f2de... -> 575885ea.... Tests: `tests_claim/test_match_screenshot_gate.py`
     (RED `5144f83`); three existing assertions changed in their own commit (`15b9055`, F in `test_edited_text_differs` and the
     calibration constants, and the honest rows of `ConstantsHoldTheTable` are the gate-passing ones); vectors regenerated in their own
     commit (three new vectors for the gate). Reversible by recalibrating; if no gate had given F >= 8000 the result would have been
     F 1200 as built (decision 157).
159. **match.screenshot: gate G 9150 -> 8500, F 8700 -> 8490, T stays 9500** (DECISIONS BD19 addendum 2; brief BRIEF-SC3.md; this is
     an amendment of decision 158, which stays as written for its reasoning). `measured_gate.json` shows every honest image that
     would be `differs` at F 8500 to 8700 has readability <= 8050 (all resampled to 0.5); the next readability up is 8987 (a
     forgery) / 8996 (honest). G 9150 sat 48 and 75 points from honest images on both sides (9102 gated, 9177 = the regression
     fixture passing): a knife edge for any image Tesseract reads a little differently. G 8500 sits about 450 points clear on both
     sides (the highest gated image reads 8050, the lowest passing 8987). With G 8500 the lowest passing honest image scores 8740
     (`b3-honest-full-s75-png`), so **F = 8490** keeps 250 bp under it, and is 465 bp under the lowest clear full-size honest page
     (8955) instead of 255. Cost: one forgery moves from `differs` to `undecided` (41 `differs` instead of 42). A false `differs` is the worst error
     (BD19), so robustness wins. Effects (G 8500, F 8490, T 9500, from `measured_gate_prod.json`, the shipped code run in pod
     `claim-screenshot-cal4` from the live image): honest 42 `consistent` / 23 `undecided` / 8 `unreadable` / 0 `differs`;
     forgeries 41 `differs` / 23 `undecided` / 8 `unreadable` / 0 `consistent`; other page 12 `differs`. Every other rule is
     unchanged (a missing `ocr_readability` is not gated; `None` is `unreadable`). Tests: `RobustGate` in
     `tests_claim/test_match_screenshot_gate.py` (constants, no image of any kind within 400 of G, honest passers >= F + 250, the
     8499 / 8500 edge); vectors move to 8499 (unreadable, assertion true and false) and 8500 (judged). `match_screenshot.py` changed:
     the image must be rebuilt (code_sha256 is the image digest); methods library stays 1.7.0, `methods_code_sha256` recorded in the
     commit message of the vectors commit. Reversible by recalibrating.

### Builder decision, witness-verify reads the anchor transaction (160-; branch v1/claim-seal-chain; DECISIONS BD21)

160. **`witness-verify --rpc URL` reads each base-sepolia anchor transaction** (supersedes decision 81's `SKIP seal-chain`; decision
     81 stays as written for its reasoning). Measured on Base Sepolia: a seal is one transaction to `0x0` from armarium's notary
     account (shared by every armarium user) whose input is the UTF-8 JSON datablock `{"correlationId", "previousChunkBlockId",
     "chunkData", "mode": "hash", "payload": {"label": "claim-witness/batch/1", "over": "sha256:<hex>"}}` (tx 0x7cf24d51..., block
     63379082, 233 bytes; SPEC §6 step 4's `{"over"}` is the payload inside this envelope). The vector is the two JSON-RPC
     answers (`eth_getTransactionByHash`, `eth_getBlockByNumber`) in `tests_claim/fixtures/base-sepolia/`, served by a fake RPC on
     127.0.0.1, so the tests use no network. Rule, per base-sepolia anchor: the transaction exists, is to 0x0, the input decodes as
     that datablock with `mode` "hash" and `payload.over` equal to the notary's `over`, the transaction's block number is the
     anchor's `block`, the block's hash is the transaction's `blockHash`, and the block timestamp equals the anchor's `block_time`
     to the second. Each failure is `FAIL seal-chain` with the reason by name (`not found`, `not to 0x0`, `not a hash-mode
     datablock`, `different over`, `block mismatch`, `time mismatch`, `not a sealer`). An RPC that cannot be reached, times out
     (20 s), is not http(s), answers an error or junk is `FAIL seal-chain` naming the RPC's scheme://host:port (never its path or
     userinfo, which may carry an API key), exit 1: never a PASS. **Sender**: the key list's `sealers` entries for base-sepolia
     (`address`, `valid_from`, `valid_to`) must contain the sender at the block time; `--sealer ADDRESS` (repeatable) is the
     verifier's own list and replaces the key list's. The deployed key list (seq 1) has `sealers: []`, so today the PASS line says
     the sender was not checked against a sealer list; publishing the address needs a signed key list seq 2 (the operator's).
     **Anchor time**: with `--rpc` the time key validity uses is the chain's timestamp of the earliest base-sepolia anchor that
     passed (equal to its `block_time`; a seal whose `block_time` disagrees fails). lab-qbft and any other chain are `SKIP
     seal-chain` naming it as the operator's own chain, and do not turn the result into FAIL. Without `--rpc` nothing changes
     but the sentence of the SKIP, which now names `--rpc`. `verify.py` stays one module, standard library only (urllib), network
     only when `--rpc` is given. Not changed: `claim_witness/methods/` and so the methods tarball and every `code_sha256`.

### Builder decision, the bundle carries the tarball the record names (161-; branch v1/claim-bundle-tarball)

161. **A record's bundle holds the methods tarball its `method.code_sha256` names, from an archive, never today's by default.**
     Measured on 25 Nov: public record b0973af4... (quote.in-source 1.0.0, signed 09:58:49Z) names `code_sha256` 0d691773...
     (library 1.5.0); `Records.bundle` wrote `tarball.build_methods_tarball()`, today's 1.7.0 (1d8b3e75...), so `witness-verify
     --bundle` printed `FAIL methods-tarball`. Every record signed before a methods change was hit, and every record signed today
     is hit at the next one. `verify.py` is not changed: it stays strict, a wrong tarball is still `FAIL methods-tarball`.
     - **The archive** is `claim_witness/methods_archive/`: `<sha256>.tar.gz` per distinct tarball plus `index.json` (`sha256`,
       `library_version`, `commit`, `first_commit_date`). It sits in the package, outside `claim_witness/methods/`, so the current
       tarball and `methods_code_sha256` do not change (the builder reads `methods/` only), and `Dockerfile.claim`'s
       `COPY claim_witness/` carries it into the image with no change to the Dockerfile. `claim_witness/archived.py` reads it and
       checks each file's sha256 on every read: a file that is not the sha256 it is named by counts as absent.
     - **What is in it**: 11 tarballs, every distinct `methods_code_sha256` on the first-parent history of `f99a04e` since
       `claim_witness/tarball.py` existed (f3432fb), enumerated by building each commit whose `methods/` or `tarball.py` tree
       changed with that commit's own builder: libraries 1.0.0, 1.1.0, 1.2.0, 1.3.0, 1.4.0 (two: 678e142 and the calibration
       merge 65cf380), 1.5.0, 1.6.0 and 1.7.0 (three: 007168c, 58940cf, 24fb2a8). **A library version does not identify a
       tarball** (1.4.0 and 1.7.0 each have several), so the archive is keyed by sha256 and only the bundle's file name uses the
       version. Commits on side branches that were never first-parent are not enumerated; a record signed by an image built from
       one of them gets the missing-tarball case below.
     - **Rebuild**: each entry is rebuilt byte-identical from its `commit` by the repo's own builder:
       `python3 tools/archive_methods_tarball.py rebuild <commit> --out FILE` (`git archive` of `claim_witness/` at that commit,
       then `tarball.build_methods_tarball()` of that commit, `python -I`); `... check` does it for every entry; `... add [commit]`
       archives a commit's tarball. A methods change is archived in the next commit with `add`, naming the commit that carries
       it.
     - **A new methods change cannot ship unarchived**: `tests_claim/test_methods_archive.py` fails unless
       `tarball.methods_code_sha256()` is in the index with the same bytes. The tests also walk the archive (each file is the
       sha256 it is named by, the library version inside is the index's, no file outside the index) and rebuild every entry from
       its commit (skipped, saying so, when the commit is not in the clone).
     - **The bundle**: the record's `method.code_sha256` is read from its envelope (public or private: the envelope names the
       method either way). Equal to the current build: the current tarball, `witness-methods-<version>.tar.gz`, as before.
       In the archive: that tarball, named `witness-methods-<its library version>.tar.gz`. Not a methods tarball
       (`match.screenshot`: the image digest; the method is not `pure`): the current tarball, as before. Anything else: **no
       tarball**, and `witness-methods-missing.txt` names the sha256. witness-verify (which globs `witness-methods-*.tar.gz`)
       then prints `SKIP method-rerun: no methods tarball given (--methods); the record names methods tarball sha256 <sha256>`,
       never `FAIL methods-tarball`, never `PASS` (the SKIP names the sha256 since holdout BT-08, 25 Nov; the note file names it too).
     - `GET /v1/methods` is unchanged: the current library only. Not changed: `claim_witness/methods/` (so the current tarball and
       every `code_sha256`), `verify.py`, any method's behaviour. The deployed image must be rebuilt for the archive to be served;
       until then the old bundle code runs.

### Builder decisions, own model key (162-; branch v1/claim-own-key; DESIGN M-20261126-CLAIMS-DOCS-BYOK C1 witness part, C2)

Where the design left a choice open, the reading that keeps the key private and the public chain untouched was taken.

162. **Tests.** RED first (`3b54dee`: `tests_claim/test_own_key.py`, `test_own_key_pg.py`; 50 of 51 failing on f4a56a7, the one
     passing being "the witness's own key refused is not model-key-rejected", today's behaviour). One test fix in its own commit
     (`6cfc057`, no rule loosened: a clock step between two captures, and the B3 tick that notarizes twice). Test fakes gained
     what the tests need: `fake_models` accepts or refuses extra keys (`accepted_keys`, `key_answers`) and serves a whole
     completion object; `FakeNotary` takes a `profile` and `chains`; `HttpsNotary` a `chain`. The migration-list tests and
     `test_sealer`'s header key set changed in the RED commit.
163. **The header is one token.** `X-Witness-Model-Key` is stripped and must be 1 to 4,096 printable ASCII characters with no
     space; empty or malformed is `model-key-missing` (the value is never echoed). It is read on `POST /v1/witness` and
     `POST /v1/observe` only, and only used with billing own-key. The witness does not check the `sk-or-` shape: the BFF does,
     and a standalone backend may use another.
164. **`/v1/observe` takes `options: {billing}` only**, with the same rules (an unknown option is `invalid-options`, the header is
     required with billing own-key although an observation calls no model; the key is then neither used nor kept).
165. **`model-key-rejected` needs every run refused** with 401, 402 or 403; the detail names the first run's status. Some runs
     refused and others failing otherwise (5xx, timeout) or answering: a record as today, with the failed runs noted. No model
     run at all (unreadable, too large, a hard injection flag, untrusted evidence): a record as today, the key unused. A paid
     check whose configured key is refused is unchanged (failed runs, a record).
166. **Scrubbing.** In own-key mode every string in a provider's answer (message content, `model`, `provider`, the whole object)
     has the key replaced by `[model-key]` before anything parses, hashes, signs or keeps it, so `raw_output_sha256` is the hash
     of the scrubbed text. Error bodies are never read, only their status. `Prepared` has a `repr` without the key.
167. **Own-key price lines** are the paid lines with `credits: 0` (the `check` line stays, at 0), plus `paid_by: "own-key"` on
     model-run lines; the observation fields (`fresh_observations`, `reused_observations`, `free_left_today`) stay.
168. **The observation allowance is checked up front, worst case**: an own-key check needs one fresh fetch per url item
     (`page.live` two, for its confirmation); `/v1/observe` one, even when `max_age` might reuse. Past the allowance: 402 before
     anything is fetched or signed; checked again before each fresh fetch. The counter is the account's existing daily one
     (paid fresh fetches count too). The detail names the configured number (50 by default, the design's sentence).
169. **Reuse across tiers.** A public-tier request never reuses an own-tier observation (its seal is on OneDroid's chain only);
     an own-key request may reuse a public one. An observe answer's `anchoring` is the observation's own tier, so a reused public
     observation says `public` even to an own-key request. (A paid and an own-key capture of the same page in the same second are
     the same payload; the log then holds it twice, and `log_tier` and the seal answer for the first row.)
170. **The object-only idempotency fingerprint includes billing**, so a paid answer is never served for an own-key request and
     back (different tier, price and anchoring). Idempotency-Key repeats return the first answer as before (the body, billing
     included, is in `request_sha256`).
171. **The tier travels in the sign request** (`"tier"`, sent only when not public). The signer refuses an unknown tier and a
     batch header whose `anchoring` is not its tier, logs the tier and echoes it; the API refuses (503, signer-unavailable) an
     answer that does not echo the tier it asked for, so a signer without tiers can never log an own row as public unnoticed.
172. **A batch header's own leaf takes the batch's tier**, so the header of an own batch is sealed in the next own batch, never
     in a public one: nothing from an own-key check reaches base-sepolia, not even a header hash. Each tick closes public batches
     first, then own; headers signed in the tick wait for the next one, as before.
173. **Every new header carries `anchoring`**, public ones too (signed). `sealer.header_of` adds it only when given, so the B3
     seal vectors are unchanged; witness-verify never checked the header's key set, so older verifiers verify the new headers.
174. **`WITNESS_NOTARY_OWN_PROFILE`**: unset means `hash/1-own` (the design's default); empty or `off` means no own profile (own
     batches close unanchored); `hash/1` is refused at start like any other bad notary setting. `WITNESS_NOTARY_OWN_TOKEN_FILE` is
     required: unset, empty or not mounted means no own client (own batches close unanchored), never the public notary token
     (fixed 26 Nov after the own-key holdout's PROBE-own-token-unset; before, it fell back to the notary token). The sealer uses
     the own client only when its `profile` is not hash/1 (a client without one counts as hash/1) and it is not the public client.
     The k8s manifest is unchanged: on dev the own profile is `hash/1-own` with the witness's notary token.
175. **The own-chain guard is in the sealer** (it holds for any notary client): any anchor on a chain other than lab-qbft, or an
     answer for profile hash/1, makes the result `failed` with no anchors kept and a reason naming the chain(s); the batch stays
     pending and is asked again each tick with the own client. `HttpNotary` also refuses a 200 for another profile than the one
     it asked for.
176. **Unanchored own batches** (no own client) are `unanchored` with `notary.status: off`, as public batches without a notary.
     An own batch left pending when the own profile is later removed stays pending and is sent nowhere.
177. **`anchoring` is reported, not signed into the record**: check answers and job answers (stored with the answer; an answer
     stored before this change reads as public), `POST /v1/observe` answers, and `GET /v1/records/{id}` (from the signing log's
     tier). The keep answer, the seal route and the bundle are unchanged; the seal's signed header carries it.
178. **witness-verify** prints the INFO line whenever the header says own (pending or anchored seal), FAILs `seal` for a
     base-sepolia anchor in any state on an own header (the RPC is then never asked), and FAILs `seal` for an `anchoring` that is
     neither public nor own.
179. **Migration `008_signing_log_tier.sql`** (`ADD COLUMN IF NOT EXISTS tier ... DEFAULT 'public' CHECK`, plus an index for
     pending leaves per tier). 006 stays free (left for B5b, which needed none).
180. **Not changed**: `claim_witness/methods/` (methods tarball `1d8b3e75...` and every `code_sha256` as before), the existing
     vectors (own-seal vectors are added in their own commit), `/.well-known/witness.json`, keep, the graph, search and n-dim.
181. **Own-seal vectors** (`own_seal` in `vectors.json`, its own commit): a batch of the stored public vector record and two
     fillers under a signed header with `anchoring: "own"`, a fixed hash/1-own notary result on lab-qbft only, the seal that
     witness-verify must pass with the INFO line and no FAIL, and the same seal with a base-sepolia anchor added, which it must
     `FAIL seal` naming base-sepolia. The key was added to the stored file without regenerating the rest (every existing key is
     byte-identical): `generate()` here reproduces the stored envelopes only up to their `method.runtime` (the file was written
     on python3.14, this venv is 3.12), so the own seal is built over the stored record, as `--check` pairs them.

### Builder decisions, ranked models, decision models, any OpenRouter model (182-; branch feat/witness-models; DESIGN M-20261127-WITNESS-MODELS WM-1..WM-4, WM-7 witness part)

182. **Tests.** RED first (`5f490f4`: `tests_claim/test_witness_models.py`, plus the existing tests the design moves:
     `models_option` names the shape and takes count 1..5, `select_models` is rank order, `options_used.models` names the shape
     and the ids, the public model entry gains `rank`, `kind`, `rank_note`, the library pins move to 1.8.0; 60 failing on
     626a490 + RED). Two test changes in their own commits: the record's probabilities are basis points (`probabilities_bp`:
     a signed record is RFC 8785 with integers only and the signer refuses floats), and a private record's `options_used`
     names no model id (RED had put them there, against the same test's rule that model ids are in the body only). The fake
     (`tests_claim/fake_models.py`) gained `POST /alpha/decisions`, `GET /v1/models` and `usage.cost` per model.
183. **The list (WM-1).** `{id, vendor, price_factor, timeout}` plus optional `kind` (`chat` default, `decision`) and
     `rank_note` (1 to 200 characters); at most 5; the order is the rank. The live ConfigMap (three entries, no `kind`) loads
     unchanged as three chat models ranked in their order. `GET /v1/models` is public (no key), lists `{rank, id, vendor, kind,
     price_factor, credits_per_run, timeout_s, rank_note}` and states the selection shapes and the two price rules; `GET
     /v1/methods` and `GET /v1/price` carry the same entries in `models`. Without a configured judge `models` is `[]` and
     `served: false`.
184. **Selection (WM-3).** `{count}` takes the top `count` in rank order: BD2's one-per-vendor reordering is dropped
     (Michal: "called in that order"), so `{count: 2}` on today's list is still gpt-4.1-mini then gemini-2.5-flash-lite, but
     a list with two models of one vendor at ranks 1 and 2 now calls both. `{ids}` keeps the order given (the record's
     `models`, `runs` and the price lines follow it). `max_credits_per_run` belongs to the `{ids}` shape only (it bounds
     unlisted runs; with `{count}` it is 422). A wrong shape is 422 `invalid-request` (the design's code) with a detail
     naming both shapes; more models than listed stays 422 `invalid-options` as before. Unlisted ids are checked with
     `check_unlisted_id` (the regex, `refuse_routers`, `openrouter/...`) before the catalogue is read, so a router or an alias
     costs no network call. `options_used.models` is `{shape: "count", count, require, ids}` or `{shape: "ids", ids, require,
     max_credits_per_run}`; in a private record the ids are left out (with `count` kept), because `options_used` is in the
     public part and a private record names its models in its body only.
185. **The catalogue.** `GET <base>/models` (`https://openrouter.ai/api/v1/models`), no Authorization header (it is public),
     at most 32 MiB, cached 1 h in the process. An entry is usable when `pricing.prompt` and `pricing.completion` are numbers
     >= 0 (OpenRouter writes strings; `-1` is how it lists a router such as `typesafe/jev-router`): otherwise, or when the id
     is absent, 422 `unknown-model`. An unreadable catalogue is 503 `model-catalogue-unavailable`. A request naming listed ids
     only never reads it. Unlisted models get timeout 60 s and vendor = the id's prefix.
186. **Decision models (WM-2).** The rule is in `claim_witness/methods/judge_supports.py` (`decision_questions`,
     `decision_questions_sha256`, `decision_run`, and `decide()` accepts a decision answer), so anyone can re-decide from a
     stored answer with the tarball. The request body is exactly `{model, state, questions}` (no `provider`, `user` or
     `session_id`), mirroring trilix's `decision_probe.py` (`Runner.call`, body at line 66; fields read at lines 93-99:
     `answers`, `provider`, `model`, `usage.cost`) and the docs. `state` is the chat input (`build_input`), so the injection
     gates and the datamarking are the same for both kinds. The verdict is the argmax of `probabilities` (the `choice` field is
     recorded nowhere and never decides; a tie is silent); kept when `confidence` >= 0.8, or the argmax probability >= 0.8 when
     the answer has no `confidence` (12 Nov finding 18: "confidence from the choice confidence at >= 0.8"); else judged-silent
     with note `below-confidence`. Probabilities outside 0..1, options outside supports/contradicts/silent, a missing
     `verdict` or `probabilities`, or a refusal answer are `wrong-shape` (undecided). The question set's sha256 hashes the
     questions and the threshold (sorted compact JSON): `c02db1e5f56227ea864c92121570b866d5bde0cd578acab164096f84d66c5d7f`.
     Decision runs give no quotes, so "a positive finding needs a verified quote" (VR-7) applies to chat runs only. A chat
     model's request, record entries and raw output are unchanged.
187. **Price (WM-4).** Listed: `ceil(10 x price_factor)` as before. Unlisted: `min(ceil(usage.cost / 0.001) + 2,
     max_credits_per_run)` in decimal arithmetic. The estimate is `prompt tokens x pricing.prompt + max_tokens x
     pricing.completion (+ pricing.request)`, rounded up to US$0.001, + 2; prompt tokens are judge_supports' own estimate
     (ceil(characters / 4) of the prompt and the input; for a decision model the input and the question set). It is checked
     after the injection gates and before any model is called; over the cap the whole request is 422 `model-over-cap`
     (detail: the model, the estimate in credits, the cap), nothing signed, nothing charged, no attempt counted, listed
     models of the same request not called either. Choices the design left open: a failed unlisted call (timeout, HTTP error)
     costs the run fee only; an answer without `usage.cost` costs the estimate, capped. Own key: the cap is not applied
     (OneDroid charges only the run fee, 2 credits, per unlisted run; the model cost is on the user's key), listed runs stay 0,
     so an own-key price can now be above 0.
188. **Library 1.7.0 -> 1.8.0**, judge.supports stays method 1.0.0 (a chat run's output shape is unchanged; decision runs
     are new entries). `methods_code_sha256` 1d8b3e75... -> 8db0f509aca57b3a840ba7a42c9fcf7e5c6b060d13bdcf87302805bedd9913d3
     (every pure method's `code_sha256` moves with it). The library pins moved in the RED commit. The vectors were regenerated
     with `python3 -m claim_witness.vectors --write` on python3.14 (the stored runtime), in the GREEN commit: only the
     envelopes, the record_methods records over them and the two seals change; `--check` passes on 3.12 and 3.14. The new
     tarball is archived in the next commit (`tools/archive_methods_tarball.py add <GREEN commit>`), as decision 161 requires.
     The image must be rebuilt and the BFF (WM-5) and MCP/site (WM-6) follow separately.
189. **Not changed:** the chat prompt, the injection rules, BD13 quote verification, the own-key key handling, the k8s
     manifest (the example list is `k8s/claim-witness-judge-models.example.json`, not applied), migrations, `/.well-known`.

### Builder decisions, the evidence's word is not evidence (190-; branch feat/witness-reliance; M-20261127-WITNESS-MODELS BRIEF-W2)

190. **The defect and the rule.** Measured on a sealed set: when the only support for a claim is text inside the evidence
     that vouches for itself or asks the reader to rely on it (a self-report standing in for lost or "unneeded" output; a
     proxy, another environment, file or version, said by itself to be the claimed thing; a stand-in, a skipped test, a TODO,
     a ticket, said to count as the result), most chat models answered judged-supports. The right finding is judged-silent;
     when the evidence also shows the fact, the vouching text changes nothing. These passages are addressed to a human, not to
     a model, so the hard gate does not and must not stop them. Tests first: `49d34ba` ("test change:", the version pins only)
     and RED `25c4360` (`tests_claim/test_witness_reliance.py`, 32 tests, 26 failing at RED).
     - **The prompt** (`judge.supports-1.1.0.txt`, Rules) gains three bullets: evidence must show the fact, not ask to be
       believed; a passage that asserts the statement while it vouches for itself, vouches for a stand-in, or asks the reader
       to rely on it, accept it without checking or treat it as proof is not evidence, and with nothing else, the answer is
       judged-silent; evidence about a different thing (another environment, server, file, version, branch or build) shows the
       thing named only when the evidence itself shows the two are the same; a shown fact still decides.
     - **Decision models** get the same rule in `DECISION_INSTRUCTIONS`, and the `supports` criterion says a passage that only
       vouches does not count. `decision_questions_sha256` moves c02db1e5... (decision 186) ->
       `155faba32a80ba285e948857bf433c3fab3e8a5de2a01bafef0737ffa23bb59b`.
     - **The soft flag** `reliance-request` (`judge_supports.RELIANCE`, case-insensitive, one compiled pattern of 23 branches
       in seven families: someone's word or assurance; asked to trust or rely on the author or this passage; no checking
       needed; this passage is to be relied on; counts or serves as proof or as done; a stand-in for the output; a different
       thing said to be the same so its results apply). Each branch needs a self-reference, an addressee or a proof word, so
       "reliable", "relies on the cache", "dependency", "trust store", "treat warnings as errors", "check out a branch" stay
       quiet (tested on 21 ordinary texts; 20 reliance phrasings in other words than the code's examples fire). Recorded in
       `injection_flags` (soft) and `detail.injection_soft`, counted in the new `detail.reliance_requests`; never a stop.
     - **The one decision change**: a chat run's judged-supports whose every verified quote lies inside a reliance line (a
       line of the visible text holding a reliance request; `reliance_lines`) is judged-silent, quotes [], run note
       `reliance-only`. A support with any quote on another line (the real output) stands; contradicted and silent runs are
       untouched; nothing moves toward judged-supports. Decision runs give no quotes, so they rely on the question text alone.
       Why lines and not the whole item: a CI log or a page that shows the fact can carry such a sentence too, and the brief's
       rule is "decide on what is shown"; a self-report and its vouching on separate lines is left to the prompt (the flag is
       still recorded for the reader). The check is in `judge_run`, so the witness (`judge.py`) and the vectors replay apply
       the same rule.
191. **Versions.** judge.supports method **1.0.0 -> 1.1.0** (minor: same claim shape, `method_major` 1, same output shape):
     decision 63 kept 1.0.0 only because the prompt did not change, and the record's `rubric_version` is the method version,
     so a changed rubric under the old number would mislead a verifier. The prompt file is renamed to
     `judge.supports-1.1.0.txt` (old prompt bytes stay in the archived tarballs); `prompt_sha256` 5950996a... ->
     `78fc2b6ec04e9fbbc43c5142e5540f8fbe8e27e95f2044969954c88f863f31d3`. Library **1.8.0 -> 1.9.0**: 1.8.0 was never deployed
     (decision 188), but its tarball 8db0f509... is already archived and on a branch others built from, so reusing the name
     would make `witness-methods-1.8.0.tar.gz` name two tarballs. `methods_code_sha256` 8db0f509... ->
     `518c3fe1da5ade591d51fa27165526fcbb2428ea7c6fcc815ca8596967988140`. The vectors were regenerated with
     `python3 -m claim_witness.vectors --write` on python3.14: every earlier judge vector decides as before (only
     `input_tokens_est`, the new `detail.reliance_requests` and the prompt sha256 move), two judge vectors are added (a support
     quoting only the reliance line -> judged-silent `reliance-only`; the same text with the fact on its own line -> supports);
     `--check` passes on 3.12 and 3.14. The tarball is archived in the next commit (decision 161).
192. **Not changed:** the hard injection rules and their order, BD13 quote verification, the agreement rule, the price, the
     decision threshold, the model list and selection, the k8s manifest, migrations. The image must be rebuilt, and anything
     downstream that names library 1.8.0 or judge.supports 1.0.0 (BFF WM-5, MCP/site WM-6) follows separately.

### Builder decision, a per-model reasoning setting (193; branch feat/witness-reasoning from 5634748; BRIEF-W3)

193. **`"reasoning": false` in the model list.** Measured live 27 Nov: reasoning models (anthropic/claude-haiku-5.5,
     qwen/qwen3.7-flash, deepseek/deepseek-v4-flash-0731) answer HTTP 200 with empty content under `max_tokens` 1024, because
     the hidden reasoning uses the whole budget, and the call is still charged. OpenRouter's request field
     `"reasoning": {"enabled": false}` makes them answer (haiku 28/36 against 16/36). Some models refuse that field
     (z-ai/glm-5.3-flash answers 400), so it is a per-model setting, never global. The rule:
     - a list entry may carry `"reasoning": false`. Absent, the request is what it was before, byte for byte. False: every
       chat call to that model adds `"reasoning": {"enabled": false}` as the body's last key, and nothing else in the body
       changes. Any other value (`true`, a string, an object, `0`, `null`) is refused when the list is loaded (ValueError
       naming `reasoning`), and so is the field on a `decision` entry: the Decisions API body stays `{model, state, questions}`;
     - `GET /v1/models`, `/v1/price` and `/v1/methods` list it as `"reasoning": false` on that entry only; other entries
       carry no `reasoning` key, as before;
     - an empty answer (200 with empty, whitespace-only or missing content) is unchanged: run note `no-content`, no finding,
       and the run still counts for the price (a listed run its `ceil(10 x price_factor)`, an unlisted one its reported
       `usage.cost`). `tests_claim/test_witness_reasoning.py` pins it;
     - **unlisted ids** (`{ids}` shape, any plain OpenRouter model id) are not affected: no `reasoning` field is sent for
       them, unless a later decision says otherwise. A caller who needs it for a reasoning model asks for it to be listed;
     - the signed record is unchanged: `judgment.sampling` stays `{temperature, max_tokens}` and does not name the reasoning
       setting (a reader finds it on `GET /v1/models`). Whether the record should carry it is left to a later decision.

     **Not changed:** `claim_witness/methods/` and the methods library version (1.9.0, tarball `518c3fe1...`): the change is
     in `claim_witness/judge.py`, which the methods tarball does not ship (`claim_witness/tarball.py` packs only
     `METHODS_DIR = claim_witness/methods`, files ending `.py` or `.txt`). The prompt, the injection rules, quote
     verification, the agreement rule, the price, the decision threshold, selection, the k8s manifest and migrations are
     unchanged. Turning the setting on for a live model is a ConfigMap change, and the image must be rebuilt first.

## NS-4A: browse (subjects, keywords, categories)

Branch `feat/witness-browse` from `68d4706` (M-20261127-NAME-SITE, NS-3-SPEC.md sections 2-4, 7, 9). `claim_witness/methods/` is
not touched, so every `code_sha256` and the methods library (1.9.0) are unchanged. Migration `009_browse.sql`; code
`claim_witness/browse.py`, `claim_witness/unlisted_seed.py`; storage methods on both backends; hooks in `records.keep`,
`records.takedown`, `search.query` and the start-up backfill; tests `tests_claim/test_browse.py` and `test_browse_pg.py`.

**Listed.** A record is listed iff it is public, kept, not taken down, not deleted and not in `unlisted_records`. Every browse
list, count and existence test, and the browse filters of `/v1/search`, use listed records only, joined at query time (no stored
count). `unlisted_records` starts with the 28 test record ids of the site's `lib/agent/seo-exclude.ts`.

**Routes** (all GET, public; an `Authorization`, `X-Witness-Account` or signature header is never read, so every reader gets the
same bytes; an unknown parameter or a bad value is `422 invalid-request`; `limit` 1-100, default 50; `offset` 0-10000;
`next_offset` is null at the end; no list carries a total):

| route | query | 200 answer |
|---|---|---|
| `/v1/browse/subjects` | `kind` (required: `page`, `site`, `profile`), `parent` (a sid, with `kind=page` only), `prefix` (`a`-`z` or `other`, on the first character of `display` after a leading `@`), `limit`, `offset` | `{subjects: [Subject], next_offset}` in `display` order, then `sid` |
| `/v1/browse/subjects/{sid}` | none | `{subject: Subject, parent: SubjectRef or null, children, types: [{value, records}]}`; 404 unknown or no listed record; 422 a malformed sid |
| `/v1/browse/keywords` | `sort` (`alpha` default, `records`: records desc then word), `prefix`, `limit`, `offset` | `{keywords: [{word, records, last_witnessed_at}], next_offset}`, listed keywords only |
| `/v1/browse/keywords/{word}` | none | `{keyword, subjects}` (subjects: the number of sites and profiles with these records); 301 with `Location: /v1/browse/keywords/<canonical>` and `{canonical}` when the path word is not in canonical form (NFKC, casefold); 404 not listed |
| `/v1/browse/categories` | none | `{facets: [{facet: "type", values}, {facet: "method", values}]}`, each value `{facet, value, label, records}` with records >= 1 |
| `/v1/browse/records/{id}` | none | `{record_id, type, subjects: [SubjectRef], keywords (listed only), method}`; 404 private, unknown or unlisted; 410 taken down |
| `POST /v1/records/{id}/unlist` | body `{}` or `{reason?}` (not stored) | an operator account only (`WITNESS_OPERATOR_ACCOUNTS`; anyone else 403 `not-operator`): `{record_id, unlisted: true, at, reason, note}`; the same answer again; 404 not kept |
| `/v1/search` (B7) | adds `subject` (sid), `keyword` (word), `type` (one of the six types) | hits gain `type` (null when not listed) and `subjects` ([] then); with any of the three only listed records match, ANDed with the other filters; without them the answer is as before |

`Subject = {sid, kind, key, display, platform, parent_sid, href, records, counts: {SUPPORTED, NOT_SUPPORTED, CANNOT_WITNESS},
first_witnessed_at, last_witnessed_at}`; `SubjectRef = {sid, kind, key, display, platform, parent_sid}`. `href` (pages only) is
the URL as the most recent listed record wrote it, userinfo removed. Types: `record`, `test-run`, `social-post`,
`social-profile`, `web-page`, `document`.

`WITNESS_KEYWORD_DENYLIST_FILE` (optional): one word a line, `#` comments; a denylisted word is never a candidate at index time,
never listed and never shown, whatever its count.

### Builder decisions, NS-4A browse (194-)

194. **Computed in the witness at keep time, counted at query time** (spec P1). `browse.index` runs in `records.keep` beside
     `search.index` for a public record only (a failure is logged and the keep stands; the start-up backfill writes the rows of
     any public kept record that has none); `browse.remove` runs in `records.takedown` beside `search.remove`, in the same
     request. Reads take one snapshot of the listed records' rows (one Postgres transaction) and aggregate in Python, so a list,
     a count and an existence test can never disagree or go stale. This reads every listed row per request: right for today's
     tens of records, and the place to add SQL aggregation when the record count grows (materialised counts are out of scope).
195. **canon is Table 1 applied to a fixed point** (V2). Table 1 says "remove ONE leading `www.`" and "strip ONE trailing `/`",
     but with exactly one removal `canon("https://" + canon(u))` changes `www.www.ex.com` and `/a//` again, which V2 forbids.
     The rule is applied until nothing changes (`www.www.ex.com` -> `ex.com`, `/a//` -> `/a`); every Table 1 example gives its
     output. Percent escapes are normalised before dot segments are removed, so `%2E` segments are dot segments (WHATWG).
     Query: a pair with an empty key and an empty value is dropped; `+` is a space and is written `%20`; tracking keys are
     compared case-insensitively after decoding. IDNA uses the standard library (`encodings.idna`, nameprep), not a UTS-46
     package: the image adds no dependency; for ordinary IDNs (`BÜCHER.de` -> `xn--bcher-kva.de`) the result is the same.
     **Path case is kept** (Table 1 step 6 keeps `C`): the spec's fixture R1 `https://WWW.Example.COM:443/About/...` therefore
     makes `example.com/About?a=1&b=2`, not R2's `example.com/about?a=1&b=2` as S1 says. The tests use `/about/` for R1 so S1,
     S30, S40 and S41 test what they mean; the spec's R1 line is a typo against its own Table 1, flagged to the orchestrator.
196. **Table 2 details.** Aliases map to the main host for both the page and the profile (`twitter.com/ExampleCo/status/42` ->
     page `x.com/exampleco/status/42`, profile `x.com/exampleco`). The profile segments of a page key are written as the profile
     key writes them (handle or name lower-cased; a bsky DID kept as written). Any path under a derivable profile is a page with
     that parent (x, github, linkedin, youtube, tiktok, bsky); instagram and facebook profiles are one-segment paths only, and
     a deeper path (and `/p/`, `/reel/`) has no parent. A platform host with a port is an ordinary host. Profile display:
     `@name on Bluesky|X|Instagram`, `name on GitHub|LinkedIn|Facebook`, `@name on YouTube|TikTok` (the `@` is the name's own).
197. **post.by-author's page hangs under the handle's profile** (V8, S8): on bsky.app the profile is
     `bsky.app/profile/{params.handle lower-cased}` and the post page's `parent_sid` is that profile, not the DID profile the URL
     would give; no DID profile subject is written. A subject's `parent_sid` is first-write-wins (`ON CONFLICT DO NOTHING`).
198. **The page cap (V1) counts distinct page URLs**: a record's rows hold up to 5 pages plus their parents. Rows keep the
     record's own order in a `pos` column on `record_subjects` and `record_keywords` (an addition to the spec's columns), so a
     record's subjects are listed page then parent, in evidence order, and its keywords in source order.
199. **record.valid inherits, record.disclose discloses** (V13). record.valid copies the rows of the record it checks when that
     record is listed at index time; when that record is taken down or unlisted, every record.valid that checks it is
     re-indexed in the same request (and has no subject). record.disclose runs Table 3 over the disclosed body, its keywords
     from the body's quote and statement; its observations are private and give no subject (V12). Both are type `record`.
200. **Keyword sources skip a profile's handle** (3.2 "Never: ... handles"): the URL text a keyword may come from is the path
     past the profile segments plus the query values, so `bsky.app/profile/did:plc:abc123/post/3kxyz` gives no `profile`,
     `plc` or handle word. The stop list is the NLTK English list (179 words), the URL-noise list and every word of every
     method template with its `{fields}` removed, built from `methods.METHODS` at import.
201. **Types** (V23): `social-post` is a platform page that is not the profile URL itself (and instagram `/p/`, `/reel/`, x
     `/i/status/`); `social-profile` a platform page whose key is its profile's key; a platform page with no parent (`x.com/search`)
     is `web-page`. Category labels are singular ("Web page"); method labels are the method ids.
202. **`/v1/search` filters**: `keyword` matches only a listed keyword (a word one account alone used, or a denylisted one,
     matches nothing); a malformed `subject`, an unknown `type`, an empty or over-128-byte `keyword` is 422. Hits of records that
     are not listed (private, test ids) carry `type: null, subjects: []`. The other search parameters keep their B7 behaviour
     (unknown parameters are still ignored there).
203. **unlist** is operator-only, idempotent and needs a kept record (404 otherwise); an unlisted record keeps its own page,
     bundle and seal. There is no route to list a record again: that is a database operation for the operator.

## NS-11: match.image-text (an image shows a given text)

Branch `feat/witness-image-text` from `09930bb` (M-20261127-NAME-SITE, BRIEF-NS-11-OCR; Michal, 27 Nov, Slack
C0CDYK0D6KW/1795817936.145609: "build match.image-text: yes, build"). Code: `claim_witness/methods/match_image_text.py` (pure,
in the tarball), `claim_witness/transcribe.py` (the model call), `service.py` (`_image_text_checks`, `_image_text`),
`verify.py` (`rerun_image_text`); tests `tests_claim/test_match_image_text.py`; example list
`k8s/claim-witness-image-text-models.example.json`.

- **Claim**: `{"method": "match.image-text", "method_major": 1, "params": {"text": "<the claimed block>"}, "assertion":
  true|false, "statement": null}`. `text` is 1 to 20,000 characters of NFC text (newlines and tabs allowed, no other control
  characters). **Slot `image`**: exactly one object, `image/png`, `image/jpeg` or `image/webp`, whose bytes start as that
  format (PNG signature, JPEG SOI, RIFF....WEBP), at most the witness's object limit (20 MiB, like match.screenshot). An image
  is refused on a public claim (VR-21, `media-not-allowed`), so every record of this method is private.
- **T**: "The submitted image {sha} shows the text with sha256 {text_sha256}." **F**: "The submitted image {sha} does not show
  the text with sha256 {text_sha256}." (`text_sha256` = sha256 of `params.text` in UTF-8: the block itself can be 20,000
  characters, the statement names it by hash.) **Limits**: "A vision model only transcribed the image; the witness compared
  that transcription with the text by rule R1 (a missing number or date, or three missing words, differs). The pixels were
  not proven: an image can be edited, and a model can misread one."
- **The model only transcribes.** The witness sends one user message: the OCR eval's fixed prompt (`match_image_text.PROMPT`,
  byte for byte `eval_vision.py`'s, sha256 `c57f8c28c99b4a6993916248ee15026cdc2fe47cafd4c08021c5b91067093600`) and the image
  as a data URL; the eval's request shape (`temperature` 0, `max_tokens` 8192, `usage: {include: true}`), and
  `"reasoning": {"enabled": false}` last for an entry listed with `"reasoning": false`. It never sends the claimed text, the
  claim, the account or the options.
- **Rule R1** (the eval's `orch_strict_score.py`, ported unchanged, with a parity test against a restated copy of the eval's
  code): both sides through canon/1 `normalise`, split into tokens; a block token is covered when difflib's matching blocks of
  (block, transcription) cover it (in order, autojunk off); `missing` = the uncovered block tokens, `missing_numbers` = those
  holding a digit or being a month name (after stripping `. , ; : ( )`, lower-cased). **differs iff missing_numbers >= 1 or
  missing >= 3**, else consistent. Extra text in the image around the block does not count against it.
- **Findings**: `consistent` (+) and `differs` (−), so SUPPORTED / NOT_SUPPORTED by the outcome table. No finding
  (CANNOT_WITNESS): `unreadable` (every model answered empty, or the transcription has no readable token, or more than half of
  its tokens are `[illegible]`: a property of the reading only, never of the claimed text), `model-unavailable` (every model
  of the list failed: timeout, HTTP error, wrong shape), `too-large` (over 50,000 tokens, or the model stopped at its token
  budget, `finish_reason: length`, and R1 would say `differs`: what is missing may lie past the cut; a cut transcription that
  still covers the block stays `consistent`).
- **The record.** `detail` (in the private payload too) holds integers and enums only: `{rule: "R1", text_tokens,
  transcription_tokens, missing, missing_numbers, truncated}` (`{transcription: "failed"}` when every model failed). The body
  (the disclosure) adds `judgment`: `{kind: "transcription", prompt_sha256, sampling: {temperature, max_tokens}, served: {id,
  provider, version, rank} | null, runs: [{model, rank, note, status, finish_reason}], transcription, transcription_sha256,
  truncated, rule, text_sha256, missing_tokens, missing_number_tokens}`, so anyone can re-run R1 and see which model read the
  image. `method.code_sha256` is the methods tarball (the method is `pure`: R1 ships in it), `determinism` is `model`.
- **The models** (`WITNESS_IMAGE_TEXT_MODELS_FILE`, with the judge's `WITNESS_JUDGE_BASE_URL` and `WITNESS_JUDGE_API_KEY_FILE`;
  `WITNESS_IMAGE_TEXT_MAX_TOKENS`, default 8192): an ordered list of 1 to 5 `{id, vendor, timeout, reasoning?: false,
  rank_note?}`; routers, aliases, variants and free tiers are refused as in the judge list. They are tried in order and the
  first that answers with text is used; an empty answer, a timeout or an error moves on. The example list is the eval's best
  three: `bytedance-seed/seed-2.0-mini` (reasoning off), `anthropic/claude-haiku-5.5` (reasoning off),
  `google/gemma-4-31b-it`. Without the list the method answers 503 `transcriber-not-configured` and signs nothing.
- **Privacy**: the image is read by a model provider, so a (private) claim needs `options.allow_provider: true`, else 422
  `provider-not-allowed`, as judge.supports' §5.7. With billing own-key the user's key reads the image; a key refused on every
  run (401, 402, 403) is 422 `model-key-rejected` with nothing signed.
- **Price**: the house rule for a mechanical check over objects, one `check` line (1 credit); the transcription is part of
  the check, its model runs are not billed apart (the eval's transcriptions cost US$0.0001 to US$0.0007 each, under one
  credit's US$0.001 even when all three models are tried). Own key: the check costs 0, like every own-key mechanical check.
  `GET /v1/price` lists `image_text: {method, credits, rule, models}`; `GET /v1/methods` lists the method with
  `prompt_sha256`, `rule`, `media_types`, `models` and `served`.
- **witness-verify** re-runs R1 offline from the tarball over the disclosed body's transcription: `PASS transcription-sha256`
  (the text is the sha256 the record names), `PASS transcription-prompt` (the record's prompt is the tarball's), `SKIP
  transcription-rerun` (the model's reading is not re-run: it needs the model), `PASS method-rerun: match.image-text 1.0.0
  re-ran R1 over the recorded transcription to <finding or reason>` (finding, reason, outcome, detail, statement, limits and the
  missing tokens must all match). Without the disclosure: `SKIP method-rerun: private record and no disclosure given`.

**The evidence behind it** (M-20261127-WITNESS-MODELS, the OCR eval, read not redone): ranking page
https://engram.onedroid.ai/l/6f1754c1-7820-40e0-9d2b-9d342e06ff65/f247b26c-58d2-4a71-9dce-b0881fcb751e/81cbd043-8848-435f-9ce0-defb0518b4ef;
code and logs in the claims notepad, `.df/missions/M-20261127-WITNESS-MODELS/eval/` (`eval_vision.py`, `orch_strict_score.py`,
`vision-round1.jsonl`, `vision-round1-strict.json`). A sealed set of 64 image/text cases (32 honest, 32 forged: 12 one
sentence, 14 one number, 6 unrelated texts). A similarity score cannot catch a one-number forgery even with a perfect reader
(one token in 50 to 200 moves it about 100 bp; 0/14 caught at match.screenshot's thresholds). R1 caught every forgery with
every one of the 16 vision models (32/32; gemini-3.5-flash ran 52 of the 64 cases and caught its 26); on the 32 honest images seed-2.0-mini and claude-haiku-5.5 (reasoning off) made no false
`differs` (64/64), gemma-4-31b-it one (63/64), Tesseract 20 (44/64).

### Builder decisions, NS-11 match.image-text (204-)

204. **Tests first.** `b0bfcb9` ("test change:": the library pins 1.9.0 -> 1.10.0 and the method set gains match.image-text,
     each pin replaced by its new exact value), RED `93abe0b` (`tests_claim/test_match_image_text.py`, 47 tests, 47 failing),
     two "test change:" fixes of the RED file's own bugs (`ce3ceb5`: the archive index is `{"entries": [...]}`; `1686cf0`: a
     helper's parameter clashed with a keyword), assertions unchanged. GREEN `9b2a9ad`, archive `54c9c3e`.
205. **Pure rule, recorded reading.** The model call is the only impure step and is recorded, so the method is `pure` (R1 in
     the tarball, `code_sha256` the tarball's) and witness-verify re-runs the decision; unlike match.screenshot (Tesseract in
     the image, `code_sha256` the image digest, "re-run skipped (needs image)"). The transcription and the missing tokens are
     content, so they live in the body (`judgment`), never in the private payload's `detail`.
206. **"Unreadable" looks at the reading only**: no token with a letter or digit, or more than half `[illegible]` markers, or
     every model answering empty. A model that errors on every try is `model-unavailable`, not `unreadable` (the image was
     never read; a no-finding reason the schema already has). A `[illegible]` marker that replaces a claimed word simply counts
     as missing, as in the eval.
207. **A cut transcription never signs `differs`**: `max_tokens` 8192 (the eval's 2048 would cut a 20,000-character block),
     and `finish_reason: length` with an R1 `differs` is `too-large`.
208. **Price = the check line.** About one credit was asked; the house rule already prices a mechanical check over objects at
     the list's `check` (1), and a separate model-run line (10 x price_factor) would make it 11. The transcriber list carries
     no price_factor.
209. **Library 1.9.0 -> 1.10.0** (a new method), match.image-text method 1.0.0; every other method's version is unchanged, but
     every pure method's `code_sha256` moves with the tarball. The vectors were regenerated with `python3 -m
     claim_witness.vectors --write` on python3.14 (only `envelope`, `seal`, `own_seal` and `record_methods` change; `--check`
     passes on 3.12 and 3.14). The tarball is archived in the next commit (`tools/archive_methods_tarball.py add <GREEN
     commit>`, decision 161).
210. **No replay.** A model reads the image, so the object-only idempotency rule (item 5) does not apply, as for
     judge.supports: the same check again asks the models again and signs a new record, counted as the next attempt
     (`attempt.prior` shows the earlier answers). Found while building (a check whose models all failed was replayed for 24 h):
     RED `cf3c959`, then the fix (`prepare`: no `auto_fp` for `determinism: model`).
211. **Not changed:** match.screenshot, match.text and every other method's behaviour, judge.supports and its model list, the
     price list, migrations, the k8s manifest (the example list is not applied). Serving the method needs the image rebuilt
     and a ConfigMap for `WITNESS_IMAGE_TEXT_MODELS_FILE`; the BFF, MCP and site follow separately.
