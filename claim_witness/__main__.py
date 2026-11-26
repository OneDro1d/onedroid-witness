"""python3 -m claim_witness api | signer ... | dev

  api      the HTTP API. Env: WITNESS_ID, WITNESS_SIGNER_SOCKET (the signer sidecar's Unix socket), WITNESS_DATABASE_URL
           (Postgres, first connection retried up to WITNESS_DB_START_TIMEOUT_S = 120, then migrated), WITNESS_ATTEMPT_KEY_FILE,
           WITNESS_MASTER_KEY_FILE, WITNESS_REDACT_BIN, WITNESS_DEV_KEYS_FILE (optional), WITNESS_CALLER_KEYS_URL (optional),
           WITNESS_HOST (0.0.0.0), WITNESS_PORT (8080). judge.supports: WITNESS_JUDGE_BASE_URL, WITNESS_JUDGE_API_KEY_FILE,
           WITNESS_JUDGE_MODELS_FILE (all three, else judge.supports answers 503), optionally WITNESS_JUDGE_MAX_TOKENS and
           WITNESS_PRICE_LIST_FILE (claim_witness/judge.py). Observations: FETCHER_URL and FETCHER_SECRET_FILE (url evidence),
           WITNESS_RESOLVERS (1.1.1.1,8.8.8.8), WITNESS_CONFIRM_DELAY_S (60), WITNESS_FREE_OBSERVATIONS_PER_DAY (50),
           WITNESS_OBSERVATION_PRICE (5), WITNESS_HOST_FETCHES_PER_MINUTE (6), WITNESS_IMAGE_DIGEST and WITNESS_TESSERACT_BIN
           (match.screenshot). B3: WITNESS_BATCH_INTERVAL_S (3600), WITNESS_BATCH_MAX_LEAVES (100000), WITNESS_SEALER
           (1; 0 runs no sealer in this process), WITNESS_SEALER_POLL_S (30), WITNESS_NOTARY_URL, WITNESS_NOTARY_TOKEN_FILE,
           WITNESS_NOTARY_CA_FILE, WITNESS_NOTARY_TIMEOUT_S (no token file: batches are closed but never anchored),
           WITNESS_NOTARY_OWN_PROFILE (hash/1-own; "" or off: own-key batches close unanchored; hash/1 is refused),
           WITNESS_NOTARY_OWN_TOKEN_FILE (optional, else the notary token),
           ARMARIUM_URL, ARMARIUM_TOKEN_FILE, ARMARIUM_CA_FILE, ARMARIUM_CASE (no URL: nothing is written to n-dim),
           NDIM_STORE_EVIDENCE (0), WITNESS_LINK_BASE (https://evidence.onedroid.ai), WITNESS_OPERATOR_ACCOUNTS (comma list).
           B7: WITNESS_EMBEDDER_URL (an OpenAI-compatible /v1/embeddings endpoint; unset: GET /v1/search mode=semantic answers
           503 and mode=hybrid answers keyword results flagged degraded), WITNESS_EMBEDDER_MODEL, WITNESS_EMBEDDER_KEY_FILE.
  signer   the signer sidecar (`signer serve`) and the operator key-list commands (`signer keylist init|rotate|show`); see
           claim_witness/signer.py.
  dev      API and signer in one process for a laptop: memory storage unless WITNESS_DATABASE_URL is set, a throwaway
           signing key unless WITNESS_SIGNING_KEY_FILE is set, throwaway attempt and master keys. Never for a cluster.
"""
import os
import sys


def _env_key(env, name):
    from .service import read_key_file
    path = (env.get(name) or "").strip()
    if not path:
        raise SystemExit(f"{name} is required (a file holding standard base64 of 32 bytes)")
    return read_key_file(path, name)


def _auth(env):
    from . import api, reqauth
    dev = (env.get("WITNESS_DEV_KEYS_FILE") or "").strip()
    url = (env.get("WITNESS_CALLER_KEYS_URL") or "").strip()
    return api.Auth(dev_keys=api.DevKeys.from_file(dev) if dev else None,
                    caller_keys=reqauth.CallerKeys(url, log=lambda line: print(line, flush=True)) if url else None)


def run_api(env, signer_client, storage, attempt_key, master_key):
    import shutil

    from . import api, dns, fetcher, judge, ndim, notary, search, service
    log = lambda line: print(line, flush=True)  # noqa: E731
    armarium, case = ndim.from_env(env)
    cfg = service.Config(witness_id=env.get("WITNESS_ID") or "witness:onedroid", attempt_key=attempt_key, master_key=master_key,
                         redact_bin=(env.get("WITNESS_REDACT_BIN") or "").strip() or None,
                         rate_per_minute=int(env.get("WITNESS_RATE_PER_MINUTE") or 60),
                         judge=judge.from_env(env, log=log), price=judge.price_from_env(env),
                         fetcher=fetcher.FetcherClient.from_env(env), resolvers=dns.resolvers_from_env(env),
                         confirm_delay_s=int(env.get("WITNESS_CONFIRM_DELAY_S") or 60),
                         free_observations_per_day=int(env.get("WITNESS_FREE_OBSERVATIONS_PER_DAY") or 50),
                         observation_price=int(env.get("WITNESS_OBSERVATION_PRICE") or 5),
                         image_digest=(env.get("WITNESS_IMAGE_DIGEST") or "").strip() or None,
                         tesseract_bin=(env.get("WITNESS_TESSERACT_BIN") or "").strip() or shutil.which("tesseract"),
                         host_fetches_per_minute=int(env.get("WITNESS_HOST_FETCHES_PER_MINUTE") or 6),
                         notary=notary.from_env(env), notary_own=notary.own_from_env(env), armarium=armarium, ndim_case=case,
                         ndim_store_evidence=(env.get("NDIM_STORE_EVIDENCE") or "0").strip() == "1",
                         batch_interval_s=int(env.get("WITNESS_BATCH_INTERVAL_S") or 3600),
                         batch_max_leaves=int(env.get("WITNESS_BATCH_MAX_LEAVES") or 100000),
                         sealer_poll_s=float(env.get("WITNESS_SEALER_POLL_S") or 30),
                         link_base=(env.get("WITNESS_LINK_BASE") or "").strip() or "https://evidence.onedroid.ai",
                         operator_accounts=[a.strip() for a in (env.get("WITNESS_OPERATOR_ACCOUNTS") or "").split(",") if a.strip()],
                         embedder=search.embedder_from_env(env))
    print(f"claim-witness: fetcher {'configured' if cfg.fetcher else 'not configured (url evidence answers 503)'}; "
          f"match.screenshot {'ready' if cfg.image_digest and cfg.tesseract_bin else 'unavailable (needs WITNESS_IMAGE_DIGEST and tesseract)'}",
          flush=True)
    print(f"claim-witness: notary {'configured' if cfg.notary else 'not configured (batches close, never anchored)'}; "
          f"n-dim {('claimant chain per owner under case ' + case) if armarium else 'not configured (nothing is written)'}"
          f"{' with kept evidence' if armarium and cfg.ndim_store_evidence else ''}", flush=True)
    print(f"claim-witness: own-key batches "
          f"{('notarized with profile ' + cfg.notary_own.profile) if cfg.notary_own else 'close unanchored (no own notary profile)'}",
          flush=True)
    witness = service.Witness(storage, signer_client, cfg)
    try:  # B7: edges and search rows for records signed or kept before this version; idempotent, never fatal
        g, s = witness.graph.backfill(), witness.search.backfill()
        print(f"claim-witness: graph backfill {g['records']} record(s), {g['edges']} edge(s); search index +{s}; "
              f"embedder {'configured' if cfg.embedder else 'not configured (semantic search answers 503, hybrid is keyword)'}",
              flush=True)
        if cfg.embedder:
            witness.search.embed_missing(1000)
    except Exception as e:
        print(f"claim-witness: graph/search backfill failed ({type(e).__name__}); the API still starts", flush=True)
    if (env.get("WITNESS_SEALER") or "1").strip() != "0":
        witness.sealer.start()
        print(f"claim-witness: sealer every {cfg.sealer_poll_s:g} s, batches of {cfg.batch_interval_s} s or "
              f"{cfg.batch_max_leaves} leaves", flush=True)
    host, port = env.get("WITNESS_HOST") or "0.0.0.0", int(env.get("WITNESS_PORT") or 8080)
    srv = api.make_server(witness, _auth(env), host, port)
    print(f"claim-witness api {cfg.witness_id} on {host}:{port}", flush=True)
    srv.serve_forever()
    return 0


def main(argv, env=None):
    env = dict(os.environ) if env is None else env
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0 if argv else 2
    cmd, rest = argv[0], argv[1:]
    if cmd == "signer":
        from . import signer
        return signer.main(rest, env)
    from . import signer, storage as storage_mod
    if cmd == "api":
        st = storage_mod.from_env(env)
        client = signer.SocketSignerClient(signer.socket_path_from_env(env))
        return run_api(env, client, st, _env_key(env, "WITNESS_ATTEMPT_KEY_FILE"), _env_key(env, "WITNESS_MASTER_KEY_FILE"))
    if cmd == "dev":
        st = storage_mod.from_env(env)
        witness_id = env.get("WITNESS_ID") or "witness:dev"
        env = dict(env, WITNESS_ID=witness_id)
        key_file = (env.get("WITNESS_SIGNING_KEY_FILE") or "").strip()
        seed = signer.read_seed(key_file) if key_file else os.urandom(32)
        key_id = env.get("WITNESS_KEY_ID") or f"{witness_id}:dev"
        if st.latest_key_list() is None:
            signer.keylist_init(st, seed, key_id, witness_id)
        core = signer.SignerCore(seed, key_id, witness_id, st)
        return run_api(env, signer.LocalSignerClient(core), st, os.urandom(32), os.urandom(32))
    print(f"unknown command {cmd!r}\n{__doc__}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
