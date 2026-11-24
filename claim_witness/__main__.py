"""python3 -m claim_witness api | signer ... | dev

  api      the HTTP API. Env: WITNESS_ID, WITNESS_SIGNER_SOCKET (the signer sidecar's Unix socket), WITNESS_DATABASE_URL
           (Postgres, first connection retried up to WITNESS_DB_START_TIMEOUT_S = 120, then migrated), WITNESS_ATTEMPT_KEY_FILE,
           WITNESS_MASTER_KEY_FILE, WITNESS_REDACT_BIN, WITNESS_DEV_KEYS_FILE (optional), WITNESS_CALLER_KEYS_URL (optional),
           WITNESS_HOST (0.0.0.0), WITNESS_PORT (8080). B2b: FETCHER_URL and FETCHER_SECRET_FILE (url evidence),
           WITNESS_RESOLVERS (1.1.1.1,8.8.8.8), WITNESS_CONFIRM_DELAY_S (60), WITNESS_FREE_OBSERVATIONS_PER_DAY (50),
           WITNESS_OBSERVATION_PRICE (5), WITNESS_HOST_FETCHES_PER_MINUTE (6), WITNESS_IMAGE_DIGEST and WITNESS_TESSERACT_BIN
           (match.screenshot).
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

    from . import api, dns, fetcher, service
    cfg = service.Config(witness_id=env.get("WITNESS_ID") or "witness:onedroid", attempt_key=attempt_key, master_key=master_key,
                         redact_bin=(env.get("WITNESS_REDACT_BIN") or "").strip() or None,
                         rate_per_minute=int(env.get("WITNESS_RATE_PER_MINUTE") or 60),
                         fetcher=fetcher.FetcherClient.from_env(env), resolvers=dns.resolvers_from_env(env),
                         confirm_delay_s=int(env.get("WITNESS_CONFIRM_DELAY_S") or 60),
                         free_observations_per_day=int(env.get("WITNESS_FREE_OBSERVATIONS_PER_DAY") or 50),
                         observation_price=int(env.get("WITNESS_OBSERVATION_PRICE") or 5),
                         image_digest=(env.get("WITNESS_IMAGE_DIGEST") or "").strip() or None,
                         tesseract_bin=(env.get("WITNESS_TESSERACT_BIN") or "").strip() or shutil.which("tesseract"),
                         host_fetches_per_minute=int(env.get("WITNESS_HOST_FETCHES_PER_MINUTE") or 6))
    print(f"claim-witness: fetcher {'configured' if cfg.fetcher else 'not configured (url evidence answers 503)'}; "
          f"match.screenshot {'ready' if cfg.image_digest and cfg.tesseract_bin else 'unavailable (needs WITNESS_IMAGE_DIGEST and tesseract)'}",
          flush=True)
    witness = service.Witness(storage, signer_client, cfg)
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
