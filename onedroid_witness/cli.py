"""The command line: `serve` runs the service from a configuration file; `run` is the one-shot private mode (a snapshot folder in, an answer
folder out, the same code the service runs); `keys` lists or retires the service's keys.

Configuration (JSON): {"models": [{"id", "kind": "chat|decision", "max_tokens"}], "daily_cap_usd", "keys_dir", "jobs_dir", "ledger_path",
"check_py", "openrouter_key_file" (or the environment variable OPENROUTER_API_KEY), "private_mode", "host", "port", "profiles_served"
(default request.PROFILES_SERVED: cited-sources, agent-work, test-run; publisher-surfaces is out until NEXT-REVISION 23)}. The key file is
read once and never logged.
"""
import argparse
import json
import os
import pathlib
import sys

from . import __version__, answer, checkpin, request
from .jobs import JobStore, Worker
from .openrouter import Client, Ledger, fetch_prices, refuse_routers
from .signing import KeyStore


def read_key(cfg):
    path = cfg.get("openrouter_key_file")
    if path:
        text = pathlib.Path(path).read_text(encoding="utf-8").strip()
        # a one-line key, or an env-style file: the first line whose name holds "openrouter"
        if "=" in text:
            for line in text.splitlines():
                if "openrouter" in line.split("=")[0].lower():
                    return line.partition("=")[2].strip().strip('"').strip("'")
        return text
    key = os.environ.get("OPENROUTER_API_KEY")
    if not key:
        sys.exit("no OpenRouter key: set openrouter_key_file in the configuration or OPENROUTER_API_KEY")
    return key


def load_cfg(path):
    cfg = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
    for m in cfg["models"]:
        refuse_routers(m["id"])
        m.setdefault("kind", "chat")
        if m["kind"] == "chat":
            m.setdefault("max_tokens", 400)
    return cfg


def build(cfg, prices=None):
    check = checkpin.load_check(cfg["check_py"])
    ledger = Ledger(cfg.get("ledger_path", "ledger.json"), cfg.get("daily_cap_usd", 2.0))
    client = Client(read_key(cfg), ledger)
    keystore = KeyStore(cfg.get("keys_dir", "keys"))
    if prices is None:
        try:
            prices = fetch_prices()
        except Exception as e:  # the estimate falls back to zero prices and says so
            print(f"warning: prices not fetched ({type(e).__name__}); the estimate uses zero prices", file=sys.stderr)
            prices = {}
    return check, ledger, client, keystore, prices


def cmd_serve(args):
    cfg = load_cfg(args.config)
    check, ledger, client, keystore, prices = build(cfg)
    store = JobStore(cfg.get("jobs_dir", "jobs"))
    known = {m["id"]: m for m in cfg["models"]}
    worker = Worker(store, client, keystore, check, lambda ids: [known[i] for i in ids], prices, private_mode=bool(cfg.get("private_mode")))
    worker.start()
    from .server import serve
    serve({"store": store, "worker": worker, "models_cfg": cfg["models"], "prices": prices, "ledger": ledger, "keystore": keystore,
           "private_mode": bool(cfg.get("private_mode")), "version": __version__,
           "profiles_served": tuple(cfg.get("profiles_served", request.PROFILES_SERVED))}, host=cfg.get("host", "0.0.0.0"), port=int(cfg.get("port", 8080)))


def cmd_run(args):
    cfg = load_cfg(args.config)
    check, ledger, client, keystore, prices = build(cfg)
    known = {m["id"]: m for m in cfg["models"]}
    ids = args.models.split(",") if args.models else list(known)
    models = [known[i] for i in ids]
    req = request.Request(args.snapshot, private_mode=True, profiles_served=tuple(cfg.get("profiles_served", request.PROFILES_SERVED)))
    svc = answer.run(req, models, client, keystore, check, args.answer, prices=prices, max_cost_usd=args.max_cost_usd, private_mode=True)
    print(json.dumps({"models_run": svc["models_run"], "models_skipped": svc["models_skipped"], "total_cost_usd": svc["total_cost_usd"], "split_claims": svc["split_claims"],
                      "per_model": {m: {k: v[k] for k in ("agrees_with_primary", "undecided", "cost_usd")} for m, v in svc["per_model"].items()}}, indent=1))
    return 0


def cmd_keys(args):
    cfg = load_cfg(args.config)
    ks = KeyStore(cfg.get("keys_dir", "keys"))
    if args.retire:
        ks.retire(args.retire)
    print(json.dumps(ks.keys_list(), indent=1))
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(prog="onedroid-witness", description=__doc__.split("\n")[0])
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("serve", help="run the service")
    s.add_argument("--config", required=True)
    s.set_defaults(fn=cmd_serve)
    r = sub.add_parser("run", help="private mode, one shot: snapshot folder in, answer folder out")
    r.add_argument("--config", required=True)
    r.add_argument("snapshot")
    r.add_argument("answer")
    r.add_argument("--models", help="comma-separated ids from the configuration; default all")
    r.add_argument("--max-cost-usd", type=float, default=None)
    r.set_defaults(fn=cmd_run)
    k = sub.add_parser("keys", help="list the service's keys, or retire one model's current key")
    k.add_argument("--config", required=True)
    k.add_argument("--retire", help="the model id whose current key is retired (a rotation)")
    k.set_defaults(fn=cmd_keys)
    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
