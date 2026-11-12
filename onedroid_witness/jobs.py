"""Jobs (contract 3c.9): a request is a job. POST /witness answers 202 with a job id at once; the answer is fetched by job id as a tar
with its sha256. Each job is a folder: request/ (the parts as sent), answer/ (what the run wrote), status.json (queued | running | done |
refused | failed, with the estimate, the service record's summary and the tar's sha256). One worker thread runs jobs in order; the
folder survives a restart and a queued job is resumed.
"""
import hashlib
import io
import json
import os
import pathlib
import queue
import secrets
import tarfile
import threading
import time

from . import answer as answer_mod
from . import request as request_mod
from .openrouter import RouterRefused


class JobStore:
    def __init__(self, root):
        self.root = pathlib.Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.lock = threading.Lock()

    def new(self):
        jid = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + "-" + secrets.token_hex(6)
        d = self.root / jid
        (d / "request").mkdir(parents=True)
        self.write_status(jid, {"job_id": jid, "state": "queued", "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())})
        return jid

    def incoming(self):
        """A folder for a request under check: outside the job folders, removed by `discard` when the request is refused, moved into a
        job by `adopt` when it is accepted. A refused request therefore leaves no job and no bytes (gate D11)."""
        d = self.root / ".incoming" / secrets.token_hex(8)
        d.mkdir(parents=True)
        return d

    def discard(self, incoming_dir):
        import shutil
        shutil.rmtree(incoming_dir, ignore_errors=True)

    def adopt(self, incoming_dir):
        """The checked request becomes a job: its folder is moved to <jid>/request and the job is queued."""
        jid = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + "-" + secrets.token_hex(6)
        d = self.root / jid
        d.mkdir(parents=True)
        os.replace(incoming_dir, d / "request")
        self.write_status(jid, {"job_id": jid, "state": "queued", "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())})
        return jid

    def dir(self, jid):
        if not jid or "/" in jid or ".." in jid or not (self.root / jid).is_dir():
            return None
        return self.root / jid

    def write_status(self, jid, status):
        d = self.root / jid
        tmp = d / "status.json.tmp"
        tmp.write_text(json.dumps(status, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
        os.replace(tmp, d / "status.json")

    def status(self, jid):
        d = self.dir(jid)
        if d is None:
            return None
        try:
            return json.loads((d / "status.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None

    def answer_tar(self, jid):
        """The answer folder as a tar (deterministic order, zeroed mtimes) and its sha256."""
        d = self.dir(jid)
        if d is None or not (d / "answer").is_dir():
            return None, None
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            for p in sorted((d / "answer").rglob("*")):
                if p.is_file():
                    info = tar.gettarinfo(str(p), arcname=str(p.relative_to(d / "answer")))
                    info.mtime, info.uid, info.gid, info.uname, info.gname = 0, 0, 0, "", ""
                    with open(p, "rb") as f:
                        tar.addfile(info, f)
        data = buf.getvalue()
        return data, hashlib.sha256(data).hexdigest()

    def queued(self):
        out = []
        for d in sorted(self.root.iterdir()):
            if d.name.startswith("."):
                continue
            s = self.status(d.name)
            if s and s.get("state") in ("queued", "running"):
                out.append(d.name)
        return out


class Worker(threading.Thread):
    """Runs jobs one at a time. `models_of(job)` resolves the requested model ids to the configured entries; `client`, `keystore`,
    `check`, `prices` as in answer.run; `private_mode` and `catalogue_lookup` as in request.check_published."""

    def __init__(self, store, client, keystore, check, models_of, prices, private_mode=False, catalogue_lookup=None, service_name="onedroid-witness"):
        super().__init__(daemon=True, name="witness-worker")
        self.store, self.client, self.keystore, self.check, self.models_of, self.prices = store, client, keystore, check, models_of, prices
        self.private_mode, self.catalogue_lookup, self.service_name = private_mode, catalogue_lookup, service_name
        self.q = queue.Queue()
        for jid in store.queued():
            self.q.put(jid)

    def submit(self, jid):
        self.q.put(jid)

    def run_one(self, jid):
        d = self.store.dir(jid)
        status = self.store.status(jid) or {"job_id": jid}
        status.update({"state": "running", "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())})
        self.store.write_status(jid, status)
        try:
            params = json.loads((d / "request" / "params.json").read_text(encoding="utf-8")) if (d / "request" / "params.json").exists() else {}
            req = request_mod.Request(d / "request", private_mode=self.private_mode)
            published = request_mod.check_published(req, params.get("published_url"), self.catalogue_lookup)
            models = self.models_of(params.get("models") or [])
            svc = answer_mod.run(req, models, self.client, self.keystore, self.check, d / "answer", prices=self.prices,
                                 max_cost_usd=params.get("max_cost_usd"), private_mode=self.private_mode, published=published, service_name=self.service_name)
            _, sha = self.store.answer_tar(jid)
            status.update({"state": "done", "finished_at": svc["finished_at"], "models_run": svc["models_run"], "models_skipped": svc["models_skipped"],
                           "total_cost_usd": svc["total_cost_usd"], "estimate_usd": svc["estimate_usd"]["total"], "split_claims": svc["split_claims"], "answer_sha256": sha,
                           "answer_url": f"/witness/{jid}/answer.tar"})
        except (request_mod.Refused, RouterRefused, ValueError) as e:
            status.update({"state": "refused", "reason": str(e)[:500], "finished_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())})
        except Exception as e:  # a failure is recorded, never silent
            status.update({"state": "failed", "reason": f"{type(e).__name__}: {str(e)[:500]}", "finished_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())})
        self.store.write_status(jid, status)
        return status

    def run(self):
        while True:
            jid = self.q.get()
            if jid is None:
                return
            try:
                self.run_one(jid)
            except Exception:
                pass
