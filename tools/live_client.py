#!/usr/bin/env python3
"""live_client.py BASE_URL SNAPSHOT_DIR OUT_DIR MODELS PUBLISHED_URL: the whole public path against a running service: GET /healthz, /models,
POST /witness (multipart) with the snapshot's parts, poll the job, GET the tar, check its sha256 against the status and the header, unpack it,
then add_witness.py into a copy of the snapshot and check.py. Prints every step's result. Standard library only."""
import hashlib, http.client, io, json, pathlib, shutil, subprocess, sys, tarfile, time, urllib.parse, uuid

base, snap, out, models, published = sys.argv[1], pathlib.Path(sys.argv[2]), pathlib.Path(sys.argv[3]), sys.argv[4], sys.argv[5]
VENDOR = pathlib.Path(__file__).resolve().parents[1] / "vendor"  # the repository's own pinned scripts, so the client runs from a fresh clone (gate D6)
u = urllib.parse.urlparse(base)
out.mkdir(parents=True, exist_ok=True)


def conn():
    return http.client.HTTPConnection(u.hostname, u.port or 80, timeout=120)


def get(path):
    c = conn(); c.request("GET", path); r = c.getresponse(); return r.status, dict(r.getheaders()), r.read()


st, _, body = get("/healthz")
print("healthz", st, body.decode()[:300])
st, _, body = get("/models")
print("models", st, [m["id"] for m in json.loads(body)["models"]])
parts = {n: (snap / n).read_bytes() for n in ("manifest.json", "audit.jsonl", "audit.jsonl.sig", "allowed_signers", "signatures.json", "page.txt")}
boundary = "----live" + uuid.uuid4().hex
buf = io.BytesIO()
for k, v in {"models": models, "max_cost_usd": "0.5", "published_url": published}.items():
    buf.write(f"--{boundary}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n".encode())
for name, data in parts.items():
    buf.write(f"--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"; filename=\"{name}\"\r\nContent-Type: application/octet-stream\r\n\r\n".encode())
    buf.write(data); buf.write(b"\r\n")
buf.write(f"--{boundary}--\r\n".encode())
body = buf.getvalue()
c = conn(); c.request("POST", "/witness", body=body, headers={"Content-Type": f"multipart/form-data; boundary={boundary}", "Content-Length": str(len(body))})
r = c.getresponse(); ans = json.loads(r.read())
print("POST /witness", r.status, json.dumps(ans)[:400])
if r.status != 202:
    sys.exit(1)
jid = ans["job_id"]
for _ in range(900):
    st, _, body = get(f"/witness/{jid}")
    s = json.loads(body)
    if s["state"] in ("done", "refused", "failed"):
        break
    time.sleep(1)
print("status", json.dumps({k: s.get(k) for k in ("state", "models_run", "models_skipped", "total_cost_usd", "estimate_usd", "split_claims", "answer_sha256", "reason")}))
if s["state"] != "done":
    sys.exit(1)
st, headers, tar_bytes = get(f"/witness/{jid}/answer.tar")
sha = hashlib.sha256(tar_bytes).hexdigest()
print("answer.tar", st, len(tar_bytes), "bytes; sha matches status:", sha == s["answer_sha256"], "; matches header:", headers.get("X-Answer-SHA256") == sha)
(out / "answer.tar").write_bytes(tar_bytes)
if sha != s["answer_sha256"] or headers.get("X-Answer-SHA256") != sha:
    # 3c.9: an answer whose tar sha256 differs from the one the status announced is refused; nothing is unpacked or inserted (gate D6)
    print("REFUSED: the tar's sha256 differs from the announced one; nothing unpacked, nothing inserted")
    sys.exit(2)
ans_dir = out / "answer"
with tarfile.open(fileobj=io.BytesIO(tar_bytes)) as tar:
    tar.extractall(ans_dir, filter="data")
svc = json.loads((ans_dir / "service.json").read_text())
print("service.json mode", svc["mode"], "published", json.dumps(svc["published"])[:160])
for m, v in svc["per_model"].items():
    print("  ", m, "served", list(v["served"]), v["agrees_with_primary"], "undecided", v["undecided"], "cost", v["cost_usd"])
snap2 = out / "snap"
if snap2.exists():
    shutil.rmtree(snap2)
shutil.copytree(snap, snap2)
adder = out / "adder"
if not adder.exists():
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(adder)], check=True)
r = subprocess.run([sys.executable, "-I", str(VENDOR / "add_witness.py"), str(snap2), str(ans_dir), "--key", str(adder), "--identity", "live-client-test-adder"], capture_output=True, text=True)
print("add_witness exit", r.returncode)
print("\n".join(l for l in (r.stdout + r.stderr).splitlines() if l.startswith(("added", "SUMMARY", "manifest.json"))))
