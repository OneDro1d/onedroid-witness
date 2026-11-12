#!/usr/bin/env python3
"""make_secret.py: read the service's OpenRouter key (variable openrouter_witness_dev in the onedro1d notepads .env, D84 A) and create the
Kubernetes Secret onedroid-witness-openrouter in namespace witness-dev on prov-poland-aks with one key `key`. The value goes from the file
to kubectl's stdin as a Secret manifest and is never printed, never written to disk."""
import base64, json, subprocess, sys
ENV = "/home/coder/code/onedro1d/notepads/.env"
val = None
with open(ENV, encoding="utf-8") as f:
    for line in f:
        if line.strip().startswith("openrouter_witness_dev"):
            val = line.strip().partition("=")[2].strip().strip('"').strip("'")
if not val:
    sys.exit("no openrouter_witness_dev line in the env file")
manifest = {"apiVersion": "v1", "kind": "Secret", "metadata": {"name": "onedroid-witness-openrouter", "namespace": "witness-dev"}, "type": "Opaque",
            "data": {"key": base64.b64encode(val.encode()).decode()}}
r = subprocess.run(["kubectl", "--context", "prov-poland-aks", "apply", "-f", "-"], input=json.dumps(manifest), capture_output=True, text=True)
print(r.stdout.strip() or r.stderr.strip()[:300])
print(f"key length {len(val)}, prefix shape {'sk-or-' if val.startswith('sk-or-') else 'other'}")
sys.exit(r.returncode)
