#!/usr/bin/env python3
"""acr_login.py DOCKER_CONFIG_DIR: get a short-lived token for acrpwwpoland with the signed-in az identity and write a docker config.json
(mode 0600) that buildctl reads for the push. Prints only the directory and the token's length, never the token."""
import json, os, pathlib, subprocess, sys
d = pathlib.Path(sys.argv[1]); d.mkdir(parents=True, exist_ok=True)
out = subprocess.run(["az", "acr", "login", "--name", "acrpwwpoland", "--expose-token", "-o", "json"], capture_output=True, text=True, check=True).stdout
tok = json.loads(out)["accessToken"]
import base64
auth = base64.b64encode(("00000000-0000-0000-0000-000000000000:" + tok).encode()).decode()
cfg = d / "config.json"
cfg.write_text(json.dumps({"auths": {"acrpwwpoland.azurecr.io": {"auth": auth}}}))
os.chmod(cfg, 0o600)
print(f"docker config written to {d} (token length {len(tok)}; expires in about 3 h)")
