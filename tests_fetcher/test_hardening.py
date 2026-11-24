"""Follow-up tests (added after the B2a RED commit 5511eb5, before the GREEN): hardening and gaps found while
reviewing the first draft.

- the worker gets its own mount namespace and the service's secret directory and the service-account token are
  covered by an empty tmpfs inside it, so a browser escape cannot read them;
- a request in origin form (page script dialling the bridge port directly) gets no answer at all;
- the user agent names the real browser version and the witness's token;
- the manifest gives response.body a media type (SPEC 2.3);
- more hiding tricks are marked as hidden.
"""
import asyncio
import hashlib
import json
import os
import tempfile

import pytest

from claim_fetcher import capture as C
from claim_fetcher import nsrun, sandbox
from claim_fetcher import proxy as P
from conftest import FIXTURE_IP, FakeResolver, need_sandbox, seam_connector
from test_isolation import Elements, fixture_capture, page


# unit -----------------------------------------------------------------------------------------------------------------

def test_worker_gets_a_mount_namespace_too():
    cmd = nsrun.ns_command(["capture"], python="/usr/bin/python3")
    assert cmd[:4] == ["unshare", "--user", "--net", "--map-root-user"]
    assert "--mount" in cmd[:cmd.index("--")]


def test_hide_paths_default_covers_secret_dir_and_service_account(monkeypatch):
    monkeypatch.setenv("FETCHER_SECRET_FILE", "/etc/claim-fetcher/secret/secret")
    s = C.Settings.from_env()
    assert "/etc/claim-fetcher/secret" in s.hide_paths
    assert "/var/run/secrets/kubernetes.io" in s.hide_paths


def test_verdict_fails_when_a_hidden_path_is_still_readable():
    ok = {"interfaces": ["lo"], "probes": [{"target": "10.0.0.1:80", "result": "failed"}],
          "proxy_probe": {"result": "refused"}, "browser": "chromium 1",
          "hidden_paths": [{"path": "/etc/x", "result": "hidden"}]}
    assert sandbox.verdict(ok)["passed"] is True
    bad = dict(ok, hidden_paths=[{"path": "/etc/x", "result": "readable"}])
    assert sandbox.verdict(bad)["passed"] is False


def test_origin_form_request_gets_no_answer():
    async def body():
        with tempfile.TemporaryDirectory() as tmp:
            conn = seam_connector({})
            proxy = P.EgressProxy(os.path.join(tmp, "e.sock"), resolver=FakeResolver({}), connector=conn)
            await proxy.start()
            try:
                r, w = await asyncio.open_unix_connection(proxy.socket_path)
                w.write(b"GET / HTTP/1.1\r\nHost: 127.0.0.1:41234\r\n\r\n")
                await w.drain()
                assert await asyncio.wait_for(r.read(), 5) == b""
                w.close()
                assert conn.calls == []
                assert proxy.log[-1]["result"] == "blocked"
            finally:
                await proxy.close()
    asyncio.run(body())


def test_manifest_gives_response_body_a_media_type():
    files = {"response.body": b"x"}
    m = C.build_manifest(requested_url="http://a.test/", final_url="http://a.test/", redirects=[],
                         fetched_at="2026-11-24T10:41:07Z", fetch_ms=1, status=200, resolved_ips=[FIXTURE_IP],
                         tls=None, robots="allowed", browser="chromium 1", viewport=[1280, 900], files=files,
                         body_media_type="text/html")
    assert m["files"][0]["media_type"] == "text/html"


def test_default_user_agent_names_the_browser_version():
    ua = C.user_agent_for("159.0.8154.6")
    assert "Chrome/159.0.8154.6" in ua and "OneDroidWitness/" in ua and "HeadlessChrome" not in ua


# integration ----------------------------------------------------------------------------------------------------------

@pytest.mark.integration
def test_selftest_hides_secret_paths_from_the_namespace(tmp_path):
    need_sandbox()
    secret_dir = tmp_path / "secret"
    secret_dir.mkdir()
    (secret_dir / "secret").write_text("do-not-leak")
    result = C.run_selftest(C.Settings(hide_paths=(str(secret_dir),)))
    assert result["passed"] is True, result
    assert {"path": str(secret_dir), "result": "hidden"} in result["hidden_paths"]


@pytest.mark.integration
def test_capture_user_agent_and_body_media_type(site_factory):
    need_sandbox()
    site = site_factory({"/ua.html": page("<p>ua</p>")})
    result = fixture_capture(site, "/ua.html")
    page_hits = [h for p, h in site.hits if p == "/ua.html"]
    ua = page_hits[0].get("User-Agent")
    version = result.manifest["fetcher"]["browser"].split(" ", 1)[1]
    assert f"Chrome/{version}" in ua and "OneDroidWitness/" in ua
    robots_hits = [h for p, h in site.hits if p == "/robots.txt"]
    assert robots_hits and "OneDroidWitness/" in robots_hits[0].get("User-Agent", "")
    assert result.manifest["fetcher"]["user_agent"] == ua
    body_entry = [f for f in result.manifest["files"] if f["name"] == "response.body"][0]
    assert body_entry["media_type"] == "text/html"


@pytest.mark.integration
def test_more_hiding_tricks_are_marked(site_factory):
    need_sandbox()
    body = """
<div style="background:#fff"><p id="white" style="color:#fff">HIDDEN-same-colour</p></div>
<div style="height:0;overflow:hidden"><p id="zh">HIDDEN-zero-height-parent</p></div>
<p id="ti" style="text-indent:-9999px;overflow:hidden;white-space:nowrap">HIDDEN-text-indent</p>
<p id="cp" style="clip-path:inset(50%)">HIDDEN-clip-path</p>
<p id="sc" style="transform:scale(0)">HIDDEN-scale</p>
<div style="background:#000"><p id="contrast" style="color:#fff">VISIBLE-white-on-black</p></div>
<div style="height:40px;overflow:hidden"><p id="tall">VISIBLE-in-clipped-box</p></div>
<p id="plain">VISIBLE-plain</p>
"""
    site = site_factory({"/more.html": page(body)})
    result = fixture_capture(site, "/more.html")
    p = Elements()
    p.feed(result.files["rendered.html"].decode())
    for el in ("contrast", "tall", "plain"):
        assert "data-witness-hidden" not in p.by_id[el], el
    for el in ("white", "zh", "ti", "cp", "sc"):
        assert p.by_id[el].get("data-witness-hidden") == "1", el
    nodes = json.loads(result.files["hidden-nodes.json"])
    excerpts = {n["excerpt"] for n in nodes}
    assert "HIDDEN-same-colour" in excerpts
    assert all(n["sha256"] == hashlib.sha256(n["excerpt"].encode()).hexdigest() for n in nodes
               if len(n["excerpt"]) < 200)
