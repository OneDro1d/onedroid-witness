"""The isolation path end to end: Chromium in an unprivileged user + network namespace with only `lo`, a loopback
bridge over a Unix socket to the egress proxy outside it, and the capture files it produces.

Unit checks of the pieces come first; the integration tests (marker `integration`) run the real namespace and browser
and skip politely when this machine cannot (no unshare permission, no Chromium) or, for the public test, is offline.
"""
import hashlib
import html.parser
import io
import json
import time
import zipfile

import pytest

from claim_fetcher import capture as C
from claim_fetcher import nsrun, sandbox
from conftest import FIXTURE_IP, FakeResolver, need_sandbox, online, primary_ip, seam_connector

PROC_NET_DEV_LO = """Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo:       0       0    0    0    0     0          0         0        0       0    0    0    0     0       0          0
"""
PROC_NET_DEV_ETH = PROC_NET_DEV_LO + "  eth0: 1234 5 0 0 0 0 0 0 99 1 0 0 0 0 0 0\n"


# unit -----------------------------------------------------------------------------------------------------------------

def test_interfaces_parsed_from_proc_net_dev():
    assert sandbox.interfaces(PROC_NET_DEV_LO) == ["lo"]
    assert sandbox.interfaces(PROC_NET_DEV_ETH) == ["lo", "eth0"]


def test_selftest_verdict():
    ok = {"interfaces": ["lo"], "probes": [{"target": "10.0.0.1:80", "result": "failed"}],
          "proxy_probe": {"result": "refused"}, "browser": "chromium 131"}
    assert sandbox.verdict(ok)["passed"] is True
    bad_if = dict(ok, interfaces=["lo", "eth0"])
    assert sandbox.verdict(bad_if)["passed"] is False
    reached = dict(ok, probes=[{"target": "10.0.0.1:80", "result": "connected"}])
    assert sandbox.verdict(reached)["passed"] is False
    no_probe = dict(ok, probes=[])
    assert sandbox.verdict(no_probe)["passed"] is False


def test_namespace_command():
    cmd = nsrun.ns_command(["selftest"], python="/usr/bin/python3")
    assert cmd[:4] == ["unshare", "--user", "--net", "--map-root-user"]
    assert cmd[-3:] == ["-m", "claim_fetcher.sandbox", "selftest"] or cmd[-1] == "selftest"


def test_worker_environment_carries_no_secret(monkeypatch):
    monkeypatch.setenv("FETCHER_SECRET_FILE", "/etc/claim-fetcher/secret/secret")
    monkeypatch.setenv("SOME_TOKEN", "x")
    env = nsrun.worker_env()
    assert "FETCHER_SECRET_FILE" not in env and "SOME_TOKEN" not in env
    assert "PATH" in env


def test_browser_flags():
    args = sandbox.BROWSER_ARGS
    for flag in ("--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
                 "--webrtc-ip-handling-policy=disable_non_proxied_udp", "--disable-quic", "--dns-prefetch-disable"):
        assert flag in args
    assert any(a.startswith("--host-resolver-rules=") and "NOTFOUND" in a for a in args)


def test_capture_rejects_bad_targets_before_any_browser(monkeypatch):
    monkeypatch.setattr(nsrun, "run_worker", lambda *a, **k: pytest.fail("the browser must not start"))
    r = FakeResolver({"priv.test": ["10.0.0.1"]})
    for url, code in (("ftp://x.test/", "scheme"), ("http://x.test:8080/", "port"), ("http://priv.test/", "blocked"),
                      ("http://127.0.0.1/", "blocked"), ("http://nx.test/", "unreachable")):
        with pytest.raises(C.CaptureError) as e:
            C.capture_sync(url, (1280, 900), C.Settings(), resolver=r, connector=seam_connector({}))
        assert e.value.code == code, url


# integration helpers --------------------------------------------------------------------------------------------------

def fixture_capture(site, path, settings=None, extra_hosts=None, viewport=(1280, 900)):
    hosts = {"fixture.test": [FIXTURE_IP]}
    hosts.update(extra_hosts or {})
    resolver = FakeResolver(hosts)
    conn = seam_connector({(FIXTURE_IP, 80): (site.host, site.port)})
    return C.capture_sync(f"http://fixture.test{path}", viewport, settings or C.Settings(), resolver=resolver,
                          connector=conn)


class Elements(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.by_id = {}

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if "id" in a:
            self.by_id[a["id"]] = a


def page(body, head=""):
    return (200, {"Content-Type": "text/html; charset=utf-8"},
            f"<!doctype html><html><head><meta charset='utf-8'>{head}</head><body>{body}</body></html>".encode())


# integration ----------------------------------------------------------------------------------------------------------

@pytest.mark.integration
def test_selftest_namespace_shows_only_lo_and_private_probe_fails(site_factory):
    need_sandbox()
    ip = primary_ip()
    probes = []
    priv = None
    if ip:
        priv = site_factory({"/": (200, {}, b"private")}, host=ip)
        probes.append((ip, priv.port))
    result = C.run_selftest(C.Settings(), extra_probes=probes)
    assert result["interfaces"] == ["lo"]
    assert result["probes"], result
    assert all(p["result"] != "connected" for p in result["probes"]), result["probes"]
    assert result["proxy_probe"]["result"] == "refused"
    assert result["browser"].startswith("chromium")
    assert result["passed"] is True
    if priv:
        assert priv.hits == []
        assert any(p["target"] == f"{ip}:{priv.port}" for p in result["probes"])


PROBE_JS = """
<ol id="results"></ol>
<script>
const out = document.getElementById("results");
function row(t, r){ const li = document.createElement("li"); li.textContent = t + " => " + r; out.appendChild(li); }
const targets = TARGETS;
for (const t of targets) {
  const c = new AbortController(); setTimeout(() => c.abort(), 3000);
  fetch(t, {mode: "no-cors", signal: c.signal}).then(() => row(t, "REACHED")).catch(() => row(t, "failed"));
}
try {
  const pc = new RTCPeerConnection({iceServers: [{urls: "stun:stun.l.google.com:19302"}]});
  pc.createDataChannel("x");
  pc.onicecandidate = e => { if (e.candidate && e.candidate.candidate) row("webrtc-candidate", "REACHED " + e.candidate.candidate); };
  pc.createOffer().then(o => pc.setLocalDescription(o));
  setTimeout(() => row("webrtc", "done"), 3000);
} catch (e) { row("webrtc", "unavailable " + e); }
</script>
"""


def _rows(rendered):
    text = rendered.decode()
    start = text.index('id="results"')
    seg = text[start:text.index("</ol>", start)]
    return [x.split("</li>")[0] for x in seg.split("<li>")[1:]]


@pytest.mark.integration
def test_page_script_cannot_reach_a_private_server(site_factory):
    need_sandbox()
    ip = primary_ip()
    if not ip:
        pytest.skip("no non-loopback address on this machine to serve from")
    priv = site_factory({"/secret": (200, {"Access-Control-Allow-Origin": "*"}, b"SECRET")}, host=ip)
    targets = [f"http://{ip}:{priv.port}/secret", f"http://{ip}/secret", f"https://{ip}/secret"]
    body = (f"<img src='http://{ip}:{priv.port}/secret?img'><iframe src='http://{ip}:{priv.port}/secret?frame'></iframe>"
            + PROBE_JS.replace("TARGETS", json.dumps(targets)))
    site = site_factory({"/probe.html": page(body)})
    result = fixture_capture(site, "/probe.html")
    rows = _rows(result.files["rendered.html"])
    assert priv.hits == [], "the private server was reached"
    assert not any("REACHED" in r for r in rows), rows
    assert sum(r.endswith("failed") for r in rows) == len(targets), rows
    refused = [e for e in result.proxy_log if e.get("host") == ip]
    assert refused and all(e["result"] in ("blocked", "port") for e in refused)
    # and the private address as the page itself
    with pytest.raises(C.CaptureError) as e:
        C.capture_sync(f"http://{ip}/", (1280, 900), C.Settings())
    assert e.value.code == "blocked"


@pytest.mark.integration
def test_loopback_fetch_and_webrtc_record_failures(site_factory):
    need_sandbox()
    targets = ["http://127.0.0.1:9/", "http://127.0.0.1/", "http://localhost/", "http://[::1]/",
               "http://169.254.169.254/latest/meta-data/", "http://kubernetes.default.svc/",
               "http://claim-witness.witness-dev.svc.cluster.local/healthz", "http://10.0.0.1/"]
    site = site_factory({"/rtc.html": page(PROBE_JS.replace("TARGETS", json.dumps(targets)))})
    result = fixture_capture(site, "/rtc.html")
    rows = _rows(result.files["rendered.html"])
    assert not any("REACHED" in r for r in rows), rows
    assert sum(r.endswith("failed") for r in rows) == len(targets), rows
    assert "webrtc =&gt; done" in rows or "webrtc => done" in rows, rows
    hosts = {e.get("host") for e in result.proxy_log if e["result"] != "ok"}
    assert {"127.0.0.1", "localhost", "169.254.169.254"} <= hosts, result.proxy_log


@pytest.mark.integration
def test_hidden_elements_marked_and_listed(site_factory):
    need_sandbox()
    body = """
<p id="vis">VISIBLE-MARKER</p>
<p id="dn" style="display:none">HIDDEN-display</p>
<p id="vh" class="cls-hidden">HIDDEN-visibility</p>
<style>.cls-hidden{visibility:hidden}</style>
<p id="op" style="opacity:0">HIDDEN-opacity</p>
<p id="fs" style="font-size:0">HIDDEN-fontsize</p>
<p id="off" style="position:absolute;left:-9999px;top:0">HIDDEN-offscreen</p>
<p id="sr" style="position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0,0,0,0)">HIDDEN-clip</p>
<p id="attr" hidden>HIDDEN-attribute</p>
<div style="display:none"><span id="child">HIDDEN-child</span></div>
<p id="tr" style="color:transparent">HIDDEN-transparent</p>
<p id="vis2">ALSO-VISIBLE</p>
"""
    site = site_factory({"/hidden.html": page(body)})
    result = fixture_capture(site, "/hidden.html")
    p = Elements()
    p.feed(result.files["rendered.html"].decode())
    for el in ("vis", "vis2"):
        assert "data-witness-hidden" not in p.by_id[el], el
    for el in ("dn", "vh", "op", "fs", "off", "sr", "attr", "child", "tr"):
        assert p.by_id[el].get("data-witness-hidden") == "1", el
    nodes = json.loads(result.files["hidden-nodes.json"])
    assert all(set(n) >= {"xpath", "excerpt", "sha256"} for n in nodes)
    excerpts = {n["excerpt"]: n for n in nodes}
    assert "HIDDEN-display" in excerpts
    n = excerpts["HIDDEN-display"]
    assert n["sha256"] == hashlib.sha256(b"HIDDEN-display").hexdigest()
    assert n["xpath"].startswith("/html[1]/body[1]/p[")
    assert not any("VISIBLE-MARKER" in n["excerpt"] for n in nodes)


@pytest.mark.integration
def test_manifest_files_and_raw_body(site_factory):
    need_sandbox()
    raw = (b"<!doctype html><html><head><meta charset='windows-1252'><title>caf\xe9</title></head>"
           b"<body><p>caf\xe9 \x93quoted\x94</p><script src='/app.js'></script></body></html>")
    site = site_factory({"/w.html": (200, {"Content-Type": "text/html; charset=windows-1252"}, raw),
                         "/app.js": (200, {"Content-Type": "application/javascript"}, b"document.title += '!'")})
    t0 = time.time()
    result = fixture_capture(site, "/w.html")
    m = result.manifest
    assert m["requested_url"] == "http://fixture.test/w.html" == m["final_url"]
    assert m["status"] == 200 and m["redirects"] == []
    assert m["resolved_ips"] == [FIXTURE_IP]
    assert m["tls"] is None
    assert m["robots"] == "allowed"
    assert m["fetcher"]["viewport"] == [1280, 900] and m["fetcher"]["browser"].startswith("chromium")
    assert 0 < m["fetch_ms"] <= (time.time() - t0) * 1000 + 50
    assert result.files["response.body"] == raw
    names = [f["name"] for f in m["files"]]
    assert names == ["capture.wacz", "response.body", "screenshot.png", "rendered.html", "hidden-nodes.json"]
    for f in m["files"]:
        assert f["sha256"] == hashlib.sha256(result.files[f["name"]]).hexdigest()
        assert f["size"] == len(result.files[f["name"]])
    assert result.files["screenshot.png"][:8] == b"\x89PNG\r\n\x1a\n"
    width = int.from_bytes(result.files["screenshot.png"][16:20], "big")
    assert width == 1280
    z = zipfile.ZipFile(io.BytesIO(result.files["capture.wacz"]))
    from warcio.archiveiterator import ArchiveIterator
    got = {}
    for rec in ArchiveIterator(io.BytesIO(z.read("archive/data.warc.gz"))):
        if rec.rec_type == "response":
            got[rec.rec_headers.get_header("WARC-Target-URI")] = rec.content_stream().read()
    assert got["http://fixture.test/w.html"] == raw
    assert got["http://fixture.test/app.js"] == b"document.title += '!'"


@pytest.mark.integration
def test_redirects_recorded_and_private_redirect_blocked(site_factory):
    need_sandbox()
    site = site_factory({"/r": (302, {"Location": "/final"}, b""), "/final": page("<p>final</p>"),
                         "/evil": (302, {"Location": "http://10.0.0.5/"}, b""),
                         "/evil2": (302, {"Location": "http://meta.test/latest"}, b"")})
    result = fixture_capture(site, "/r")
    m = result.manifest
    assert m["final_url"] == "http://fixture.test/final"
    assert m["redirects"] == [{"url": "http://fixture.test/r", "status": 302, "location": "http://fixture.test/final"}]
    for path, host in (("/evil", "10.0.0.5"), ("/evil2", "meta.test")):
        with pytest.raises(C.CaptureError) as e:
            fixture_capture(site, path, extra_hosts={"meta.test": ["169.254.169.254"]})
        assert e.value.code == "blocked", path
        assert any(x.get("host") == host and x["result"] == "blocked" for x in e.value.proxy_log)


@pytest.mark.integration
def test_too_many_redirects_blocked(site_factory):
    need_sandbox()
    routes = {f"/l{i}": (302, {"Location": f"/l{i + 1}"}, b"") for i in range(10)}
    site = site_factory(routes)
    with pytest.raises(C.CaptureError) as e:
        fixture_capture(site, "/l0")
    assert e.value.code == "blocked" and "redirect" in e.value.detail


@pytest.mark.integration
def test_robots_disallowed_means_no_capture(site_factory):
    need_sandbox()
    site = site_factory({"/robots.txt": (200, {"Content-Type": "text/plain"}, b"User-agent: *\nDisallow: /private\n"),
                         "/private/x": page("<p>x</p>")})
    with pytest.raises(C.CaptureError) as e:
        fixture_capture(site, "/private/x")
    assert e.value.code == "robots-disallowed"
    assert [h[0] for h in site.hits] == ["/robots.txt"]


@pytest.mark.integration
def test_main_document_over_cap_is_too_large(site_factory):
    need_sandbox()
    big = b"<html><body>" + b"a" * 300_000 + b"</body></html>"
    site = site_factory({"/big": (200, {"Content-Type": "text/html"}, big)})
    with pytest.raises(C.CaptureError) as e:
        fixture_capture(site, "/big", settings=C.Settings(max_response_bytes=100_000))
    assert e.value.code == "too-large"


@pytest.mark.integration
def test_wall_time_cap_is_timeout(site_factory):
    need_sandbox()

    def slow(handler):
        time.sleep(12)
        return b"late"

    site = site_factory({"/slow": (200, {"Content-Type": "text/html"}, slow)})
    t0 = time.time()
    with pytest.raises(C.CaptureError) as e:
        fixture_capture(site, "/slow", settings=C.Settings(timeout_s=5))
    assert e.value.code == "timeout"
    assert time.time() - t0 < 9


@pytest.mark.integration
def test_public_url_captures_when_online():
    need_sandbox()
    if not online():
        pytest.skip("offline: example.com:443 not reachable from this machine")
    result = C.capture_sync("https://example.com/", (1280, 900), C.Settings())
    m = result.manifest
    assert m["status"] == 200
    assert m["final_url"].startswith("https://example.com/")
    assert m["tls"]["version"].startswith("TLS")
    assert len(m["tls"]["leaf_sha256"]) == 64
    assert m["resolved_ips"]
    assert m["robots"] in ("allowed", "unavailable")
    assert b"Example Domain" in result.files["response.body"]
