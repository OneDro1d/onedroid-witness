# claim-fetcher (slice B2a)

The claim witness's page fetcher: a small HTTP service, called only by the witness, that opens one web page in Chromium
and returns what it observed: the archive, the raw bytes, a screenshot, the rendered DOM with hidden elements marked,
and a manifest (SPEC §2.3) with every file's sha256 and size.

Package `claim_fetcher/`, image `Dockerfile.fetcher`, dev manifest `k8s/fetcher-dev.yaml`, tests `tests_fetcher/`.

## API

```
POST /v1/capture    {"url": "https://…", "capture": "page", "viewport": [1280, 900]}
                    header X-Fetcher-Secret: <the shared secret>
  200 application/x-tar   manifest.json first, then capture.wacz, response.body, screenshot.png, rendered.html,
                          hidden-nodes.json
  4xx application/json    {"error": <code>, "detail": "…"}                      refused before any request
                          {"error": <code>, "detail": "…", "manifest": {…}}     after at least one request
GET  /healthz       {"ok": true, "selftest": {…}}
```

**Error answers carry a partial manifest** once at least one request was made (robots.txt counts; a refusal of the URL
or its host before anything was fetched has none):

```json
{"error": "blocked", "detail": "blocked 169.254.169.254: address-not-public 169.254.169.254",
 "manifest": {"requested_url": "https://postman-echo.com/redirect-to?url=http://169.254.169.254/",
              "redirects": [{"url": "https://postman-echo.com/redirect-to?url=http://169.254.169.254/",
                             "status": 302, "location": "http://169.254.169.254/"}],
              "fetched_at": "2026-11-24T10:41:07Z", "fetch_ms": 1204, "resolved_ips": ["…"],
              "robots": "allowed",
              "robots_txt": {"url": "https://postman-echo.com/robots.txt", "status": 404, "sha256": "…"}}}
```

- `redirects`: the main document's hops recorded so far, so a hop the proxy refused still leaves the hop before it (its
  URL, status and `Location`) on record; the refused hop itself is never fetched.
- `resolved_ips`: the addresses vetted so far for the hosts of that chain (the first host's, then each later hop's).
- `robots`: `allowed` | `disallowed` | `unavailable`, or `null` when the error came before robots.txt was decided.
- `robots_txt`: `{url, status, sha256}` of the robots.txt that was read (`url` after its own redirects, `sha256` over
  the bytes kept, at most 512 KiB), or `null` when none could be read.
- The service's log line (`capture-refused`) records the code, the detail, the redirect chain, robots and fetch_ms; the
  success line (`capture`) records the redirect chain too.

| code | HTTP | meaning |
|---|---|---|
| `bad-request` | 400 | not JSON, no url, url over 4096 chars, `capture` other than `page`, bad viewport |
| `scheme` | 400 | not http or https (checked before anything else runs) |
| `port` | 400 | a port other than 80 or 443 |
| `unauthorized` | 401 | missing or wrong secret (`hmac.compare_digest`) |
| `blocked` | 403 | the host or an address it resolves to is not public, credentials in the URL, a redirect to such a place, more than 5 redirects |
| `robots-disallowed` | 403 | robots.txt disallows the path for `OneDroidWitness` (partial manifest: `"robots": "disallowed"`) |
| `timeout` | 408 | the 15 s wall time ran out, or the main document's connect got no answer (no SYN-ACK within 5 s) on every vetted address |
| `too-large` | 413 | the main document is over 10 MB, or the capture's byte budget (30 MB) ran out |
| `unreachable` | 422 | the host does not resolve (NXDOMAIN or no address from the public resolvers), or a vetted address refused the connection |
| `busy` | 503 | more than `FETCHER_MAX_CONCURRENT` (2) captures at once |

The manifest: `requested_url, final_url, redirects [{url, status, location}], fetched_at, fetch_ms, status,
resolved_ips` (the vetted addresses of the final host), `tls {version, leaf_sha256}` (null over http), `robots`
(`allowed` | `disallowed` | `unavailable`), `fetcher {id, version, browser, viewport, user_agent, isolation}`, and
`files [{name, sha256, size, media_type}]`.

Files:
- `capture.wacz`: WACZ 1.1.1, built by hand with `warcio` WARC records: `archive/data.warc.gz` (warcinfo, then a
  response and a request record per exchange; bodies decoded, original `Content-Encoding` kept as
  `X-Archive-Orig-Content-Encoding`), `indexes/index.cdx` (CDXJ, sorted, offsets checked by the tests),
  `pages/pages.jsonl`, `datapackage.json` (sha256 and size per file) and `datapackage-digest.json`. It is deterministic:
  the same exchanges give the same bytes.
- `response.body`: the main document's bytes exactly as received (content-decoded, never charset-decoded), read through
  the DevTools Fetch domain at the Response stage.
- `screenshot.png`: full page at the viewport width (1280), capped at 16384 px high.
- `rendered.html`: the DOM after load (plus up to 5 s for scripts to settle), every element that is not visible carrying
  `data-witness-hidden="1"`.
- `hidden-nodes.json`: `[{xpath, excerpt, sha256, reason}]` for the marked elements; `sha256` is over the element's
  whole whitespace-normalised text, `excerpt` its first 200 characters.

"Not visible" (`claim_fetcher/hidden.js`): `display:none`, the `hidden` attribute, `visibility:hidden|collapse`,
`opacity:0` (on it or an ancestor, through `checkVisibility()`), `font-size:0`, a transparent text colour, a text colour
equal to the opaque background behind it, a box wholly left of or above the page, the 1x1 `sr-only` pattern, and own
text whose rendered boxes keep no area after clipping by every clipping ancestor (`overflow:hidden|clip`, `clip`,
`clip-path: inset()`), which covers `height:0` containers, `text-indent:-9999px`, `clip-path: inset(50%)` and
`transform: scale(0)`.

## Isolation (ARCHITECTURE §4 TB2)

The cluster refuses `NET_ADMIN` and does not enforce NetworkPolicy, so the pod cannot firewall itself. Instead:

```
 pod network namespace                       | worker: user + network + mount namespace (unshare, unprivileged)
                                             |   only `lo`
 API :8090 ── capture ── EgressProxy         |
                         (asyncio, Unix      |   bridge 127.0.0.1:<random> ── Unix socket ──┐
                          socket only, 0600, |        ▲                                      │
                          in a 0700 tmp dir) |        │ HTTP proxy                           │
                            ▲                |   Chromium (headless shell)                  │
                            └─────────────── Unix socket (the one way out) ◄────────────────┘
                            │
                            └── resolves once, vets every address, dials the pinned IP on 80/443 → internet
```

- **The worker** (`claim_fetcher/sandbox.py`) is started by `nsrun` as
  `unshare --user --net --map-root-user --mount --propagation unchanged -- python -m claim_fetcher.sandbox capture`,
  in its own process group (killed whole at the deadline) with a minimal environment (no secret path, no tokens). In
  its new network namespace the only interface is `lo`, which it brings up. It opens a TCP listener on
  127.0.0.1:<random> that bridges each connection over the Unix socket to the egress proxy outside, and starts Chromium
  with that listener as its HTTP proxy. Playwright forces loopback through the proxy too (`<-loopback>`), so even
  `http://127.0.0.1/` goes to the proxy, which refuses it.
- **Browser flags:** `--force-webrtc-ip-handling-policy=disable_non_proxied_udp`,
  `--webrtc-ip-handling-policy=disable_non_proxied_udp`, `--disable-quic`, `--dns-prefetch-disable`,
  `--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE 127.0.0.1` (the browser never resolves a name itself), plus
  background networking, component update, sync, pings and DoH off. Service workers are blocked, downloads refused.
  Even with every flag ignored, page script (WebRTC, QUIC, direct sockets) meets a namespace with no route anywhere.
- **The egress proxy** (`claim_fetcher/proxy.py`) runs outside the namespace and listens **only on the Unix socket**,
  never on TCP, so no other pod can use it. CONNECT (https) and plain HTTP in absolute form. For every request (and so
  for every redirect, which is a new request) it resolves the host once, refuses unless every address is allowed, and
  dials the vetted address, never the name. A refused CONNECT gets 403/502/504 with `X-Fetcher-Refused: <code>`; a
  refused plain-HTTP or origin-form request is closed without a byte, so page script sees a network error, never an
  answer it could read.
- **DNS** (`claim_fetcher/dnsclient.py`): names are resolved only through the configured **public** resolvers
  (`FETCHER_RESOLVERS`, default `1.1.1.1,8.8.8.8`), queried directly: A, then AAAA, over UDP, retried over TCP when the
  answer is truncated; the next resolver when one does not answer or answers SERVFAIL/REFUSED. The system resolver
  (`getaddrinfo`) is never called for a capture target, robots.txt included, so no query goes to the pod's cluster DNS
  service (a private address). Each resolver must itself pass the address rules below (public, outside
  `FETCHER_BLOCKED_CIDRS`), or the service refuses to start. The query name is absolute (there is no search list).
  NXDOMAIN is `unreachable`. An answer is used only when its ID, flags and question match the query, and only the
  addresses on the CNAME chain from the asked name count.
- **Address rules** (`claim_fetcher/addr.py`, a superset of the argus-claims toolkit's `fetch.py` `is_public` and
  `_vet`, the egress guard onedroid-audit's `external_fetcher` uses: resolve once, every address global and outside the
  refused ranges, dial only vetted addresses; one difference: the toolkit refuses every IPv4-mapped address, this judges
  it as the IPv4 it carries): refused are this-network, RFC 1918, CGNAT 100.64/10, loopback, link-local
  (metadata 169.254.169.254), the Azure wire server 168.63.129.16, the IETF and TEST-NETs, benchmarking, multicast,
  reserved and broadcast; IPv6 unspecified, loopback, link-local, unique-local, site-local, multicast, documentation and
  discard. IPv4-mapped IPv6 is judged as its IPv4; every other IPv4-carrying form (compat `::/96`, NAT64 `64:ff9b::/96`
  and `64:ff9b:1::/48`, 6to4 `2002::/16`, Teredo `2001::/32`) is refused outright. Plus `FETCHER_BLOCKED_CIDRS` (the
  cluster's own ranges), in every form. Names are refused before DNS when they are single-label or end in `localhost`,
  `local`, `localdomain`, `internal`, `home.arpa`, `lan`, `svc` or `cluster.local`; numeric hosts in every legacy form
  (`2130706433`, `0x7f000001`, `017700000001`, `127.1`) are judged without DNS. A mixed answer (one public, one private
  address) is refused. Ports 80 and 443 only; http and https only; no credentials in URLs; at most 5 redirects.
- **Caps:** 10 MB per response (the proxy cuts plain-HTTP responses; for https the browser-side recorder stops the main
  document), 30 MB of bytes back to the browser per capture (every tunnel is then cut), 15 s wall time for the whole
  capture, robots.txt included.
- **Secrets out of reach:** the worker runs under the service's own uid. The service makes itself non-dumpable
  (`PR_SET_DUMPABLE 0`) once it holds the secret, so the worker can neither ptrace it nor read its `/proc/<pid>/mem`.
  The worker also covers the secret's directory and `/var/run/secrets/kubernetes.io` with an empty read-only tmpfs in
  its own mount namespace, where the host allows `mount(2)` (see Known limits). The dev manifest also mounts no
  service-account token at all.

## Self-test

At start, before the API listens, the service runs the worker in a fresh namespace (`run_selftest`), which:
1. covers the hidden paths and reports each as `hidden`, `absent` or `failed: <errno>`;
2. reads `/proc/net/dev` inside the namespace: it must list only `lo`;
3. connects directly to 10.0.0.1:80, 169.254.169.254:80, 172.16.0.1:443, 192.168.0.1:80, 100.64.0.1:80, 1.1.1.1:443,
   8.8.8.8:53, [2606:4700:4700::1111]:443, and to a listener the service opens on the pod's own address outside the
   namespace (a private address that really answers): every connect must fail, and the listener must see no connection;
4. sends `CONNECT 10.0.0.1:443` through the bridge: the proxy must refuse it;
5. starts Chromium through the bridge and runs a page-script `fetch("http://10.0.0.1/")`: it must fail;
6. lists the DNS resolvers in use (`"resolvers": ["1.1.1.1", "8.8.8.8"]`); a resolver that fails the address rules
   fails the self-test (and `FETCHER_RESOLVERS` with one already stops the start).

The result is logged as one JSON line (`selftest {...}`); if it did not pass, the service exits with status 3 and never
serves. `/healthz` returns it. To run it alone:

```
python -m claim_fetcher --selftest-only            # prints the JSON, exit 0 if it passed
python -m claim_fetcher --capture https://example.com/ --out /tmp/x   # one capture, manifest printed, files written
```

## Tests

```
python3 -m venv .venv
.venv/bin/pip install -r requirements-fetcher.txt pytest
.venv/bin/python -m playwright install chromium
.venv/bin/python -m pytest -q tests_fetcher                    # everything
.venv/bin/python -m pytest -q tests_fetcher -m "not integration"   # no namespace or browser needed
```

The integration tests (marker `integration`) run the real namespace, bridge, proxy and browser, and skip with the
reason when `unshare` cannot make a user + network namespace, Chromium is missing, or (for the example.com test) the
machine is offline. The fixture site is given a public address by a fake resolver, and the proxy's outbound connector
carries that pinned address to a local test server: that is the one seam; everything from the page to the last hop is
real. The isolation tests start a server on this machine's own private address and prove that page script (fetch, img,
iframe, WebRTC) cannot reach it, nor 127.0.0.1, localhost, [::1], the metadata address, `kubernetes.default.svc` or
the cluster DNS names.

## Configuration (env)

| variable | default | |
|---|---|---|
| `FETCHER_SECRET_FILE` | (required) | file holding the shared secret |
| `FETCHER_BLOCKED_CIDRS` | empty | the cluster's CIDRs, comma or space separated; unparsable (the placeholder) stops the start |
| `FETCHER_PORT`, `FETCHER_HOST` | 8090, 0.0.0.0 | the API |
| `FETCHER_RESOLVERS` | `1.1.1.1,8.8.8.8` | public DNS resolvers (IP addresses, comma or space separated); one that is not public or lies in `FETCHER_BLOCKED_CIDRS` stops the start |
| `FETCHER_CONNECT_TIMEOUT_S` | 5 | per vetted address; no SYN-ACK on every one of the main document's is `timeout` |
| `FETCHER_TIMEOUT_S` | 15 | wall time per capture |
| `FETCHER_MAX_RESPONSE_BYTES` | 10485760 | per response |
| `FETCHER_SETTLE_MS` | 5000 | wait after load for scripts, within the wall time |
| `FETCHER_MAX_CONCURRENT` | 2 | captures at once |
| `FETCHER_ROBOTS_UNAVAILABLE` | allow | `deny` refuses a capture when robots.txt cannot be read |
| `FETCHER_HIDE_PATHS` | | extra directories to cover in the worker, colon separated |
| `FETCHER_REQUIRE_HIDDEN` | off | `1`: a path that cannot be covered fails the self-test |
| `FETCHER_WORK_DIR` | system tmp | per-capture private directories |
| `FETCHER_USER_AGENT` | derived | override the user agent |

## Deploying (dev)

`k8s/fetcher-dev.yaml`: Deployment `claim-fetcher` and Service `claim-fetcher` (port 80 to 8090) in `witness-dev`. The
orchestrator fills `IMAGE_PLACEHOLDER` and `CLUSTER_CIDRS_PLACEHOLDER` and creates the Secret `claim-fetcher-secret`
(key `secret`). No capability is added (`drop: ALL`, no privilege escalation, read-only root, non-root uid 10001). The
user namespace works unprivileged because **the default seccomp in these pods is Unconfined** (measured by the
orchestrator on witness-dev, 24 Nov 2026); the manifest therefore sets no `seccompProfile`. `RuntimeDefault` would
refuse `unshare(CLONE_NEWUSER)`, and the self-test would then keep the pod from serving, which is the intended
failure.

`FETCHER_RESOLVERS` is set to `1.1.1.1,8.8.8.8` in the manifest: the pod needs outbound UDP and TCP port 53 to those
addresses. The pod's own `/etc/resolv.conf` (the cluster DNS service) is never used for capture targets.

## Builder decisions

1. **Error codes to HTTP:** `scheme`, `port`, `bad-request` 400; `blocked`, `robots-disallowed` 403; `timeout` 408;
   `too-large` 413; `unreachable` 422; `busy` 503; `unauthorized` 401. Too many redirects is `blocked` with
   "too-many-redirects" in the detail.
2. **The answer is a tar** (`application/x-tar`, PAX, mtime 0), `manifest.json` first. Simpler to stream and verify
   than multipart.
3. **robots.txt unavailable** (5xx, network failure, refusal) means the capture goes ahead and the manifest says
   `unavailable`; 4xx (including 401 and 403) means `allowed`, per RFC 9309 2.3.1.3. A one-off fetch of a user-named URL
   is not crawling; `FETCHER_ROBOTS_UNAVAILABLE=deny` makes it a refusal. robots.txt is read through the same proxy,
   outside the namespace, by the service (it needs no browser).
4. **resolved_ips** are the vetted addresses of the final host, in resolver order; the proxy dials the first that
   accepts.
5. **tls** comes from the browser (DevTools `securityDetails.protocol`, written `TLS1.3`, and `Network.getCertificate`,
   whose first entry is the leaf DER): the proxy only tunnels https and never sees inside it. `null` over http.
6. **response.body** is read at the DevTools Fetch Response stage for main-frame documents (exact bytes, any charset);
   `Network.getResponseBody` is the fallback.
7. **Byte caps:** 10 MB per response as SPEC §8 says; a 30 MB per-capture budget on top, so a page cannot pull an
   unbounded number of 10 MB subresources inside 15 s. Subresource bodies over 10 MB are archived without a body.
8. **Hidden-path covering** is best effort by default and a gate only with `FETCHER_REQUIRE_HIDDEN=1`: the
   containerd AppArmor profile, which pods run under by default, refuses `mount(2)` (measured on the build host:
   EACCES). The self-test always records the result, and `readable` (mounted, yet contents visible) always fails it.
9. **`--propagation unchanged`** for the mount namespace: `private` needs a remount the build host refused ("cannot
   change root filesystem propagation: Permission denied"). Mounts copied into a namespace owned by a less privileged
   user namespace become slaves, so nothing propagates out either way.
10. **User agent:** a desktop Chrome string with the browser's real version, then
    `OneDroidWitness/1.0 (+https://onedroid.ai/witness)`; robots.txt is read with the token alone. Matching robots
    groups use the token `OneDroidWitness`.
11. **Viewport** range 320-3840 x 240-4320; default 1280x900. Screenshots are full page at the viewport width, cut at
    16384 px high.
12. **Settle time:** after `load`, up to 5 s more for scripts, always inside the 15 s wall time.
13. **Extra manifest fields** beyond the brief: `fetcher.user_agent`, `fetcher.isolation`, and `media_type` per file
    (`response.body` takes the main response's MIME type).
14. **Single-label and internal names** are refused by name before DNS (defence in depth; their addresses would be
    refused anyway).

Decisions for the four acceptance defects of 24 Nov 2026 (D1-D4; tests `tests_fetcher/test_acceptance_fixes.py`):

15. **A small stdlib DNS client, not dnspython** (D1): `claim_fetcher/dnsclient.py`, about 200 lines, so no new
    dependency enters the image and every byte on the wire is in this repo. It sends one question per query (RD set,
    no EDNS), a random 16-bit ID from `secrets`, over a connected UDP socket (only the resolver's own datagrams are
    read; the kernel picks a random source port), checks the reply's ID, QR, opcode and question, and retries over TCP
    only when the reply is truncated (TC). It asks A, then AAAA, of the first resolver; a timeout, SERVFAIL or a
    malformed reply moves to the next resolver; 2 s per try, 4 s per name (inside the proxy's 5 s resolve limit).
    NXDOMAIN is final (no second opinion). If A answers but AAAA fails on every resolver, the A addresses are used.
    Addresses are returned A first: the pod has no IPv6 egress to fall back from.
16. **Only the CNAME chain counts** (D1): addresses whose owner name is not on the chain from the asked name are ignored,
    so a stray record in an answer cannot add an address.
17. **`addr.resolve` (getaddrinfo) is kept but unused** (D1): its existing unit test stays as it was; nothing on the
    capture path calls it (`vet_host`, the proxy and the capture all take a `PublicResolver`, and `vet_host` without a
    resolver falls back to the default public resolvers). Two tests replace `socket.getaddrinfo` with a spy that answers
    nothing and assert it is never called during a capture (one with the real namespace and Chromium).
18. **Resolvers are checked twice** (D1): `Settings.from_env` refuses a resolver that is not public or lies in
    `FETCHER_BLOCKED_CIDRS` (the service exits 2 before the self-test), and `PublicResolver` refuses one at construction
    (the self-test fails with the reason if a hand-made `Settings` slips one through).
19. **The partial manifest** (D2, D4) has exactly the brief's fields plus `robots_txt {url, status, sha256}` (null when
    robots.txt could not be read). The success manifest is unchanged (no `robots_txt`), so the witness's existing reader
    is not affected. `resolved_ips` there are the vetted addresses of every host on the chain so far, where the success
    manifest gives the final host's only.
20. **The redirect hops come from the browser** (D2): the worker now returns the main document's recorded hops with
    every failure, not only with success. Chromium reports a redirect (`requestWillBeSent` with `redirectResponse`)
    before it asks the proxy for the next hop, so a hop the proxy refuses leaves the hop before it on record. A worker
    killed at the wall time returns nothing: its partial manifest then has no hops.
21. **A dropped connection is `timeout`** (D3) when the proxy's last attempt at the main document's current hop (the
    last URL of its chain) timed out on every vetted address; one refused address in the mix keeps it `unreachable`.
    The proxy answers such a CONNECT with 504 and `X-Fetcher-Refused: timeout` (a plain-HTTP request is still closed
    without a byte). The 5 s connect limit and the 15 s wall time are unchanged: for `http://8.8.4.4/` robots.txt and
    the page each wait 5 s, so the answer is a 408 after about 11 s. A robots.txt connect timeout alone is still
    `unavailable` (decision 3).

## Known limits

- **Chromium's own sandbox is off** (`--no-sandbox`, Playwright's default): inside the worker's user namespace,
  Chromium's namespace sandbox fails to start on the build host ("Chromium sandboxing failed!"). A renderer exploit
  therefore runs as the worker: it still has no network but the proxy, but it can read what the uid can read where
  mount covering is refused. The secret only lets a caller ask for captures. Revisit with a seccomp-only Chromium
  sandbox or a host that allows it.
- On https, the 10 MB per-response cap for subresources is enforced in the browser recorder, not at the proxy (it sees
  only the tunnel); the 30 MB per-capture budget is enforced at the proxy.
- `text.canonical.txt` and `platform.json` (SPEC §2.3) are not produced here: the canonicaliser and the social `post`
  capture belong to later slices.
