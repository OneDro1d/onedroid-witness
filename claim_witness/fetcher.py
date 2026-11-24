"""The witness's client for claim_fetcher (README_FETCHER.md on branch v1/claim-fetcher): POST {FETCHER_URL}/v1/capture with
X-Fetcher-Secret (read from FETCHER_SECRET_FILE), answered by a tar whose first member is manifest.json, or by 4xx JSON
{error, detail, manifest?}. The optional manifest of an error answer is the fetcher's partial manifest (requested_url,
redirects so far, fetched_at, fetch_ms, resolved_ips, robots).

Every failure becomes FetchFailed with one of the SPEC reasons the methods may give (§2.4): blocked, unreachable, timeout,
too-large, robots-disallowed. The fetcher's own failures (busy after retries, unauthorized, internal, no answer, an answer
that does not check out) are `unreachable` with code `fetcher-unavailable`, so a fetch failure is a signed CANNOT_WITNESS,
never a 5xx to the caller.
"""
import hashlib
import http.client
import io
import json
import tarfile
import time
import urllib.error
import urllib.request

REASONS = {"blocked": "blocked", "scheme": "blocked", "port": "blocked", "bad-request": "blocked",
           "robots-disallowed": "robots-disallowed", "timeout": "timeout", "too-large": "too-large", "unreachable": "unreachable"}
UNAVAILABLE = "fetcher-unavailable"
MAX_ANSWER = 64 << 20
NXDOMAIN_PREFIX = "host-not-found"


class Capture:
    __slots__ = ("manifest", "files")

    def __init__(self, manifest, files):
        self.manifest, self.files = manifest, files


class FetchFailed(Exception):
    """reason: the SPEC reason; code: the fetcher's error code (or fetcher-unavailable); detail: the fetcher's text, never
    signed; partial: the partial manifest when the fetcher sent one, else None."""

    def __init__(self, reason, code, detail="", partial=None):
        super().__init__(f"{reason} ({code}): {detail}")
        self.reason, self.code, self.detail = reason, code, str(detail or "")[:300]
        self.partial = partial if isinstance(partial, dict) else None

    @property
    def nxdomain(self):
        return self.code == "unreachable" and self.detail.startswith(NXDOMAIN_PREFIX)


class FetcherClient:
    def __init__(self, url, secret, timeout=45, busy_retries=2, busy_delay_s=1.0, sleep=time.sleep):
        self.url = url.rstrip("/")
        self.secret = secret.decode("utf-8") if isinstance(secret, bytes) else str(secret)
        self.timeout, self.busy_retries, self.busy_delay_s, self.sleep = timeout, int(busy_retries), float(busy_delay_s), sleep

    @classmethod
    def from_env(cls, env):
        """None when FETCHER_URL is unset (url evidence is then refused 503); SystemExit when the secret file is missing."""
        url = (env.get("FETCHER_URL") or "").strip()
        if not url:
            return None
        path = (env.get("FETCHER_SECRET_FILE") or "").strip()
        if not path:
            raise SystemExit("FETCHER_URL is set: FETCHER_SECRET_FILE is required too")
        with open(path, "rb") as f:
            secret = f.read().strip()
        if not secret:
            raise SystemExit("FETCHER_SECRET_FILE: the file is empty")
        return cls(url, secret, timeout=int(env.get("FETCHER_CLIENT_TIMEOUT_S") or 45))

    def _post(self, url, capture):
        body = json.dumps({"url": url, "capture": capture}).encode("utf-8")
        req = urllib.request.Request(self.url + "/v1/capture", data=body, method="POST",
                                     headers={"Content-Type": "application/json", "X-Fetcher-Secret": self.secret})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return resp.status, resp.headers.get("Content-Type", ""), resp.read(MAX_ANSWER + 1)
        except urllib.error.HTTPError as e:
            try:
                data = e.read(1 << 20)
            except (OSError, http.client.HTTPException):
                data = b""
            return e.code, e.headers.get("Content-Type", "") if e.headers else "", data
        except TimeoutError:
            raise FetchFailed("timeout", "fetcher-timeout", "the fetcher did not answer in time") from None
        except (urllib.error.URLError, OSError, http.client.HTTPException) as e:
            raise FetchFailed("unreachable", UNAVAILABLE, f"the fetcher does not answer: {type(e).__name__}") from None

    def capture(self, url, capture="page"):
        """A Capture, or FetchFailed."""
        for attempt in range(self.busy_retries + 1):
            status, ctype, data = self._post(url, capture)
            if status == 503 and attempt < self.busy_retries:
                self.sleep(self.busy_delay_s * (attempt + 1))
                continue
            break
        if status == 200:
            return _read_tar(data)
        try:
            err = json.loads(data.decode("utf-8")) if data else {}
        except (UnicodeDecodeError, ValueError):
            err = {}
        code = err.get("error") if isinstance(err, dict) else None
        detail = err.get("detail", "") if isinstance(err, dict) else ""
        partial = err.get("manifest") if isinstance(err, dict) else None
        if code in REASONS:
            raise FetchFailed(REASONS[code], code, detail, partial)
        raise FetchFailed("unreachable", UNAVAILABLE, f"fetcher answered {status} {code or ''}".strip(), partial)


def _read_tar(data):
    if len(data) > MAX_ANSWER:
        raise FetchFailed("too-large", "too-large", "the capture is larger than the witness accepts")
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as tf:
            members = tf.getmembers()
            if not members or members[0].name != "manifest.json":
                raise ValueError("manifest.json is not the first member")
            blobs = {}
            for m in members:
                if not m.isfile() or "/" in m.name or m.name.startswith(".") or m.name in blobs:
                    raise ValueError(f"unexpected member {m.name!r}")
                blobs[m.name] = tf.extractfile(m).read()
        manifest = json.loads(blobs.pop("manifest.json").decode("utf-8"))
        if not isinstance(manifest, dict) or not isinstance(manifest.get("files"), list):
            raise ValueError("manifest without files")
        listed = {}
        for e in manifest["files"]:
            name, sha = e.get("name"), e.get("sha256")
            if name not in blobs or hashlib.sha256(blobs[name]).hexdigest() != sha:
                raise ValueError(f"file {name!r} does not match the manifest")
            listed[name] = blobs[name]
        if set(listed) != set(blobs):
            raise ValueError("the tar holds files the manifest does not list")
        for k in ("requested_url", "final_url", "fetched_at", "status"):
            if k not in manifest:
                raise ValueError(f"manifest without {k}")
    except (tarfile.TarError, ValueError, UnicodeDecodeError, AttributeError, TypeError) as e:
        raise FetchFailed("unreachable", UNAVAILABLE, f"the fetcher's answer does not check out: {e}") from None
    return Capture(manifest, listed)
