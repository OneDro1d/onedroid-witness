"""The egress proxy: the browser's only way out of its namespace. Standard library asyncio.

- It listens ONLY on a Unix socket (mode 0600, in a 0700 directory made per capture), never on TCP, so no other pod
  and no other local user can use it as a proxy.
- CONNECT host:port (https, and anything tunnelled) and plain HTTP in absolute form (GET http://host/path).
- Every request is checked from the start (addr.check_url / addr.vet_host): the host is resolved exactly once, every
  address must be allowed, and the connection goes to a vetted address (pinned), never to a name. A redirect is a new
  request from the browser, so it is checked the same way; DNS rebinding between requests changes nothing.
- Refusals: a CONNECT gets 403 (502 for unreachable) with X-Fetcher-Refused: <code>, which Chromium reports as a tunnel
  failure. A plain-HTTP request is refused by closing the connection without a byte: an answer from the proxy would
  look to page script like an answer from the origin (a no-cors fetch would resolve), a closed connection is a network
  error.
- Caps: a plain-HTTP response over max_response_bytes is cut; all bytes sent back to the browser in one capture are
  capped at max_total_bytes, after which every tunnel is cut. Either sets `too_large`.
Every request leaves one entry in `log`; `resolved` maps each host to the addresses it was vetted with.
"""
import asyncio
import contextlib
import os
import urllib.parse

from . import addr

CHUNK = 65536
HOP_HEADERS = {"proxy-connection", "proxy-authorization", "proxy-authenticate", "connection", "keep-alive", "te",
               "trailer", "upgrade"}
MAX_REQUEST_BODY = 2 * 1024 * 1024


async def default_connector(ip, port):
    return await asyncio.open_connection(ip, port)


class EgressProxy:
    def __init__(self, socket_path, resolver=None, connector=None, extra_cidrs=(), max_response_bytes=10 * 1024 * 1024,
                 max_total_bytes=30 * 1024 * 1024, connect_timeout=5.0, resolve_timeout=5.0, head_timeout=10.0):
        self.socket_path = socket_path
        self.resolver = resolver
        self.connector = connector or default_connector
        self.extra = tuple(extra_cidrs)
        self.max_response_bytes, self.max_total_bytes = max_response_bytes, max_total_bytes
        self.connect_timeout, self.resolve_timeout, self.head_timeout = connect_timeout, resolve_timeout, head_timeout
        self.log, self.resolved = [], {}
        self.bytes_down = 0
        self.too_large = False
        self.server = None
        self._writers = set()

    # lifecycle ------------------------------------------------------------------------------------------------------

    async def start(self):
        old = os.umask(0o177)
        try:
            self.server = await asyncio.start_unix_server(self._handle, path=self.socket_path)
        finally:
            os.umask(old)
        os.chmod(self.socket_path, 0o600)
        return self

    async def close(self):
        if self.server is not None:
            self.server.close()
        for w in list(self._writers):
            with contextlib.suppress(Exception):
                w.close()
        if self.server is not None:
            with contextlib.suppress(Exception):
                await asyncio.wait_for(self.server.wait_closed(), 2)
        with contextlib.suppress(FileNotFoundError):
            os.unlink(self.socket_path)

    # helpers ----------------------------------------------------------------------------------------------------------

    def _track(self, *writers):
        for w in writers:
            self._writers.add(w)

    def _untrack(self, *writers):
        for w in writers:
            self._writers.discard(w)
            with contextlib.suppress(Exception):
                w.close()

    async def _vet(self, host, port):
        loop = asyncio.get_running_loop()
        try:
            ips = await asyncio.wait_for(
                loop.run_in_executor(None, addr.vet_host, host, port, self.resolver, self.extra), self.resolve_timeout)
        except asyncio.TimeoutError:
            raise addr.Refused("unreachable", f"resolve-timeout {host}") from None
        self.resolved[host] = list(ips)
        return ips

    async def _dial(self, ips, port):
        last = None
        for ip in ips:
            try:
                r, w = await asyncio.wait_for(self.connector(ip, port), self.connect_timeout)
                return ip, r, w
            except (OSError, asyncio.TimeoutError) as e:
                last = e
        raise addr.Refused("unreachable", f"connect-failed {type(last).__name__ if last else ''}".strip())

    def _budget(self, n):
        """True when n more bytes may go back to the browser."""
        if self.bytes_down + n > self.max_total_bytes:
            self.too_large = True
            return False
        self.bytes_down += n
        return True

    @staticmethod
    async def _respond(writer, status, reason, code=None):
        extra = f"X-Fetcher-Refused: {code}\r\n" if code else ""
        writer.write(f"HTTP/1.1 {status} {reason}\r\n{extra}Content-Length: 0\r\nConnection: close\r\n\r\n".encode())
        with contextlib.suppress(Exception):
            await writer.drain()

    # dispatch ---------------------------------------------------------------------------------------------------------

    async def _handle(self, reader, writer):
        self._track(writer)
        try:
            try:
                head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), self.head_timeout)
            except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, asyncio.TimeoutError, ConnectionError):
                return
            lines = head.decode("latin-1").split("\r\n")
            parts = lines[0].split(" ")
            if len(parts) != 3 or not parts[2].startswith("HTTP/"):
                await self._respond(writer, 400, "Bad Request")
                return
            method, target, _version = parts
            headers = []
            for line in lines[1:]:
                if not line:
                    continue
                k, sep, v = line.partition(":")
                if not sep:
                    await self._respond(writer, 400, "Bad Request")
                    return
                headers.append((k.strip(), v.strip()))
            if method.upper() == "CONNECT":
                await self._connect(reader, writer, target)
            elif "://" in target:
                await self._http(reader, writer, method, target, headers)
            else:
                # origin form ("GET / HTTP/1.1"): only page script dialling the bridge port directly sends this.
                # Closed without a byte, so it is a network error, never a response the page could read.
                self.log.append({"kind": "origin-form", "host": None, "port": None, "ips": None, "pinned": None,
                                 "result": "blocked", "detail": "origin-form request", "bytes_down": 0})
        except Exception:  # noqa: BLE001 - one broken connection must never take the proxy down
            pass
        finally:
            self._untrack(writer)

    # CONNECT ----------------------------------------------------------------------------------------------------------

    async def _connect(self, reader, writer, target):
        host, sep, port_s = target.rpartition(":")
        if not sep or not host or not port_s.isdigit():
            await self._respond(writer, 400, "Bad Request")
            return
        host = host[1:-1] if host.startswith("[") and host.endswith("]") else host
        host, port = host.lower(), int(port_s)
        entry = {"kind": "connect", "host": host, "port": port, "ips": None, "pinned": None, "result": None,
                 "detail": "", "bytes_down": 0}
        self.log.append(entry)
        try:
            ips = await self._vet(host, port)
            entry["ips"] = ips
            ip, ur, uw = await self._dial(ips, port)
        except addr.Refused as e:
            entry["result"], entry["detail"] = e.code, e.detail
            await self._respond(writer, 502 if e.code == "unreachable" else 403,
                                "Bad Gateway" if e.code == "unreachable" else "Forbidden", e.code)
            return
        entry["pinned"], entry["result"] = ip, "ok"
        self._track(uw)
        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()
        try:
            await self._splice(reader, writer, ur, uw, entry)
        finally:
            self._untrack(uw)

    async def _splice(self, cr, cw, ur, uw, entry):
        async def up():
            with contextlib.suppress(Exception):
                while True:
                    data = await cr.read(CHUNK)
                    if not data:
                        break
                    uw.write(data)
                    await uw.drain()
            with contextlib.suppress(Exception):
                uw.write_eof()

        async def down():
            with contextlib.suppress(Exception):
                while True:
                    data = await ur.read(CHUNK)
                    if not data:
                        break
                    if not self._budget(len(data)):
                        entry["result"], entry["detail"] = "too-large", "capture byte budget"
                        break
                    entry["bytes_down"] += len(data)
                    cw.write(data)
                    await cw.drain()

        t_up, t_down = asyncio.ensure_future(up()), asyncio.ensure_future(down())
        await t_down
        t_up.cancel()
        with contextlib.suppress(BaseException):
            await t_up

    # plain HTTP -------------------------------------------------------------------------------------------------------

    async def _http(self, reader, writer, method, target, headers):
        entry = {"kind": "http", "url": target, "host": None, "port": None, "ips": None, "pinned": None,
                 "result": None, "detail": "", "bytes_down": 0}
        self.log.append(entry)
        try:
            scheme, host, port = addr.check_url(target)
            entry["host"], entry["port"] = host, port
            if scheme != "http":
                raise addr.Refused("scheme", "absolute-form proxying is for http only")
            ips = await self._vet(host, port)
            entry["ips"] = ips
            ip, ur, uw = await self._dial(ips, port)
        except addr.Refused as e:
            entry["result"], entry["detail"] = e.code, e.detail
            return  # closed without a byte: page script sees a network error
        entry["pinned"], entry["result"] = ip, "ok"
        self._track(uw)
        try:
            await self._forward(reader, writer, method, target, headers, host, port, ur, uw, entry)
        finally:
            self._untrack(uw)

    async def _forward(self, reader, writer, method, target, headers, host, port, ur, uw, entry):
        parts = urllib.parse.urlsplit(target)
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        length = 0
        out = [f"{method} {path} HTTP/1.1"]
        for k, v in headers:
            lk = k.lower()
            if lk in HOP_HEADERS or lk == "host":
                continue
            if lk == "transfer-encoding":
                entry["result"], entry["detail"] = "blocked", "chunked request body"
                return
            if lk == "content-length":
                length = int(v) if v.isdigit() else -1
            out.append(f"{k}: {v}")
        if length < 0 or length > MAX_REQUEST_BODY:
            entry["result"], entry["detail"] = "blocked", "request body"
            return
        host_header = f"[{host}]" if ":" in host else host
        if port != 80:
            host_header += f":{port}"
        out.insert(1, f"Host: {host_header}")
        out.append("Connection: close")
        uw.write(("\r\n".join(out) + "\r\n\r\n").encode("latin-1"))
        if length:
            uw.write(await reader.readexactly(length))
        await uw.drain()
        try:
            head = await asyncio.wait_for(ur.readuntil(b"\r\n\r\n"), self.head_timeout)
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, asyncio.TimeoutError, ConnectionError):
            entry["result"], entry["detail"] = "unreachable", "no response head"
            return
        lines = head.decode("latin-1").split("\r\n")
        declared = None
        kept = [lines[0]]
        for line in lines[1:]:
            if not line:
                continue
            k, _, v = line.partition(":")
            lk = k.strip().lower()
            if lk in ("connection", "keep-alive", "proxy-connection"):
                continue
            if lk == "content-length" and v.strip().isdigit():
                declared = int(v.strip())
            kept.append(line)
        if declared is not None and declared > self.max_response_bytes:
            entry["result"], entry["detail"] = "too-large", f"content-length {declared}"
            self.too_large = True
            return
        kept.append("Connection: close")
        out_head = ("\r\n".join(kept) + "\r\n\r\n").encode("latin-1")
        if not self._budget(len(out_head)):
            entry["result"], entry["detail"] = "too-large", "capture byte budget"
            return
        writer.write(out_head)
        body = 0
        while True:
            data = await ur.read(CHUNK)
            if not data:
                break
            body += len(data)
            if body > self.max_response_bytes:
                entry["result"], entry["detail"] = "too-large", "response body"
                self.too_large = True
                break
            if not self._budget(len(data)):
                entry["result"], entry["detail"] = "too-large", "capture byte budget"
                break
            entry["bytes_down"] += len(data)
            writer.write(data)
            await writer.drain()
        with contextlib.suppress(Exception):
            await writer.drain()
