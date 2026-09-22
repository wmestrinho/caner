"""HTTP surface: a background scan loop plus a tiny read-only JSON API."""

from __future__ import annotations

import json
import os
import secrets
import threading
import time
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from . import __version__, crashscan, netscan, procscan

WEB_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "web")
CONTENT_TYPES = {".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8",
                 ".css": "text/css; charset=utf-8", ".svg": "image/svg+xml"}


def self_rss_mb() -> float:
    try:
        with open("/proc/self/status", encoding="utf-8") as handle:
            for line in handle:
                if line.startswith("VmRSS:"):
                    return round(int(line.split()[1]) / 1024, 1)
    except OSError:
        pass
    return 0.0


class Cache:
    """Last good result per scanner, with the error if the latest attempt failed."""

    def __init__(self):
        self._lock = threading.Lock()
        self._data: dict[str, dict] = {}

    def put(self, name: str, payload: dict, error: str = "") -> None:
        with self._lock:
            entry = self._data.setdefault(name, {})
            if not error:
                entry["data"] = payload
                entry["updated"] = time.time()
            entry["error"] = error

    def get(self, name: str) -> dict:
        with self._lock:
            entry = self._data.get(name, {})
            return {"data": entry.get("data"), "updated": entry.get("updated"),
                    "error": entry.get("error", ""),
                    "age_s": round(time.time() - entry["updated"], 1) if entry.get("updated") else None}

    def snapshot(self) -> dict:
        return {name: self.get(name) for name in ("proc", "crash", "net")}


class Scanner(threading.Thread):
    daemon = True

    def __init__(self, cache: Cache, cfg: dict):
        super().__init__(name="caner-scan")
        self.cache, self.cfg = cache, cfg
        self.stop_event = threading.Event()
        self._force = threading.Event()

    def force(self) -> None:
        self._force.set()

    def run(self) -> None:
        intervals = self.cfg["intervals_s"]
        next_at = {name: 0.0 for name in intervals}
        while not self.stop_event.is_set():
            now = time.monotonic()
            forced = self._force.is_set()
            self._force.clear()
            for name, runner in (("proc", self._proc), ("crash", self._crash), ("net", self._net)):
                if forced or now >= next_at[name]:
                    try:
                        self.cache.put(name, runner())
                    except Exception:                       # never let one scanner kill the loop
                        self.cache.put(name, {}, error=traceback.format_exc(limit=3))
                    next_at[name] = time.monotonic() + intervals[name]
            self.stop_event.wait(1.0)

    def _proc(self) -> dict:
        return procscan.scan(stale_after_s=self.cfg["stale_after_hours"] * 3600,
                             reveal_cmdlines=self.cfg["reveal_cmdlines"])

    def _crash(self) -> dict:
        return crashscan.scan(known_issues_path=self.cfg["known_issues"])

    def _net(self) -> dict:
        return netscan.scan(endpoints=self.cfg["endpoints"],
                            public_resolvers=self.cfg["public_resolvers"])


def make_handler(cache: Cache, cfg: dict, scanner: Scanner):
    token = cfg.get("token", "")

    class Handler(BaseHTTPRequestHandler):
        server_version = f"caner/{__version__}"
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):         # quiet by default
            if os.environ.get("CANER_ACCESS_LOG"):
                super().log_message(fmt, *args)

        def _authorised(self, query) -> bool:
            if not token:
                return True
            supplied = (self.headers.get("X-Caner-Token")
                        or (query.get("token", [""])[0] if query else ""))
            return secrets.compare_digest(supplied, token)

        def _send(self, code: int, body: bytes, ctype: str) -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _json(self, code: int, payload: dict) -> None:
            self._send(code, json.dumps(payload, default=str).encode(), "application/json; charset=utf-8")

        def do_HEAD(self):
            self.do_GET()

        def do_GET(self):
            parsed = urlparse(self.path)
            query = parse_qs(parsed.query)
            path = parsed.path

            if path == "/api/health":              # unauthenticated liveness only
                return self._json(200, {"ok": True, "version": __version__,
                                        "self_rss_mb": self_rss_mb()})
            if not self._authorised(query):
                return self._json(401, {"error": "missing or bad token"})

            if path == "/api/snapshot":
                payload = cache.snapshot()
                payload["meta"] = {
                    "version": __version__,
                    "self_rss_mb": self_rss_mb(),
                    "hostname": os.uname().nodename,
                    "now": time.time(),
                    "cmdlines_revealed": cfg["reveal_cmdlines"],
                }
                return self._json(200, payload)
            if path == "/api/rescan":
                scanner.force()
                return self._json(200, {"ok": True})

            rel = "index.html" if path == "/" else path.lstrip("/")
            target = os.path.normpath(os.path.join(WEB_DIR, rel))
            if not target.startswith(WEB_DIR) or not os.path.isfile(target):
                return self._json(404, {"error": "not found"})
            ext = os.path.splitext(target)[1]
            with open(target, "rb") as handle:
                self._send(200, handle.read(), CONTENT_TYPES.get(ext, "application/octet-stream"))

    return Handler


def serve(cfg: dict) -> None:
    cache = Cache()
    scanner = Scanner(cache, cfg)
    scanner.start()
    httpd = ThreadingHTTPServer((cfg["bind_host"], cfg["bind_port"]),
                                make_handler(cache, cfg, scanner))
    shown = cfg["bind_host"] if cfg["bind_host"] != "0.0.0.0" else os.uname().nodename
    suffix = f"?token={cfg['token']}" if cfg["token"] else ""
    print(f"caner {__version__} — http://{shown}:{cfg['bind_port']}/{suffix}")
    print(f"  own footprint: {self_rss_mb()} MB")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopping")
    finally:
        scanner.stop_event.set()
        httpd.server_close()
