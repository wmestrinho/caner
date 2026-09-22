"""history -- keep enough of the past to see a trend, and no more.

A point-in-time reading tells you the box is short of memory. It does not tell
you whether that is a leak growing over two hours or a browser someone just
opened, and those call for opposite responses. This keeps a small ring of
samples so the dashboard can draw the shape.

Deliberately modest: a few numbers per sample, a bounded ring in memory, and an
optional JSONL file with a hard size cap. A monitor that fills the disk it is
monitoring has failed at its job.
"""

from __future__ import annotations

import json
import os
import time
from collections import deque

# Numeric series only. Storing whole snapshots would grow without bound and
# defeat the point of a featherweight monitor.
FIELDS = ("t", "avail_mb", "reclaim_mb", "swap_mb", "self_mb", "dumps", "net_ok", "net_bad")


class History:
    def __init__(self, retain: int = 1080, path: str | None = None,
                 max_bytes: int = 4 * 1024 * 1024):
        self.ring: deque[dict] = deque(maxlen=retain)
        self.path = path
        self.max_bytes = max_bytes
        self.write_error = ""
        if path:
            self._load()

    # ---- capture -------------------------------------------------------
    def sample(self, proc: dict | None, crash: dict | None, net: dict | None,
               self_mb: float, now: float | None = None) -> dict | None:
        """Record one point. Returns it, or None if there was nothing to record."""
        if not proc:
            return None                      # first scan has not landed yet
        endpoints = (net or {}).get("endpoints", [])
        point = {
            "t": round(now if now is not None else time.time(), 1),
            "avail_mb": proc.get("available_mb", 0),
            "reclaim_mb": proc.get("reclaimable_mb", 0),
            "swap_mb": proc.get("swap_used_mb", 0),
            "self_mb": self_mb,
            "dumps": (crash or {}).get("total_dumps", 0),
            "net_ok": sum(1 for e in endpoints if e.get("status") == "ok"),
            "net_bad": sum(1 for e in endpoints if e.get("status") != "ok"),
        }
        self.ring.append(point)
        self._append(point)
        return point

    def series(self, since_s: float | None = None) -> list[dict]:
        if since_s is None:
            return list(self.ring)
        cutoff = time.time() - since_s
        return [p for p in self.ring if p["t"] >= cutoff]

    def summary(self) -> dict:
        """Direction of travel, which is the only thing a number cannot show."""
        pts = list(self.ring)
        if len(pts) < 2:
            return {"samples": len(pts), "span_s": 0, "avail_trend_mb": 0.0}
        span = pts[-1]["t"] - pts[0]["t"]
        # Compare the mean of the first and last fifth: robust against a single
        # spike in a way that first-vs-last point is not.
        n = max(1, len(pts) // 5)
        head = sum(p["avail_mb"] for p in pts[:n]) / n
        tail = sum(p["avail_mb"] for p in pts[-n:]) / n
        return {
            "samples": len(pts),
            "span_s": round(span, 1),
            "avail_trend_mb": round(tail - head, 1),
            "avail_min_mb": min(p["avail_mb"] for p in pts),
            "avail_max_mb": max(p["avail_mb"] for p in pts),
        }

    def findings(self, min_span_s: int = 900, drop_mb: int = 250) -> list[dict]:
        """A sustained decline is the thing a single reading cannot show."""
        summary = self.summary()
        out: list[dict] = []
        if summary["span_s"] >= min_span_s:
            trend = summary["avail_trend_mb"]
            mins = int(summary["span_s"] // 60)
            if trend <= -drop_mb:
                out.append({"level": "warn", "text": (
                    f"Available memory has fallen {abs(trend):.0f} MB over the last "
                    f"{mins} min (now {self.ring[-1]['avail_mb']:.0f} MB). Steady decline "
                    f"rather than a spike — check for something leaking.")})
            elif trend >= drop_mb:
                out.append({"level": "info", "text": (
                    f"Available memory recovered {trend:.0f} MB over the last {mins} min.")})
        return out

    # ---- persistence ---------------------------------------------------
    def _append(self, point: dict) -> None:
        if not self.path:
            return
        try:
            # Truncate rather than rotate: this is disposable trend data, and a
            # rotation scheme would be more machinery than the data is worth.
            if os.path.exists(self.path) and os.path.getsize(self.path) > self.max_bytes:
                keep = list(self.ring)[-len(self.ring) // 2:]
                with open(self.path, "w", encoding="utf-8") as handle:
                    for kept in keep:
                        handle.write(json.dumps(kept) + "\n")
                return
            with open(self.path, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(point) + "\n")
            self.write_error = ""
        except OSError as exc:
            self.write_error = str(exc)      # never let disk trouble stop a scan

    def _load(self) -> None:
        try:
            with open(self.path, encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        point = json.loads(line)
                    except ValueError:
                        continue             # tolerate a torn final line
                    if isinstance(point, dict) and "t" in point:
                        self.ring.append(point)
        except OSError:
            pass
