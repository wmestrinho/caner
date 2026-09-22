"""Desktop notifications for findings that deserve interrupting you.

A dashboard only helps if someone is looking at it, and on an always-on box
nobody is. This pushes the small number of findings that actually warrant
attention, and — more importantly — refuses to push anything else. A monitor
that cries wolf gets muted, and a muted monitor is worse than none.

Three rules keep it quiet:
  * only findings at or above `min_level`;
  * the same finding never fires twice inside `cooldown_s`;
  * a finding must persist across two consecutive scans before it fires, so a
    transient blip during a scan does not wake you.
"""

from __future__ import annotations

import hashlib
import re
import shutil
import subprocess
import time

LEVELS = {"info": 0, "warn": 1, "alert": 2}
URGENCY = {"info": "low", "warn": "normal", "alert": "critical"}

# Numbers drift every scan ("981.0 MB" -> "984.2 MB"). Without this, a finding
# would look new each time and the cooldown would never apply.
_NUMBERS = re.compile(r"\d+(?:\.\d+)?")


def fingerprint(finding: dict) -> str:
    stable = _NUMBERS.sub("#", finding.get("text", ""))
    return hashlib.sha256(f"{finding.get('level')}|{stable}".encode()).hexdigest()[:16]


class Notifier:
    def __init__(self, enabled: bool = True, min_level: str = "alert",
                 cooldown_s: int = 1800, require_repeat: bool = True):
        self.enabled = enabled and shutil.which("notify-send") is not None
        self.min_level = LEVELS.get(min_level, 2)
        self.cooldown_s = cooldown_s
        self.require_repeat = require_repeat
        self._last_sent: dict[str, float] = {}
        self._seen_once: set[str] = set()
        self.sent_count = 0
        self.last_error = ""

    def _eligible(self, finding: dict) -> bool:
        return LEVELS.get(finding.get("level", "info"), 0) >= self.min_level

    def process(self, findings: list[dict], now: float | None = None) -> list[dict]:
        """Return the findings actually notified. Safe to call every scan."""
        if not self.enabled:
            return []
        now = time.time() if now is None else now
        candidates = [f for f in findings if self._eligible(f)]
        current = {fingerprint(f): f for f in candidates}

        fired = []
        for key, finding in current.items():
            if self.require_repeat and key not in self._seen_once:
                continue                                  # wait for confirmation
            # "never sent" is not "sent at epoch 0" — defaulting to 0.0 would make
            # the cooldown depend on `now` being a large wall-clock value.
            last = self._last_sent.get(key)
            if last is not None and now - last < self.cooldown_s:
                continue
            if self._send(finding):
                self._last_sent[key] = now
                self.sent_count += 1
                fired.append(finding)

        # Only findings present *this* scan stay armed; a cleared one must
        # reappear twice before it can fire again.
        self._seen_once = set(current)
        return fired

    def _send(self, finding: dict) -> bool:
        level = finding.get("level", "info")
        text = finding.get("text", "")
        title = {"alert": "caner — action needed",
                 "warn": "caner — worth a look"}.get(level, "caner")
        try:
            subprocess.run(
                ["notify-send", "--app-name=caner",
                 f"--urgency={URGENCY.get(level, 'normal')}",
                 "--icon=utilities-system-monitor", title, text[:400]],
                check=False, capture_output=True, timeout=10)
            return True
        except (OSError, subprocess.SubprocessError) as exc:
            self.last_error = str(exc)
            return False
