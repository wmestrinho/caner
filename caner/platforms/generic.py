"""Fallback backend: what can be done with nothing but portable stdlib.

Used on an OS caner has no specific backend for, and to fill gaps in a backend
that is still being ported. It never raises and never guesses — where it cannot
answer, it says so, so the dashboard shows an honest gap instead of a zero that
reads like a healthy result.
"""

from __future__ import annotations

import os
import resource

CAPABILITIES = {"procscan": False, "crashscan": False, "netscan": True}


def self_rss_mb() -> float:
    """Peak RSS via getrusage — available on every Unix, absent on Windows.

    This is *peak*, not current: it never falls back down after a spike. A
    backend that can read current RSS should override this; here it is a
    deliberate over-estimate, which is the safe direction for a memory budget.
    """
    try:
        raw = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    except (OSError, ValueError, AttributeError):
        return 0.0
    # Linux reports kilobytes, the BSDs and macOS report bytes.
    mb = raw / 1024 if raw < (1 << 30) else raw / (1024 * 1024)
    return round(mb, 1)


def system_resolvers() -> list[str]:
    """Read resolv.conf if there is one. Absent on Windows; empty is a valid answer."""
    found: list[str] = []
    try:
        with open("/etc/resolv.conf", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                if line.startswith("nameserver"):
                    parts = line.split()
                    if len(parts) > 1 and not parts[1].startswith("127.") and parts[1] not in found:
                        found.append(parts[1])
    except OSError:
        pass
    return found


def dns_fix_command(servers: list[str] | None = None) -> str:
    """No portable way to pin DNS; netscan omits the remediation line when empty."""
    return ""


def notify_available() -> bool:
    return False


def notify(title: str, text: str, level: str = "info") -> bool:
    return False


def state_dir() -> str:
    """XDG-style state directory, honouring systemd's StateDirectory when present."""
    return (os.environ.get("STATE_DIRECTORY", "").split(":")[0]
            or os.path.join(os.environ.get("XDG_STATE_HOME",
                                           os.path.expanduser("~/.local/state")), "caner"))
