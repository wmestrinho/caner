"""Linux backend — the original implementation, unchanged in behaviour."""

from __future__ import annotations

import shutil
import subprocess

from .generic import state_dir  # noqa: F401  (XDG is already the Linux answer)

CAPABILITIES = {"procscan": True, "crashscan": True, "netscan": True}

URGENCY = {"info": "low", "warn": "normal", "alert": "critical"}


def self_rss_mb() -> float:
    try:
        with open("/proc/self/status", encoding="utf-8") as handle:
            for line in handle:
                if line.startswith("VmRSS:"):
                    return round(int(line.split()[1]) / 1024, 1)
    except OSError:
        pass
    return 0.0


def system_resolvers() -> list[str]:
    """Upstream resolvers actually in use, skipping the 127.0.0.53 stub.

    systemd-resolved writes the real upstreams to its own resolv.conf;
    /etc/resolv.conf usually just points at the local stub, which would tell us
    nothing about what is really being asked.
    """
    found: list[str] = []
    for path in ("/run/systemd/resolve/resolv.conf", "/etc/resolv.conf"):
        try:
            with open(path, encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    if line.startswith("nameserver"):
                        parts = line.split()
                        if len(parts) > 1 and not parts[1].startswith("127."):
                            if parts[1] not in found:
                                found.append(parts[1])
        except OSError:
            continue
        if found:
            break
    return found


def dns_fix_command(servers: list[str] | None = None) -> str:
    addrs = ",".join(servers or ["9.9.9.9", "1.1.1.1"])
    return (f'nmcli con mod "<connection>" ipv4.ignore-auto-dns yes ipv4.dns "{addrs}"')


def notify_available() -> bool:
    return shutil.which("notify-send") is not None


def notify(title: str, text: str, level: str = "info") -> bool:
    try:
        subprocess.run(
            ["notify-send", "--app-name=caner",
             f"--urgency={URGENCY.get(level, 'normal')}",
             "--icon=utilities-system-monitor", title, text[:400]],
            check=False, capture_output=True, timeout=10)
        return True
    except (OSError, subprocess.SubprocessError):
        return False
