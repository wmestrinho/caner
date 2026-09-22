"""macOS backend.

Two things differ from Linux in ways worth stating. There is no /proc, so
current RSS comes from `ps`. And /etc/resolv.conf on macOS is a compatibility
file that often does not reflect what the system actually queries — per-interface
resolvers live in the dynamic store, so `scutil --dns` is the real source and
resolv.conf is only the fallback.
"""

from __future__ import annotations

import os
import re
import subprocess

from .generic import self_rss_mb as _rusage_rss

CAPABILITIES = {"procscan": False, "crashscan": False, "netscan": True}

_NAMESERVER = re.compile(r"^\s*nameserver\[\d+\]\s*:\s*(\S+)")


def _run(cmd: list[str], timeout: float = 5.0) -> str:
    try:
        done = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError):
        return ""
    return done.stdout


def self_rss_mb() -> float:
    """Current RSS from `ps`, falling back to getrusage's peak figure.

    `ps -o rss=` reports kilobytes. The fallback is a peak rather than a current
    reading, so it over-reports after a spike — acceptable, and flagged in
    `generic.self_rss_mb`.
    """
    out = _run(["ps", "-o", "rss=", "-p", str(os.getpid())], timeout=3.0).strip()
    if out.isdigit():
        return round(int(out) / 1024, 1)
    return _rusage_rss()


def system_resolvers() -> list[str]:
    """Resolvers from the dynamic store, skipping loopback stubs.

    `scutil --dns` lists every scoped resolver, so the same address appears
    repeatedly; order is preserved and duplicates dropped, which puts the
    primary interface's resolvers first.
    """
    found: list[str] = []
    for line in _run(["scutil", "--dns"]).splitlines():
        match = _NAMESERVER.match(line)
        if not match:
            continue
        addr = match.group(1)
        if addr.startswith("127.") or addr == "::1" or addr in found:
            continue
        found.append(addr)
    if found:
        return found
    from .generic import system_resolvers as _resolv_conf
    return _resolv_conf()


def _primary_service() -> str:
    """Name of the active network service, as `networksetup` spells it.

    The DNS fix has to name a service ("Wi-Fi", "Ethernet"), and guessing wrong
    makes the command fail. Derive it from the interface holding the default
    route rather than assuming Wi-Fi.
    """
    dev = ""
    for line in _run(["route", "-n", "get", "default"]).splitlines():
        if "interface:" in line:
            dev = line.split(":", 1)[1].strip()
            break
    if not dev:
        return "Wi-Fi"
    order, service = _run(["networksetup", "-listnetworkserviceorder"]), ""
    for block in order.split("\n\n"):
        if f"Device: {dev})" in block:
            for line in block.splitlines():
                if line.startswith("(") and ") " in line:
                    service = line.split(") ", 1)[1].strip()
                    break
    return service or "Wi-Fi"


def dns_fix_command(servers: list[str] | None = None) -> str:
    addrs = " ".join(servers or ["9.9.9.9", "1.1.1.1"])
    return f'networksetup -setdnsservers "{_primary_service()}" {addrs}'


def notify_available() -> bool:
    return os.path.exists("/usr/bin/osascript")


def notify(title: str, text: str, level: str = "info") -> bool:
    """Notification Centre via osascript.

    AppleScript string literals take no escape sequences, so a quote or
    backslash in a finding would end the literal and break the script. Both are
    stripped rather than escaped — findings are diagnostic prose and lose
    nothing by it.
    """
    def literal(value: str) -> str:
        return value.replace("\\", "").replace('"', "'")

    script = (f'display notification "{literal(text[:400])}" '
              f'with title "{literal(title)}"')
    try:
        subprocess.run(["osascript", "-e", script],
                       check=False, capture_output=True, timeout=10)
        return True
    except (OSError, subprocess.SubprocessError):
        return False


def state_dir() -> str:
    """macOS keeps per-application state under Application Support."""
    return os.path.expanduser("~/Library/Application Support/caner")
