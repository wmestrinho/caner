"""procscan -- attribute memory to applications, not PIDs.

`top` sorted by RSS is useless when one application is thirty processes: you see
thirty rows of 40 MB and miss that they sum to 1.2 GB. procscan groups processes
into applications, totals them, and says what you would get back by closing the
stale ones.

Everything here is read from /proc. No root, no dependencies.
"""

from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass, field

HZ = os.sysconf("SC_CLK_TCK")
PROC = "/proc"

# (group key, display label, predicate on (comm, cmdline)) -- first match wins.
# Ordering matters: the crash-investigator rule must precede the generic
# agent-session rule, or every investigator disappears into the generic bucket.
DEFAULT_RULES: list[tuple[str, str, str]] = [
    ("crash-agent",   "AI agent — auto-spawned crash investigator", r"systemd-coredump recorded|diagnose-crash"),
    ("agent-session", "AI agent session",                           r"^(claude|codex|aider|cursor-agent)$"),
    ("browser",       "Browser",                                    r"^(chromium|chrome|firefox|brave|google-chrome)"),
    ("electron",      "Electron / CEF app",                         r"--type=(renderer|zygote|gpu-process|utility)"),
    ("editor",        "Editor / IDE",                               r"^(code|codium|zed|sublime_text|nvim|vim|emacs)$"),
    ("container",     "Container runtime",                          r"^(dockerd|containerd|podman)$"),
    ("compositor",    "Desktop / compositor",                       r"^(Hyprland|quickshell|waybar|foot|alacritty|ghostty|kitty)$"),
]

# Never suggest closing these, whatever their age.
PROTECTED_COMMS = {"systemd", "Hyprland", "quickshell", "init", "dbus-broker",
                   "pipewire", "wireplumber", "gnome-keyring-d", "sshd"}


@dataclass
class Proc:
    pid: int
    comm: str
    rss_kb: int
    ppid: int
    age_s: float
    scope: str
    cmdline: str


@dataclass
class Group:
    key: str
    label: str
    rss_kb: int = 0
    count: int = 0
    oldest_s: float = 0.0
    pids: list[int] = field(default_factory=list)
    scopes: set[str] = field(default_factory=set)
    protected: bool = False


def _read(path: str) -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            return handle.read()
    except (OSError, ValueError):
        return ""


def _uptime() -> float:
    head = _read(f"{PROC}/uptime").split()
    return float(head[0]) if head else 0.0


def _scope_of(pid: int) -> str:
    """The systemd unit/scope a process belongs to -- i.e. what launched it."""
    for line in _read(f"{PROC}/{pid}/cgroup").splitlines():
        leaf = line.rsplit("/", 1)[-1]
        if leaf.endswith((".scope", ".service")):
            return leaf.replace("\\x2d", "-")
    return ""


def read_processes(uid: int | None = None) -> list[Proc]:
    """Snapshot every readable process. `uid=None` means all users."""
    up = _uptime()
    out: list[Proc] = []
    for entry in os.listdir(PROC):
        if not entry.isdigit():
            continue
        pid = int(entry)
        status = _read(f"{PROC}/{pid}/status")
        if not status:
            continue                       # exited between listdir and read
        fields: dict[str, str] = {}
        for line in status.splitlines():
            key, _, value = line.partition(":")
            fields[key] = value.strip()
        if uid is not None:
            owner = fields.get("Uid", "").split()
            if not owner or int(owner[0]) != uid:
                continue
        rss = fields.get("VmRSS", "0 kB").split()
        rss_kb = int(rss[0]) if rss and rss[0].isdigit() else 0
        if rss_kb == 0:
            continue                       # kernel threads
        stat = _read(f"{PROC}/{pid}/stat")
        age = 0.0
        if stat:
            # comm can contain spaces and parens, so split after the last ')'
            tail = stat[stat.rfind(")") + 2:].split()
            if len(tail) >= 20:
                age = max(0.0, up - int(tail[19]) / HZ)
        out.append(Proc(
            pid=pid,
            comm=fields.get("Name", "?"),
            rss_kb=rss_kb,
            ppid=int(fields.get("PPid", "0") or 0),
            age_s=age,
            scope=_scope_of(pid),
            cmdline=_read(f"{PROC}/{pid}/cmdline").replace("\0", " ").strip(),
        ))
    return out


def classify(proc: Proc, rules=DEFAULT_RULES) -> tuple[str, str]:
    for key, label, pattern in rules:
        if re.search(pattern, proc.comm) or re.search(pattern, proc.cmdline):
            return key, label
    return f"other:{proc.comm}", proc.comm


def scan(stale_after_s: float = 4 * 3600, reveal_cmdlines: bool = False,
         self_pid: int | None = None) -> dict:
    """Group processes and compute what closing the stale groups would free."""
    procs = read_processes(uid=os.getuid())
    groups: dict[str, Group] = {}
    for proc in procs:
        key, label = classify(proc)
        group = groups.setdefault(key, Group(key=key, label=label))
        group.rss_kb += proc.rss_kb
        group.count += 1
        group.oldest_s = max(group.oldest_s, proc.age_s)
        group.pids.append(proc.pid)
        if proc.scope:
            group.scopes.add(proc.scope)
        if proc.comm in PROTECTED_COMMS or proc.pid == self_pid or proc.pid == os.getpid():
            group.protected = True

    rows = []
    for group in sorted(groups.values(), key=lambda g: -g.rss_kb):
        stale = (not group.protected
                 and group.oldest_s >= stale_after_s
                 and group.key in {"agent-session", "crash-agent", "browser", "editor"})
        rows.append({
            "key": group.key,
            "label": group.label,
            "rss_mb": round(group.rss_kb / 1024, 1),
            "count": group.count,
            "oldest_s": int(group.oldest_s),
            "pids": sorted(group.pids)[:24],
            "scopes": sorted(group.scopes)[:4],
            "protected": group.protected,
            "stale": stale,
            # A crash investigator is redundant the moment the crash is understood,
            # so it is always worth flagging regardless of age.
            "reclaimable": stale or group.key == "crash-agent",
        })

    meminfo = {}
    for line in _read(f"{PROC}/meminfo").splitlines():
        key, _, value = line.partition(":")
        meminfo[key] = int(value.split()[0]) if value.split() else 0

    reclaim_mb = round(sum(r["rss_mb"] for r in rows if r["reclaimable"] and not r["protected"]), 1)
    total_mb = round(meminfo.get("MemTotal", 0) / 1024, 1)
    avail_mb = round(meminfo.get("MemAvailable", 0) / 1024, 1)

    findings = []
    for row in rows:
        if row["key"] == "crash-agent" and row["count"]:
            findings.append({
                "level": "warn",
                "text": (f"{row['count']} auto-spawned crash investigator(s) holding "
                         f"{row['rss_mb']} MB. Each crash costs this much again — a crash "
                         f"on a small box makes the next failure likelier."),
            })
        elif row["stale"]:
            findings.append({
                "level": "info",
                "text": (f"{row['label']}: {row['rss_mb']} MB across {row['count']} process(es), "
                         f"oldest {row['oldest_s'] // 3600}h idle."),
            })
    if reclaim_mb > 0 and avail_mb > 0 and reclaim_mb > avail_mb * 0.4:
        findings.insert(0, {
            "level": "alert",
            "text": (f"Closing stale groups would free ~{reclaim_mb} MB against "
                     f"{avail_mb} MB available — more than a 40% swing in headroom."),
        })

    return {
        "total_mb": total_mb,
        "available_mb": avail_mb,
        "swap_used_mb": round((meminfo.get("SwapTotal", 0) - meminfo.get("SwapFree", 0)) / 1024, 1),
        "reclaimable_mb": reclaim_mb,
        "groups": rows,
        "findings": findings,
        "cmdlines_revealed": reveal_cmdlines,
    }
