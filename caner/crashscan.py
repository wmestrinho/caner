"""crashscan -- collapse core dumps into signatures, and say which ones matter.

A crash list is a poor diagnostic: thirty-eight dumps look like catastrophe when
they are two bugs, one of them harmless. crashscan groups dumps by *signature*
(executable + signal + normalised top frames), separates fatal from survived,
and states plainly whether anything was actually killed for memory -- because an
OOM kill is SIGKILL with no core, and every core dump on disk is by definition
something else.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from collections import defaultdict

SIGNALS = {4: "SIGILL", 5: "SIGTRAP", 6: "SIGABRT", 7: "SIGBUS", 8: "SIGFPE",
           11: "SIGSEGV", 31: "SIGSYS"}

COREDUMP_DIR = "/var/lib/systemd/coredump"
_FRAME = re.compile(r"^#(\d+)\s+0x[0-9a-f]+\s+(.+?)\s*$")
_sig_cache: dict[int, list[str]] = {}


def _run(cmd: list[str], timeout: int = 20) -> str:
    try:
        done = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        return done.stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def _normalise(frame: str) -> str:
    """Turn a raw frame into something comparable across runs.

    Absolute addresses differ every run (ASLR), so they are useless for grouping.
    What is stable is `symbol` or `library + offset`, which is exactly what
    systemd already prints.
    """
    frame = frame.strip()
    match = re.match(r"^(?:n/a|(\S+))\s*\(([^)]+)\)", frame)
    if match:
        symbol, where = match.group(1), match.group(2)
        where = re.sub(r"\s+", "", where)
        return f"{symbol}@{where}" if symbol else where
    return frame[:80]


def _frames_for(pid: int, limit: int = 16) -> list[str]:
    if pid in _sig_cache:
        return _sig_cache[pid]
    text = _run(["coredumpctl", "info", str(pid)])
    frames: list[str] = []
    in_stack = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("Stack trace of thread"):
            if in_stack:            # only the first (crashing) thread
                break
            in_stack = True
            continue
        if in_stack:
            match = _FRAME.match(stripped)
            if match:
                frames.append(_normalise(match.group(2)))
                if len(frames) >= limit:
                    break
            elif stripped and not stripped.startswith("#"):
                break
    _sig_cache[pid] = frames
    return frames


# Frames every abort shares. They say "this process called abort()", which is
# true of all of them, so grouping on them would merge unrelated bugs into one
# bucket. The signature starts at the first frame that names real code.
_BOILERPLATE = re.compile(
    r"(libc\.so|libstdc\+\+\.so|libgcc_s\.so|ld-linux|"
    r"__cxa_|__gxx_personality|_Unwind_|abort@|raise@|pthread_kill)")


def signature_frames(frames: list[str], want: int = 4) -> list[str]:
    """First `want` frames that actually identify the fault."""
    meaningful = [f for f in frames if not _BOILERPLATE.search(f)]
    return (meaningful or frames)[:want]


def _oom_events() -> list[str]:
    out = _run(["journalctl", "-b", "--no-pager", "-o", "cat",
                "--grep", "Out of memory|oom-kill|oom_reaper"])
    return [line for line in out.splitlines() if line.strip()]


def _dir_size_mb(path: str) -> float:
    total = 0
    try:
        with os.scandir(path) as entries:
            for entry in entries:
                try:
                    total += entry.stat(follow_symlinks=False).st_size
                except OSError:
                    continue
    except OSError:
        return 0.0
    return round(total / 1024 / 1024, 1)


def _running(exe: str) -> bool:
    name = os.path.basename(exe)[:15]
    return bool(_run(["pgrep", "-x", name]).strip())


def load_known_issues(path: str) -> list[dict]:
    try:
        with open(path, encoding="utf-8") as handle:
            return json.load(handle).get("issues", [])
    except (OSError, ValueError):
        return []


def scan(known_issues_path: str = "known_issues.json", max_inspect: int = 60,
         storm_window_s: int = 300, storm_count: int = 5) -> dict:
    raw = _run(["coredumpctl", "list", "--json=short", "--no-pager"])
    try:
        dumps = json.loads(raw) if raw.strip() else []
    except ValueError:
        dumps = []

    dumps.sort(key=lambda d: d.get("time", 0), reverse=True)
    inspect = dumps[:max_inspect]

    known = load_known_issues(known_issues_path)
    buckets: dict[tuple, dict] = {}
    for dump in inspect:
        pid = dump.get("pid", 0)
        exe = dump.get("exe") or "?"
        signal = SIGNALS.get(dump.get("sig", 0), f"sig{dump.get('sig')}")
        frames = _frames_for(pid)
        key = (exe, signal, tuple(signature_frames(frames)))
        bucket = buckets.setdefault(key, {
            "exe": exe, "signal": signal, "frames": frames[:10],
            "sig_frames": signature_frames(frames),
            "count": 0, "first_us": None, "last_us": None, "pids": [], "times": [],
        })
        bucket["count"] += 1
        bucket["pids"].append(pid)
        when = dump.get("time", 0)
        bucket["times"].append(when)
        bucket["first_us"] = when if bucket["first_us"] is None else min(bucket["first_us"], when)
        bucket["last_us"] = when if bucket["last_us"] is None else max(bucket["last_us"], when)

    groups, findings = [], []
    for bucket in sorted(buckets.values(), key=lambda b: -b["count"]):
        times = sorted(bucket["times"])
        storm = False
        for i in range(len(times)):
            window = [t for t in times if 0 <= t - times[i] <= storm_window_s * 1_000_000]
            if len(window) >= storm_count:
                storm = True
                break
        blob = " ".join(bucket["frames"]) + " " + bucket["exe"]
        matches = [k for k in known
                   if all(frag in blob for frag in k.get("match_all", []))
                   and k.get("signal", bucket["signal"]) == bucket["signal"]]
        survived = _running(bucket["exe"])
        groups.append({
            "exe": bucket["exe"],
            "exe_short": os.path.basename(bucket["exe"]),
            "signal": bucket["signal"],
            "count": bucket["count"],
            "frames": bucket["frames"],
            "sig_frames": bucket["sig_frames"],
            "first_iso": _iso(bucket["first_us"]),
            "last_iso": _iso(bucket["last_us"]),
            "storm": storm,
            "still_running": survived,
            "known_issues": [{"title": m["title"], "url": m["url"]} for m in matches],
            "pids": bucket["pids"][:12],
        })
        if storm:
            findings.append({"level": "warn", "text": (
                f"{bucket['count']}x {bucket['signal']} in {os.path.basename(bucket['exe'])} "
                f"clustered within {storm_window_s}s — one repeating fault, not {bucket['count']} problems."
                + (" The application is still running, so these are non-fatal." if survived else ""))})
        for match in matches:
            findings.append({"level": "info",
                             "text": f"Known upstream issue: {match['title']} — {match['url']}"})

    ooms = _oom_events()
    disk_mb = _dir_size_mb(COREDUMP_DIR)
    findings.insert(0, {
        "level": "info" if not ooms else "alert",
        "text": (f"{len(ooms)} OOM kill(s) this boot." if ooms else
                 "No OOM kills this boot. Every core dump here is a crash the program "
                 "caused itself — an OOM kill is SIGKILL and leaves no core."),
    })
    if disk_mb > 250:
        findings.append({"level": "info", "text": (
            f"Core dumps are using {disk_mb} MB in {COREDUMP_DIR}. "
            f"`coredumpctl --vacuum-size=100M` trims them.")})

    return {
        "total_dumps": len(dumps),
        "inspected": len(inspect),
        "signatures": len(groups),
        "oom_kills": len(ooms),
        "coredump_disk_mb": disk_mb,
        "groups": groups,
        "findings": findings,
    }


def _iso(micros: int | None) -> str:
    if not micros:
        return ""
    import datetime
    return datetime.datetime.fromtimestamp(micros / 1_000_000).strftime("%Y-%m-%d %H:%M:%S")
