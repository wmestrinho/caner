"""Windows backend.

Deliberately avoids PowerShell for anything on the scan path. A PowerShell
start-up costs 300-500 ms, and caner polls; paying that per scan would make the
monitor a bigger load than most of what it watches. Working set comes from a
`ctypes` call into kernel32 and resolvers come from the registry through
`winreg` — both stdlib, both effectively instant. PowerShell appears exactly
once, for notifications, which are rate-limited to at most one per cooldown.
"""

from __future__ import annotations

import ctypes
import os
import socket
import subprocess

try:                                    # importable on any OS so tests can read it
    import winreg
except ImportError:                     # pragma: no cover - not Windows
    winreg = None                       # type: ignore[assignment]

CAPABILITIES = {"procscan": False, "crashscan": False, "netscan": True}

_INTERFACES = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"


class _PROCESS_MEMORY_COUNTERS(ctypes.Structure):
    _fields_ = [
        ("cb", ctypes.c_ulong),
        ("PageFaultCount", ctypes.c_ulong),
        ("PeakWorkingSetSize", ctypes.c_size_t),
        ("WorkingSetSize", ctypes.c_size_t),
        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
        ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
        ("PagefileUsage", ctypes.c_size_t),
        ("PeakPagefileUsage", ctypes.c_size_t),
    ]


def self_rss_mb() -> float:
    """Working set size — the Windows equivalent of RSS."""
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)   # type: ignore[attr-defined]
        counters = _PROCESS_MEMORY_COUNTERS()
        counters.cb = ctypes.sizeof(counters)
        ok = kernel32.K32GetProcessMemoryInfo(
            kernel32.GetCurrentProcess(), ctypes.byref(counters), counters.cb)
        if not ok:
            return 0.0
        return round(counters.WorkingSetSize / (1024 * 1024), 1)
    except (AttributeError, OSError, ValueError):
        return 0.0


def _outbound_ip() -> str:
    """Local address the default route would use. No packet is sent."""
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1.0)
        sock.connect(("8.8.8.8", 53))
        return sock.getsockname()[0]
    except OSError:
        return ""
    finally:
        if sock is not None:
            sock.close()


def _read(key, name: str) -> str:
    try:
        value, _ = winreg.QueryValueEx(key, name)
    except OSError:
        return ""
    return value.strip() if isinstance(value, str) else ""


def system_resolvers() -> list[str]:
    """Per-interface resolvers from the registry, active interface first.

    Windows keeps one subkey per interface, including long-dead ones, and the
    registry does not say which is in use. Ordering by the interface whose
    address matches the default route's source address puts the resolvers that
    are actually being queried first — which is the whole point, since netscan
    compares the system resolver against public ones.
    """
    if winreg is None:
        return []
    local, active, other = _outbound_ip(), [], []
    try:
        root = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _INTERFACES)
    except OSError:
        return []
    try:
        for index in range(winreg.QueryInfoKey(root)[0]):
            try:
                sub = winreg.OpenKey(root, winreg.EnumKey(root, index))
            except OSError:
                continue
            try:
                # A static NameServer overrides whatever DHCP supplied.
                raw = _read(sub, "NameServer") or _read(sub, "DhcpNameServer")
                addrs = [a for a in raw.replace(",", " ").split() if a]
                if not addrs:
                    continue
                mine = local and local in (
                    _read(sub, "DhcpIPAddress"), _read(sub, "IPAddress"))
                (active if mine else other).extend(addrs)
            finally:
                sub.Close()
    finally:
        root.Close()

    found: list[str] = []
    for addr in active + other:
        if addr.startswith("127.") or addr == "::1" or addr in found:
            continue
        found.append(addr)
    return found


def dns_fix_command(servers: list[str] | None = None) -> str:
    """netsh needs an elevated prompt; say so rather than let it fail silently."""
    addrs = servers or ["9.9.9.9", "1.1.1.1"]
    lines = [f'netsh interface ip set dns name="<interface>" static {addrs[0]} primary']
    lines += [f'netsh interface ip add dns name="<interface>" {a} index={i}'
              for i, a in enumerate(addrs[1:], start=2)]
    return " ; ".join(lines) + "   (run as Administrator)"


def notify_available() -> bool:
    return bool(_powershell())


def _powershell() -> str:
    for candidate in ("powershell.exe", "pwsh.exe"):
        path = os.environ.get("SystemRoot", r"C:\Windows")
        full = os.path.join(path, "System32", "WindowsPowerShell", "v1.0", candidate)
        if os.path.exists(full):
            return full
    import shutil
    return shutil.which("powershell") or shutil.which("pwsh") or ""


def notify(title: str, text: str, level: str = "info") -> bool:
    """Balloon tip via NotifyIcon — present on stock Windows, no modules needed.

    Launched without waiting: the script has to keep the tray icon alive for the
    balloon to stay visible, and blocking the scan loop for those seconds is a
    worse trade than not learning whether it rendered.
    """
    shell = _powershell()
    if not shell:
        return False
    icon = {"alert": "Error", "warn": "Warning"}.get(level, "Info")
    sysicon = {"alert": "Error", "warn": "Warning"}.get(level, "Information")

    def literal(value: str) -> str:
        return value.replace("'", "''")

    script = (
        "Add-Type -AssemblyName System.Windows.Forms,System.Drawing; "
        "$n = New-Object System.Windows.Forms.NotifyIcon; "
        f"$n.Icon = [System.Drawing.SystemIcons]::{sysicon}; "
        "$n.Visible = $true; "
        f"$n.ShowBalloonTip(10000, '{literal(title)}', '{literal(text[:400])}', "
        f"[System.Windows.Forms.ToolTipIcon]::{icon}); "
        "Start-Sleep -Seconds 8; $n.Dispose()")
    try:
        subprocess.Popen([shell, "-NoProfile", "-NonInteractive", "-Command", script],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         stdin=subprocess.DEVNULL)
        return True
    except (OSError, subprocess.SubprocessError):
        return False


def state_dir() -> str:
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser(r"~\AppData\Local")
    return os.path.join(base, "caner")
