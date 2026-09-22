"""Host-specific facts, behind one interface.

caner's value is in its grouping and verdict logic, which is the same everywhere.
What differs between machines is only *where the facts come from*: /proc or ps or
a Win32 call; resolv.conf or scutil or the registry; notify-send or osascript or
a balloon tip. Those live here, one module per OS, so no scanner has to know
which machine it is running on.

Named `platforms` rather than `platform` so it cannot be confused with the
standard-library module of that name, which this package itself uses.

A backend implements the functions listed in `_REQUIRED`. Anything it cannot do
on this host it declines: `system_resolvers()` returns an empty list, `notify()`
returns False, `dns_fix_command()` returns "". Declining is normal and must not
raise — an unknown OS falls back to `generic`, which declines everything it
cannot do portably and still leaves the dashboard working.
"""

from __future__ import annotations

import platform as _stdlib_platform
import socket
import sys

_REQUIRED = ("self_rss_mb", "system_resolvers", "dns_fix_command",
             "notify_available", "notify", "state_dir")


def _pick() -> tuple[str, object]:
    if sys.platform.startswith("linux"):
        from . import linux
        return "linux", linux
    if sys.platform == "darwin":
        from . import darwin
        return "darwin", darwin
    if sys.platform in ("win32", "cygwin"):
        from . import windows
        return "windows", windows
    from . import generic
    return "generic", generic


NAME, _backend = _pick()


def backend_name() -> str:
    """The backend actually in use, read from the module rather than a constant.

    `NAME` is fixed at import. Tests (and a future manual override) swap
    `_backend`, and a message that still said "linux" while running the darwin
    backend would be a lie in exactly the place a reader is trying to work out
    what their machine can do.
    """
    return getattr(_backend, "__name__", "unknown").rsplit(".", 1)[-1]


def _resolve(attr: str):
    """Backend attribute, falling back to `generic` for gaps.

    A backend that has not implemented something yet is a normal state during a
    port, not an error — the generic implementation keeps the scan loop running.
    """
    try:
        return getattr(_backend, attr)
    except AttributeError:
        pass
    from . import generic
    try:
        return getattr(generic, attr)
    except AttributeError:
        raise AttributeError(
            f"{attr!r} is not part of the platform interface "
            f"(backend {NAME!r})") from None


def __getattr__(attr: str):
    """Forward the backend interface to callers outside this package.

    Note this hook is *not* consulted for lookups made inside this module, so
    code here calls `_resolve` directly.
    """
    if attr.startswith("_"):
        raise AttributeError(attr)
    return _resolve(attr)


def hostname() -> str:
    """`os.uname()` does not exist on Windows; this does, everywhere."""
    return _stdlib_platform.node() or "unknown-host"


def describe() -> dict:
    """What this host is, and which scanners can actually run on it.

    Surfaced by /api/health so a dashboard read from another seat says plainly
    what the machine underneath could and could not measure, rather than
    showing an empty panel that looks like a healthy zero.
    """
    caps = capabilities()
    return {
        "backend": backend_name(),
        "system": _stdlib_platform.system(),
        "release": _stdlib_platform.release(),
        "machine": _stdlib_platform.machine(),
        "python": _stdlib_platform.python_version(),
        "hostname": hostname(),
        "capabilities": caps,
        "unsupported": sorted(k for k, v in caps.items() if not v),
    }


def capabilities() -> dict:
    """Per-scanner support on this host. Backends override what they implement."""
    default = {"procscan": False, "crashscan": False, "netscan": True, "notify": False}
    try:
        default.update(_backend.CAPABILITIES)
    except AttributeError:
        pass
    default["notify"] = bool(_resolve("notify_available")())
    return default


def have_ipv6_route() -> bool:
    """True if this host has a route to the global IPv6 internet.

    Done with a UDP `connect`, which performs a route lookup without sending a
    packet and without a subprocess, so it costs the same on every OS. A host
    holding only a link-local address has no route to a global address and
    correctly reports False.
    """
    sock = None
    try:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        sock.settimeout(1.0)
        sock.connect(("2001:4860:4860::8888", 53))
        return True
    except OSError:
        return False
    finally:
        if sock is not None:
            sock.close()
