"""netscan -- catch the resolver that hands you a dead address.

Normal reachability checks resolve a name the system way and connect. That hides
the failure this module exists for: DNS answers correctly, the name resolves, and
the address you were given is a black hole -- while a different resolver would
have handed you a working one. CDNs pick an edge per resolver, so "DNS works" and
"you can reach the service" are genuinely different questions.

netscan asks every resolver separately, then connects to each distinct answer.
"""

from __future__ import annotations

import concurrent.futures
import socket
import time

from . import dnsquery, platforms

DEFAULT_PUBLIC_RESOLVERS = ["9.9.9.9", "1.1.1.1", "8.8.8.8"]

# RFC 5737 TEST-NET-1: reserved for documentation and guaranteed never routed.
# Nothing on the public internet may answer here, which makes it a control.
BLACKHOLE_IP = "192.0.2.1"

DEFAULT_ENDPOINTS = [
    {"host": "sisu.xboxlive.com", "port": 443, "label": "Xbox sign-in (Minecraft auth)"},
    {"host": "login.live.com", "port": 443, "label": "Microsoft account"},
    {"host": "api.minecraftservices.com", "port": 443, "label": "Minecraft services"},
    {"host": "github.com", "port": 443, "label": "GitHub"},
    {"host": "example.com", "port": 443, "label": "Internet canary"},
]


def have_ipv6_route() -> bool:
    """Delegates to `platforms`, which route-tests with a socket, not a subprocess."""
    return platforms.have_ipv6_route()


def tcp_probe(ip: str, port: int, timeout: float = 5.0) -> dict:
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    started = time.monotonic()
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((ip, port))
        return {"ip": ip, "ok": True, "ms": round((time.monotonic() - started) * 1000, 1), "error": ""}
    except socket.timeout:
        return {"ip": ip, "ok": False, "ms": round((time.monotonic() - started) * 1000, 1),
                "error": "timeout — no SYN-ACK"}
    except OSError as exc:
        return {"ip": ip, "ok": False, "ms": round((time.monotonic() - started) * 1000, 1),
                "error": exc.strerror or str(exc)}
    finally:
        sock.close()


def probe_selftest(port: int = 443, timeout: float = 4.0) -> dict:
    """Confirm an unreachable address is actually reported unreachable.

    This is a control, not a formality. If a connection to a reserved,
    unroutable address *succeeds*, something between this machine and the
    internet is accepting every connection — a captive portal, a transparent
    proxy, a hijacking resolver. In that state every reachability result
    netscan produces is meaningless, and saying so is far more useful than
    quietly reporting that all endpoints are fine.
    """
    result = tcp_probe(BLACKHOLE_IP, port, timeout)
    return {
        "target": f"{BLACKHOLE_IP}:{port}",
        "connected": result["ok"],
        "trustworthy": not result["ok"],
        "detail": result["error"] or "connected (unexpected)",
    }


def degraded_finding(host: str, bad: list[str], good: list[str]) -> dict:
    """The alert for "a working service you cannot reach".

    Split out so the remediation path is directly testable on a machine that is
    not the one the command is for: the fix line is per-OS, and a backend with
    no portable answer returns "", in which case the finding says nothing rather
    than printing a command that cannot run here.
    """
    fix = platforms.dns_fix_command(DEFAULT_PUBLIC_RESOLVERS[:2])
    return {"level": "alert", "text": (
        f"{host}: your system resolver returns {', '.join(bad) or 'no usable address'} "
        f"(unreachable), but a public resolver returns {', '.join(good)} (reachable). "
        f"This is a working service you cannot reach. Pin DNS to a public resolver"
        + (f": {fix}" if fix else "."))}


def scan(endpoints=None, public_resolvers=None, timeout: float = 4.0,
         workers: int = 8) -> dict:
    endpoints = endpoints or DEFAULT_ENDPOINTS
    link = dnsquery.system_resolvers()
    public = [r for r in (public_resolvers or DEFAULT_PUBLIC_RESOLVERS) if r not in link]
    resolvers = [{"addr": r, "kind": "system"} for r in link] + \
                [{"addr": r, "kind": "public"} for r in public]
    v6 = have_ipv6_route()

    def resolve(endpoint, resolver):
        try:
            return endpoint, resolver, sorted(dnsquery.query(resolver["addr"], endpoint["host"],
                                                             timeout=timeout)), ""
        except dnsquery.DNSError as exc:
            return endpoint, resolver, [], str(exc)

    answers: dict[str, dict[str, dict]] = {e["host"]: {} for e in endpoints}
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        for endpoint, resolver, ips, err in pool.map(
                lambda pair: resolve(*pair),
                [(e, r) for e in endpoints for r in resolvers]):
            answers[endpoint["host"]][resolver["addr"]] = {
                "ips": ips, "error": err, "kind": resolver["kind"]}

    # One probe per (ip, port), shared across whichever resolvers returned it.
    targets = set()
    for endpoint in endpoints:
        for record in answers[endpoint["host"]].values():
            for ip in record["ips"]:
                if ":" in ip and not v6:
                    continue                      # no route; probing would only add noise
                targets.add((ip, endpoint["port"]))
    probes: dict[tuple, dict] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        for result in pool.map(lambda t: (t, tcp_probe(t[0], t[1], timeout)), sorted(targets)):
            probes[result[0]] = result[1]

    selftest = probe_selftest(timeout=timeout)

    rows, findings = [], []
    for endpoint in endpoints:
        host, port = endpoint["host"], endpoint["port"]
        per_resolver = []
        reachable_by_kind = {"system": False, "public": False}
        for resolver in resolvers:
            record = answers[host][resolver["addr"]]
            ip_status = []
            for ip in record["ips"]:
                probe = probes.get((ip, port))
                if probe is None:
                    ip_status.append({"ip": ip, "ok": None, "ms": None,
                                      "error": "skipped (no IPv6 route)"})
                    continue
                ip_status.append(probe)
                if probe["ok"]:
                    reachable_by_kind[record["kind"]] = True
            per_resolver.append({
                "resolver": resolver["addr"], "kind": resolver["kind"],
                "error": record["error"], "ips": ip_status,
            })

        all_ips = {ip for r in answers[host].values() for ip in r["ips"]}
        v4 = {ip for ip in all_ips if ":" not in ip}
        divergent = len({tuple(sorted(r["ips"])) for r in answers[host].values() if r["ips"]}) > 1
        any_ok = any(p["ok"] for (ip, prt), p in probes.items() if prt == port and ip in all_ips)

        status = "ok" if reachable_by_kind["system"] else ("degraded" if any_ok else "down")
        rows.append({
            "host": host, "port": port, "label": endpoint.get("label", ""),
            "status": status, "divergent": divergent,
            "distinct_ips": len(v4), "resolvers": per_resolver,
        })

        if status == "degraded":
            good = sorted({p["ip"] for (ip, prt), p in probes.items()
                           if prt == port and ip in all_ips and p["ok"]})
            bad = sorted({p["ip"] for (ip, prt), p in probes.items()
                          if prt == port and ip in all_ips and not p["ok"]})
            findings.append(degraded_finding(host, bad, good))
        elif status == "down":
            findings.append({"level": "warn", "text": (
                f"{host}: no resolver produced a reachable address on port {port}.")})
        elif divergent:
            findings.append({"level": "info", "text": (
                f"{host}: resolvers disagree on the address, but everything reachable. "
                f"Normal for CDN-hosted names — worth knowing if it starts failing.")})

    if not v6:
        aaaa = sum(1 for e in endpoints for r in answers[e["host"]].values()
                   for ip in r["ips"] if ":" in ip)
        if aaaa:
            findings.append({"level": "info", "text": (
                f"No IPv6 default route, yet {aaaa} AAAA record(s) came back. Clients that "
                f"try IPv6 first can stall before falling back to IPv4.")})

    if not selftest["trustworthy"]:
        findings.insert(0, {"level": "alert", "text": (
            f"Connection to {selftest['target']} succeeded — that address is reserved "
            f"and unroutable, so something is accepting every connection (captive "
            f"portal, transparent proxy, or hijacking middlebox). Every reachability "
            f"result below is unreliable until that is resolved.")})

    return {
        "platform": platforms.backend_name(),
        "resolvers": resolvers,
        "ipv6_route": v6,
        "selftest": selftest,
        "endpoints": rows,
        "findings": findings,
    }
