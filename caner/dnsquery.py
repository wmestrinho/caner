"""Minimal DNS-over-UDP resolver.

Exists so netscan can ask *specific* resolvers what they return, which
`socket.getaddrinfo` cannot do -- it only ever uses the system resolver, and the
whole point of netscan is catching the case where the system resolver is the
thing that is wrong. Pure stdlib: no dnspython, no dig.
"""

from __future__ import annotations

import random
import socket
import struct

from . import platforms

TYPE_A = 1
TYPE_AAAA = 28
CLASS_IN = 1


class DNSError(Exception):
    pass


def _encode_name(name: str) -> bytes:
    out = bytearray()
    for label in name.rstrip(".").split("."):
        encoded = label.encode("idna") if any(ord(c) > 127 for c in label) else label.encode()
        if not 0 < len(encoded) < 64:
            raise DNSError(f"bad label in {name!r}")
        out.append(len(encoded))
        out += encoded
    out.append(0)
    return bytes(out)


def _skip_name(data: bytes, off: int) -> int:
    """Advance past a (possibly compressed) name, returning the new offset."""
    while True:
        if off >= len(data):
            raise DNSError("truncated name")
        length = data[off]
        if length == 0:
            return off + 1
        if length & 0xC0 == 0xC0:          # compression pointer: 2 bytes, no tail
            return off + 2
        off += length + 1


def query(server: str, name: str, rtype: int = TYPE_A, timeout: float = 3.0) -> list[str]:
    """Ask `server` for `name`, returning a list of address strings.

    Raises DNSError on timeout, refusal, or a malformed reply. CNAME chains are
    followed implicitly: we ignore non-matching record types and collect every
    address record in the answer section.
    """
    txid = random.randint(0, 0xFFFF)
    header = struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0)  # RD=1
    question = _encode_name(name) + struct.pack(">HH", rtype, CLASS_IN)

    family = socket.AF_INET6 if ":" in server else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(header + question, (server, 53))
        while True:
            data, _ = sock.recvfrom(4096)
            if len(data) >= 2 and struct.unpack(">H", data[:2])[0] == txid:
                break
    except socket.timeout as exc:
        raise DNSError("timeout") from exc
    except OSError as exc:
        raise DNSError(str(exc)) from exc
    finally:
        sock.close()

    if len(data) < 12:
        raise DNSError("short reply")
    _, flags, qdcount, ancount, _, _ = struct.unpack(">HHHHHH", data[:12])
    rcode = flags & 0xF
    if rcode != 0:
        raise DNSError({1: "format error", 2: "server failure", 3: "NXDOMAIN",
                        4: "not implemented", 5: "refused"}.get(rcode, f"rcode {rcode}"))

    off = 12
    for _ in range(qdcount):
        off = _skip_name(data, off) + 4

    results: list[str] = []
    for _ in range(ancount):
        off = _skip_name(data, off)
        if off + 10 > len(data):
            raise DNSError("truncated record")
        rr_type, _rr_class, _ttl, rdlen = struct.unpack(">HHIH", data[off:off + 10])
        off += 10
        rdata = data[off:off + rdlen]
        off += rdlen
        if rr_type == TYPE_A and rdlen == 4:
            results.append(socket.inet_ntoa(rdata))
        elif rr_type == TYPE_AAAA and rdlen == 16:
            results.append(socket.inet_ntop(socket.AF_INET6, rdata))
    return results


def system_resolvers() -> list[str]:
    """Upstream resolvers this host actually queries.

    Where they are recorded is entirely OS-specific — resolv.conf, the macOS
    dynamic store, the Windows registry — so the lookup lives in `platforms`.
    Kept here as the name netscan and the tests already call.
    """
    return platforms.system_resolvers()
