"""Entry point: python3 -m caner [--config caner.json]"""

from __future__ import annotations

import argparse
import sys

from . import __version__, config, server


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="caner", description=(
        "Featherweight diagnostic scanner: memory attribution, crash signatures, "
        "and DNS/endpoint reachability."))
    parser.add_argument("--config", "-c", help="path to a JSON config file")
    parser.add_argument("--host", help="override bind host")
    parser.add_argument("--port", type=int, help="override bind port")
    parser.add_argument("--once", action="store_true",
                        help="run each scanner once, print JSON, exit (no server)")
    parser.add_argument("--version", action="version", version=f"caner {__version__}")
    args = parser.parse_args(argv)

    try:
        cfg = config.load(args.config)
        if args.host:
            cfg["bind_host"] = args.host
        if args.port:
            cfg["bind_port"] = args.port
        if args.host or args.port:
            config.validate(cfg)
    except config.ConfigError as exc:
        print(f"caner: {exc}", file=sys.stderr)
        return 2

    if args.once:
        import json
        from . import crashscan, netscan, procscan
        print(json.dumps({
            "proc": procscan.scan(stale_after_s=cfg["stale_after_hours"] * 3600),
            "crash": crashscan.scan(known_issues_path=cfg["known_issues"]),
            "net": netscan.scan(endpoints=cfg["endpoints"],
                                public_resolvers=cfg["public_resolvers"]),
        }, indent=2, default=str))
        return 0

    server.serve(cfg)
    return 0


if __name__ == "__main__":
    sys.exit(main())
