"""Configuration: defaults, JSON overlay, and the one rule that is not negotiable."""

from __future__ import annotations

import json
import os

DEFAULTS = {
    "bind_host": "127.0.0.1",
    "bind_port": 8787,
    # Required to bind anything other than loopback. Generate with:
    #   python3 -c "import secrets;print(secrets.token_urlsafe(24))"
    "token": "",
    "intervals_s": {"proc": 10, "crash": 120, "net": 600},
    "stale_after_hours": 4,
    # Process command lines routinely contain prompts, API keys and file paths.
    # Off by default; turning it on over a LAN bind is a deliberate choice.
    "reveal_cmdlines": False,
    "known_issues": "known_issues.json",
    "public_resolvers": ["9.9.9.9", "1.1.1.1", "8.8.8.8"],
    "endpoints": None,          # None -> netscan.DEFAULT_ENDPOINTS
    # Desktop notifications. Deliberately conservative: alerts only, one per
    # 30 min, and a finding must survive two scans before it interrupts anyone.
    # A small ring of numeric samples so the dashboard can show direction of
    # travel. Bounded in memory and on disk; a monitor must not fill the disk
    # it is monitoring.
    "history": {"persist": True, "retain_samples": 1080, "sample_every_s": 30,
                "filename": "history.jsonl"},
    "notify": {"enabled": True, "min_level": "alert", "cooldown_s": 1800,
               "require_repeat": True},
}


class ConfigError(Exception):
    pass


def load(path: str | None) -> dict:
    cfg = json.loads(json.dumps(DEFAULTS))     # deep copy of plain data
    if path:
        if not os.path.exists(path):
            raise ConfigError(f"config not found: {path}")
        with open(path, encoding="utf-8") as handle:
            user = json.load(handle)
        for key, value in user.items():
            if key.startswith("_"):
                continue
            if isinstance(value, dict) and isinstance(cfg.get(key), dict):
                cfg[key].update(value)
            else:
                cfg[key] = value
    validate(cfg)
    return cfg


def validate(cfg: dict) -> None:
    host = cfg.get("bind_host", "")
    loopback = host in ("127.0.0.1", "::1", "localhost")
    if not loopback and not cfg.get("token"):
        raise ConfigError(
            f"refusing to bind {host} without a token.\n"
            f"caner exposes process names, crash traces and your DNS layout. "
            f"Set \"token\" in the config, or bind 127.0.0.1.\n"
            f"Generate one: python3 -c \"import secrets;print(secrets.token_urlsafe(24))\"")
    if cfg.get("reveal_cmdlines") and not loopback and not cfg.get("token"):
        raise ConfigError("reveal_cmdlines on a non-loopback bind requires a token")
