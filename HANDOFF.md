# HANDOFF — caner

Cross-session state. Append newest at the top.

## 2026-09-22 — v0.3.0 (Seat 3, HP Omarchy)

**State:** running under systemd, v0.3.0. 30 tests pass, footprint 26.6 MB.

- v0.2.0 added desktop notifications — alerts only, two-scan confirmation,
  30 min cooldown, fingerprints that ignore drifting numbers.
- v0.3.0 added history, sparklines and a trend finding; samples persist to
  `~/.local/state/caner/history.jsonl` via `StateDirectory=caner` and survive a
  restart (verified).

**Open / next**
- Still no cold-boot test (only `systemctl --user restart`).
- `netscan`'s `degraded` verdict still has never fired on a live failure; the
  dead Akamai edge that motivated it healed before the scanner existed.
- Trend finding has not yet fired in production — needs a real slow leak.

## 2026-09-22 — v0.1.0, first working release (Seat 3, HP Omarchy)

**State:** working, installed and enabled as a systemd **user** service
(`systemctl --user status caner`), serving on `0.0.0.0:8787` behind a token.
Survives restart; starts at login.

Built in one session after diagnosing a Minecraft launcher crash that turned out
to be three unrelated problems, none of them the memory exhaustion they resembled.
Each scanner automates one step of that night's manual work.

Verified on this machine:
- `procscan` — 42 application groups, correctly attributed 1.08 GB of reclaimable
  memory to stale agent sessions and crash investigators.
- `crashscan` — collapsed 41 core dumps into 4 signatures; auto-matched the
  38×SIGABRT group to omarchy#11323 and the SIGSEGV to the Mojang bootstrapper bug.
- `netscan` — all five seeded endpoints reachable. The failure it was written for
  (router DNS returning a dead Akamai edge) had already healed by build time, so
  the degraded/down verdicts are covered by unit tests rather than a live case.
- Footprint 26.5 MB; 14 tests pass; responsive check clean.

**Open / next**
- Confirm it comes back after a full reboot (only `systemctl --user restart`
  has been exercised so far).
- `netscan` has never fired a real `degraded` verdict in the wild — worth
  re-checking the next time an endpoint misbehaves.
- No history/trend storage yet; the API returns point-in-time state only.
- GitHub Actions is disabled account-wide, so `version-check.yml` ships but never
  runs. Validate locally before every commit.
