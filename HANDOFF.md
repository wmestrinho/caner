# HANDOFF — caner

Cross-session state. Append newest at the top.

## 2026-09-22 — v0.5.0, platform seam + netscan on three OSes (Seat 3)

**State:** uncommitted on `main`. 69 tests pass, validators clean, service
restarted and live at 27.1 MB.

Why this came first: Seat 2 (ThinkPad) refused to clone the repo — not a git
failure, an agent reading `AGENTS.md` calling this "a scanner for low-memory
**Linux** workstations" with a Seat-3 canonical path and correctly concluding it
did not belong there. The docs were the blocker. `AGENTS.md` now carries a
platform support matrix and per-seat paths.

- `caner/platforms/` — `linux`, `darwin`, `windows`, `generic` fallback. Backends
  decline (empty list / `False` / `""`) rather than raise or fabricate; a missing
  function falls through to `generic` so a half-finished port stays alive.
- `netscan` supported on all three. Resolvers: `scutil --dns` on macOS,
  `winreg` on Windows ordered by the interface holding the default route.
- Scanners are gated on capability. `procscan`/`crashscan` report `unsupported`
  on non-Linux rather than an empty result that reads as a clean zero.
- `have_ipv6_route` no longer shells out — UDP `connect` route lookup, verified
  to agree with `ip -6 route` here.

**Unverified — this is the honest gap.** Every backend is *tested* from Seat 3,
but only the Linux one has been *run*. The macOS and Windows paths have never
executed on their own OS. First thing to do on Seats 1 and 2:

    git pull && python3 -m unittest discover -s tests && python3 -m caner --once

Then check `meta.platform` in `/api/snapshot` names the right backend, and that
`system_resolvers()` returns what the machine actually queries — that parsing is
the part most likely to be wrong, and it is the part tests cannot prove.

**Open / next**
- `procscan` + `crashscan` backends for macOS (`ps`, `.ips` crash reports) and
  Windows (ctypes Toolhelp, WER). macOS `.ips` files are JSON and arguably easier
  than `coredumpctl`.
- No launchd plist or Scheduled Task unit yet.
- `netscan`'s `degraded` verdict still has never fired on a live failure; running
  on three seats finally makes a router-vs-host comparison possible.
- Mojang report still unfiled; `known_issues.json` has nowhere to point for the
  SIGSEGV signature until it has an MCL key.

## 2026-09-22 — cold boot verified (Seat 3, HP Omarchy)

First real cold boot, 03:03 EDT. caner came back **on its own**, no intervention:

- `systemctl --user is-active` → active, is-enabled → enabled; ActiveEnterTimestamp
  03:04:58, i.e. it started at login without being touched.
- Footprint **26.9 MB** — unchanged across the boot, still well inside the 40 MB budget.
- History **survived**: 239 samples, up from 119 pre-reboot. `StateDirectory=caner`
  reloaded the existing `history.jsonl` and kept appending rather than truncating.
- LAN bind came back on the same address (192.168.0.95:8787).

This closes the "no cold-boot test" item that had been open since v0.1.0.

Still open: `netscan`'s `degraded` verdict has still never fired on a live failure,
and the trend finding has still never fired in production.

## 2026-09-22 — v0.4.0 (Seat 3, HP Omarchy)

**State:** running under systemd, v0.4.0. 33 tests pass, footprint ~26.6 MB.

- v0.2.0 added desktop notifications — alerts only, two-scan confirmation,
  30 min cooldown, fingerprints that ignore drifting numbers.
- v0.4.0 added a probe self-test against a reserved unroutable address, which
  doubles as captive-portal / transparent-proxy detection.
- v0.3.0 added history, sparklines and a trend finding; samples persist to
  `~/.local/state/caner/history.jsonl` via `StateDirectory=caner` and survive a
  restart (verified).

**Open / next**
- Still no cold-boot test (only `systemctl --user restart`).
- `netscan`'s `degraded` verdict still has never fired on a live failure; the
  dead Akamai edge that motivated it healed before the scanner existed. The
  *probe path* is now exercised on every scan by the v0.4.0 self-test against
  RFC 5737 TEST-NET-1, so a probe that cannot detect failure would be caught.
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
