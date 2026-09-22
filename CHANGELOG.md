# Changelog

All notable changes to caner are documented here, following
[Keep a Changelog](https://keepachangelog.com/) and [SemVer 2.0](https://semver.org/).

## [Unreleased]

## [0.5.0] — 2026-09-22

### Added
- **Platform backends** (`caner/platforms/`). Every host-specific fact now comes
  from one interface with a module per OS — `linux`, `darwin`, `windows`, and a
  `generic` fallback. No scanner knows which machine it is running on any more.

  The reason for doing this before adding features: caner started as a Linux
  tool and said so in `AGENTS.md`, which was enough for an agent on the Windows
  seat to decline to clone it. The tool was portable in principle and blocked in
  practice.

  Backends **decline** rather than guess — an unavailable fact is an empty list,
  `False` or `""`, never an exception and never a fabricated value. A backend
  missing a function falls through to `generic`, so a half-finished port keeps
  the scan loop alive instead of taking the service down.
- **`netscan` runs on macOS and Windows.** Resolver discovery is per-OS: the
  dynamic store via `scutil --dns` on macOS, because `/etc/resolv.conf` there is
  a compatibility file that often does not reflect what is actually queried; the
  registry via `winreg` on Windows, ordered so the interface holding the default
  route comes first, since Windows keeps subkeys for long-dead interfaces and
  does not say which is live.
- **Per-host DNS remediation.** The `degraded` alert used to hard-code an
  `nmcli` command. It now asks the platform — `networksetup` on macOS, `netsh`
  on Windows (flagged as needing elevation) — and prints no command at all when
  the host has no portable answer, rather than one that cannot run there.
- **Capability gating.** `/api/snapshot` reports `meta.platform.capabilities`, and the
  scan loop skips scanners this host cannot run, marking them `unsupported`.
  This is deliberately distinct from an error and from an empty result: on
  macOS a `procscan` returning `{}` would render as a clean zero, which is
  precisely the confident wrong conclusion this project was built to prevent.
- **Notifications on all three platforms** — `notify-send`, `osascript`, and a
  `NotifyIcon` balloon tip on Windows. Quote handling is per-host: AppleScript
  string literals take no escape sequences, PowerShell doubles single quotes.
- 36 tests (`tests/test_platforms.py`). Every backend is imported and checked on
  whatever OS runs the suite, so the contract is enforced from Seat 3 even for
  code that only runs on Seats 1 and 2. macOS resolver parsing is tested against
  captured `scutil` output.

### Changed
- `netscan.have_ipv6_route` no longer shells out to `ip -6 route`. It does a UDP
  `connect` to a global address, which performs a route lookup without sending a
  packet, costs the same on every OS, and needs no subprocess. Verified to agree
  with the previous implementation on this machine.
- `netscan.degraded_finding` extracted from `scan()` so the remediation path can
  be tested directly on a machine that is not the one the command is for.
- `server.self_rss_mb`, the state directory and the hostname all route through
  the platform seam. `os.uname()` is gone — it does not exist on Windows and
  would have failed at import.
- `AGENTS.md` states the platform support matrix and per-seat canonical paths,
  and says plainly that this is not a Linux-only project.

### Notes
- `procscan` and `crashscan` remain Linux-only, by choice rather than oversight.
  They are the larger rewrites and the least useful on the two seats that are
  not memory-starved; `netscan` is the one whose value *increases* with more
  seats, because comparing resolvers across machines distinguishes a bad router
  from a bad host — an answer a single seat structurally cannot produce.
- No supervisor unit ships for macOS or Windows yet; run `python3 -m caner`.
- Platform details sit on the authenticated `/api/snapshot`, not on
  `/api/health`. Health is unauthenticated liveness, and OS version, kernel
  release and hostname are not things to hand out without a token.
- Requires Python 3.9+ on every platform. The previous README figure of 3.11+ was
  stricter than the code: every module parses against a 3.7 target and
  `ThreadingHTTPServer` (3.7+) is the only stdlib API setting a floor. 3.9 is
  adopted as the supported minimum because it is what macOS ships. This was
  checked by parsing, not by running an older interpreter — no 3.9 runtime is
  available on Seat 3 to test against.

## [0.4.0] — 2026-09-22

### Added
- **Probe self-test** (`netscan.probe_selftest`). Every scan now also tries to
  connect to `192.0.2.1` — RFC 5737 TEST-NET-1, reserved for documentation and
  guaranteed never routed. Nothing may answer there.

  It is a control, not a formality. If that connection *succeeds*, something
  between this machine and the internet is accepting every connection — a
  captive portal, a transparent proxy, a hijacking middlebox — and in that state
  every reachability result netscan produces is meaningless. Reporting "all
  endpoints fine" would be worse than useless, so caner raises an alert saying
  the results cannot be trusted. Surfaced in the Network panel header.

  This also closes the gap noted in 0.1.0: netscan's probe path had never been
  exercised against a genuine black hole outside the unit tests. It now is, on
  every scan.
- 3 tests covering the trustworthy path, the interception path, and the alert
  that `scan()` raises when probes cannot be believed.

### Fixed
- The netscan verdict tests stubbed every address as reachable, which made the
  new self-test correctly conclude the network was intercepting traffic. The
  harness now keeps the reserved address unreachable, as a sane network would.

## [0.3.0] — 2026-09-22

### Added
- **History and sparklines** (`caner/history.py`). A point-in-time reading says
  the box is short of memory; it cannot say whether that is a leak growing over
  two hours or a browser someone just opened, and those call for opposite
  responses. caner now keeps a bounded ring of numeric samples and draws the
  shape.
  - Inline-SVG sparkline of available memory in the Memory panel, with range,
    trend and sample count. No charting library — a polyline and a fill.
  - **Trend finding**: a sustained decline of 250 MB or more over at least
    15 minutes raises a `warn`, which the notifier can then push. This is the
    first finding that is impossible to derive from a single scan.
  - Trend compares the mean of the first and last fifth of the window rather
    than first-vs-last point, so one dramatic dip does not read as a slide.
  - `/api/history` endpoint, with an optional `since_s` window.
- Persistence to `~/.local/state/caner/history.jsonl`, reloaded at startup. The
  systemd unit gains `StateDirectory=caner`, which stays writable despite
  `ProtectHome=read-only`. Hard 4 MB cap, truncating to the newest half — a
  monitor must not fill the disk it is monitoring.
- 9 further tests: ring bounding, spike rejection, span and threshold gates on
  the trend finding, persistence round-trip, tolerance of a torn final line, and
  that an unwritable path still records in memory rather than raising.

## [0.2.0] — 2026-09-22

### Added
- **Desktop notifications** (`caner/notify.py`). A dashboard only helps if someone
  is looking at it, and on an always-on box nobody is. Alert-level findings now
  push a `notify-send` to the desktop.

  The restraint is the feature — a monitor that cries wolf gets muted, and a muted
  monitor is worse than none. Three rules keep it quiet:
  - alerts only by default (`min_level`), never info or warn;
  - a finding must persist across **two consecutive scans** before it interrupts
    anyone, so a transient blip stays silent;
  - the same finding cannot fire twice inside `cooldown_s` (default 30 min), with
    fingerprints that ignore drifting numbers so "981.0 MB" and "984.2 MB" count
    as the same finding rather than a new one each scan.
- `notifications` block in `/api/snapshot` metadata (enabled, sent count, level).
- 7 further tests covering fingerprint stability, the two-scan rule, transient
  suppression, cooldown, level filtering and the disabled path.

### Fixed
- Cooldown treated "never sent" as "sent at epoch 0", so whether a first
  notification fired depended on `now` being a large wall-clock value. A finding
  with no send history is now always eligible. Caught by a unit test using small
  synthetic timestamps.

## [0.1.0] — 2026-09-22

First working release. Born out of a night spent misdiagnosing three separate
Minecraft launcher failures as "the machine is out of memory" when none of them
were.

### Added
- **procscan** — groups processes into applications and totals their RSS, so a
  thirty-process application reads as one row instead of thirty. Flags stale AI
  agent sessions and auto-spawned crash investigators, and computes how much
  closing them would actually free.
- **crashscan** — collapses core dumps into signatures (executable + signal +
  first non-boilerplate frames), so 41 dumps read as 4 problems. Detects crash
  storms, reports whether the application survived, maps signatures to known
  upstream issues via `known_issues.json`, and states plainly whether anything
  was OOM-killed — since an OOM kill is SIGKILL and leaves no core at all.
- **netscan** — queries every resolver separately and TCP-probes each distinct
  answer, catching the case where DNS resolves fine but hands you an address
  that is a black hole while another resolver would have given you a live one.
- Read-only JSON API (`/api/snapshot`, `/api/health`, `/api/rescan`) and a
  zero-build dashboard.
- Refuses to bind a non-loopback address without an access token.
- Command lines redacted by default; process arguments routinely carry secrets.
- 14 offline unit tests covering the DNS wire format, signature grouping,
  process classification, and the degraded/down/ok network verdicts.

### Notes
- Licensed MIT (code) and CC BY 4.0 (docs) — an explicit, signed-off exception
  to `ap-ops/docs/PROJECT-RULES.md` §3, which defaults every repo to proprietary.
