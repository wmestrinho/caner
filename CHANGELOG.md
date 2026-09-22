# Changelog

All notable changes to caner are documented here, following
[Keep a Changelog](https://keepachangelog.com/) and [SemVer 2.0](https://semver.org/).

## [Unreleased]

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
