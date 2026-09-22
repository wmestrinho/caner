# Changelog

All notable changes to caner are documented here, following
[Keep a Changelog](https://keepachangelog.com/) and [SemVer 2.0](https://semver.org/).

## [Unreleased]

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
