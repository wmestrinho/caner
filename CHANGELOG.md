# Changelog

All notable changes to caner are documented here, following
[Keep a Changelog](https://keepachangelog.com/) and [SemVer 2.0](https://semver.org/).

## [Unreleased]

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
