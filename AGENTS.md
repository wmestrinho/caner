# AGENTS.md — caner

Canonical path
- Seat 3 (HP, Omarchy Linux) — `~/Projects/wmestrinho/caner`, where it was written
- Seat 2 (ThinkPad, Windows)  — `%USERPROFILE%\Projects\wmestrinho\caner`
- Seat 1 (Mac Mini, macOS)    — `~/Projects/wmestrinho/caner`
- Any seat may clone it; the folder basename must stay `caner`.

Project purpose
- A featherweight diagnostic scanner for developer workstations: memory
  attribution (`procscan`), crash-signature correlation (`crashscan`), and
  DNS/endpoint reachability (`netscan`). See `README.md`.

**This is not a Linux-only project — clone it on any seat.** It began on Linux
and Linux is still the only seat where every scanner runs, but as of v0.5.0 the
host-specific parts live behind `caner/platforms/`, and `netscan` is supported on
all three. An agent on macOS or Windows should clone and work on it normally.
What it must *not* do is assume an unported scanner is broken: `/api/snapshot`
reports `meta.platform.capabilities`, and a scanner marked `unsupported` there is
a known gap, not a regression. (It is *not* on `/api/health`, which is
unauthenticated liveness — OS version and hostname do not belong on an endpoint
that needs no token.)

Platform support (v0.5.0)

| Scanner    | Linux | macOS | Windows |
|------------|-------|-------|---------|
| `netscan`  | yes   | yes   | yes     |
| `procscan` | yes   | not yet | not yet |
| `crashscan`| yes   | not yet | not yet |

- Requires Python **3.9+**, stdlib only, on every platform.
- Adding a platform backend: implement `platforms._REQUIRED` in a new module and
  register it in `platforms._pick`. Anything the host cannot do must *decline*
  (empty list, `False`, `""`) — never raise, and never fake a value.
- Never reintroduce an OS-specific call outside `caner/platforms/`. The check is
  `grep -rn "/proc\|os.uname\|notify-send\|coredumpctl" caner/ --exclude-dir=platforms`.

Required baseline for AI agents
- Read this file before editing.
- Check `git status --short --branch` before editing, committing, rebasing, or pushing.
- Start every session with a receive and end it with a send, per the Session
  Protocol Standard (2026-09-22). From any seat with the `ap` launcher installed:

      ap receive caner        # start of session
      ap send caner           # end of session

  **Use `ap`, not the vendored script.** `python3 scripts/check_machine_sync.py receive`
  run from inside this repo fails with `FileNotFoundError: machines.json` — that
  file lives in `ap-ops` and is not duplicated here. The launcher resolves it via
  `--repo`, which is what makes the check work in any registered repo. The
  vendored copy is kept only because `validate_agent_baseline.py` requires it;
  whether it should be removed is Seat 1's call (raised in the relay, 2026-09-22).
- Log deliveries in `docs/MACHINE-RELAY.md`; the canonical protocol is
  `ap-ops/docs/CROSS-MACHINE-HANDOFF.md`. The copy in this repo's `docs/` is a
  snapshot and may lag.
- Preserve project-specific instructions in `CLAUDE.md`.
- Run validation before commit.

Hard constraints — do not regress these
- **Standard library only.** No pip, no npm, no build step. A dependency that
  needs installing on a 3.2 GB box defeats the purpose of the tool.
- **Stay under ~40 MB RSS.** A memory monitor that eats 300 MB is self-defeating.
  `/api/health` reports the live figure; check it after any change.
- **Read-only.** caner never kills a process, edits config, or writes outside its
  own directory. It prints the command and lets the human decide.
- **No secrets over the wire.** Command lines carry prompts and API keys;
  `reveal_cmdlines` stays `false` by default and a non-loopback bind requires a token.

Version rule
- Versioning, CHANGELOG, tags and CI conventions:
  <https://github.com/wmestrinho/ap-ops/blob/main/docs/PROJECT-RULES.md>.
- LICENCE is a signed-off exception to §3: MIT for code, CC BY 4.0 for docs.

Deployment
- No hosted deploy. Runs on the machine being measured; read the dashboard from
  another machine over the LAN.
- Linux: systemd **user** service (`systemd/caner.service`).
- macOS and Windows: no supervisor unit ships yet — run `python3 -m caner` by
  hand. launchd and Scheduled Task units are open work.

Validation
- Run: `python3 -m unittest discover -s tests`
- Run: `python3 scripts/validate_agent_baseline.py`

Coordination warning
- Multiple AI agents may work across this workspace. Do not run destructive git
  commands without checking status and coordinating with Luiz.
