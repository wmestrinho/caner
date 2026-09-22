# AGENTS.md — caner

Canonical path
- `~/Projects/wmestrinho/caner` (Seat 3, HP Omarchy — where it was written)
- Any seat may clone it; the folder basename must stay `caner`.

Project purpose
- A featherweight diagnostic scanner for low-memory Linux workstations:
  memory attribution (`procscan`), crash-signature correlation (`crashscan`),
  and DNS/endpoint reachability (`netscan`). See `README.md`.

Required baseline for AI agents
- Read this file before editing.
- Check `git status --short --branch` before editing, committing, rebasing, or pushing.
- Run `python3 scripts/check_machine_sync.py receive` at the start of a session and
  log deliveries in `docs/MACHINE-RELAY.md`; the protocol is in
  `docs/CROSS-MACHINE-HANDOFF.md`.
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
- No hosted deploy. Runs as a systemd **user** service on the machine being
  measured; read the dashboard from another machine over the LAN.

Validation
- Run: `python3 -m unittest discover -s tests`
- Run: `python3 scripts/validate_agent_baseline.py`

Coordination warning
- Multiple AI agents may work across this workspace. Do not run destructive git
  commands without checking status and coordinating with Luiz.
