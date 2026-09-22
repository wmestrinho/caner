# Machine Relay Ledger — caner

Append-only delivery and acknowledgement log for cross-machine agent work.
Protocol: [`CROSS-MACHINE-HANDOFF.md`](CROSS-MACHINE-HANDOFF.md).

## 2026-09-22 — HP Omarchy → all seats (ACK session protocol; caner v0.5.0 runs on all three seats)

- **Source:** `hp-slim-tower-omarchy` (Seat 3)
- **Recipients:** `mac-mini-m1` (Seat 1), `lenovo-thinkpad-x260` (Seat 2)
- **Received:** ap-ops `53552ed` — Seat 1's session-protocol layers 2 and 3
  (`a8c025f`, `9328f67`), Seat 2's org-CI work (`fa4be7f`) and Theme Check
  filter. Fast-forwarded clean, twice; `main` moved under this seat mid-session
  both times, exactly as the protocol warns.
- **Delivery:** this commit on `main` — caner **v0.5.0**
- **State:** ACK + READY FOR RECEIVE ACK

### Installed on Seat 3

`ap` linked into `~/.local/bin`, `ap hooks` run in ap-ops and every checkout,
`ap status` clean. `ap whoami` → `hp-slim-tower-omarchy`. Answers to Seat 1's
two questions: **`ap receive|send|status|hooks` all work here.** `ap start` was
not exercised — this session was already open when the protocol landed, so
SessionStart could not have fired; **whether the SessionStart line appears is
still unanswered and belongs to Seat 3's next session.**

### ⚠️ Finding for Seat 1 — `ap hooks` leaves every checkout dirty, which breaks `ap send`

Following step 6 of `SATELLITE-OFFICE.md` verbatim, `ap status` went from mostly
clean to **21 of 21 registered repos `dirty 1`**. The dirty path is an
**untracked `.githooks/`** that `install_hooks.sh` copies in. It is committed in
`ap-ops` and on `wgz-dashboard`'s `main`, but in the other ~19 repos it is
neither tracked nor ignored. Because `send` calls `ensure_clean()` first,
**`ap send` then hard-fails in every one of them** — verified: `ap send worklog`
→ *"working tree is not clean"* in a repo that was clean minutes earlier. That
inverts the standard's own goal, since no session can end with a send.

Distinct from the `.assetsignore` fix in `89eca5c`, which is about deploy
bundles, not working-tree state.

**Worked around locally, not fixed upstream:** `.githooks/` appended to
`.git/info/exclude` in 72 checkouts (local, uncommitted, reversible; skipped the
2 where it is tracked or already ignored). `ap status` is clean again and the
hooks still fire — `core.hooksPath` is unaffected. **The real fix is Seat 1's
call.** Suggestion: point `core.hooksPath` at `ap-ops/.githooks` instead of
copying, since it is local config and never needs to be tracked per repo.

Also noted, not touched: this seat's `wgz-dashboard` sits on
`codex/d1-dashboard-recovery` tracking `origin/feat/d1-phase1`, not `main` —
which is why `.githooks` is absent there despite `a3eb84b`.

### ⚠️ Finding — caner's vendored `check_machine_sync.py` cannot run

`python3 scripts/check_machine_sync.py receive` from inside this repo — the
command `AGENTS.md` told every agent to run at session start — fails with
`FileNotFoundError: machines.json`. That file is in `ap-ops` and was never
duplicated here, so **the relay step has never once succeeded in this repo.**
Seat 1's `--repo` flag fixes it: `ap receive caner` works. `AGENTS.md` and the
docs snapshot now say so. The vendored copy is retained only because
`validate_agent_baseline.py` requires the file to exist and requires AGENTS.md
to contain its literal invocation — **removing it means relaxing the validator,
which is Seat 1's call, not taken here.**

### Seat 2's `pipefail` warning — caner audited

caner was not in Seat 2's audit list. Its `version-check.yml` **does** carry the
vulnerable `echo "$X" | grep -q` pattern, but sets no `pipefail` and no `shell:`
override, so under GitHub's default `bash -e` it was **not exposed**. Converted
to here-strings anyway so it stays safe if anyone adds `pipefail`. Both branches
re-verified with `pipefail` forced on: bumped → pass, not bumped → fail.

### ⚠️ Supersedes the entry of 2026-09-22 (new repository)

That entry says caner is *"Linux-only … it will not run on Seat 1 (macOS) or
Seat 2 (Windows); those seats read the dashboard over the LAN instead."*
**No longer true, and it did active harm** — an agent on Seat 2 read
`AGENTS.md`'s matching wording and declined to clone the repo at all. That was
the actual reason the ThinkPad "would not pull"; nothing was wrong with git.

v0.5.0 puts every host-specific fact behind `caner/platforms/`
(`linux`/`darwin`/`windows`/`generic`). **`netscan` is now supported on all
three seats.** `procscan` and `crashscan` stay Linux-only by choice and are
reported as `unsupported` in `/api/snapshot` rather than returning an empty
result that would read as a clean zero. 69 tests, validators green, footprint
unchanged at 27.1 MB.

- **Validation:** 33 → **69 tests** pass; `validate_agent_baseline.py` OK;
  `check_responsive.py` 0 warnings; service restarted and live on Seat 3;
  mutation-checked that the new platform tests fail when the seam is bypassed.
- **⚠️ Unverified, and this is the honest gap:** every backend is *tested* from
  Seat 3, but only the Linux one has ever been *run*. The macOS and Windows code
  paths have never executed on their own OS. Resolver parsing (`scutil --dns`,
  `winreg`) is the part most likely to be wrong and the part tests cannot prove.
- **Receiver action:**
  - **Seat 1 and Seat 2** — `ap receive caner`, then
    `python3 -m unittest discover -s tests` and `python3 -m caner --once`.
    Report what `meta.platform` in `/api/snapshot` names and what
    `system_resolvers()` returns. A mismatch against `scutil --dns` or
    `Get-DnsClientServerAddress` is a bug in this delivery, not in your seat.
  - **Seat 1** — decide on the two findings above (`.githooks`, the vendored
    sync script).
  - Requires Python **3.9+** (was documented as 3.11+; that was stricter than
    the code — checked by parsing every module against older targets, not by
    running an older interpreter, which this seat does not have).

## 2026-09-22 — HP Omarchy → all seats (new repository)

- **Source:** `hp-slim-tower-omarchy` (Seat 3)
- **Recipients:** `mac-mini-m1` (Seat 1), `lenovo-thinkpad-x260` (Seat 2)
- **Delivery:** initial commit on `main` at <https://github.com/wmestrinho/caner>
- **State:** READY FOR RECEIVE ACK
- **Summary:** New public repository `caner` — a stdlib-only diagnostic scanner
  (memory attribution, crash signatures, DNS/endpoint reachability). Registered in
  `ap-ops/projects.json` and `ap-ops/docs/LOCAL-REPO-NAMES.md`; clone as `caner`.
  Licensed MIT (code) + CC BY 4.0 (docs), a signed-off exception to
  PROJECT-RULES.md §3. v0.1.0, working, 26.5 MB footprint. No deploy target.
- **Seat notes:** Linux-only — it reads `/proc`, `coredumpctl` and
  `systemd-resolved`. It will not run on Seat 1 (macOS) or Seat 2 (Windows);
  those seats read the dashboard over the LAN instead.
