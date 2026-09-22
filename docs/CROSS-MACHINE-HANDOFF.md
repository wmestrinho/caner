# Cross-Machine Agent Handoff

GitHub is the transport between every AP workstation. Local files, chat history,
and an agent's memory are never assumed to exist on another machine. The
workstations form the **Satellite Office**; seat rules, the meaning of "I'm at
the Satellite Office", and the Seat 3 bootstrap are in
[`SATELLITE-OFFICE.md`](SATELLITE-OFFICE.md).

## Machine IDs

Use the IDs from `machines.json`:

- `mac-mini-m1` — Seat 1
- `lenovo-thinkpad-x260` — Seat 2
- `hp-slim-tower-omarchy` — Seat 3
- `acer-chromebook-flip` — loaner device, not a seat

Each checkout carries its own ID in a gitignored `.ap-machine` file (any
encoding PowerShell or a shell writes; a byte-order mark is tolerated), so
`--machine` may be omitted below; `python3 scripts/check_machine_sync.py whoami`
shows what a checkout believes it is.

One-time bootstrap for a machine that does not yet have the sync script:

```bash
git status --short --branch
git pull --ff-only
```

Only bootstrap from a clean, non-diverged tree. After that first pull, use the
receive command below for every session.

## Receive protocol — start of every session

1. Open the canonical checkout for that machine. This repo's folder is
   `ap-ops`; the workspace-wide local folder list is in
   [`LOCAL-REPO-NAMES.md`](LOCAL-REPO-NAMES.md).
2. Run `git status --short --branch` before changing anything.
3. If the tree is clean, run:

   ```bash
   python3 scripts/check_machine_sync.py receive --machine MACHINE_ID
   ```

   This fetches `origin`, refuses divergent or unpushed local work, and
   fast-forwards to the upstream branch.
4. Read `AGENTS.md`, `CLAUDE.md`, the newest section of `HANDOFF.md`, and the
   latest entries in `docs/MACHINE-RELAY.md` addressed to this machine.
5. Acknowledge a material incoming relay in `docs/MACHINE-RELAY.md` during the
   session's outgoing commit. An acknowledgement states the received commit and
   what the receiving agent is taking ownership of.

If the tree is dirty, do not pull, reset, rebase, or discard files. Identify the
owner of the local work and reconcile it with Luiz first.

## Send protocol — end of every meaningful session

1. Update `HANDOFF.md` with verified state, remaining work, and the exact next
   pickup.
2. Append one concise outbound entry to `docs/MACHINE-RELAY.md` naming the source
   machine, intended recipient machines, work commit (`this commit` is valid),
   validation performed, blockers, and requested acknowledgement.
3. Run repository validation and review the full diff for secrets and unrelated
   changes.
4. Commit and push the work. A local-only commit is not a handoff.
5. Confirm the branch is clean and synchronized:

   ```bash
   python3 scripts/check_machine_sync.py send --machine MACHINE_ID
   ```

The send check fails if the branch is dirty, ahead, behind, divergent, or if the
current commit does not include `HANDOFF.md` or `docs/MACHINE-RELAY.md`.

## Relay rules

- `HANDOFF.md` is the current project narrative; `MACHINE-RELAY.md` is the
  append-only delivery and acknowledgement ledger. Do not put task details in
  the ledger that belong in the handoff.
- Never put secrets, tokens, private client data, or uncommitted filesystem paths
  in either file.
- Do not overwrite another machine's unacknowledged entry. Append an
  acknowledgement or a superseding entry.
- GitHub commit history is the evidence that a message was sent. A receiver's
  acknowledgement commit is the evidence that it was received.
- A machine listed as `onboarding` in `machines.json` (Seat 3 and the
  Chromebook today) is sent relays when relevant, but receipt is never assumed
  until its own acknowledgement is pushed. Its first pushed ACK is the commit
  that flips it to `active`.
- With more than one seat live in the same session, fetch before every commit;
  `main` can move under you between receive and send.
