# Machine Relay Ledger — caner

Append-only delivery and acknowledgement log for cross-machine agent work.
Protocol: [`CROSS-MACHINE-HANDOFF.md`](CROSS-MACHINE-HANDOFF.md).

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
