# CLAUDE.md — caner

Guidance for Claude Code when working in this repository. Read `AGENTS.md` first;
this file adds detail rather than repeating it.

## What this repo is

A diagnostic scanner, written after a night where three unrelated failures were
all misread as "out of memory". Its job is to make that mistake harder — so the
bar for every feature is: *does this stop someone reaching a confident wrong
conclusion?*

## Design rules that carry the value

**Group before you list.** Thirty rows of 40 MB hide a 1.2 GB application; 41
crash rows hide the fact that there are 4 problems. Every scanner collapses raw
events into the unit a human reasons about.

**Say what the evidence rules out, not just what it shows.** "No OOM kills this
boot — an OOM kill is SIGKILL and leaves no core" is more useful than a crash
count, because it closes off the wrong answer.

**Signatures skip boilerplate.** `abort`/`raise`/`_Unwind_Resume`/`__cxa_*` frames
are identical across every C++ abort. Grouping on them merges unrelated bugs.
`crashscan.signature_frames()` drops them; there are tests for this — keep them.

**Ask each resolver separately.** `socket.getaddrinfo` only ever uses the system
resolver, which is the thing netscan is trying to catch being wrong. That is why
`dnsquery.py` speaks DNS over UDP directly.

## Layout

```
caner/procscan.py    /proc walk, application grouping, reclaimable maths
caner/crashscan.py   coredumpctl -> signatures, storms, known-issue mapping
caner/netscan.py     per-resolver DNS + TCP probe, divergence verdicts
caner/dnsquery.py    minimal DNS/UDP client (no dnspython)
caner/server.py      scan loop + read-only JSON API + static files
caner/config.py      defaults, JSON overlay, the non-loopback token rule
web/                 zero-build dashboard (vanilla JS)
known_issues.json    signature fragments -> upstream issue URLs
```

## Gotchas

- `/proc` races: a PID can vanish between `listdir` and `open`. Every read is
  guarded; keep it that way.
- `coredumpctl info` is one subprocess per dump. Results are cached by PID in
  `_sig_cache`; do not remove the cache without bounding the work another way.
- The responsive standard is enforced (`scripts/check_responsive.py`): viewport
  meta on every page, no `overflow:hidden` on `html`/`body`, breakpoints at
  600/900/1200, `minmax(0,1fr)` rather than bare `1fr`, controls at 16px+.
- `caner.json` holds the access token and is gitignored. Never commit it.

## Adding a scanner

Return `{"findings": [{"level": "alert|warn|info", "text": "..."}], ...}` and
register it in `server.Scanner.run`. A finding should name the fix, not just the
symptom — netscan emits the actual `nmcli` command.
