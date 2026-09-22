# caner

A featherweight diagnostic scanner for low-memory Linux workstations.
Three scanners, one dashboard, **Python standard library only** — no pip, no npm,
no build step. It runs in about **26 MB**.

> *caner*, short for *scanner*. Built on an HP 260-a114 with 3.2 GB of RAM, where
> being wrong about memory costs you an evening.

## Why

Three failures in one night all looked like "the machine is out of memory."
None of them were:

| Looked like | Actually was |
| --- | --- |
| Application crashed on launch | A NULL vtable call — a `clicked` handler written with an event-handler signature, reading its `self` from the wrong register |
| Crashed again at sign-in | A clean exit, status 0, after sign-in was cancelled |
| Crashed again, "memory struggling" | A clean exit again — the router's DNS was handing out a dead CDN edge |

Meanwhile the machine's largest memory consumer turned out to be seven stale AI
agent sessions holding 1.2 GB, which nothing surfaced. caner surfaces all of it.

## The three scanners

### procscan — memory attributed to applications, not PIDs
`top` sorted by RSS is useless when one application is thirty processes: you see
thirty rows of 40 MB and miss that they sum to 1.2 GB. procscan groups processes
into applications, totals them, and computes what closing the stale ones frees.
It knows about AI agent sessions specifically, including auto-spawned crash
investigators — which are pure duplicated work and worth closing on sight.

### crashscan — core dumps collapsed into signatures
A crash list is a poor diagnostic. 41 dumps grouped into 4 signatures is a good
one. The signature is executable + signal + the first frames that are *not*
`abort`/`raise`/`_Unwind_Resume` boilerplate, because every C++ abort shares
those and grouping on them merges unrelated bugs.

It also answers the question that cost the most time: **was anything actually
OOM-killed?** An OOM kill is SIGKILL and leaves no core, so every core dump on
disk is by definition something the program did to itself.

### netscan — the resolver that hands you a dead address
Ordinary reachability checks resolve a name the system way and connect, which
hides the interesting failure: DNS answers correctly and the address you were
given is a black hole, while a different resolver would have handed you a
working one. CDNs pick an edge per resolver, so "DNS works" and "you can reach
the service" are different questions. netscan asks every resolver separately and
TCP-probes each distinct answer.

## Install and run

```bash
git clone https://github.com/wmestrinho/caner.git
cd caner
cp config.example.json caner.json
python3 -c "import secrets;print(secrets.token_urlsafe(24))"   # paste into caner.json
python3 -m caner --config caner.json
```

Then open `http://<host>:8787/?token=<your-token>`.

One-shot JSON, no server:

```bash
python3 -m caner --once | less
```

Requires Python 3.11+ and Linux (`/proc`, `coredumpctl`, `systemd-resolved`).

## Deployment

caner is meant to be read **from another machine**, so the box being measured
does not spend 300 MB on a browser tab to watch its own memory.

Binding anything other than loopback **requires a token** — caner refuses to
start otherwise. It exposes process names, crash traces and your DNS layout, so
treat the URL as a credential and keep it to a trusted LAN.

Process command lines are redacted by default (`reveal_cmdlines: false`). They
routinely contain prompts, API keys and file paths.

Run it under systemd as a user service:

```bash
cp systemd/caner.service ~/.config/systemd/user/
systemctl --user daemon-reload && systemctl --user enable --now caner
```

The unit caps memory at 128 MB and sets `OOMScoreAdjust=500` — if the box truly
runs out of memory, the monitor should be the first thing sacrificed, not the
work you were doing.

### History and trends

caner keeps a bounded ring of samples and draws available memory as a sparkline,
because the useful question is rarely "how much is free" but "which way is it
going". A sustained fall of 250 MB or more over 15 minutes raises a warning —
the one finding that cannot be derived from a single scan.

Samples persist to `~/.local/state/caner/history.jsonl` (capped at 4 MB) and
reload on restart. Tune in `caner.json`:

```json
"history": { "persist": true, "retain_samples": 1080, "sample_every_s": 30 }
```

### Notifications

Alert-level findings push a desktop notification via `notify-send`, because an
always-on box is one nobody is watching. It is deliberately quiet: alerts only,
a finding must survive two consecutive scans before it fires, and the same
finding cannot repeat inside 30 minutes. Tune or disable it in `caner.json`:

```json
"notify": { "enabled": true, "min_level": "alert", "cooldown_s": 1800, "require_repeat": true }
```

caner never kills a process. It prints the command and leaves the decision to you.

## Version

Current: see [`VERSION`](VERSION). Strict SemVer; see
[`CHANGELOG.md`](CHANGELOG.md) and
[ap-ops/docs/PROJECT-RULES.md](https://github.com/wmestrinho/ap-ops/blob/main/docs/PROJECT-RULES.md).

## Validation

```bash
python3 -m unittest discover -s tests -v   # 14 offline tests, no network, no root
python3 scripts/validate_agent_baseline.py
python3 scripts/check_responsive.py
```

## Licence

Split, deliberately:

- **Code** — [MIT](LICENSE). Permissive, short, and the default people expect
  from a small utility.
- **Documentation** — [CC BY 4.0](LICENSE-DOCS). Creative Commons
  [recommends against](https://creativecommons.org/faq/#can-i-apply-a-creative-commons-license-to-software)
  applying CC licences to software, so it covers prose only.

This is an explicit exception to `PROJECT-RULES.md` §3, which defaults every AP
repo to proprietary and requires sign-off to open-source one.
