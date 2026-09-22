#!/usr/bin/env python3
"""Verify and synchronize AP Ops cross-machine Git handoffs."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
MACHINES_FILE = ROOT / "machines.json"
# Gitignored per-checkout marker holding this machine's ID, so every session on
# a seat resolves the same ID without guessing. See docs/SATELLITE-OFFICE.md.
SEAT_FILE = ROOT / ".ap-machine"
SEAT_ENV = "AP_MACHINE_ID"
HANDOFF_PATHS = {"HANDOFF.md", "docs/MACHINE-RELAY.md"}


def git(*args: str, check: bool = True) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if check and result.returncode:
        detail = result.stderr.strip() or result.stdout.strip()
        raise RuntimeError(f"git {' '.join(args)} failed: {detail}")
    return result.stdout.strip()


def machine_ids() -> list[str]:
    data = json.loads(MACHINES_FILE.read_text(encoding="utf-8"))
    return [machine["id"] for machine in data["machines"]]


def detect_machine() -> str | None:
    """Resolve this seat's ID: --machine, then $AP_MACHINE_ID, then .ap-machine."""
    from_env = os.environ.get(SEAT_ENV, "").strip()
    if from_env:
        return from_env
    if SEAT_FILE.is_file():
        raw = SEAT_FILE.read_bytes()
        for encoding in ("utf-8-sig", "utf-16"):
            try:
                marker = raw.decode(encoding).strip().strip("\ufeff")
            except UnicodeDecodeError:
                continue
            if marker and "\x00" not in marker:
                return marker
    return None


def whoami() -> None:
    machine = detect_machine()
    if machine is None:
        raise RuntimeError(
            f"no seat marker: write this machine's ID to {SEAT_FILE.name} "
            f"(one line, gitignored) or export {SEAT_ENV}"
        )
    if machine not in machine_ids():
        raise RuntimeError(f"{machine!r} is not an ID in machines.json")
    print(machine)


def ensure_clean() -> None:
    if git("status", "--porcelain"):
        raise RuntimeError(
            "working tree is not clean; preserve and reconcile local work before syncing"
        )


def upstream() -> str:
    name = git("rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}")
    if not name:
        raise RuntimeError("current branch has no upstream")
    return name


def divergence() -> tuple[int, int]:
    counts = git("rev-list", "--left-right", "--count", "HEAD...@{u}").split()
    if len(counts) != 2:
        raise RuntimeError("could not determine upstream divergence")
    return int(counts[0]), int(counts[1])


def latest_relay() -> str:
    return git(
        "log",
        "-1",
        "--date=iso-strict",
        "--format=%h %ad %s",
        "--",
        "HANDOFF.md",
        "docs/MACHINE-RELAY.md",
    )


def receive(machine: str) -> None:
    ensure_clean()
    upstream_name = upstream()
    git("fetch", "origin")
    ahead, behind = divergence()
    if ahead and behind:
        raise RuntimeError(
            f"branch diverged from {upstream_name}; coordinate before merging or rebasing"
        )
    if ahead:
        raise RuntimeError(
            f"branch has {ahead} unpushed commit(s); complete the outgoing handoff first"
        )
    if behind:
        git("merge", "--ff-only", "@{u}")
    print(f"RECEIVE OK [{machine}] {git('rev-parse', '--short', 'HEAD')}")
    print(f"Latest handoff/relay: {latest_relay() or 'none'}")


def send(machine: str) -> None:
    ensure_clean()
    upstream_name = upstream()
    git("fetch", "origin")
    ahead, behind = divergence()
    if ahead or behind:
        raise RuntimeError(
            f"branch is not synchronized with {upstream_name}: ahead={ahead}, behind={behind}"
        )
    # `git diff-tree` shows an empty diff for merge commits unless told which
    # parent to diff against — diff against the first parent so a merge that
    # carries a real HANDOFF.md/relay update (as every legitimate merge here
    # must) is still detected correctly.
    parents = git("rev-list", "--parents", "-n", "1", "HEAD").split()[1:]
    if len(parents) > 1:
        changed = set(git("diff", "--name-only", parents[0], "HEAD").splitlines())
    else:
        changed = set(
            git("diff-tree", "--no-commit-id", "--name-only", "-r", "HEAD").splitlines()
        )
    if not changed.intersection(HANDOFF_PATHS):
        raise RuntimeError(
            "current commit has no HANDOFF.md or docs/MACHINE-RELAY.md update"
        )
    print(f"SEND OK [{machine}] {git('rev-parse', '--short', 'HEAD')} -> {upstream_name}")
    print(f"Latest handoff/relay: {latest_relay() or 'none'}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("receive", "send", "whoami"))
    parser.add_argument(
        "--machine",
        choices=machine_ids(),
        help=f"this seat's ID; defaults to ${SEAT_ENV} or the .ap-machine marker",
    )
    args = parser.parse_args()
    if args.mode == "whoami":
        try:
            whoami()
        except RuntimeError as error:
            print(f"MACHINE SYNC FAILED: {error}", file=sys.stderr)
            return 1
        return 0
    machine = args.machine or detect_machine()
    if machine is None:
        print(
            f"MACHINE SYNC FAILED: pass --machine, export {SEAT_ENV}, or write the "
            f"ID to {SEAT_FILE.name}",
            file=sys.stderr,
        )
        return 2
    if machine not in machine_ids():
        print(f"MACHINE SYNC FAILED: {machine!r} is not in machines.json", file=sys.stderr)
        return 2
    try:
        if args.mode == "receive":
            receive(machine)
        else:
            send(machine)
    except RuntimeError as error:
        print(f"MACHINE SYNC FAILED [{machine}]: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

