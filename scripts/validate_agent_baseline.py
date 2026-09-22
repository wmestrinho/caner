#!/usr/bin/env python3
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
errors = []

def require(path, label):
    if not path.exists():
        errors.append(f"Missing {label}: {path.relative_to(ROOT)}")

require(ROOT / "README.md", "README")
if not (ROOT / "AGENTS.md").exists() and not (ROOT / "CLAUDE.md").exists():
    errors.append("Missing AI-agent instructions: AGENTS.md or CLAUDE.md")
require(ROOT / "VERSION", "VERSION")
require(ROOT / "HANDOFF.md", "cross-session handoff")
require(ROOT / "docs" / "CROSS-MACHINE-HANDOFF.md", "cross-machine protocol")
require(ROOT / "docs" / "MACHINE-RELAY.md", "machine relay ledger")
require(ROOT / "scripts" / "check_machine_sync.py", "machine sync checker")

if (ROOT / "VERSION").exists():
    version = (ROOT / "VERSION").read_text(errors="replace").strip().splitlines()[0].strip()
    if not re.fullmatch(r"\d+\.\d+\.\d+(?:-(?:alpha|beta|rc)\.\d+)?", version):
        errors.append(f"VERSION has invalid format: {version!r}")

readme = ROOT / "README.md"
if readme.exists():
    txt = readme.read_text(errors="replace")
    for phrase in ["Deployment", "Version", "Validation"]:
        if phrase.lower() not in txt.lower():
            errors.append(f"README.md missing {phrase} notes")

agents = ROOT / "AGENTS.md"
if agents.exists():
    agents_text = agents.read_text(errors="replace")
    for marker in ["check_machine_sync.py receive", "docs/MACHINE-RELAY.md"]:
        if marker not in agents_text:
            errors.append(f"AGENTS.md missing cross-machine marker: {marker}")

# Responsive / Mobile Standard (~/.claude/standards/responsive-standard.md):
# viewport meta on every shipped page, no overflow-x:hidden on body, etc.
sys.path.insert(0, str(ROOT / "scripts"))
try:
    import check_responsive
except ImportError:
    errors.append("Missing responsive check: scripts/check_responsive.py")
else:
    resp_errors, resp_warnings = check_responsive.run()
    for warning in resp_warnings:
        print(f"WARN  {warning}")
    errors.extend(resp_errors)

if errors:
    print("AGENT BASELINE VALIDATION FAILED")
    for error in errors:
        print(f"- {error}")
    sys.exit(1)

print("AGENT BASELINE VALIDATION OK")
