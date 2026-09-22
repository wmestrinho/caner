#!/usr/bin/env python3
"""Static responsive-contract check (workspace Responsive / Mobile Standard).

Reference implementation for the workspace. Copy this file verbatim into a
repo when it is retrofitted and adjust only the configuration block below.
Runs with no dependencies; called from validate_agent_baseline.py so it fires
wherever that already runs (local, cross-machine send check, CI).

Checks:
  FAIL  every shipped *.html has a viewport meta with width=device-width
  FAIL  the viewport meta does not disable zoom (user-scalable=no, maximum-scale=1)
  FAIL  no `overflow-x: hidden` (or `overflow: hidden`) on `html`/`body` in authored CSS
  WARN  @media width values outside the canonical set {600, 900, 1200} px with no
        same-line comment documenting the component exception
  WARN  a file that renders <table> without any table-wrap class in the same file
  WARN  grid-template-columns with a bare `1fr` track (auto minimum → one long
        string blows the column out; standard §1.12 wants minmax(0, 1fr))
  WARN  a form control styled below 16px (iOS Safari zooms the viewport on focus
        and never zooms back, which reads as "the page scrolls sideways";
        standard §1.11)

Standard: ~/.claude/standards/responsive-standard.md
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# ── configuration (the only block that changes per repo) ──────────────────
SKIP_DIRS = {"plan", "node_modules", ".git", ".wrangler", "assets", "docs",
             "supabase", "google-apps-script", "__pycache__", "site"}
AUTHORED_CSS = ["css"]                # dirs (or files) of hand-written CSS
TEMPLATE_JS = ["js"]                  # dirs of JS that may render <table>
CANONICAL_BREAKPOINTS_PX = {600, 900, 1200}
TABLE_WRAP_CLASSES = ("table-wrap",)  # substring match; "hq-table-wrap" counts
# ──────────────────────────────────────────────────────────────────────────

VIEWPORT_RE = re.compile(r'<meta\s+[^>]*name\s*=\s*["\']viewport["\'][^>]*>', re.I)
CONTENT_RE = re.compile(r'content\s*=\s*["\']([^"\']*)["\']', re.I)
ZOOM_LOCK_RE = re.compile(r'user-scalable\s*=\s*(?:no|0)|maximum-scale\s*=\s*1(?:\.0+)?(?![\d.])', re.I)
GRID_COLS_RE = re.compile(r'grid-template-columns\s*:\s*([^;{}]+)', re.I)
def _strip_minmax(value: str) -> str:
    """Remove every minmax(...) call, nested parentheses included (var(--x) inside)."""
    out, i = [], 0
    while True:
        j = value.lower().find("minmax(", i)
        if j < 0:
            out.append(value[i:]); return "".join(out)
        out.append(value[i:j]); depth, k = 0, j + len("minmax")
        while k < len(value):
            if value[k] == "(": depth += 1
            elif value[k] == ")":
                depth -= 1
                if depth == 0: break
            k += 1
        i = k + 1
BARE_1FR_RE = re.compile(r'(?<![\w.-])1fr\b')
# selector list made only of html/body (not body::before, not .body-x)
ROOT_RULE_RE = re.compile(
    r'(?<![\w.#\-:])((?:html|body)(?:\s*,\s*(?:html|body))*)\s*\{([^}]*)\}', re.I)
OVERFLOW_RE = re.compile(r'overflow(?:-x)?\s*:\s*hidden', re.I)
MEDIA_WIDTH_RE = re.compile(
    r'@media[^{]*?\((?:min|max)-width\s*:\s*(\d+(?:\.\d+)?)\s*(px|em|rem)\s*\)', re.I)

# Any rule body, with its selector list. `[^{}]` never crosses a brace, so the
# prelude of an @media block is skipped and its inner rules match on their own.
RULE_RE = re.compile(r'([^{}]+)\{([^{}]*)\}')
FONT_SIZE_RE = re.compile(r'(?:^|;)\s*font-size\s*:\s*([^;}!]+)', re.I)
# The subject of a selector: the last compound after any combinator.
SUBJECT_RE = re.compile(r'[^\s>+~]+$')
CONTROL_RE = re.compile(r'^(input|select|textarea)\b', re.I)
# Types that are not text fields, so focusing them never triggers the zoom.
NON_TEXT_INPUT_RE = re.compile(
    r'type\s*[~|^$*]?=\s*["\']?(checkbox|radio|file|hidden|submit|reset|button|image|range|color)',
    re.I)


def _iter_files(suffixes: tuple[str, ...], roots: list[str] | None = None):
    bases = [ROOT / r for r in roots] if roots else [ROOT]
    for base in bases:
        if base.is_file():
            yield base
            continue
        if not base.exists():
            continue
        for path in sorted(base.rglob("*")):
            if path.suffix.lower() not in suffixes or not path.is_file():
                continue
            rel_parts = path.relative_to(ROOT).parts
            if any(part in SKIP_DIRS for part in rel_parts[:-1]):
                continue
            yield path


def _rel(path: Path) -> str:
    return str(path.relative_to(ROOT))


def check_viewport(errors: list[str]) -> None:
    for path in _iter_files((".html",)):
        html = path.read_text(errors="replace")
        m = VIEWPORT_RE.search(html)
        if not m:
            errors.append(f"{_rel(path)}: missing <meta name=\"viewport\"> (responsive-standard §1.1)")
            continue
        content = CONTENT_RE.search(m.group(0))
        value = content.group(1) if content else ""
        if "width=device-width" not in value.replace(" ", ""):
            errors.append(f"{_rel(path)}: viewport meta lacks width=device-width")
        if ZOOM_LOCK_RE.search(value):
            errors.append(f"{_rel(path)}: viewport meta disables pinch-zoom ({value!r})")


COMMENT_RE = re.compile(r'/\*.*?\*/', re.S)


def _strip_comments(css: str) -> str:
    # Blank out comment bodies but keep their newlines so line numbers hold.
    return COMMENT_RE.sub(lambda m: re.sub(r'[^\n]', ' ', m.group(0)), css)


def check_css(errors: list[str], warnings: list[str]) -> None:
    for path in _iter_files((".css",), AUTHORED_CSS):
        css = path.read_text(errors="replace")
        for m in ROOT_RULE_RE.finditer(_strip_comments(css)):
            if OVERFLOW_RE.search(m.group(2)):
                line = css.count("\n", 0, m.start()) + 1
                errors.append(
                    f"{_rel(path)}:{line}: `{m.group(1)}` sets overflow hidden — "
                    "banned, it masks horizontal overflow (responsive-standard §1.6)")
        for idx, text in enumerate(css.splitlines(), 1):
            for mm in MEDIA_WIDTH_RE.finditer(text):
                value, unit = float(mm.group(1)), mm.group(2).lower()
                px = value if unit == "px" else value * 16
                if int(px) in CANONICAL_BREAKPOINTS_PX:
                    continue
                if "/*" in text:
                    continue  # documented component exception
                warnings.append(
                    f"{_rel(path)}:{idx}: @media {int(px)}px is not a canonical breakpoint "
                    "(600/900/1200) and has no same-line comment")


def check_bare_1fr(warnings: list[str]) -> None:
    """WARN on grid-template-columns tracks that use a bare `1fr` (standard §1.12)."""
    for path in _iter_files((".css",), AUTHORED_CSS):
        css = _strip_comments(path.read_text(encoding="utf-8", errors="replace"))
        for m in GRID_COLS_RE.finditer(css):
            value = _strip_minmax(m.group(1))
            if BARE_1FR_RE.search(value):
                line = css[: m.start()].count("\n") + 1
                warnings.append(f"{_rel(path)}:{line}: bare 1fr track in grid-template-columns "
                                f"({m.group(1).strip()[:60]}) — use minmax(0, 1fr) (standard §1.12)")


def _font_size_px(value: str) -> float | None:
    """Resolve a font-size to px where it can be done statically.

    em is treated as 16px-relative: it compounds through ancestors, so this is a
    heuristic, but a control at under 1em is under 16px unless something up the
    tree enlarged it — rare, and a warning is the right weight for that.
    Returns None for values that cannot be judged (calc, var, keywords, clamp).
    """
    value = value.strip().lower()
    m = re.fullmatch(r'([\d.]+)(px|rem|em|pt|%)', value)
    if not m:
        return None            # calc(), var(), clamp(), medium, larger, …
    number, unit = float(m.group(1)), m.group(2)
    return {
        "px": number,
        "rem": number * 16,
        "em": number * 16,
        "pt": number * 96 / 72,
        "%": number * 16 / 100,
    }[unit]


def check_control_font_size(warnings: list[str]) -> None:
    """WARN on form controls styled below 16px (standard §1.11).

    iOS Safari zooms the viewport when a text control under 16px takes focus and
    does not zoom back, leaving the page wider than the screen and panning
    sideways. It presents as a layout bug and is not one, so it is worth naming
    explicitly rather than leaving to a device check.

    Limit: only element-typed selectors are visible here. A control styled
    through a class alone (`.note { font-size: .85rem }` on a <textarea>) cannot
    be resolved without the HTML, so this narrows the gap rather than closing
    it — the device probe in standard §5 stays the pass/fail line.
    """
    for path in _iter_files((".css",), AUTHORED_CSS):
        css = _strip_comments(path.read_text(encoding="utf-8", errors="replace"))
        for rule in RULE_RE.finditer(css):
            selectors, body = rule.group(1), rule.group(2)
            fs = FONT_SIZE_RE.search(body)
            if not fs:
                continue
            px = _font_size_px(fs.group(1))
            if px is None or px >= 16:
                continue
            for selector in selectors.split(","):
                selector = selector.strip()
                if not selector or selector.startswith("@"):
                    continue
                subject = SUBJECT_RE.search(selector)
                if not subject or not CONTROL_RE.match(subject.group(0)):
                    continue
                if "::" in subject.group(0):
                    continue   # ::placeholder sizing does not drive the zoom
                if NON_TEXT_INPUT_RE.search(subject.group(0)):
                    continue   # checkbox, radio, file … never trigger the zoom
                line = css[: rule.start()].count("\n") + 1
                warnings.append(
                    f"{_rel(path)}:{line}: `{selector}` sets font-size "
                    f"{fs.group(1).strip()} (~{px:.0f}px) — form controls must be "
                    "16px or larger or iOS Safari zooms on focus (standard §1.11)")
                break


def check_tables(warnings: list[str]) -> None:
    files = list(_iter_files((".html",))) + list(_iter_files((".js",), TEMPLATE_JS))
    for path in files:
        text = path.read_text(errors="replace")
        if "<table" not in text.lower():
            continue
        if any(cls in text for cls in TABLE_WRAP_CLASSES):
            continue
        warnings.append(f"{_rel(path)}: renders <table> without a table-wrap wrapper (responsive-standard §1.5)")


def run() -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []
    check_viewport(errors)
    check_css(errors, warnings)
    check_tables(warnings)
    check_bare_1fr(warnings)
    check_control_font_size(warnings)
    return errors, warnings


def main() -> int:
    errors, warnings = run()
    for w in warnings:
        print(f"WARN  {w}")
    if errors:
        print("RESPONSIVE CHECK FAILED")
        for e in errors:
            print(f"- {e}")
        return 1
    print(f"RESPONSIVE CHECK OK ({len(warnings)} warning(s))")
    return 0


if __name__ == "__main__":
    sys.exit(main())
