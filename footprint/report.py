"""Render a RunResult as Markdown or JSON.

Entity resolution here is deliberately *conservative*: we don't claim distinct
findings are the same human. We group by the identifier they're about, surface
"same-person signals" (repeated names/usernames across sources) as hints, and
attach confidence everywhere so the reader does the final judgement.
"""
from __future__ import annotations

import json
from collections import Counter

from .models import Kind, RunResult


def to_json(result: RunResult) -> str:
    return json.dumps(result.to_dict(), indent=2, ensure_ascii=False)


def to_markdown(result: RunResult) -> str:
    lines: list[str] = []
    seeds = ", ".join(f"`{s.value}`" for s in result.seeds)
    lines.append("# Footprint report")
    lines.append("")
    lines.append(f"**Subject seed(s):** {seeds}")
    lines.append(f"**Findings:** {len(result.findings)}  ·  "
                 f"**Identifiers surfaced:** {len(result.identifiers)}")
    lines.append("")
    lines.append("> Public-source audit. Confidence is this tool's estimate that a "
                 "datum belongs to the subject — verify before acting.")
    lines.append("")

    # --- same-person signals --------------------------------------------------
    names = Counter(i.value for i in result.identifiers if i.kind == Kind.NAME)
    usernames = Counter(i.value for i in result.identifiers if i.kind == Kind.USERNAME)
    repeated = [(k, c) for k, c in (names + usernames).items() if c > 1]
    if repeated:
        lines.append("## Same-person signals")
        lines.append("")
        lines.append("Values that showed up from more than one source (stronger link):")
        lines.append("")
        for val, count in sorted(repeated, key=lambda x: -x[1]):
            lines.append(f"- `{val}` — seen {count}×")
        lines.append("")

    # --- findings -------------------------------------------------------------
    lines.append("## Findings")
    lines.append("")
    if not result.findings:
        lines.append("_No public findings. For a personal address with no published "
                     "profiles, this is the expected (good) result._")
        lines.append("")
    for f in result.findings:
        bar = _conf_bar(f.confidence)
        lines.append(f"### {f.title}  {bar} `{f.confidence:.2f}`")
        lines.append(f"- **source module:** `{f.module}`  ·  **about:** "
                     f"`{f.subject.value}` ({f.subject.kind})")
        if f.url:
            lines.append(f"- **link:** {f.url}")
        if f.evidence:
            lines.append(f"- **evidence:** {f.evidence}")
        for k, v in f.data.items():
            lines.append(f"- **{k}:** {_fmt(v)}")
        lines.append("")

    # --- all identifiers ------------------------------------------------------
    lines.append("## All surfaced identifiers")
    lines.append("")
    lines.append("| kind | value | confidence | via |")
    lines.append("|------|-------|-----------:|-----|")
    for i in result.identifiers:
        lines.append(f"| {i.kind} | `{i.value}` | {i.confidence:.2f} | {i.source} |")
    lines.append("")

    # --- run notes ------------------------------------------------------------
    if result.skipped:
        lines.append("## Modules skipped")
        lines.append("")
        for s in result.skipped:
            lines.append(f"- `{s['module']}` — {s['reason']}")
        lines.append("")
    if result.errors:
        lines.append("## Errors")
        lines.append("")
        for e in result.errors:
            lines.append(f"- `{e.get('module')}` on `{e.get('subject')}`: {e.get('error')}")
        lines.append("")

    lines.append("## Reduce your exposure")
    lines.append("")
    lines.append("- Remove or lock down any profile above you didn't mean to make public.")
    lines.append("- For breached addresses: rotate reused passwords, enable 2FA, "
                 "consider an email alias per service.")
    lines.append("- Clear old data-broker listings (most honor opt-out requests).")
    lines.append("")
    return "\n".join(lines)


def _conf_bar(c: float) -> str:
    filled = round(max(0.0, min(1.0, c)) * 5)
    return "▰" * filled + "▱" * (5 - filled)


def _fmt(v) -> str:
    if isinstance(v, (list, tuple)):
        if not v:
            return "_(none)_"
        if all(isinstance(x, str) for x in v):
            return ", ".join(f"`{x}`" for x in v[:20]) + ("…" if len(v) > 20 else "")
        return json.dumps(v, ensure_ascii=False)[:500]
    if isinstance(v, dict):
        return json.dumps(v, ensure_ascii=False)[:500]
    return str(v)
