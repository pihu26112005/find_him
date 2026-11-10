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

    # --- confirmed links ------------------------------------------------------
    confirmed = [f for f in result.findings if f.module == "correlate"]
    if confirmed:
        lines.append("## Confirmed links to the seed email")
        lines.append("")
        for f in confirmed:
            lines.append(f"- **{f.title}** — {f.data.get('method')}")
        lines.append("")

    # --- accounts table -------------------------------------------------------
    rows = accounts(result)
    counts = {}
    for r in rows:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    lines.append(f"## Accounts found ({len(rows)})")
    lines.append("")
    if rows:
        lines.append("CONFIRMED = proven tied to the email · EMAIL REGISTERED = the site "
                     "says this email has an account · LEAD = a profile with this handle "
                     "exists (may be someone else)")
        lines.append("")
        lines.append("| status | platform | account | found by |")
        lines.append("|--------|----------|---------|----------|")
        for r in rows:
            account = r["url"] or r["platform"]
            if r["handle"]:
                account = f"{account} (`{r['handle']}`)"
            lines.append(f"| {r['status']} | {r['platform']} | {account} | "
                         f"{', '.join(r['modules'])} |")
        lines.append("")
        lines.append("Totals: " + " · ".join(f"{k}: {v}" for k, v in counts.items()))
    else:
        lines.append("_No accounts found. Inconclusive checks (see each module below) "
                     "are not evidence of absence._")
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
            if isinstance(v, list) and v and all(isinstance(x, dict) for x in v):
                lines.append(f"- **{k}:** ({len(v)})")
                for item in v:
                    lines.append("  - " + " · ".join(
                        f"{ik}: {_fmt(iv)}" for ik, iv in item.items()
                        if iv not in (None, "", [], {})))
            else:
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


_ORDER = {"CONFIRMED": 0, "EMAIL REGISTERED": 1, "LEAD + email registered on site": 2,
          "LEAD": 3}


def _norm(url: str) -> str:
    u = url.lower().split("://", 1)[-1].split("?", 1)[0].rstrip("/")
    return u[4:] if u.startswith("www.") else u


def accounts(result: RunResult) -> list[dict]:
    """Merge every account-level finding (any engine) into one row per account."""
    confirmed = {_norm(f.url) for f in result.findings if f.module == "correlate" and f.url}
    email_sites = {f.platform.lower() for f in result.findings
                   if f.module == "holehe" and f.platform}
    groups: dict[str, dict] = {}
    for f in result.findings:
        if not f.platform:
            continue
        by_email = f.module == "holehe"
        key = ("email:" + f.platform.lower()) if (by_email or not f.url) else _norm(f.url)
        g = groups.setdefault(key, {
            "platform": f.platform, "url": None if by_email else f.url,
            "handle": None if by_email or f.subject.kind != Kind.USERNAME else f.subject.value,
            "modules": [], "confidence": 0.0, "by_email": by_email, "confirmed": False})
        if f.module not in g["modules"]:
            g["modules"].append(f.module)
        g["confidence"] = max(g["confidence"], f.confidence)
        if key in confirmed or f.confidence >= 0.95:
            g["confirmed"] = True

    rows = []
    for key, g in groups.items():
        host = _norm(g["url"] or "").split("/", 1)[0]
        if g["confirmed"]:
            status = "CONFIRMED"
        elif g["by_email"]:
            status = "EMAIL REGISTERED"
        elif host in email_sites:
            status = "LEAD + email registered on site"
        else:
            status = "LEAD"
        rows.append({**g, "status": status})
    rows.sort(key=lambda r: (_ORDER[r["status"]], -r["confidence"], r["platform"].lower()))
    return rows


def _conf_bar(c: float) -> str:
    filled = round(max(0.0, min(1.0, c)) * 5)
    return "▰" * filled + "▱" * (5 - filled)


_MAX_LIST = 600  # long enough to print every site sherlock/holehe checked


def _fmt(v) -> str:
    if isinstance(v, (list, tuple)):
        if not v:
            return "_(none)_"
        if all(isinstance(x, str) for x in v):
            shown = ", ".join(f"`{x}`" for x in v[:_MAX_LIST])
            extra = len(v) - _MAX_LIST
            return f"({len(v)}) " + shown + (f" … (+{extra} more)" if extra > 0 else "")
        return json.dumps(v, ensure_ascii=False)
    if isinstance(v, dict):
        return json.dumps(v, ensure_ascii=False)
    return str(v)
