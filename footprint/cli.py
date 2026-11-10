"""Command-line entry point.

    python -m footprint --basis own me@example.com
    python -m footprint --basis authorized --reference SOW-2026-14 \
        --operator alice target-handle --format json --out report.json

The authorization gate runs *before* any network call.
"""
from __future__ import annotations

import argparse
import asyncio
import getpass
import re
import sys

from .authorization import Authorization, AuthorizationError, Basis, record
from .config import Config
from .models import Identifier, Kind
from .orchestrator import Orchestrator, default_modules
from .report import to_json, to_markdown

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_URL_RE = re.compile(r"^https?://", re.I)
_DOMAIN_RE = re.compile(r"^[a-z0-9.-]+\.[a-z]{2,}$", re.I)


def classify(raw: str) -> Identifier:
    s = raw.strip()
    if _EMAIL_RE.match(s):
        return Identifier(Kind.EMAIL, s)
    if _URL_RE.match(s):
        return Identifier(Kind.URL, s)
    if _DOMAIN_RE.match(s) and "/" not in s:
        return Identifier(Kind.DOMAIN, s)
    return Identifier(Kind.USERNAME, s.lstrip("@"))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="footprint",
        description="Consent-gated public-source footprint auditor.",
    )
    p.add_argument("subjects", nargs="+",
                   help="seed identifier(s): email, username, URL or domain")
    p.add_argument("--basis", required=True, choices=sorted(Basis.ALL),
                   help="legitimate basis: " +
                        "; ".join(f"{k}={v}" for k, v in Basis.HELP.items()))
    p.add_argument("--reference", default="",
                   help="consent record id or engagement/authorization reference "
                        "(required for consent/authorized; 'own' defaults to 'self')")
    p.add_argument("--operator", default="",
                   help="who is running this (for the audit log); defaults to OS user")
    p.add_argument("--config", default=None, help="path to config.yaml")
    p.add_argument("--audit-log", default="footprint-audit.log",
                   help="append-only authorization log path")
    p.add_argument("--depth", type=int, default=None, help="override max discovery depth")
    p.add_argument("--format", choices=["md", "json"], default="md")
    p.add_argument("--out", default=None, help="write report to file instead of stdout")
    p.add_argument("--kind", choices=sorted(Kind.ALL), default=None,
                   help="force the seed kind instead of autodetecting")
    return p


async def _run(args) -> int:
    config = Config.load(args.config)
    if args.depth is not None:
        config.max_depth = args.depth

    operator = args.operator or getpass.getuser()
    reference = args.reference or ("self" if args.basis == Basis.OWN else "")
    auth = Authorization(basis=args.basis, reference=reference, operator=operator)
    try:
        auth.validate()
    except AuthorizationError as e:
        print(f"authorization error: {e}", file=sys.stderr)
        return 2

    # Build + record BEFORE any lookups.
    seeds = [
        Identifier(args.kind, s) if args.kind else classify(s)
        for s in args.subjects
    ]
    record(auth, [s.value for s in seeds], args.audit_log)

    orch = Orchestrator(default_modules(), config)
    result = await orch.run(seeds)

    text = to_json(result) if args.format == "json" else to_markdown(result)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text)
        print(f"wrote {args.format} report to {args.out} "
              f"({len(result.findings)} findings)", file=sys.stderr)
    else:
        print(text)
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return asyncio.run(_run(args))
    except KeyboardInterrupt:  # pragma: no cover
        return 130


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
