"""Holehe adapter — which sites have an account registered to an email.

Holehe (github.com/megadose/holehe) checks ~120 sites using their public
signup / login / reset responses ("this email is already taken"). We call its
modules as a library rather than scraping its terminal output, which gives a
per-site verdict and any masked recovery hints a site leaks.

Defaults chosen for safety:
  * password-recovery modules are skipped (same as holehe's -NP flag), so a
    check never kicks off a reset flow on a real account. Opt in with
    `holehe_password_recovery: true`.
  * concurrency is capped (default 12) to stay polite and proxy-friendly.

Verdicts: registered / not registered / inconclusive. Holehe records ANY
failure (blocked host, rate limit, CAPTCHA, outdated module) as `rateLimit`,
so those are reported as inconclusive -- never as "not registered".

Scope: account-existence reveals where a person has accounts. Only run it on
your own address, a consenting subject, or an authorized assessment.
"""
from __future__ import annotations

import asyncio
import importlib.util

from ..models import Finding, Identifier, Kind
from .base import Module

# holehe's -NP list: modules that work by triggering password recovery
_RECOVERY_MODULES = {"adobe", "mail_ru", "odnoklassniki", "samsung"}


class HoleheModule(Module):
    name = "holehe"
    accepts = frozenset({Kind.EMAIL})
    requires_config = True
    propagation = 0.5
    run_timeout = 240.0

    def is_configured(self, config) -> bool:
        if config.extra.get("holehe_disabled"):
            return False
        return importlib.util.find_spec("holehe") is not None

    async def run(self, ident: Identifier, config, http) -> list[Finding]:
        import httpx
        from holehe.core import import_submodules, launch_module

        allow_recovery = bool(config.extra.get("holehe_password_recovery", False))
        only = {s.lower() for s in (config.extra.get("holehe_only") or [])}
        concurrency = int(config.extra.get("holehe_concurrency", 12))

        checks, skipped_recovery = [], []
        for full_name, mod in import_submodules("holehe.modules").items():
            parts = full_name.split(".")
            if len(parts) <= 3:  # package, not a site module
                continue
            site = parts[-1]
            fn = mod.__dict__.get(site)
            if fn is None:
                continue
            if site in _RECOVERY_MODULES and not allow_recovery:
                skipped_recovery.append(site)
                continue
            if only and site not in only:
                continue
            checks.append(fn)

        out: list[dict] = []
        sem = asyncio.Semaphore(concurrency)
        # holehe modules expect their own client; trust_env picks up proxy + CA.
        async with httpx.AsyncClient(timeout=config.timeout_seconds) as client:
            async def one(fn):
                async with sem:
                    await launch_module(fn, ident.value, client, out)
            await asyncio.gather(*(one(fn) for fn in checks))

        registered = sorted((r for r in out if r.get("exists")),
                            key=lambda r: r.get("domain") or "")
        not_registered = sorted(r["domain"] for r in out
                                if not r.get("exists") and not r.get("rateLimit"))
        inconclusive = sorted(r["domain"] for r in out
                              if not r.get("exists") and r.get("rateLimit"))

        findings: list[Finding] = []
        for r in registered:
            data = {"method": r.get("method")}
            for k in ("emailrecovery", "phoneNumber", "others"):
                if r.get(k):
                    data[k] = r[k]
            findings.append(Finding(
                module=self.name,
                subject=ident,
                title=f"Account registered on {r['domain']}",
                confidence=0.8,
                url=f"https://{r['domain']}",
                data=data,
                evidence=(f"{r['domain']} confirmed this email is registered "
                          f"(via its {r.get('method') or 'public'} flow)."),
            ))

        hints = [
            {"site": r["domain"], **{k: r[k] for k in ("emailrecovery", "phoneNumber", "others")
                                     if r.get(k)}}
            for r in registered if r.get("emailrecovery") or r.get("phoneNumber") or r.get("others")
        ]
        summary = {
            "checked": len(out),
            "registered_on": [r["domain"] for r in registered],
            "not_registered_on": not_registered,
            "inconclusive": inconclusive,
            "password_recovery_modules_skipped": sorted(skipped_recovery),
        }
        if hints:
            summary["recovery_hints"] = hints
        findings.append(Finding(
            module=self.name,
            subject=ident,
            title=(f"holehe: registered on {len(registered)}, not on {len(not_registered)}, "
                   f"inconclusive {len(inconclusive)} (of {len(out)} checked)"),
            confidence=0.6 if registered else 0.4,
            data=summary,
            evidence=("Inconclusive = blocked by network policy, rate-limited, CAPTCHA, "
                      "or the site changed; it is not evidence of absence."),
        ))
        return findings
