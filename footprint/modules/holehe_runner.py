"""Holehe adapter — which sites have an account registered to an email.

Holehe (github.com/megadose/holehe) checks ~120 sites using their public
signup / login / reset responses ("this email is already taken"). We call its
modules as a library rather than scraping its terminal output, which gives a
per-site verdict and any masked recovery hints a site leaks.

Holehe's own error reporting can't be trusted for absence: some modules swallow
network errors and report "not registered" (blip), others append twice on
failure (diigo). So each site check gets its own HTTP client that records every
transport error and every 401/403/407/429/5xx response, and the verdict is:

  registered     -> the module confirmed the email exists on the site
  inconclusive   -> any request failed or was blocked, or holehe flagged a
                    rate limit / error, or the module reported nothing
  not registered -> the site answered cleanly that the email is unknown

Defaults chosen for safety:
  * password-recovery modules are skipped (same as holehe's -NP flag), so a
    check never kicks off a reset flow on a real account. Opt in with
    `holehe_password_recovery: true`.
  * concurrency is capped (default 12) to stay polite and proxy-friendly.

Scope: account-existence reveals where a person has accounts. Only run it on
your own address, a consenting subject, or an authorized assessment.
"""
from __future__ import annotations

import asyncio
import importlib.util

import httpx

from ..models import Finding, Identifier, Kind
from .base import Module

# holehe's -NP list: modules that work by triggering password recovery
_RECOVERY_MODULES = {"adobe", "mail_ru", "odnoklassniki", "samsung"}
_BLOCKED_STATUSES = {401, 403, 407, 429}


class _RecordingClient(httpx.AsyncClient):
    """AsyncClient that remembers failed / blocked requests.

    Overriding send() (not the transport) keeps httpx's env-proxy and CA
    handling intact.
    """

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.failures: list[str] = []

    async def send(self, request, **kwargs):
        try:
            resp = await super().send(request, **kwargs)
        except Exception as e:
            self.failures.append(f"{request.url.host}: {type(e).__name__}")
            raise
        if resp.status_code in _BLOCKED_STATUSES or resp.status_code >= 500:
            self.failures.append(f"{request.url.host}: HTTP {resp.status_code}")
        return resp


def _make_client(config) -> _RecordingClient:
    return _RecordingClient(timeout=config.timeout_seconds)


def _verdict(entries: list[dict], failures: list[str]) -> str:
    if any(e.get("exists") for e in entries):
        return "registered"
    if not entries or failures or any(e.get("rateLimit") for e in entries):
        return "inconclusive"
    return "not_registered"


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
            checks.append((site, fn))

        sem = asyncio.Semaphore(concurrency)

        async def one(site, fn) -> dict:
            async with sem:
                entries: list[dict] = []
                async with _make_client(config) as client:
                    await launch_module(fn, ident.value, client, entries)
                    failures = list(client.failures)
                verdict = _verdict(entries, failures)
                best = next((e for e in entries if e.get("exists")), entries[0] if entries else {})
                return {"site": site, "domain": best.get("domain") or site,
                        "verdict": verdict, "entry": best, "failures": failures}

        results = await asyncio.gather(*(one(s, fn) for s, fn in checks))
        results.sort(key=lambda r: r["domain"])

        registered = [r for r in results if r["verdict"] == "registered"]
        not_registered = [r["domain"] for r in results if r["verdict"] == "not_registered"]
        inconclusive = [r["domain"] for r in results if r["verdict"] == "inconclusive"]

        findings: list[Finding] = []
        for r in registered:
            e = r["entry"]
            data = {"method": e.get("method")}
            for k in ("emailrecovery", "phoneNumber", "others"):
                if e.get(k):
                    data[k] = e[k]
            findings.append(Finding(
                module=self.name,
                subject=ident,
                title=f"Account registered on {r['domain']}",
                confidence=0.8,
                url=f"https://{r['domain']}",
                data=data,
                evidence=(f"{r['domain']} confirmed this email is registered "
                          f"(via its {e.get('method') or 'public'} flow)."),
            ))

        hints = [
            {"site": r["domain"], **{k: r["entry"][k] for k in ("emailrecovery", "phoneNumber",
                                                                "others") if r["entry"].get(k)}}
            for r in registered
            if any(r["entry"].get(k) for k in ("emailrecovery", "phoneNumber", "others"))
        ]
        summary = {
            "checked": len(results),
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
                   f"inconclusive {len(inconclusive)} (of {len(results)} checked)"),
            confidence=0.6 if registered else 0.4,
            data=summary,
            evidence=("Inconclusive = a request failed or was blocked (network policy, rate "
                      "limit, CAPTCHA) or the site changed; it is not evidence of absence."),
        ))
        return findings
