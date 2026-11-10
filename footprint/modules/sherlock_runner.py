"""Sherlock adapter — find a username's public profile pages across sites.

Sherlock (github.com/sherlock-project/sherlock) knows how to tell, for ~480
sites, whether a profile page exists for a handle. We call it as a library with
its bundled site list (no download), NSFW sites off, and read its per-site
status instead of parsing terminal output:

  CLAIMED   -> a profile page exists for the handle           (lead)
  AVAILABLE -> no such profile                                 (absent)
  ILLEGAL   -> handle isn't valid on that site                 (n/a)
  UNKNOWN / WAF -> error, block or bot-wall                    (inconclusive)

This is the "username pivot": it proves a handle exists on a site, not that it
belongs to the same human. Many common handles are taken by different people.
"""
from __future__ import annotations

import asyncio
import importlib.util
import os

from ..models import Finding, Identifier, Kind
from .base import Module


class SherlockModule(Module):
    name = "sherlock"
    accepts = frozenset({Kind.USERNAME})
    requires_config = True
    propagation = 0.6
    run_timeout = 300.0

    def is_configured(self, config) -> bool:
        if config.extra.get("sherlock_disabled"):
            return False
        return importlib.util.find_spec("sherlock_project") is not None

    async def run(self, ident: Identifier, config, http) -> list[Finding]:
        username = ident.value.strip().lstrip("@")
        if not username or " " in username or "/" in username:
            return []
        results = await asyncio.to_thread(_run_sherlock, username, config)

        found, absent, illegal, inconclusive = [], [], [], []
        for site, r in sorted(results.items(), key=lambda kv: kv[0].lower()):
            status = getattr(r.get("status"), "status", None)
            label = getattr(status, "name", str(status))
            if label == "CLAIMED":
                found.append((site, r.get("url_user")))
            elif label == "AVAILABLE":
                absent.append(site)
            elif label == "ILLEGAL":
                illegal.append(site)
            else:
                inconclusive.append(site)

        findings: list[Finding] = []
        for site, url in found:
            findings.append(Finding(
                module=self.name,
                subject=ident,
                title=f"Handle '{username}' has a profile on {site}",
                confidence=round(0.6 * ident.confidence, 3),
                url=url,
                evidence="Profile page exists for this handle; same person not proven.",
                discovered=[self.discover(Kind.URL, url, ident.confidence)] if url else [],
            ))
        findings.append(Finding(
            module=self.name,
            subject=ident,
            title=(f"sherlock '{username}': found on {len(found)}, absent on {len(absent)}, "
                   f"inconclusive {len(inconclusive)} (of {len(results)} sites)"),
            confidence=0.4,
            data={
                "found": [{"site": s, "url": u} for s, u in found],
                "absent_on": absent,
                "handle_not_valid_on": illegal,
                "inconclusive": inconclusive,
            },
            evidence=("Inconclusive = blocked by network policy, bot-wall/WAF or error; "
                      "not evidence of absence."),
        ))
        return findings


def _run_sherlock(username: str, config) -> dict:
    import sherlock_project
    from sherlock_project.notify import QueryNotify
    from sherlock_project.sherlock import sherlock
    from sherlock_project.sites import SitesInformation

    data_path = os.path.join(os.path.dirname(sherlock_project.__file__),
                             "resources", "data.json")
    sites = SitesInformation(data_path, honor_exclusions=False)
    if not config.extra.get("sherlock_nsfw", False):
        sites.remove_nsfw_sites()
    site_data = {s.name: s.information for s in sites}

    only = {s.lower() for s in (config.extra.get("sherlock_sites") or [])}
    if only:
        site_data = {k: v for k, v in site_data.items() if k.lower() in only}

    timeout = int(config.extra.get("sherlock_timeout", config.timeout_seconds))
    return sherlock(username, site_data, QueryNotify(), timeout=timeout)
