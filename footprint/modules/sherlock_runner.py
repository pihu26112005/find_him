"""Sherlock adapter — find a username's public profile pages across sites.

Sherlock (github.com/sherlock-project/sherlock) knows how to tell, for ~480
sites, whether a profile page exists for a handle. We call it as a library with
its bundled site list (no download), NSFW sites off, and read its per-site
status instead of parsing terminal output.

When Maigret is installed this module steps aside by default: Maigret's database
is a superset of Sherlock's with stricter checks, and running both doubles the
traffic to every site (inviting rate limits). Set `sherlock_enabled: true` to
run both.

Sherlock's own verdicts are too trusting, so each one is re-checked (see
_web.py): "status_code" sites call ANY non-2xx response "available", "message"
sites call a block page "claimed", and HEAD-only hits have no body to inspect,
so they are re-fetched with GET before being reported.

  found        -> a profile page exists for the handle            (lead)
  absent       -> the site's own not-found response                (absent)
  not valid    -> handle isn't a legal username on that site       (n/a)
  inconclusive -> error, block, bot wall or rate limit             (unknown)

It proves a handle exists on a site, not that it belongs to the same human.
"""
from __future__ import annotations

import asyncio
import importlib.util
import os

from ..models import Finding, Identifier, Kind
from ._web import avatar_hashes, classify, verify_hit  # noqa: F401  (re-exported)
from .base import Module


class SherlockModule(Module):
    name = "sherlock"
    accepts = frozenset({Kind.USERNAME})
    requires_config = True
    propagation = 0.6
    run_timeout = 300.0

    def skip_reason(self, config) -> str | None:
        if config.extra.get("sherlock_disabled"):
            return "disabled in config"
        if importlib.util.find_spec("sherlock_project") is None:
            return "not installed (pip install sherlock-project)"
        if (importlib.util.find_spec("maigret") is not None
                and not config.extra.get("sherlock_enabled")):
            return ("maigret is installed and covers sherlock's sites "
                    "(set sherlock_enabled: true to run both)")
        return None

    async def run(self, ident: Identifier, config, http) -> list[Finding]:
        username = ident.value.strip().lstrip("@")
        if not username or " " in username or "/" in username:
            return []
        results, site_data = await asyncio.to_thread(_run_sherlock, username, config)

        found, absent, not_valid, inconclusive, downgraded = [], [], [], [], []
        for site, r in sorted(results.items(), key=lambda kv: kv[0].lower()):
            status = getattr(r.get("status"), "status", None)
            label = getattr(status, "name", str(status))
            verdict = classify(label, r.get("http_status"), r.get("response_text"))
            body = r.get("response_text")
            if verdict == "found" and not body:
                # HEAD-only evidence: re-fetch the URL sherlock probed.
                info = site_data.get(site, {})
                probe = (info.get("urlProbe") or info.get("url") or "").replace("{}", username)
                check, body = await verify_hit(http, probe or r.get("url_user"))
                if check != "ok":
                    inconclusive.append(site)
                    downgraded.append(f"{site} (sherlock said claimed; GET re-check: {check})")
                    continue
            if verdict == "found":
                found.append((site, r.get("url_user"), avatar_hashes(body)))
            elif verdict == "absent":
                absent.append(site)
            elif verdict == "not_valid":
                not_valid.append(site)
            else:
                inconclusive.append(site)
                if label in ("CLAIMED", "AVAILABLE"):
                    downgraded.append(f"{site} (sherlock said {label.lower()}, "
                                      f"HTTP {r.get('http_status')})")

        findings: list[Finding] = []
        for site, url, hashes in found:
            findings.append(Finding(
                module=self.name,
                subject=ident,
                title=f"Handle '{username}' has a profile on {site}",
                confidence=round(0.6 * ident.confidence, 3),
                url=url,
                platform=site,
                data={"avatar_hashes": hashes} if hashes else {},
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
                "found": [{"site": s, "url": u} for s, u, _ in found],
                "absent_on": absent,
                "handle_not_valid_on": not_valid,
                "inconclusive": inconclusive,
                "verdicts_downgraded_to_inconclusive": downgraded,
            },
            evidence=("Inconclusive = blocked by network policy, bot wall, rate limit or "
                      "error; not evidence of absence."),
        ))
        return findings


def _run_sherlock(username: str, config):
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
    return sherlock(username, site_data, QueryNotify(), timeout=timeout), site_data
