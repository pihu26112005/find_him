"""Sherlock adapter — find a username's public profile pages across sites.

Sherlock (github.com/sherlock-project/sherlock) knows how to tell, for ~480
sites, whether a profile page exists for a handle. We call it as a library with
its bundled site list (no download), NSFW sites off, and read its per-site
status instead of parsing terminal output.

Sherlock's own verdicts are too trusting, so each one is re-checked against the
raw response it recorded:

  * "status_code" sites: sherlock calls ANY non-2xx response "available", so a
    403 bot-block, 429 rate limit or 5xx outage became a false "absent".
  * "message" sites: a block page that lacks the site's not-found text became
    a false "claimed".
  * redirects to bot-checks ("Security Verification", Cloudflare "Just a
    moment...") come back as 200 and were read as "claimed".

So a verdict backed by a bot wall or a 401/403/407/429/5xx response is
downgraded to inconclusive. "status_code" sites are checked with HEAD requests,
which carry no body to inspect, so every such "found" hit is re-fetched once
with GET and its final URL and page are checked for bot walls and login
redirects before it is reported. Final verdicts:

  found        -> a profile page exists for the handle            (lead)
  absent       -> the site's own not-found response                (absent)
  not valid    -> handle isn't a legal username on that site       (n/a)
  inconclusive -> error, block, bot wall or rate limit             (unknown)

This is the "username pivot": it proves a handle exists on a site, not that it
belongs to the same human. Many common handles are taken by different people.
Found pages that embed a Gravatar avatar get its hash extracted, so the
orchestrator can check whether it matches a seed email (a hard link).
"""
from __future__ import annotations

import asyncio
import importlib.util
import os
import re

from ..models import Finding, Identifier, Kind
from .base import Module

_BLOCKED_STATUSES = {401, 403, 407, 429}

# Markers of bot walls / interstitials / policy blocks, matched case-insensitively.
_WALL_MARKERS = (
    "just a moment...",                     # Cloudflare challenge
    "attention required! | cloudflare",
    "/cdn-cgi/challenge-platform",
    "checking your browser",
    "security verification",                # Apple and others
    "verify-human",
    "_incapsula_resource",                  # Imperva
    "px-captcha",                           # PerimeterX
    "ddos protection by",
    "this github api path is not available",  # sandboxed GitHub proxy policy
)

# A HEAD-confirmed hit whose GET lands on one of these paths is a soft 404 / wall.
_WALL_URL_MARKERS = ("verify-human", "captcha", "/challenge", "/login", "/signin",
                     "/sign_in", "/sign-in", "/auth/", "/accounts/login")

# Same UA sherlock uses, so the re-check sees what sherlock's request saw.
_UA = "Mozilla/5.0 (X11; Linux x86_64; rv:129.0) Gecko/20100101 Firefox/129.0"

_GRAVATAR_RE = re.compile(r"gravatar\.com/avatar/([0-9a-f]{64}|[0-9a-f]{32})", re.I)


async def verify_hit(http, url: str) -> tuple[str, str]:
    """GET a HEAD-only hit. Returns (verdict, page text) with verdict one of
    ok / walled / blocked / gone."""
    try:
        r = await http.get(url, headers={"User-Agent": _UA})
    except Exception:
        return "blocked", ""
    text = r.text[:400_000]
    final = str(r.url).lower()
    if (any(m in final for m in _WALL_URL_MARKERS)
            or any(m in text.lower() for m in _WALL_MARKERS)):
        return "walled", text
    if r.status_code in _BLOCKED_STATUSES or r.status_code >= 500:
        return "blocked", text
    if r.status_code >= 400:
        return "gone", text
    return "ok", text


def classify(label: str, http_status, response_text) -> str:
    """Map sherlock's status + the raw response to a trustworthy verdict."""
    text = _text(response_text).lower()
    walled = any(m in text for m in _WALL_MARKERS)
    blocked = isinstance(http_status, int) and (
        http_status in _BLOCKED_STATUSES or http_status >= 500)
    if label == "CLAIMED":
        return "inconclusive" if (walled or blocked) else "found"
    if label == "AVAILABLE":
        return "inconclusive" if (walled or blocked) else "absent"
    if label == "ILLEGAL":
        return "not_valid"
    return "inconclusive"  # UNKNOWN, WAF, anything new


def avatar_hashes(response_text) -> list[str]:
    return sorted({h.lower() for h in _GRAVATAR_RE.findall(_text(response_text))})


def _text(response_text) -> str:
    if isinstance(response_text, bytes):
        return response_text[:400_000].decode("utf-8", errors="replace")
    return str(response_text or "")[:400_000]


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
            data = {"avatar_hashes": hashes} if hashes else {}
            findings.append(Finding(
                module=self.name,
                subject=ident,
                title=f"Handle '{username}' has a profile on {site}",
                confidence=round(0.6 * ident.confidence, 3),
                url=url,
                data=data,
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
    return sherlock(username, site_data, QueryNotify(), timeout=timeout), site_data
