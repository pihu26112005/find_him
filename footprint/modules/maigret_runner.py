"""Maigret adapter — username search over Maigret's ~5,900-site database.

Maigret (github.com/soxoj/maigret) is the most complete open-source username
engine: ~5,900 site checks (800 social), and for found profiles it extracts
data the page exposes -- full name, bio, links, *other usernames and IDs*. Those
extracted usernames and links are returned as discovered identifiers, so the
engine pivots on them (searching a linked handle everywhere else).

Default site selection: the top 500 sites by traffic plus every site tagged
"social" (~1,000 per username), minus:
  * sites Maigret can only check by impersonating a browser's TLS fingerprint
    to get past bot protection (`tls_fingerprint`), and sites behind a login --
    this tool does not bypass access controls; they are listed as skipped
  * "similar search" sites, which match similar names rather than the handle
  * porn / erotic / dating tags (`maigret_exclude_tags` to change)
Maigret's own Cloudflare-bypass and AI features are never enabled.

Verdicts get the same distrust rules as sherlock's (see _web.py); hits backed
only by a status code are re-fetched with GET before being believed.
"""
from __future__ import annotations

import asyncio
import importlib.util
import logging
import os

from ..models import Finding, Identifier, Kind
from ._web import classify, handle_from_url, verify_hit
from .base import Module

_POLICY_SKIP = {"tls_fingerprint": "needs browser-TLS impersonation to bypass bot protection",
                "login": "needs a logged-in session"}
_DEFAULT_EXCLUDE_TAGS = ("porn", "erotic", "dating")
# Profile fields worth showing from Maigret's page extraction.
_PROFILE_KEYS = ("fullname", "name", "bio", "about", "location", "country", "city",
                 "created_at", "website", "image", "gender", "occupation", "company")

_db = None


def _load_db():
    global _db
    if _db is None:
        import maigret
        from maigret.sites import MaigretDatabase
        path = os.path.join(os.path.dirname(maigret.__file__), "resources", "data.json")
        _db = MaigretDatabase().load_from_path(path)
    return _db


def select_sites(db, config) -> tuple[dict, dict[str, str]]:
    """Returns (sites to check, {skipped site: reason})."""
    exclude = list(config.extra.get("maigret_exclude_tags", _DEFAULT_EXCLUDE_TAGS))
    names = list(config.extra.get("maigret_sites") or [])
    if names:
        sites = db.ranked_sites_dict(names=names, disabled=False, id_type="username")
    else:
        top = int(config.extra.get("maigret_top_sites", 500))
        tags = list(config.extra.get("maigret_tags", ["social"]))
        sites = db.ranked_sites_dict(top=top, disabled=False, id_type="username",
                                     excluded_tags=exclude)
        if tags:
            sites = {**sites, **db.ranked_sites_dict(tags=tags, disabled=False,
                                                     id_type="username",
                                                     excluded_tags=exclude)}
    skipped: dict[str, str] = {}
    for name, site in list(sites.items()):
        hit = next((p for p in (site.protection or []) if p in _POLICY_SKIP), None)
        if hit:
            skipped[name] = _POLICY_SKIP[hit]
        elif site.similar_search:
            skipped[name] = "matches similar names, not the exact handle"
        else:
            continue
        del sites[name]
    return sites, skipped


async def _search(username: str, sites: dict, config) -> dict:
    from maigret.checking import maigret as maigret_search

    logger = logging.getLogger("footprint.maigret")
    logger.setLevel(logging.CRITICAL)
    logger.propagate = False
    return await maigret_search(
        username=username,
        site_dict=sites,
        logger=logger,
        timeout=int(config.extra.get("maigret_timeout", min(config.timeout_seconds, 10))),
        is_parsing_enabled=True,
        no_progressbar=True,
        max_connections=int(config.extra.get("maigret_connections", 40)),
        retries=int(config.extra.get("maigret_retries", 0)),
    )


class MaigretModule(Module):
    name = "maigret"
    accepts = frozenset({Kind.USERNAME})
    requires_config = True
    propagation = 0.6
    run_timeout = 900.0

    def skip_reason(self, config) -> str | None:
        if config.extra.get("maigret_disabled"):
            return "disabled in config"
        if importlib.util.find_spec("maigret") is None:
            return "not installed (pip install maigret)"
        return None

    def is_configured(self, config) -> bool:
        return self.skip_reason(config) is None

    async def run(self, ident: Identifier, config, http) -> list[Finding]:
        username = ident.value.strip().lstrip("@")
        if not username or " " in username or "/" in username:
            return []
        db = await asyncio.to_thread(_load_db)
        sites, policy_skipped = select_sites(db, config)
        if not sites:
            return []
        results = await _search(username, sites, config)

        found, absent, inconclusive, downgraded = [], [], [], []
        for name in sorted(results, key=str.lower):
            r = results[name]
            status = r.get("status")
            label = getattr(getattr(status, "status", None), "name", "UNKNOWN")
            v = classify(label, r.get("http_status"), "")
            if v == "found":
                site = r.get("site") or sites.get(name)
                head_only = (getattr(site, "check_type", "") == "status_code"
                             or getattr(site, "request_head_only", False))
                if head_only:
                    check, _ = await verify_hit(http, r.get("url_probe") or r.get("url_user"))
                    if check != "ok":
                        inconclusive.append(name)
                        downgraded.append(f"{name} (maigret said claimed; GET re-check: {check})")
                        continue
                found.append((name, r, status))
            elif v == "absent":
                absent.append(name)
            else:
                inconclusive.append(name)
                if label in ("CLAIMED", "AVAILABLE"):
                    downgraded.append(f"{name} (maigret said {label.lower()}, "
                                      f"HTTP {r.get('http_status')})")

        findings: list[Finding] = []
        for name, r, status in found:
            conf = round(0.6 * ident.confidence, 3)
            url = r.get("url_user")
            ids = getattr(status, "ids_data", None) or {}
            profile = {k: str(ids[k])[:300] for k in _PROFILE_KEYS if ids.get(k)}
            data: dict = {"tags": list(getattr(status, "tags", None) or [])}
            if profile:
                data["profile"] = profile

            discovered: list[Identifier] = []
            if url:
                discovered.append(self.discover(Kind.URL, url, ident.confidence))
            linked = []
            for other, id_type in (r.get("ids_usernames") or {}).items():
                if id_type == "username" and other.lower() != username.lower():
                    linked.append(other)
                    discovered.append(self.discover(Kind.USERNAME, other, conf))
            links = [str(x) for x in (r.get("ids_links") or [])][:25]
            for link in links:
                discovered.append(self.discover(Kind.URL, link, conf))
                parsed = handle_from_url(link)
                if parsed and parsed[1].lower() != username.lower():
                    platform, handle = parsed
                    linked.append(f"{handle} ({platform})")
                    d = self.discover(Kind.USERNAME, handle, conf)
                    discovered.append(Identifier(d.kind, d.value, f"{self.name}:{platform}",
                                                 d.confidence))
            if linked:
                data["linked_usernames"] = sorted(set(linked))
            if links:
                data["links_on_profile"] = links

            findings.append(Finding(
                module=self.name,
                subject=ident,
                title=f"Handle '{username}' has a profile on {name}",
                confidence=conf,
                url=url,
                platform=name,
                data=data,
                evidence="Maigret's check matched this handle; same person not proven.",
                discovered=discovered,
            ))

        findings.append(Finding(
            module=self.name,
            subject=ident,
            title=(f"maigret '{username}': found on {len(found)}, absent on {len(absent)}, "
                   f"inconclusive {len(inconclusive)} (of {len(results)} sites)"),
            confidence=0.4,
            data={
                "found": [{"site": n, "url": r.get("url_user")} for n, r, _ in found],
                "absent_on": absent,
                "inconclusive": inconclusive,
                "verdicts_downgraded_to_inconclusive": downgraded,
                "skipped_by_policy": [f"{n} ({why})" for n, why in sorted(policy_skipped.items())],
            },
            evidence=("Inconclusive = blocked by network policy, bot wall, rate limit or "
                      "error; not evidence of absence."),
        ))
        return findings
