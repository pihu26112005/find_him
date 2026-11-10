"""WhatsMyName — username checks on ~690 curated sites (195 social).

WhatsMyName (github.com/WebBreacher/WhatsMyName) is the community dataset many
OSINT tools build on. Every site has a two-sided rule:

  found   = status == e_code  AND  e_string in body
  missing = status == m_code  AND  m_string in body

anything else (both, neither, a block, a bot wall) is inconclusive. That is
much stricter than "2xx means it exists", so hits are higher-precision than
sherlock's. Redirects are not followed: ~60 sites signal "missing" with a
301/302.

The data is downloaded once, pinned to a WhatsMyName commit and verified by
SHA-256 before use, then cached in ~/.cache/footprint. Override with
`wmn_data_url` (no hash check) or `wmn_data_path` (a local file).
Data licence: CC BY-SA 4.0, (C) Micah Hoffman and contributors.

NSFW sites are skipped by default (`wmn_nsfw: true` to include), as is the
dating category (`wmn_exclude_categories` to change).
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
from pathlib import Path

from ..models import Finding, Identifier, Kind
from ._web import UA, avatar_hashes, is_blocked_status, is_walled
from .base import Module

WMN_COMMIT = "abcb19d6809f0e963e353819c571133b45b6a106"
WMN_URL = ("https://raw.githubusercontent.com/WebBreacher/WhatsMyName/"
           f"{WMN_COMMIT}/wmn-data.json")
WMN_SHA256 = "a8b8385bee4b4c79f1fcdd458749ec89ba9d8dab94230353d09020b90b436324"

_NSFW = "xx NSFW xx"
_DEFAULT_EXCLUDED = ("dating",)


def verdict(site: dict, status: int | None, text: str) -> str:
    """found / absent / inconclusive for one site's response."""
    if status is None or is_walled(text):
        return "inconclusive"
    e_ok = status == site.get("e_code") and site.get("e_string", "") in text
    m_ok = status == site.get("m_code") and site.get("m_string", "") in text
    if e_ok and not m_ok:
        return "found"
    if m_ok and not e_ok:
        return "absent"
    return "inconclusive"  # ambiguous, blocked, rate-limited or changed


def select_sites(data: dict, config) -> list[dict]:
    excluded = set(config.extra.get("wmn_exclude_categories", _DEFAULT_EXCLUDED))
    if not config.extra.get("wmn_nsfw", False):
        excluded.add(_NSFW)
    only = {c.lower() for c in (config.extra.get("wmn_categories") or [])}
    names = {n.lower() for n in (config.extra.get("wmn_sites") or [])}
    out = []
    for s in data.get("sites", []):
        if s.get("valid") is False or s.get("cat") in excluded:
            continue
        if only and (s.get("cat") or "").lower() not in only:
            continue
        if names and s["name"].lower() not in names:
            continue
        out.append(s)
    return out


def _cache_dir() -> Path:
    base = os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
    return Path(base) / "footprint"


async def load_data(config, http) -> dict:
    local = config.extra.get("wmn_data_path")
    if local:
        return json.loads(Path(local).read_text(encoding="utf-8"))
    url = config.extra.get("wmn_data_url") or WMN_URL
    pinned = url == WMN_URL
    tag = WMN_COMMIT[:12] if pinned else hashlib.sha256(url.encode()).hexdigest()[:12]
    cache = _cache_dir() / f"wmn-data-{tag}.json"
    if cache.exists():
        raw = cache.read_bytes()
        if not pinned or hashlib.sha256(raw).hexdigest() == WMN_SHA256:
            return json.loads(raw)
    resp = await http.get(url, follow_redirects=True)
    resp.raise_for_status()
    raw = resp.content
    if pinned and hashlib.sha256(raw).hexdigest() != WMN_SHA256:
        raise RuntimeError("WhatsMyName data failed its SHA-256 check; refusing to use it")
    try:
        cache.parent.mkdir(parents=True, exist_ok=True)
        cache.write_bytes(raw)
    except OSError:
        pass  # cache is best-effort
    return json.loads(raw)


async def check_site(http, site: dict, username: str, timeout: float):
    """Returns (verdict, status, text, display_url)."""
    acct = username
    for ch in site.get("strip_bad_char") or "":
        acct = acct.replace(ch, "")
    url = site["uri_check"].replace("{account}", acct)
    pretty = (site.get("uri_pretty") or site["uri_check"]).replace("{account}", acct)
    headers = {"User-Agent": UA, **(site.get("headers") or {})}
    try:
        if site.get("post_body"):
            body = site["post_body"].replace("{account}", acct)
            r = await http.post(url, content=body.encode(), headers=headers,
                                follow_redirects=False, timeout=timeout)
        else:
            r = await http.get(url, headers=headers, follow_redirects=False, timeout=timeout)
    except Exception:
        return "inconclusive", None, "", pretty
    text = r.text[:400_000]
    return verdict(site, r.status_code, text), r.status_code, text, pretty


class WhatsMyNameModule(Module):
    name = "whatsmyname"
    accepts = frozenset({Kind.USERNAME})
    requires_config = False
    propagation = 0.6
    run_timeout = 600.0

    def skip_reason(self, config) -> str | None:
        return "disabled in config" if config.extra.get("wmn_disabled") else None

    async def run(self, ident: Identifier, config, http) -> list[Finding]:
        username = ident.value.strip().lstrip("@")
        if not username or " " in username or "/" in username:
            return []
        data = await load_data(config, http)
        sites = select_sites(data, config)
        timeout = float(config.extra.get("wmn_timeout", min(config.timeout_seconds, 10)))
        sem = asyncio.Semaphore(int(config.extra.get("wmn_concurrency", 25)))

        async def one(site):
            async with sem:
                return site, await check_site(http, site, username, timeout)

        results = await asyncio.gather(*(one(s) for s in sites))
        results.sort(key=lambda r: r[0]["name"].lower())

        found, absent, inconclusive, blocked = [], [], [], 0
        for site, (v, status, text, pretty) in results:
            if v == "found":
                found.append((site, pretty, avatar_hashes(text)))
            elif v == "absent":
                absent.append(site["name"])
            else:
                inconclusive.append(site["name"])
                if status is None or is_blocked_status(status) or is_walled(text):
                    blocked += 1

        findings: list[Finding] = []
        for site, pretty, hashes in found:
            data_out = {"category": site.get("cat")}
            if hashes:
                data_out["avatar_hashes"] = hashes
            findings.append(Finding(
                module=self.name,
                subject=ident,
                title=f"Handle '{username}' has a profile on {site['name']}",
                confidence=round(0.6 * ident.confidence, 3),
                url=pretty,
                platform=site["name"],
                data=data_out,
                evidence=("WhatsMyName's found-rule matched (status and page text); "
                          "same person not proven."),
                discovered=[self.discover(Kind.URL, pretty, ident.confidence)],
            ))
        findings.append(Finding(
            module=self.name,
            subject=ident,
            title=(f"whatsmyname '{username}': found on {len(found)}, absent on "
                   f"{len(absent)}, inconclusive {len(inconclusive)} (of {len(results)} sites)"),
            confidence=0.4,
            data={
                "found": [{"site": s["name"], "category": s.get("cat"), "url": u}
                          for s, u, _ in found],
                "absent_on": absent,
                "inconclusive": inconclusive,
                "inconclusive_due_to_block_or_error": blocked,
                "dataset": f"WhatsMyName @ {WMN_COMMIT[:7]} (CC BY-SA 4.0)",
            },
            evidence=("Found/absent need both the status code and the page text to match "
                      "the site's rule; everything else is inconclusive."),
        ))
        return findings
