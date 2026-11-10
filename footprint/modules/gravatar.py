"""Gravatar — public profile by email hash.

Gravatar is a legitimate public API: a hash of the lowercased, trimmed email
maps to a public profile the user themselves created. If someone set up a
Gravatar it often links their name, location and other accounts. If they
didn't, you get nothing. This is the cleanest example of "public because the
subject published it."

Tries the current REST API first (v3, SHA-256 hash; unauthenticated requests
get the public fields), then the legacy JSON endpoint (MD5 hash).
"""
from __future__ import annotations

import hashlib

from ..models import Finding, Identifier, Kind
from ._web import handle_from_url
from .base import Module


class GravatarModule(Module):
    name = "gravatar"
    accepts = frozenset({Kind.EMAIL})
    requires_config = False
    propagation = 0.95  # the subject explicitly linked these to themselves

    async def run(self, ident: Identifier, config, http) -> list[Finding]:
        email = ident.value.strip().lower()
        sha256 = hashlib.sha256(email.encode()).hexdigest()
        md5 = hashlib.md5(email.encode()).hexdigest()

        v3 = await self._v3(sha256, ident, http)
        if v3 is not None:
            return v3
        return await self._legacy(md5, ident, http)

    # -- v3 -------------------------------------------------------------------
    async def _v3(self, sha256: str, ident: Identifier, http) -> list[Finding] | None:
        resp = await http.get(f"https://api.gravatar.com/v3/profiles/{sha256}")
        if resp.status_code == 404:
            return []  # authoritative: no public profile
        if resp.status_code != 200:
            return None  # auth/rate-limit/outage -> try legacy
        p = resp.json() or {}

        data: dict = {}
        discovered: list[Identifier] = []
        for key in ("display_name", "location", "job_title", "company",
                    "description", "pronouns"):
            if p.get(key):
                data[key] = p[key]
        if p.get("display_name"):
            discovered.append(self.discover(Kind.NAME, p["display_name"], ident.confidence))
        if p.get("location"):
            discovered.append(self.discover(Kind.LOCATION, p["location"],
                                            ident.confidence * 0.8))

        accounts = []
        for acc in p.get("verified_accounts") or []:
            if acc.get("is_hidden") or not acc.get("url"):
                continue
            accounts.append({"service": acc.get("service_label") or acc.get("service_type"),
                             "url": acc["url"]})
            discovered.append(self.discover(Kind.URL, acc["url"], ident.confidence))
            discovered += self._handles(acc["url"], ident.confidence)
        if accounts:
            data["verified_accounts"] = accounts
        if p.get("avatar_url"):
            data["avatar_url"] = p["avatar_url"]

        # profile slug, e.g. https://gravatar.com/janedoe -> "janedoe"
        profile_url = p.get("profile_url") or f"https://gravatar.com/{sha256}"
        slug = profile_url.rstrip("/").rsplit("/", 1)[-1]
        if slug and slug != sha256:
            discovered.append(self.discover(Kind.USERNAME, slug, ident.confidence * 0.9))

        return [self._finding(ident, profile_url, data, discovered)]

    # -- legacy -----------------------------------------------------------------
    async def _legacy(self, md5: str, ident: Identifier, http) -> list[Finding]:
        resp = await http.get(f"https://en.gravatar.com/{md5}.json")
        if resp.status_code == 404:
            return []
        resp.raise_for_status()
        entries = (resp.json() or {}).get("entry") or []
        if not entries:
            return []

        e = entries[0]
        discovered: list[Identifier] = []
        data: dict = {}

        display = e.get("displayName") or e.get("preferredUsername")
        if display:
            data["display_name"] = display
            discovered.append(self.discover(Kind.NAME, display, ident.confidence))
        username = e.get("preferredUsername")
        if username:
            data["username"] = username
            discovered.append(self.discover(Kind.USERNAME, username, ident.confidence))
        name = e.get("name")
        if isinstance(name, dict) and name.get("formatted"):
            discovered.append(self.discover(Kind.NAME, name["formatted"], ident.confidence))
        if e.get("currentLocation"):
            data["location"] = e["currentLocation"]
            discovered.append(self.discover(Kind.LOCATION, e["currentLocation"],
                                            ident.confidence * 0.8))

        accounts = []
        for acc in e.get("accounts") or []:
            if acc.get("url"):
                accounts.append({"service": acc.get("shortname") or acc.get("domain"),
                                 "url": acc["url"]})
                discovered.append(self.discover(Kind.URL, acc["url"], ident.confidence))
                discovered += self._handles(acc["url"], ident.confidence)
            if acc.get("username"):
                discovered.append(self.discover(Kind.USERNAME, acc["username"],
                                                ident.confidence * 0.9))
        if accounts:
            data["linked_accounts"] = accounts
        for site in e.get("urls") or []:
            if site.get("value"):
                discovered.append(self.discover(Kind.URL, site["value"],
                                                ident.confidence * 0.9))

        return [self._finding(ident, e.get("profileUrl") or f"https://gravatar.com/{md5}",
                              data, discovered)]

    def _handles(self, url: str, conf: float) -> list[Identifier]:
        """A linked profile URL -> that platform's handle, so it gets searched."""
        parsed = handle_from_url(url)
        if not parsed or parsed[0] == "LinkedIn":
            return []
        platform, handle = parsed
        d = self.discover(Kind.USERNAME, handle, conf)
        return [Identifier(d.kind, d.value, f"{self.name}:{platform}", d.confidence)]

    def _finding(self, ident, url, data, discovered) -> Finding:
        return Finding(
            module=self.name,
            subject=ident,
            title="Public Gravatar profile",
            confidence=min(0.95, ident.confidence),
            url=url,
            platform="Gravatar",
            data=data,
            evidence="Subject published a Gravatar profile tied to this email hash.",
            discovered=discovered,
        )
