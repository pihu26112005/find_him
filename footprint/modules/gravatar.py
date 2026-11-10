"""Gravatar — public profile by email hash.

Gravatar is a legitimate public API: the MD5 (or SHA-256) of a lowercased,
trimmed email maps to a public profile the user themselves created. If someone
set up a Gravatar it often links their name, location and other accounts. If
they didn't, you get nothing. This is the cleanest example of "public because
the subject published it."
"""
from __future__ import annotations

import hashlib

from ..models import Finding, Identifier, Kind
from .base import Module


class GravatarModule(Module):
    name = "gravatar"
    accepts = frozenset({Kind.EMAIL})
    requires_config = False
    propagation = 0.95  # the subject explicitly linked these to themselves

    async def run(self, ident: Identifier, config, http) -> list[Finding]:
        email = ident.value.strip().lower()
        md5 = hashlib.md5(email.encode()).hexdigest()
        url = f"https://en.gravatar.com/{md5}.json"
        resp = await http.get(url)
        if resp.status_code == 404:
            return []
        resp.raise_for_status()
        payload = resp.json()
        entries = payload.get("entry") or []
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

        for name in e.get("name", []) if isinstance(e.get("name"), list) else []:
            formatted = name.get("formatted") if isinstance(name, dict) else None
            if formatted:
                discovered.append(self.discover(Kind.NAME, formatted, ident.confidence))

        location = e.get("currentLocation")
        if location:
            data["location"] = location
            discovered.append(self.discover(Kind.LOCATION, location, ident.confidence * 0.8))

        accounts = []
        for acc in e.get("accounts", []) or []:
            acc_url = acc.get("url")
            shortname = acc.get("shortname") or acc.get("domain")
            if acc_url:
                accounts.append({"service": shortname, "url": acc_url})
                discovered.append(self.discover(Kind.URL, acc_url, ident.confidence))
            acc_user = acc.get("username")
            if acc_user:
                discovered.append(self.discover(Kind.USERNAME, acc_user, ident.confidence * 0.9))
        if accounts:
            data["linked_accounts"] = accounts

        for site in e.get("urls", []) or []:
            site_url = site.get("value")
            if site_url:
                discovered.append(self.discover(Kind.URL, site_url, ident.confidence * 0.9))

        profile_url = e.get("profileUrl") or f"https://gravatar.com/{md5}"
        return [
            Finding(
                module=self.name,
                subject=ident,
                title="Public Gravatar profile",
                confidence=min(0.95, ident.confidence),
                url=profile_url,
                data=data,
                evidence="Subject published a Gravatar profile tied to this email hash.",
                discovered=discovered,
            )
        ]
