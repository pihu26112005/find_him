"""GitLab — public user profile by username.

GitLab's public REST API returns what a user chose to show on their profile:
name, bio, location, organization, job title, website and linked social
handles (LinkedIn, X/Twitter, Discord, Skype, GitHub). No key needed.

GitLab serves avatars for users without an uploaded picture from Gravatar,
keyed by a hash of the account's email. The orchestrator compares that hash to
the seed email(s): a match proves the account is registered with that email.
"""
from __future__ import annotations

from ..models import Finding, Identifier, Kind
from .base import Module

_API = "https://gitlab.com/api/v4"
_BLOCKED = {401, 403, 407, 429}

# Public profile fields worth reporting (empty ones are dropped).
_FIELDS = ("name", "username", "state", "bio", "location", "organization", "job_title",
           "pronouns", "work_information", "website_url", "public_email", "linkedin",
           "twitter", "discord", "skype", "github", "created_at", "followers",
           "following", "local_time", "avatar_url")


class GitlabUserModule(Module):
    name = "gitlab_user"
    accepts = frozenset({Kind.USERNAME})
    requires_config = False
    propagation = 0.85

    async def run(self, ident: Identifier, config, http) -> list[Finding]:
        username = ident.value.strip().lstrip("@")
        if not username or "/" in username or " " in username:
            return []

        token = config.extra.get("gitlab_token")
        headers = {"PRIVATE-TOKEN": token} if token else {}
        resp = await http.get(f"{_API}/users", params={"username": username}, headers=headers)
        _raise_if_blocked(resp)
        resp.raise_for_status()
        users = resp.json() or []
        if not users:
            return []  # authoritative: no such user
        u = users[0]

        detail, detail_note = {}, None
        if u.get("id") is not None:
            rd = await http.get(f"{_API}/users/{u['id']}", headers=headers)
            if rd.status_code == 200:
                detail = rd.json() or {}
            else:  # say so -- an absent bio must not read as "nothing public"
                detail_note = (f"full profile not returned (HTTP {rd.status_code}); bio, "
                               "location and linked accounts were not checked"
                               + ("" if token else " -- set gitlab_token to read them"))
        merged = {**u, **detail}
        data = {k: merged[k] for k in _FIELDS if merged.get(k) not in (None, "", [], {})}
        if detail_note:
            data["profile_details"] = detail_note

        conf = ident.confidence
        discovered: list[Identifier] = []
        if merged.get("name"):
            discovered.append(self.discover(Kind.NAME, merged["name"], conf))
        if merged.get("location"):
            discovered.append(self.discover(Kind.LOCATION, merged["location"], conf * 0.8))
        if merged.get("website_url"):
            discovered.append(self.discover(Kind.URL, merged["website_url"], conf * 0.8))
        if merged.get("public_email"):
            discovered.append(self.discover(Kind.EMAIL, merged["public_email"], conf))
        if merged.get("linkedin"):
            li = merged["linkedin"]
            url = li if li.startswith("http") else f"https://www.linkedin.com/in/{li}"
            discovered.append(self.discover(Kind.URL, url, conf))
        for field in ("twitter", "github", "discord"):
            if merged.get(field):
                discovered.append(self.discover(Kind.USERNAME, merged[field], conf * 0.8))

        return [
            Finding(
                module=self.name,
                subject=ident,
                title=f"Public GitLab profile @{merged.get('username', username)}",
                confidence=min(0.9, ident.confidence),
                url=merged.get("web_url") or f"https://gitlab.com/{username}",
                data=data,
                evidence="Fields the user made public on their GitLab profile.",
                discovered=discovered,
            )
        ]


def _raise_if_blocked(resp) -> None:
    if resp.status_code in _BLOCKED or resp.status_code >= 500:
        raise RuntimeError(f"GitLab API HTTP {resp.status_code}")
