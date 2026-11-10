"""GitHub — public user profile by username.

GitHub's public API exposes exactly what a user chose to make public: name,
bio, company, location, blog, and their public repos. For a USERNAME we query
the user endpoint directly. (Email->username via commit search is intentionally
omitted: it requires auth and strays toward de-anonymization; if you want it,
add an opt-in module behind an explicit flag.)
"""
from __future__ import annotations

from ..models import Finding, Identifier, Kind
from .base import Module


class GithubUserModule(Module):
    name = "github_user"
    accepts = frozenset({Kind.USERNAME})
    requires_config = False  # works unauthenticated; token only raises rate limit
    propagation = 0.85

    async def run(self, ident: Identifier, config, http) -> list[Finding]:
        username = ident.value.strip().lstrip("@")
        if not username or "/" in username or " " in username:
            return []

        headers = {"Accept": "application/vnd.github+json"}
        if config.github_token:
            headers["Authorization"] = f"Bearer {config.github_token}"

        resp = await http.get(f"https://api.github.com/users/{username}", headers=headers)
        if resp.status_code == 404:
            return []  # authoritative: no such user
        if resp.status_code in (403, 429):
            # Rate limit or a proxy/policy block. "Couldn't check" is not
            # "not found" -- surface it so the report shows the gap.
            try:
                msg = (resp.json() or {}).get("message", "")
            except Exception:
                msg = ""
            raise RuntimeError(f"GitHub API {resp.status_code}: {msg[:160] or 'forbidden'}")
        resp.raise_for_status()
        u = resp.json()
        if u.get("type") != "User":
            return []

        data = {
            k: u.get(k)
            for k in ("name", "company", "blog", "location", "bio",
                      "twitter_username", "public_repos", "followers", "created_at")
            if u.get(k)
        }
        discovered: list[Identifier] = []
        if u.get("name"):
            discovered.append(self.discover(Kind.NAME, u["name"], ident.confidence))
        if u.get("location"):
            discovered.append(self.discover(Kind.LOCATION, u["location"], ident.confidence * 0.7))
        if u.get("blog"):
            discovered.append(self.discover(Kind.URL, u["blog"], ident.confidence * 0.8))
        if u.get("twitter_username"):
            discovered.append(
                self.discover(Kind.USERNAME, u["twitter_username"], ident.confidence * 0.7)
            )

        return [
            Finding(
                module=self.name,
                subject=ident,
                title=f"Public GitHub profile @{username}",
                confidence=min(0.9, ident.confidence),
                url=u.get("html_url"),
                data=data,
                evidence="Fields the user set to public on their GitHub profile.",
                discovered=discovered,
            )
        ]
