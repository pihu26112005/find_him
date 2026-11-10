"""Sherlock adapter — find a username across sites.

Sherlock (github.com/sherlock-project/sherlock) checks whether a username has a
public profile page on ~400 sites. We shell out to the installed CLI and parse
its output. Optional; skips cleanly if not installed.

This is the "username pivot" step: once Gravatar/GitHub hand you a username,
this finds where else that handle has public pages. It proves a handle exists
on a site, not that it's the same human — entity resolution (report.py) is where
you weigh that.
"""
from __future__ import annotations

import asyncio
import shutil

from ..models import Finding, Identifier, Kind
from .base import Module


class SherlockModule(Module):
    name = "sherlock"
    accepts = frozenset({Kind.USERNAME})
    requires_config = True
    propagation = 0.4

    def is_configured(self, config) -> bool:
        if config.extra.get("sherlock_disabled"):
            return False
        return shutil.which("sherlock") is not None

    async def run(self, ident: Identifier, config, http) -> list[Finding]:
        exe = shutil.which("sherlock")
        username = ident.value.strip().lstrip("@")
        if not exe or not username or " " in username:
            return []

        proc = await asyncio.create_subprocess_exec(
            exe, "--print-found", "--no-color", "--timeout", "10", username,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, _ = await asyncio.wait_for(
                proc.communicate(), timeout=max(30.0, config.timeout_seconds)
            )
        except asyncio.TimeoutError:
            proc.kill()
            raise

        urls: list[str] = []
        for line in stdout.decode(errors="replace").splitlines():
            line = line.strip()
            # sherlock prints "[+] SiteName: https://..."
            if line.startswith("[+]") and "http" in line:
                urls.append(line.split(":", 1)[1].strip() if ":" in line else line)
                # keep just the URL
                if "http" in urls[-1]:
                    urls[-1] = "http" + urls[-1].split("http", 1)[1]

        urls = [u for u in urls if u.startswith("http")]
        if not urls:
            return []

        discovered = [self.discover(Kind.URL, u, ident.confidence) for u in urls]
        return [
            Finding(
                module=self.name,
                subject=ident,
                title=f"Username '{username}' found on {len(urls)} site(s) (sherlock)",
                confidence=0.6,
                data={"profiles": urls},
                evidence="Public profile pages exist for this handle (same-person not proven).",
                discovered=discovered,
            )
        ]
