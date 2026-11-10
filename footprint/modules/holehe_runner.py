"""Holehe adapter — account-existence across sites, for an email.

Holehe (github.com/megadose/holehe) checks whether an email is registered on
~120 sites using their public password-reset / signup responses. We shell out
to the installed `holehe` CLI rather than re-implementing the probes, so you're
using the maintained, well-known tool and we're not hand-rolling login-form
abuse.

IMPORTANT scoping note: account-existence is the most sensitive signal here —
it reveals where a person has accounts. Only run it on your own address, a
consenting subject, or an authorized assessment. The CLI is optional; if it
isn't installed the module cleanly skips.
"""
from __future__ import annotations

import asyncio
import json
import shutil

from ..models import Finding, Identifier, Kind
from .base import Module


class HoleheModule(Module):
    name = "holehe"
    accepts = frozenset({Kind.EMAIL})
    requires_config = True
    propagation = 0.5

    def is_configured(self, config) -> bool:
        if config.extra.get("holehe_disabled"):
            return False
        return shutil.which("holehe") is not None

    async def run(self, ident: Identifier, config, http) -> list[Finding]:
        exe = shutil.which("holehe")
        if not exe:
            return []
        proc = await asyncio.create_subprocess_exec(
            exe, "--only-used", "--no-color", "-C", ident.value,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, _ = await asyncio.wait_for(
                proc.communicate(), timeout=config.timeout_seconds
            )
        except asyncio.TimeoutError:
            proc.kill()
            raise

        # holehe -C writes a CSV file; --only-used trims to hits. We parse stdout
        # lines of the form "[+] site.com". (CSV path handling kept simple.)
        used: list[str] = []
        for line in stdout.decode(errors="replace").splitlines():
            line = line.strip()
            if line.startswith("[+]"):
                used.append(line[3:].strip())

        if not used:
            return [
                Finding(
                    module=self.name, subject=ident,
                    title="No accounts found via holehe", confidence=0.4,
                    evidence="holehe reported no 'used' registrations.",
                )
            ]

        discovered = [self.discover(Kind.URL, f"https://{s}", ident.confidence * 0.4)
                      for s in used]
        return [
            Finding(
                module=self.name,
                subject=ident,
                title=f"Registered on {len(used)} site(s) (holehe)",
                confidence=0.75,
                data={"sites": sorted(used)},
                evidence="Account-existence confirmed via public reset/signup responses.",
                discovered=discovered,
            )
        ]
