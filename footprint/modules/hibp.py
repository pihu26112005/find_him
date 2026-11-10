"""Have I Been Pwned — breach exposure for an email.

HIBP is the canonical, ethical breach source: it tells you *which breaches* an
address appeared in, not the leaked passwords. This is the safe way to surface
breach exposure. Requires an API key (haveibeenpwned.com/API/Key).

Note on the difference that matters: HIBP returns breach *names*. Services that
return the actual leaked records (passwords, phones) are re-distributing stolen
data — this tool does not do that, by design.
"""
from __future__ import annotations

from urllib.parse import quote

from ..models import Finding, Identifier, Kind
from .base import Module


class HibpModule(Module):
    name = "hibp"
    accepts = frozenset({Kind.EMAIL})
    requires_config = True
    propagation = 0.6

    def is_configured(self, config) -> bool:
        return bool(config.hibp_api_key)

    async def run(self, ident: Identifier, config, http) -> list[Finding]:
        url = (
            "https://haveibeenpwned.com/api/v3/breachedaccount/"
            f"{quote(ident.value)}?truncateResponse=false"
        )
        headers = {"hibp-api-key": config.hibp_api_key}
        resp = await http.get(url, headers=headers)
        if resp.status_code == 404:
            return [
                Finding(
                    module=self.name, subject=ident,
                    title="No known breaches", confidence=0.7,
                    evidence="HIBP returned no breaches for this address.",
                )
            ]
        if resp.status_code == 401:
            raise RuntimeError("HIBP API key rejected (401)")
        if resp.status_code == 429:
            raise RuntimeError("HIBP rate limited (429) — slow down")
        resp.raise_for_status()
        breaches = resp.json()

        names = [b.get("Name") for b in breaches if b.get("Name")]
        classes: set[str] = set()
        for b in breaches:
            classes.update(b.get("DataClasses", []) or [])

        return [
            Finding(
                module=self.name,
                subject=ident,
                title=f"Appeared in {len(breaches)} known breach(es)",
                confidence=0.95,
                url="https://haveibeenpwned.com/",
                data={
                    "breaches": names,
                    "exposed_data_classes": sorted(classes),
                },
                evidence="Breach names from HIBP (no leaked credentials retrieved).",
            )
        ]
