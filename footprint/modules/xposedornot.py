"""XposedOrNot — free, keyless breach exposure for an email.

XposedOrNot (xposedornot.com, open source) is a free alternative to HIBP: it
returns the *names* of breaches an address appeared in, plus per-breach
metadata (what kinds of data leaked, year, password storage). Like HIBP it never
returns the leaked records themselves, which keeps this on the right side of the
"names, not dumps" rule.

Endpoints used:
  GET /v1/breach-analytics?email=...   rich per-breach details (preferred)
  GET /v1/check-email/{email}          plain breach-name list (fallback)
"""
from __future__ import annotations

from urllib.parse import quote

from ..models import Finding, Identifier, Kind
from .base import Module

_API = "https://api.xposedornot.com/v1"


class XposedOrNotModule(Module):
    name = "xposedornot"
    accepts = frozenset({Kind.EMAIL})
    requires_config = False
    propagation = 0.6

    def is_configured(self, config) -> bool:
        return not config.extra.get("xposedornot_disabled", False)

    async def run(self, ident: Identifier, config, http) -> list[Finding]:
        email = ident.value.strip().lower()

        details = await self._analytics(email, http)
        if details is None:  # analytics unavailable -> plain list
            names = await self._check(email, http)
            if names is None:
                return [self._none(ident)]
            details = [{"breach": n} for n in names]
        if not details:
            return [self._none(ident)]

        classes: set[str] = set()
        for d in details:
            classes.update(c.strip() for c in (d.get("xposed_data") or "").split(";")
                           if c.strip())
        return [
            Finding(
                module=self.name,
                subject=ident,
                title=f"Appeared in {len(details)} known breach(es)",
                confidence=0.9,
                url="https://xposedornot.com/",
                data={
                    "breaches": [d["breach"] for d in details],
                    "exposed_data_classes": sorted(classes),
                    "breach_details": details,
                },
                evidence="Breach names/metadata from XposedOrNot (no leaked records).",
            )
        ]

    async def _analytics(self, email: str, http) -> list[dict] | None:
        resp = await http.get(f"{_API}/breach-analytics", params={"email": email})
        if resp.status_code == 404:
            return []
        if resp.status_code == 429:
            raise RuntimeError("XposedOrNot rate limited (429)")
        if resp.status_code != 200:
            return None
        payload = resp.json() or {}
        exposed = (payload.get("ExposedBreaches") or {}).get("breaches_details") or []
        out = []
        for b in exposed:
            if not isinstance(b, dict) or not b.get("breach"):
                continue
            out.append({
                "breach": b.get("breach"),
                "domain": b.get("domain") or None,
                "year": b.get("xposed_date") or None,
                "records": b.get("xposed_records") or None,
                "xposed_data": b.get("xposed_data") or "",
                "password_risk": b.get("password_risk") or None,
                "industry": b.get("industry") or None,
            })
        return out

    async def _check(self, email: str, http) -> list[str] | None:
        resp = await http.get(f"{_API}/check-email/{quote(email)}")
        if resp.status_code == 404:
            return []
        if resp.status_code == 429:
            raise RuntimeError("XposedOrNot rate limited (429)")
        if resp.status_code != 200:
            raise RuntimeError(f"XposedOrNot HTTP {resp.status_code}")
        payload = resp.json() or {}
        raw = payload.get("breaches") or []
        # API returns [["A","B",...]]; flatten defensively
        flat: list[str] = []
        for item in raw:
            if isinstance(item, list):
                flat.extend(str(x) for x in item if x)
            elif item:
                flat.append(str(item))
        return flat

    def _none(self, ident: Identifier) -> Finding:
        return Finding(
            module=self.name, subject=ident, title="No known breaches",
            confidence=0.7,
            evidence="XposedOrNot has no breach record for this address.",
        )
