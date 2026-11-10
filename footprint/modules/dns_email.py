"""Email/domain hygiene checks — deliverability and disposable detection.

No personal data here: this inspects the *domain* of an email, not the person.
It answers "is this a real, deliverable, non-throwaway address, and who hosts
its mail?" — the useful, low-risk signal for fraud/KYC and for self-audit.

MX resolution: dnspython (plain DNS) first, then DNS-over-HTTPS via dns.google,
which also works behind HTTPS-only proxies. A lookup that *fails* is reported as
unknown — never as "no MX", which would be a false negative.
"""
from __future__ import annotations

import asyncio

from ..models import Finding, Identifier, Kind
from .base import Module

# A deliberately small seed list. In production, pull a maintained list such as
# disposable-email-domains (github.com/disposable-email-domains). Kept short
# here so the repo ships something runnable without a network fetch.
_DISPOSABLE = {
    "mailinator.com", "guerrillamail.com", "10minutemail.com", "tempmail.com",
    "temp-mail.org", "throwawaymail.com", "yopmail.com", "trashmail.com",
    "getnada.com", "maildrop.cc", "sharklasers.com", "dispostable.com",
}

# MX host suffix -> who runs the mailbox
_MX_PROVIDERS = {
    "google.com": "Google (Gmail / Workspace)",
    "googlemail.com": "Google (Gmail / Workspace)",
    "outlook.com": "Microsoft (Outlook / 365)",
    "protection.outlook.com": "Microsoft 365",
    "yahoodns.net": "Yahoo",
    "zoho.com": "Zoho",
    "zoho.in": "Zoho",
    "protonmail.ch": "Proton Mail",
    "icloud.com": "Apple iCloud",
}


class DnsEmailModule(Module):
    name = "dns_email"
    accepts = frozenset({Kind.EMAIL, Kind.DOMAIN})
    requires_config = False
    propagation = 1.0
    run_timeout = 20.0

    async def run(self, ident: Identifier, config, http) -> list[Finding]:
        if ident.kind == Kind.EMAIL:
            if "@" not in ident.value:
                return []
            domain = ident.value.rsplit("@", 1)[1].lower()
        else:
            domain = ident.value.lower()

        data: dict = {"domain": domain}
        discovered: list[Identifier] = []
        if ident.kind == Kind.EMAIL:
            discovered.append(self.discover(Kind.DOMAIN, domain, ident.confidence))

        is_disposable = domain in _DISPOSABLE
        data["disposable"] = is_disposable

        mx, via = await self._resolve_mx(domain, http)
        if mx is None:
            data["mx_records"] = "unknown (DNS lookup failed)"
        else:
            data["mx_records"] = mx
            data["has_mx"] = bool(mx)
            data["mx_resolved_via"] = via
            provider = _provider(mx)
            if provider:
                data["mail_provider"] = provider

        title = "Disposable/temporary email domain" if is_disposable else "Email domain info"
        conf = 0.9 if is_disposable else 0.4
        return [
            Finding(
                module=self.name,
                subject=ident,
                title=title,
                confidence=conf,
                data=data,
                evidence=("Domain is a known disposable provider." if is_disposable
                          else "Domain metadata (no personal data)."),
                discovered=discovered,
            )
        ]

    async def _resolve_mx(self, domain: str, http) -> tuple[list[str] | None, str]:
        mx = await asyncio.to_thread(_dnspython_mx, domain)
        if mx is not None:
            return mx, "dns"
        return await _doh_mx(domain, http), "doh:dns.google"


def _dnspython_mx(domain: str) -> list[str] | None:
    """[] = domain has no MX (authoritative); None = couldn't find out."""
    try:
        import dns.resolver  # type: ignore
    except ImportError:
        return None
    try:
        answers = dns.resolver.resolve(domain, "MX", lifetime=3.0)
        return sorted(str(r.exchange).rstrip(".").lower() for r in answers)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except Exception:
        return None


async def _doh_mx(domain: str, http) -> list[str] | None:
    try:
        resp = await http.get("https://dns.google/resolve",
                              params={"name": domain, "type": "MX"})
        if resp.status_code != 200:
            return None
        payload = resp.json()
    except Exception:
        return None
    status = payload.get("Status")
    if status == 3:  # NXDOMAIN
        return []
    if status != 0:
        return None
    out = []
    for ans in payload.get("Answer") or []:
        if ans.get("type") == 15 and ans.get("data"):
            # "5 gmail-smtp-in.l.google.com." -> host
            out.append(ans["data"].split()[-1].rstrip(".").lower())
    return sorted(out)


def _provider(mx: list[str]) -> str | None:
    for host in mx:
        for suffix, label in _MX_PROVIDERS.items():
            if host == suffix or host.endswith("." + suffix):
                return label
    return None
