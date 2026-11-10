"""Email/domain hygiene checks — deliverability and disposable detection.

No personal data here: this inspects the *domain* of an email, not the person.
It answers "is this a real, deliverable, non-throwaway address, and who hosts
its mail?" — the useful, low-risk signal for fraud/KYC and for self-audit.

MX resolution: dnspython (plain DNS) first, then DNS-over-HTTPS via dns.google,
which also works behind HTTPS-only proxies. Positive plain-DNS answers are
trusted; a *negative* one (NXDOMAIN / no MX) is only trusted once DoH agrees,
because sandboxed and filtering resolvers often answer NXDOMAIN for every
external name. If neither can answer, MX is reported as unknown — never as
"no MX", which would be a false negative.
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

# Well-known mailbox providers by email domain (works offline, no DNS needed).
_FREEMAIL = {
    "gmail.com": "Google (Gmail)", "googlemail.com": "Google (Gmail)",
    "outlook.com": "Microsoft (Outlook)", "hotmail.com": "Microsoft (Outlook)",
    "live.com": "Microsoft (Outlook)", "msn.com": "Microsoft (Outlook)",
    "yahoo.com": "Yahoo", "yahoo.co.in": "Yahoo", "ymail.com": "Yahoo",
    "icloud.com": "Apple iCloud", "me.com": "Apple iCloud", "mac.com": "Apple iCloud",
    "proton.me": "Proton Mail", "protonmail.com": "Proton Mail", "pm.me": "Proton Mail",
    "zohomail.com": "Zoho", "zohomail.in": "Zoho", "aol.com": "AOL",
    "gmx.com": "GMX", "gmx.net": "GMX", "yandex.com": "Yandex", "yandex.ru": "Yandex",
    "mail.ru": "Mail.ru", "rediffmail.com": "Rediff", "tutanota.com": "Tuta",
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
            if ident.source == self.name:
                return []  # domain we surfaced from an email: already covered
            domain = ident.value.lower()

        data: dict = {"domain": domain}
        if domain in _FREEMAIL:
            data["free_mail_provider"] = _FREEMAIL[domain]
        discovered: list[Identifier] = []
        if ident.kind == Kind.EMAIL:
            discovered.append(self.discover(Kind.DOMAIN, domain, ident.confidence))

        is_disposable = domain in _DISPOSABLE
        data["disposable"] = is_disposable

        mx, via = await self._resolve_mx(domain, http)
        if mx is None:
            data["mx_records"] = "unknown (no DNS answer reachable from this network)"
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
        if mx:  # positive answers are trusted
            return mx, "dns"
        # Plain DNS failed or said "no MX". Only DoH can confirm a negative.
        doh = await _doh_mx(domain, http)
        if doh is None:
            return None, ""
        return doh, "doh:dns.google"


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
