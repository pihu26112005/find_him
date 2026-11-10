"""Email/domain hygiene checks — deliverability and disposable detection.

No personal data here: this inspects the *domain* of an email, not the person.
It answers "is this a real, deliverable, non-throwaway address?" which is the
useful, low-risk signal for fraud/KYC and for self-audit ("is my address on a
domain that leaks?"). MX resolution uses dnspython if installed; otherwise it
degrades to the bundled disposable-domain check only.
"""
from __future__ import annotations

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


class DnsEmailModule(Module):
    name = "dns_email"
    accepts = frozenset({Kind.EMAIL, Kind.DOMAIN})
    requires_config = False
    propagation = 1.0

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

        mx = self._resolve_mx(domain)
        if mx is not None:
            data["mx_records"] = mx
            data["has_mx"] = bool(mx)

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

    @staticmethod
    def _resolve_mx(domain: str) -> list[str] | None:
        try:
            import dns.resolver  # type: ignore
        except ImportError:
            return None
        try:
            answers = dns.resolver.resolve(domain, "MX", lifetime=5.0)
            return sorted(str(r.exchange).rstrip(".") for r in answers)
        except Exception:
            return []
