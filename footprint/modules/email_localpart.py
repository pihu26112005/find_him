"""Email local part -> username candidate.

People very often reuse the part before the @ as a handle elsewhere
("john.doe91@gmail.com" -> "john.doe91"). Every commercial reverse-email tool
makes this pivot. It is a *guess*, so the discovered username carries a reduced
confidence: a profile found under it is a lead until something else (same name,
same avatar, a link back) corroborates it.
"""
from __future__ import annotations

import re

from ..models import Finding, Identifier, Kind
from .base import Module

# Role/shared mailboxes: the local part names a function, not a person.
_GENERIC = {
    "admin", "administrator", "contact", "hello", "help", "hi", "info", "mail",
    "marketing", "no-reply", "noreply", "office", "postmaster", "sales",
    "security", "support", "team", "test", "webmaster",
}

# Providers that ignore dots in the local part, so "j.doe" == "jdoe".
_DOT_INSENSITIVE = {"gmail.com", "googlemail.com"}

_MAX_CANDIDATES = 5


class EmailLocalPartModule(Module):
    name = "email_localpart"
    accepts = frozenset({Kind.EMAIL})
    requires_config = False
    propagation = 0.5  # a guess, not a published link

    async def run(self, ident: Identifier, config, http) -> list[Finding]:
        if "@" not in ident.value:
            return []
        local, domain = ident.value.lower().rsplit("@", 1)
        local = local.split("+", 1)[0]  # drop sub-addressing tags (me+news@...)

        if len(local) < 4 or local.isdigit() or local in _GENERIC:
            return []

        # (candidate, weight): the local part itself is the strongest guess
        weights: dict[str, float] = {local: 1.0}
        if domain in _DOT_INSENSITIVE and "." in local:
            weights[local.replace(".", "")] = 1.0  # same mailbox, same person
        parts = [x for x in re.split(r"[._-]+", local) if x]
        if len(parts) > 1:  # people swap separators between sites
            for joiner in (".", "_", "-", ""):
                weights.setdefault(joiner.join(parts), 0.8)
        candidates = list(weights.items())[:_MAX_CANDIDATES]

        return [
            Finding(
                module=self.name,
                subject=ident,
                title="Username candidate(s) from email local part",
                confidence=0.5,
                data={"candidates": [c for c, _ in candidates]},
                evidence=("Local part reused as a handle is common but unproven; "
                          "treat hits under it as leads. Separator variants rank lower."),
                discovered=[self.discover(Kind.USERNAME, c, ident.confidence * w)
                            for c, w in candidates],
            )
        ]
