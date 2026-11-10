"""Core data types shared across the engine and all modules."""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any


# --- Identifier kinds ---------------------------------------------------------
# A small, closed vocabulary. Modules declare which kinds they accept and which
# kinds they can discover. Keeping this closed makes the fan-out graph legible.
class Kind:
    EMAIL = "email"
    USERNAME = "username"
    NAME = "name"
    URL = "url"
    DOMAIN = "domain"
    PHONE = "phone"
    LOCATION = "location"
    HASH = "hash"

    ALL = {EMAIL, USERNAME, NAME, URL, DOMAIN, PHONE, LOCATION, HASH}


@dataclass(frozen=True)
class Identifier:
    """A single atomic piece of identity data flowing through the engine."""

    kind: str
    value: str
    # Where it came from and how sure we are it belongs to the subject (0..1).
    source: str = "seed"
    confidence: float = 1.0

    def normalized(self) -> "Identifier":
        v = self.value.strip()
        if self.kind in (Kind.EMAIL, Kind.USERNAME, Kind.DOMAIN):
            v = v.lower()
        return Identifier(self.kind, v, self.source, self.confidence)

    def key(self) -> tuple[str, str]:
        n = self.normalized()
        return (n.kind, n.value)


@dataclass
class Finding:
    """One result from one module about one identifier."""

    module: str
    subject: Identifier
    title: str
    confidence: float = 0.5
    url: str | None = None
    data: dict[str, Any] = field(default_factory=dict)
    evidence: str = ""
    # New identifiers this finding surfaced, to be fed back into the engine.
    discovered: list[Identifier] = field(default_factory=list)
    # Set when this finding is about one account on one site (e.g. "Instagram",
    # "instagram.com"); the report merges these into the accounts table.
    platform: str | None = None
    ts: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "module": self.module,
            "subject": {"kind": self.subject.kind, "value": self.subject.value},
            "title": self.title,
            "platform": self.platform,
            "confidence": round(self.confidence, 3),
            "url": self.url,
            "data": self.data,
            "evidence": self.evidence,
            "discovered": [
                {"kind": d.kind, "value": d.value, "confidence": round(d.confidence, 3)}
                for d in self.discovered
            ],
        }


@dataclass
class RunResult:
    """Everything one audit run produced."""

    seeds: list[Identifier]
    findings: list[Finding] = field(default_factory=list)
    identifiers: list[Identifier] = field(default_factory=list)
    errors: list[dict[str, str]] = field(default_factory=list)
    skipped: list[dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "seeds": [{"kind": s.kind, "value": s.value} for s in self.seeds],
            "findings": [f.to_dict() for f in self.findings],
            "identifiers": [
                {"kind": i.kind, "value": i.value, "confidence": round(i.confidence, 3),
                 "source": i.source}
                for i in self.identifiers
            ],
            "errors": self.errors,
            "skipped": self.skipped,
        }
