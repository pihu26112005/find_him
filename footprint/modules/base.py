"""Module contract. Every source adapter implements this interface."""
from __future__ import annotations

from typing import TYPE_CHECKING

from ..models import Finding, Identifier

if TYPE_CHECKING:  # pragma: no cover
    import httpx

    from ..config import Config


class Module:
    """Base class for a single data source.

    A module is small and single-purpose: it accepts one or more identifier
    kinds, and when run against a matching identifier it returns a list of
    Findings (possibly empty). It must never raise for an expected "not found"
    — it returns []. The orchestrator handles timeouts and unexpected errors.
    """

    #: stable short name, used in config, reports and the module registry
    name: str = "base"

    #: which Identifier.kind values this module knows how to query
    accepts: frozenset[str] = frozenset()

    #: does this module need an API key / external tool to do anything useful?
    requires_config: bool = False

    #: confidence multiplier applied to identifiers this module discovers
    propagation: float = 0.9

    #: wall-clock budget for one run() call, in seconds. None = the config's
    #: per-request timeout + 2s, which suits single-request modules. Modules that
    #: fan out internally (holehe, sherlock) set a larger budget.
    run_timeout: float | None = None

    def is_configured(self, config: "Config") -> bool:
        """Return True if the module can run given the current config.

        Modules with no external dependency return True. Modules needing a key
        or an installed CLI override this and check for it, so the orchestrator
        can skip (and clearly report) anything not set up.
        """
        return not self.requires_config

    def skip_reason(self, config: "Config") -> str | None:
        """Why this module won't run with this config, or None if it will.

        Override to give a specific reason (missing tool, superseded by another
        module, ...); the default derives it from is_configured().
        """
        if self.is_configured(config):
            return None
        return "not configured (missing API key or external tool)"

    async def run(
        self, ident: Identifier, config: "Config", http: "httpx.AsyncClient"
    ) -> list[Finding]:  # pragma: no cover - overridden
        raise NotImplementedError

    # -- helpers ----------------------------------------------------------------
    def discover(
        self, kind: str, value: str, base_confidence: float
    ) -> Identifier:
        """Build a discovered Identifier with propagated confidence."""
        return Identifier(
            kind=kind,
            value=value,
            source=self.name,
            confidence=round(base_confidence * self.propagation, 4),
        )
