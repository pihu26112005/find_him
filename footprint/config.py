"""Configuration loading. Keys are optional; unset = module skipped."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class Config:
    hibp_api_key: str = ""
    github_token: str = ""
    timeout_seconds: float = 15.0
    max_depth: int = 2
    # bound the search: how many usernames / emails get searched per run, and
    # how sure a discovered lead must be before it is searched itself
    max_usernames: int = 6
    max_emails: int = 3
    min_pivot_confidence: float = 0.3
    # module name allow/deny lists; empty allow = "all configured modules"
    enabled: list[str] = field(default_factory=list)
    disabled: list[str] = field(default_factory=list)
    # free-form extra settings for third-party tool paths etc.
    extra: dict[str, Any] = field(default_factory=dict)

    def module_allowed(self, name: str) -> bool:
        if name in self.disabled:
            return False
        if self.enabled:
            return name in self.enabled
        return True

    @classmethod
    def load(cls, path: str | os.PathLike | None = None) -> "Config":
        """Load from a YAML file if present, overlaid with env vars.

        Env vars (handy for CI / not committing keys):
          FOOTPRINT_HIBP_API_KEY, FOOTPRINT_GITHUB_TOKEN
        """
        data: dict[str, Any] = {}
        if path:
            p = Path(path)
            if p.exists():
                data = _read_yaml(p)

        modules = data.get("modules", {}) or {}
        cfg = cls(
            hibp_api_key=str(data.get("hibp_api_key", "") or ""),
            github_token=str(data.get("github_token", "") or ""),
            timeout_seconds=float(data.get("timeout_seconds", 15.0)),
            max_depth=int(data.get("max_depth", 2)),
            max_usernames=int(data.get("max_usernames", 6)),
            max_emails=int(data.get("max_emails", 3)),
            min_pivot_confidence=float(data.get("min_pivot_confidence", 0.3)),
            enabled=list(modules.get("enabled", []) or []),
            disabled=list(modules.get("disabled", []) or []),
            extra={k: v for k, v in data.items()
                   if k not in {"hibp_api_key", "github_token", "timeout_seconds",
                                "max_depth", "max_usernames", "max_emails",
                                "min_pivot_confidence", "modules"}},
        )

        # env overrides
        cfg.hibp_api_key = os.environ.get("FOOTPRINT_HIBP_API_KEY", cfg.hibp_api_key)
        cfg.github_token = os.environ.get("FOOTPRINT_GITHUB_TOKEN", cfg.github_token)
        return cfg


def _read_yaml(p: Path) -> dict[str, Any]:
    try:
        import yaml  # type: ignore
    except ImportError as e:  # pragma: no cover
        raise SystemExit(
            "config file given but PyYAML is not installed. "
            "pip install pyyaml, or pass config via env vars."
        ) from e
    with p.open("r", encoding="utf-8") as fh:
        loaded = yaml.safe_load(fh) or {}
    if not isinstance(loaded, dict):
        raise SystemExit(f"config at {p} must be a mapping")
    return loaded
