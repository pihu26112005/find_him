"""The engine: fan out modules over identifiers, feed discoveries back in.

Design in one breath:
  - a work queue of (identifier, depth)
  - for each identifier, every configured module that accepts its kind runs
    concurrently, each under a timeout
  - findings are collected; newly discovered identifiers are normalized,
    deduped (keeping the highest confidence seen), and enqueued at depth+1
  - stop at max_depth, or when the queue drains
"""
from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

from .models import Finding, Identifier, Kind, RunResult

if TYPE_CHECKING:  # pragma: no cover
    from .config import Config
    from .modules.base import Module


class Orchestrator:
    def __init__(self, modules: list["Module"], config: "Config") -> None:
        self.config = config
        # only keep modules allowed by config AND configured to run
        self.modules: list[Module] = []
        self.skipped: list[dict[str, str]] = []
        for m in modules:
            if not config.module_allowed(m.name):
                self.skipped.append({"module": m.name, "reason": "disabled in config"})
                continue
            if not m.is_configured(config):
                self.skipped.append(
                    {"module": m.name,
                     "reason": "not configured (missing API key or external tool)"}
                )
                continue
            self.modules.append(m)

    async def run(self, seeds: list[Identifier]) -> RunResult:
        result = RunResult(seeds=list(seeds), skipped=list(self.skipped))

        seen: dict[tuple[str, str], Identifier] = {}
        queue: asyncio.Queue[tuple[Identifier, int]] = asyncio.Queue()

        for s in seeds:
            n = s.normalized()
            seen[n.key()] = n
            result.identifiers.append(n)
            await queue.put((n, 0))

        import httpx

        timeout = httpx.Timeout(self.config.timeout_seconds)
        async with httpx.AsyncClient(
            timeout=timeout, follow_redirects=True, trust_env=True,
            headers={"User-Agent": "footprint-auditor/0.1 (+public-sources-only)"},
        ) as http:
            while not queue.empty():
                ident, depth = await queue.get()
                matching = [m for m in self.modules if ident.kind in m.accepts]
                if not matching:
                    continue

                findings = await self._run_modules(matching, ident, http, result)
                for f in findings:
                    result.findings.append(f)
                    for disc in f.discovered:
                        n = disc.normalized()
                        k = n.key()
                        if k in seen:
                            # keep the higher-confidence sighting
                            if n.confidence > seen[k].confidence:
                                seen[k] = n
                            continue
                        seen[k] = n
                        result.identifiers.append(n)
                        if depth + 1 <= self.config.max_depth:
                            await queue.put((n, depth + 1))

        result.findings.sort(key=lambda f: f.confidence, reverse=True)
        result.identifiers.sort(key=lambda i: i.confidence, reverse=True)
        return result

    async def _run_modules(
        self,
        modules: list["Module"],
        ident: Identifier,
        http,
        result: RunResult,
    ) -> list[Finding]:
        async def _guarded(m: "Module") -> list[Finding]:
            try:
                return await asyncio.wait_for(
                    m.run(ident, self.config, http),
                    timeout=self.config.timeout_seconds + 2,
                )
            except asyncio.TimeoutError:
                result.errors.append(
                    {"module": m.name, "subject": ident.value, "error": "timeout"}
                )
                return []
            except Exception as e:  # modules must not take the run down
                result.errors.append(
                    {"module": m.name, "subject": ident.value,
                     "error": f"{type(e).__name__}: {e}"}
                )
                return []

        batches = await asyncio.gather(*(_guarded(m) for m in modules))
        out: list[Finding] = []
        for b in batches:
            out.extend(b)
        return out


def default_modules() -> list["Module"]:
    """Instantiate the built-in module set."""
    from .modules.dns_email import DnsEmailModule
    from .modules.github_user import GithubUserModule
    from .modules.gravatar import GravatarModule
    from .modules.hibp import HibpModule
    from .modules.holehe_runner import HoleheModule
    from .modules.sherlock_runner import SherlockModule

    return [
        GravatarModule(),
        DnsEmailModule(),
        GithubUserModule(),
        HibpModule(),
        HoleheModule(),
        SherlockModule(),
    ]
