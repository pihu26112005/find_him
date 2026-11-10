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
import hashlib
import json
import re
from typing import TYPE_CHECKING

from .models import Finding, Identifier, Kind, RunResult

_GRAVATAR_RE = re.compile(r"gravatar\.com/avatar/([0-9a-f]{64}|[0-9a-f]{32})", re.I)

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

        correlate_gravatar(result)
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
            budget = m.run_timeout or (self.config.timeout_seconds + 2)
            try:
                return await asyncio.wait_for(
                    m.run(ident, self.config, http), timeout=budget
                )
            except asyncio.TimeoutError:
                result.errors.append(
                    {"module": m.name, "subject": ident.value, "error": "timeout"}
                )
                return []
            except Exception as e:  # modules must not take the run down
                result.errors.append(
                    {"module": m.name, "subject": ident.value, "error": describe_error(e)}
                )
                return []

        batches = await asyncio.gather(*(_guarded(m) for m in modules))
        out: list[Finding] = []
        for b in batches:
            out.extend(b)
        return out


def describe_error(e: Exception) -> str:
    """Turn transport errors into something a report reader can act on."""
    name = type(e).__name__
    if name == "ProxyError":
        return f"blocked by network policy: the HTTPS proxy refused this host ({e})"
    if name in ("ConnectError", "ConnectTimeout"):
        return f"could not connect ({name}: {e})"
    return f"{name}: {e}"


def correlate_gravatar(result: RunResult) -> None:
    """Hard-link accounts to seed emails via Gravatar avatar hashes.

    Many sites (GitLab, WordPress, Disqus, ...) show an avatar served by
    Gravatar, keyed by MD5 or SHA-256 of the account's email. If a finding's
    data contains such a hash and it equals the hash of an email we know, that
    account is registered with that email. This turns a username "lead" into a
    confirmed link, so the finding and its username are upgraded.
    """
    table: dict[str, str] = {}
    for i in result.identifiers:
        if i.kind == Kind.EMAIL:
            raw = i.value.strip().lower().encode()
            table[hashlib.md5(raw).hexdigest()] = i.value
            table[hashlib.sha256(raw).hexdigest()] = i.value
    if not table:
        return

    seen: set[tuple[str, str]] = set()
    new: list[Finding] = []
    for f in result.findings:
        if f.module == "gravatar":  # Gravatar's own profile is already keyed by the email
            continue
        blob = json.dumps(f.data, default=str, ensure_ascii=False)
        hashes = {m.lower() for m in _GRAVATAR_RE.findall(blob)}  # inside avatar URLs
        hashes.update(h.lower() for h in (f.data.get("avatar_hashes") or [])
                      if isinstance(h, str))                      # already extracted
        for h in sorted(hashes):
            email = table.get(h)
            if not email:
                continue
            f.confidence = max(f.confidence, 0.95)
            f.evidence = (f.evidence + " " if f.evidence else "") + (
                f"Confirmed: its Gravatar avatar hash equals the hash of {email}.")
            upgrades = {d.key(): 0.85 for d in f.discovered}  # fields the account published
            if f.subject.kind == Kind.USERNAME:
                upgrades[f.subject.key()] = 0.9
            for idx, ident in enumerate(result.identifiers):
                floor = upgrades.get(ident.key())
                if floor and ident.confidence < floor:
                    src = ident.source if ident.source.endswith("+correlated") \
                        else ident.source + "+correlated"
                    result.identifiers[idx] = Identifier(ident.kind, ident.value, src, floor)
            key = (email, (f.url or f.title).rstrip("/").lower())
            if key in seen:
                continue
            seen.add(key)
            new.append(Finding(
                module="correlate",
                subject=Identifier(Kind.EMAIL, email),
                title=f"{f.url or f.title} is registered with {email}",
                confidence=0.95,
                url=f.url,
                data={"method": "Gravatar avatar hash = MD5/SHA-256 of the email",
                      "hash": h, "matched_finding": f.title},
                evidence=("The account's avatar is served by Gravatar under the hash of "
                          "this exact email address."),
            ))
    result.findings.extend(new)


def default_modules() -> list["Module"]:
    """Instantiate the built-in module set."""
    from .modules.dns_email import DnsEmailModule
    from .modules.email_localpart import EmailLocalPartModule
    from .modules.github_user import GithubUserModule
    from .modules.gitlab_user import GitlabUserModule
    from .modules.gravatar import GravatarModule
    from .modules.hibp import HibpModule
    from .modules.holehe_runner import HoleheModule
    from .modules.sherlock_runner import SherlockModule
    from .modules.xposedornot import XposedOrNotModule

    return [
        GravatarModule(),
        DnsEmailModule(),
        EmailLocalPartModule(),
        XposedOrNotModule(),
        HibpModule(),
        GithubUserModule(),
        GitlabUserModule(),
        HoleheModule(),
        SherlockModule(),
    ]
