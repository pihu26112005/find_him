"""The engine: fan out modules over identifiers, feed discoveries back in.

Design in one breath:
  - a priority queue of identifiers: shallower first, then most confident, so
    the strongest leads are searched before the caps are reached
  - for each identifier, every runnable module that accepts its kind runs
    concurrently, each under its own time budget
  - findings are collected; an account whose Gravatar avatar hash matches a
    known email is confirmed on the spot, so what it links to is trusted more
  - newly discovered identifiers are normalized, deduped (keeping the highest
    confidence) and enqueued at depth+1 if they clear the confidence floor
  - stop at max_depth, at the per-kind caps, or when the queue drains
"""
from __future__ import annotations

import asyncio
import hashlib
import heapq
import itertools
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
        # only keep modules allowed by config AND able to run
        self.modules: list[Module] = []
        self.skipped: list[dict[str, str]] = []
        for m in modules:
            if not config.module_allowed(m.name):
                self.skipped.append({"module": m.name, "reason": "disabled in config"})
                continue
            reason = m.skip_reason(config)
            if reason:
                self.skipped.append({"module": m.name, "reason": reason})
                continue
            self.modules.append(m)

    async def run(self, seeds: list[Identifier]) -> RunResult:
        cfg = self.config
        result = RunResult(seeds=list(seeds), skipped=list(self.skipped))
        caps = {Kind.USERNAME: cfg.max_usernames, Kind.EMAIL: cfg.max_emails}
        searched = {k: 0 for k in caps}
        over_cap: dict[str, list[str]] = {k: [] for k in caps}
        below_floor: list[str] = []

        seen: dict[tuple[str, str], Identifier] = {}
        heap: list = []
        order = itertools.count()
        emails: dict[str, str] = {}

        def push(ident: Identifier, depth: int) -> None:
            heapq.heappush(heap, (depth, -ident.confidence, next(order), ident))

        for s in seeds:
            n = s.normalized()
            seen[n.key()] = n
            result.identifiers.append(n)
            _remember_email(n, emails)
            push(n, 0)

        import httpx

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(cfg.timeout_seconds), follow_redirects=True,
            trust_env=True,
            headers={"User-Agent": "footprint-auditor/0.2 (+public-sources-only)"},
        ) as http:
            while heap:
                depth, _, _, ident = heapq.heappop(heap)
                matching = [m for m in self.modules if ident.kind in m.accepts]
                if not matching:
                    continue
                if depth > 0 and ident.confidence < cfg.min_pivot_confidence:
                    below_floor.append(f"{ident.value} ({ident.confidence:.2f})")
                    continue
                if ident.kind in caps:
                    if searched[ident.kind] >= caps[ident.kind]:
                        over_cap[ident.kind].append(ident.value)
                        continue
                    searched[ident.kind] += 1

                findings = await self._run_modules(matching, ident, http, result)
                for f in findings:
                    _confirm_in_flight(f, emails)
                    result.findings.append(f)
                    for disc in f.discovered:
                        n = disc.normalized()
                        k = n.key()
                        if k in seen:
                            # keep the higher-confidence sighting
                            if n.confidence > seen[k].confidence:
                                seen[k] = n
                                for i, old in enumerate(result.identifiers):
                                    if old.key() == k:
                                        result.identifiers[i] = n
                            continue
                        seen[k] = n
                        result.identifiers.append(n)
                        _remember_email(n, emails)
                        if depth + 1 <= cfg.max_depth:
                            push(n, depth + 1)

        for kind, values in over_cap.items():
            if values:
                result.skipped.append({
                    "module": "engine",
                    "reason": (f"{len(values)} {kind}(s) not searched, max_{kind}s="
                               f"{caps[kind]} reached: {', '.join(values[:15])}"),
                })
        if below_floor:
            result.skipped.append({
                "module": "engine",
                "reason": (f"{len(below_floor)} lead(s) not searched, confidence below "
                           f"min_pivot_confidence={cfg.min_pivot_confidence}: "
                           f"{', '.join(below_floor[:15])}"),
            })

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


# --- Gravatar-hash correlation ------------------------------------------------
def _remember_email(ident: Identifier, table: dict[str, str]) -> None:
    if ident.kind == Kind.EMAIL:
        raw = ident.value.strip().lower().encode()
        table[hashlib.md5(raw).hexdigest()] = ident.value
        table[hashlib.sha256(raw).hexdigest()] = ident.value


def _avatar_hashes(f: Finding) -> set[str]:
    blob = json.dumps(f.data, default=str, ensure_ascii=False)
    hashes = {m.lower() for m in _GRAVATAR_RE.findall(blob)}   # inside avatar URLs
    hashes.update(h.lower() for h in (f.data.get("avatar_hashes") or [])
                  if isinstance(h, str))                         # already extracted
    return hashes


def _match(f: Finding, table: dict[str, str]) -> tuple[str, str] | None:
    if f.module == "gravatar":  # Gravatar's own profile is keyed by the email anyway
        return None
    for h in sorted(_avatar_hashes(f)):
        if h in table:
            return table[h], h
    return None


def _confirm_in_flight(f: Finding, table: dict[str, str]) -> None:
    """Raise a confirmed account's confidence *before* its links are queued,
    so handles it links to clear the pivot floor."""
    if table and _match(f, table):
        f.confidence = max(f.confidence, 0.95)
        f.discovered = [Identifier(d.kind, d.value, d.source, max(d.confidence, 0.85))
                        for d in f.discovered]


def correlate_gravatar(result: RunResult) -> None:
    """Hard-link accounts to known emails via Gravatar avatar hashes.

    Many sites (GitLab, WordPress, Disqus, ...) show an avatar served by
    Gravatar, keyed by MD5 or SHA-256 of the account's email. If a finding's
    data contains such a hash and it equals the hash of an email we know, that
    account is registered with that email. This turns a username "lead" into a
    confirmed link, so the finding and its username are upgraded.
    """
    table: dict[str, str] = {}
    for i in result.identifiers:
        _remember_email(i, table)
    if not table:
        return

    seen: set[tuple[str, str]] = set()
    new: list[Finding] = []
    for f in result.findings:
        hit = _match(f, table)
        if not hit:
            continue
        email, h = hit
        f.confidence = max(f.confidence, 0.95)
        note = f"Confirmed: its Gravatar avatar hash equals the hash of {email}."
        if note not in f.evidence:
            f.evidence = (f.evidence + " " if f.evidence else "") + note
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
    from .modules.maigret_runner import MaigretModule
    from .modules.sherlock_runner import SherlockModule
    from .modules.whatsmyname import WhatsMyNameModule
    from .modules.xposedornot import XposedOrNotModule

    return [
        GravatarModule(),
        DnsEmailModule(),
        EmailLocalPartModule(),
        XposedOrNotModule(),
        HibpModule(),
        HoleheModule(),
        GithubUserModule(),
        GitlabUserModule(),
        WhatsMyNameModule(),
        MaigretModule(),
        SherlockModule(),
    ]
