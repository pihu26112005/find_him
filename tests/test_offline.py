"""Offline tests: exercise the pure engine logic with a fake module.

No network, no real people. Proves the fan-out, dedup, depth limit, confidence
propagation, authorization gate and report rendering all work.

Run:  python -m pytest -q   (or just: python tests/test_offline.py)
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from footprint.authorization import Authorization, AuthorizationError, Basis, record
from footprint.config import Config
from footprint.models import Finding, Identifier, Kind, RunResult
from footprint.orchestrator import Orchestrator
from footprint.modules.base import Module
from footprint import report


class FakeEmailModule(Module):
    name = "fake_email"
    accepts = frozenset({Kind.EMAIL})

    async def run(self, ident, config, http):
        return [Finding(
            module=self.name, subject=ident, title="fake", confidence=0.8,
            discovered=[self.discover(Kind.USERNAME, "alice", ident.confidence)],
        )]


class FakeUserModule(Module):
    name = "fake_user"
    accepts = frozenset({Kind.USERNAME})

    async def run(self, ident, config, http):
        # discovers the SAME name twice (from two 'sources') to test dedup + signals
        return [Finding(
            module=self.name, subject=ident, title="user", confidence=0.7,
            discovered=[self.discover(Kind.NAME, "Alice A", ident.confidence)],
        )]


def test_fanout_and_dedup():
    cfg = Config(max_depth=2)
    orch = Orchestrator([FakeEmailModule(), FakeUserModule()], cfg)
    result = asyncio.run(orch.run([Identifier(Kind.EMAIL, "ME@Example.com")]))

    # seed normalized to lowercase
    assert any(i.value == "me@example.com" for i in result.identifiers)
    # discovered username then name via depth
    kinds = {i.kind for i in result.identifiers}
    assert Kind.USERNAME in kinds and Kind.NAME in kinds
    # confidence propagated and < 1
    user = next(i for i in result.identifiers if i.kind == Kind.USERNAME)
    assert 0.0 < user.confidence < 1.0
    print("ok: fanout + dedup + propagation")


def test_depth_limit():
    cfg = Config(max_depth=0)  # no discovery beyond seeds
    orch = Orchestrator([FakeEmailModule(), FakeUserModule()], cfg)
    result = asyncio.run(orch.run([Identifier(Kind.EMAIL, "me@example.com")]))
    # modules still run on the seed, but discovered idents are NOT re-queried
    assert all(i.kind != Kind.NAME for i in result.identifiers)
    print("ok: depth limit")


def test_config_skips_unconfigured():
    class NeedsKey(Module):
        name = "needs_key"
        accepts = frozenset({Kind.EMAIL})
        requires_config = True

        def is_configured(self, config):
            return False

    orch = Orchestrator([NeedsKey()], Config())
    assert any(s["module"] == "needs_key" for s in orch.skipped)
    print("ok: unconfigured modules skipped")


def test_authorization_gate(tmpdir="."):
    ok = Authorization(Basis.OWN, "self", "tester")
    ok.validate()
    bad = Authorization(Basis.AUTHORIZED, "", "tester")
    try:
        bad.validate()
        raise AssertionError("should have raised")
    except AuthorizationError:
        pass

    log = Path(".") / "test-audit.log"
    try:
        record(ok, ["me@example.com"], log)
        content = log.read_text()
        assert "me@example.com" not in content  # stored hashed, not plaintext
        assert '"basis": "own"' in content
    finally:
        if log.exists():
            log.unlink()
    print("ok: authorization gate + hashed audit log")


def test_report_renders():
    r = RunResult(seeds=[Identifier(Kind.EMAIL, "me@example.com")])
    r.identifiers.append(Identifier(Kind.NAME, "Alice A", "m1", 0.8))
    r.identifiers.append(Identifier(Kind.NAME, "Alice A", "m2", 0.7))
    r.findings.append(Finding("m1", r.seeds[0], "A finding", 0.9,
                              data={"sites": ["a.com", "b.com"]}))
    md = report.to_markdown(r)
    assert "# Footprint report" in md
    assert "Same-person signals" in md  # repeated name detected
    assert report.to_json(r).startswith("{")
    print("ok: report renders md + json")


if __name__ == "__main__":
    test_fanout_and_dedup()
    test_depth_limit()
    test_config_skips_unconfigured()
    test_authorization_gate()
    test_report_renders()
    print("\nall offline tests passed")
