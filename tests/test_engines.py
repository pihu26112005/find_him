"""Offline tests for the username engines, link pivoting, search bounds and the
accounts table. No network: HTTP is mocked, Maigret's search is stubbed.

Run:  python -m pytest -q tests   (or: python tests/test_engines.py)
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import sys
import tempfile
import types
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import httpx

from footprint.config import Config
from footprint.models import Finding, Identifier, Kind, RunResult
from footprint.modules import whatsmyname as wmn
from footprint.modules._web import handle_from_url
from footprint.modules.base import Module
from footprint.orchestrator import Orchestrator
from footprint.report import accounts, to_markdown

USER = Identifier(Kind.USERNAME, "jdoe")


def _run(coro):
    return asyncio.run(coro)


# -- profile URL -> handle ------------------------------------------------------
def test_handle_from_url():
    ok = {
        "https://x.com/jane_doe": ("X", "jane_doe"),
        "https://twitter.com/@jane_doe/": ("X", "jane_doe"),
        "instagram.com/jane.doe": ("Instagram", "jane.doe"),
        "https://www.tiktok.com/@jane.d": ("TikTok", "jane.d"),
        "https://github.com/janedoe": ("GitHub", "janedoe"),
        "https://www.linkedin.com/in/jane-doe-12ab/": ("LinkedIn", "jane-doe-12ab"),
        "https://reddit.com/u/jane_d": ("Reddit", "jane_d"),
        "https://t.me/janedoe_tg": ("Telegram", "janedoe_tg"),
        "https://www.youtube.com/@JaneDoe": ("YouTube", "JaneDoe"),
        "https://leetcode.com/u/janedoe/": ("LeetCode", "janedoe"),
    }
    for url, want in ok.items():
        assert handle_from_url(url) == want, url
    for url in ("https://x.com/home", "https://twitter.com/intent/tweet",
                "https://www.facebook.com/sharer.php", "https://github.com/orgs",
                "https://instagram.com/p/Cxyz", "https://example.com/janedoe",
                "https://x.com/jane/status/1"):
        assert handle_from_url(url) is None, url
    print("ok: profile URL -> handle (reserved paths and unknown hosts rejected)")


# -- WhatsMyName -----------------------------------------------------------------
SITES = [
    {"name": "Social1", "uri_check": "https://s1.example/{account}", "e_code": 200,
     "e_string": "profile-of", "m_code": 404, "m_string": "Not Found", "cat": "social",
     "known": ["a"]},
    {"name": "Redir", "uri_check": "https://redir.example/u/{account}", "e_code": 200,
     "e_string": "user-page", "m_code": 302, "m_string": "", "cat": "social", "known": ["a"]},
    {"name": "Poster", "uri_check": "https://post.example/api", "e_code": 200,
     "e_string": '"found":true', "m_code": 200, "m_string": '"found":false',
     "post_body": '{"name":"{account}"}', "headers": {"Content-Type": "application/json"},
     "strip_bad_char": ".", "cat": "coding", "known": ["a"]},
    {"name": "Walled", "uri_check": "https://walled.example/{account}", "e_code": 200,
     "e_string": "profile", "m_code": 404, "m_string": "nope", "cat": "social", "known": ["a"]},
    {"name": "Adult", "uri_check": "https://x.example/{account}", "e_code": 200,
     "e_string": "x", "m_code": 404, "m_string": "y", "cat": "xx NSFW xx", "known": ["a"]},
    {"name": "Date", "uri_check": "https://d.example/{account}", "e_code": 200,
     "e_string": "x", "m_code": 404, "m_string": "y", "cat": "dating", "known": ["a"]},
    {"name": "Broken", "uri_check": "https://b.example/{account}", "e_code": 200,
     "e_string": "x", "m_code": 404, "m_string": "y", "cat": "social", "known": ["a"],
     "valid": False},
]


def test_wmn_verdict_rules():
    s = SITES[0]
    assert wmn.verdict(s, 200, "<div>profile-of jdoe</div>") == "found"
    assert wmn.verdict(s, 404, "Not Found") == "absent"
    assert wmn.verdict(s, 200, "something else") == "inconclusive"     # neither rule
    assert wmn.verdict(s, 404, "profile-of Not Found") == "absent"      # m only (status)
    assert wmn.verdict(s, 429, "") == "inconclusive"
    assert wmn.verdict(s, 200, "<title>Just a moment...</title> profile-of") == "inconclusive"
    assert wmn.verdict(s, None, "") == "inconclusive"
    both = dict(s, m_code=200, m_string="profile-of")
    assert wmn.verdict(both, 200, "profile-of") == "inconclusive"       # ambiguous
    print("ok: WhatsMyName two-sided rules; walls, blocks, ambiguity -> inconclusive")


def test_wmn_site_selection():
    names = lambda cfg: [s["name"] for s in wmn.select_sites({"sites": SITES}, cfg)]
    assert names(Config()) == ["Social1", "Redir", "Poster", "Walled"]
    assert "Adult" in names(Config(extra={"wmn_nsfw": True}))
    assert "Date" in names(Config(extra={"wmn_exclude_categories": []}))
    assert names(Config(extra={"wmn_categories": ["coding"]})) == ["Poster"]
    print("ok: WhatsMyName selection (NSFW, dating, invalid excluded; category filter)")


def _wmn_handler(req: httpx.Request) -> httpx.Response:
    host = req.url.host
    if host == "s1.example":
        return httpx.Response(200, text="<div>profile-of jdoe</div>")
    if host == "redir.example":
        return httpx.Response(302, headers={"Location": "/signup"})  # must NOT be followed
    if host == "post.example":
        body = json.loads(req.content)
        assert req.method == "POST" and body == {"name": "jdoe"}    # '.' stripped
        assert req.headers["content-type"] == "application/json"
        return httpx.Response(200, text='{"found":true}')
    if host == "walled.example":
        return httpx.Response(200, text="<title>Just a moment...</title>")
    return httpx.Response(500)


def test_wmn_module_end_to_end():
    with tempfile.TemporaryDirectory() as d:
        data = Path(d) / "wmn.json"
        data.write_text(json.dumps({"sites": SITES}))
        cfg = Config(extra={"wmn_data_path": str(data)})

        async def go():
            async with httpx.AsyncClient(transport=httpx.MockTransport(_wmn_handler),
                                         follow_redirects=True) as c:
                return await wmn.WhatsMyNameModule().run(Identifier(Kind.USERNAME, "j.doe"),
                                                         cfg, c)
        out = _run(go())
    s = out[-1].data
    assert [x["site"] for x in s["found"]] == ["Poster", "Social1"]
    assert s["absent_on"] == ["Redir"]          # 302 = missing for this site
    assert s["inconclusive"] == ["Walled"]
    hits = [f for f in out if f.platform]
    assert {f.platform for f in hits} == {"Poster", "Social1"}
    print("ok: WhatsMyName module: POST + strip chars, no redirect follow, walls")


def test_wmn_data_pinning_and_cache():
    good = json.dumps({"sites": SITES[:1]}).encode()
    calls = []

    def handler(req):
        calls.append(str(req.url))
        return httpx.Response(200, content=good)

    async def load(cfg):
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
            return await wmn.load_data(cfg, c)

    with tempfile.TemporaryDirectory() as d:
        old = os.environ.get("XDG_CACHE_HOME")
        os.environ["XDG_CACHE_HOME"] = d
        try:
            # pinned URL: content whose hash doesn't match the pin is refused
            try:
                _run(load(Config()))
                raise AssertionError("hash mismatch must be refused")
            except RuntimeError as e:
                assert "SHA-256" in str(e)
            assert not list(Path(d).rglob("*.json"))  # nothing cached
            # custom URL: no pin, cached after first fetch
            cfg = Config(extra={"wmn_data_url": "https://mirror.example/wmn.json"})
            assert _run(load(cfg))["sites"][0]["name"] == "Social1"
            n = len(calls)
            assert _run(load(cfg))["sites"][0]["name"] == "Social1"
            assert len(calls) == n                    # served from cache
        finally:
            if old is None:
                os.environ.pop("XDG_CACHE_HOME", None)
            else:
                os.environ["XDG_CACHE_HOME"] = old
    print("ok: WhatsMyName data pinned by SHA-256; custom URL cached")


# -- Maigret ---------------------------------------------------------------------
def _site(name, check="message", protection=(), similar=False):
    return types.SimpleNamespace(name=name, check_type=check, protection=list(protection),
                                 similar_search=similar, request_head_only=False)


class _FakeDB:
    def __init__(self, sites):
        self.sites = sites

    def ranked_sites_dict(self, **kw):
        return {s.name: s for s in self.sites}


def test_maigret_policy_filter():
    from footprint.modules.maigret_runner import select_sites
    db = _FakeDB([_site("Insta", protection=["tls_fingerprint"]), _site("Priv", protection=["login"]),
                  _site("Fuzzy", similar=True), _site("Ok"), _site("Cf", protection=["cf_js_challenge"])])
    sites, skipped = select_sites(db, Config())
    assert sorted(sites) == ["Cf", "Ok"]
    assert "bot protection" in skipped["Insta"] and "logged-in" in skipped["Priv"]
    assert "similar" in skipped["Fuzzy"]
    print("ok: maigret skips TLS-impersonation, login and similar-search sites")


def test_maigret_results_classified_and_pivoted():
    import footprint.modules.maigret_runner as mr

    def st(label, ids=None, tags=None):
        return types.SimpleNamespace(status=types.SimpleNamespace(name=label),
                                     ids_data=ids or {}, tags=tags or [])

    sites = {n: _site(n, check=c) for n, c in [("Keybase", "message"), ("Spot", "status_code"),
                                                ("Gone", "status_code"), ("Blocked", "message"),
                                                ("Nope", "message")]}
    results = {
        "Keybase": {"status": st("CLAIMED", {"fullname": "Jane Doe", "links": "[]"}, ["tech"]),
                    "http_status": 200, "url_user": "https://keybase.io/jdoe",
                    "ids_usernames": {"jane_d": "username", "12345": "vk_id"},
                    "ids_links": ["https://x.com/jane_tw", "https://keybase.io/jdoe"]},
        "Spot": {"status": st("CLAIMED"), "http_status": 200,
                 "url_user": "https://spot.example/user/jdoe"},
        "Gone": {"status": st("CLAIMED"), "http_status": 200,
                 "url_user": "https://gone.example/jdoe"},
        "Blocked": {"status": st("AVAILABLE"), "http_status": 403, "url_user": ""},
        "Nope": {"status": st("AVAILABLE"), "http_status": 404, "url_user": ""},
    }

    async def fake_search(username, s, config):
        return results

    def handler(req):
        if req.url.host == "spot.example":
            return httpx.Response(200, text="<html>user page</html>")
        return httpx.Response(302, headers={"Location": "/login?next=/jdoe"}) \
            if "login" not in req.url.path else httpx.Response(200, text="log in")

    saved = mr._load_db, mr._search, mr.select_sites
    mr._load_db = lambda: _FakeDB(list(sites.values()))
    mr._search = fake_search
    try:
        async def go():
            async with httpx.AsyncClient(transport=httpx.MockTransport(handler),
                                         follow_redirects=True) as c:
                return await mr.MaigretModule().run(Identifier(Kind.USERNAME, "jdoe"),
                                                    Config(), c)
        out = _run(go())
    finally:
        mr._load_db, mr._search, mr.select_sites = saved

    s = out[-1].data
    assert [x["site"] for x in s["found"]] == ["Keybase", "Spot"]
    assert s["absent_on"] == ["Nope"]
    assert s["inconclusive"] == ["Blocked", "Gone"]   # 403, and GET landed on /login
    kb = next(f for f in out if f.platform == "Keybase")
    assert kb.data["profile"]["fullname"] == "Jane Doe"
    pivots = {(d.value, d.source) for d in kb.discovered if d.kind == Kind.USERNAME}
    assert ("jane_d", "maigret") in pivots and ("jane_tw", "maigret:X") in pivots
    assert all(v != "12345" for v, _ in pivots)       # non-username ids not searched
    print("ok: maigret verdicts re-checked; extracted usernames + linked handles pivot")


# -- orchestrator bounds -----------------------------------------------------------
class _Fan(Module):
    """Seed username -> discovers 8 usernames with falling confidence."""
    name = "fan"
    accepts = frozenset({Kind.USERNAME})
    calls: list = []

    async def run(self, ident, config, http):
        type(self).calls.append(ident.value)
        if ident.value != "seed":
            return []
        conf = [0.9, 0.8, 0.7, 0.6, 0.5, 0.4, 0.2, 0.1]
        return [Finding(self.name, ident, "fan", 0.5, discovered=[
            Identifier(Kind.USERNAME, f"u{i}", self.name, c) for i, c in enumerate(conf)])]


def test_priority_caps_and_floor():
    _Fan.calls = []
    cfg = Config(max_usernames=4, min_pivot_confidence=0.3)
    r = _run(Orchestrator([_Fan()], cfg).run([Identifier(Kind.USERNAME, "seed")]))
    assert _Fan.calls == ["seed", "u0", "u1", "u2"]          # most confident first, cap 4
    notes = " ".join(x["reason"] for x in r.skipped if x["module"] == "engine")
    assert "max_usernames=4" in notes and "u3" in notes       # over the cap, listed
    assert "min_pivot_confidence=0.3" in notes and "u6" in notes  # below the floor
    print("ok: priority queue, max_usernames cap, min_pivot_confidence floor")


def test_confirmed_account_lifts_its_links_over_the_floor():
    email = "jane@example.com"
    sha = hashlib.sha256(email.encode()).hexdigest()

    class Profile(Module):
        name = "profile"
        accepts = frozenset({Kind.USERNAME})
        seen: list = []

        async def run(self, ident, config, http):
            type(self).seen.append(ident.value)
            if ident.value != "janedoe":
                return []
            return [Finding(self.name, ident, "profile", 0.3, url="https://p.example/janedoe",
                            platform="P", data={"avatar_hashes": [sha]},
                            discovered=[Identifier(Kind.USERNAME, "jane_alt", self.name, 0.18)])]

    class Local(Module):
        name = "local"
        accepts = frozenset({Kind.EMAIL})

        async def run(self, ident, config, http):
            return [Finding(self.name, ident, "lp", 0.5,
                            discovered=[Identifier(Kind.USERNAME, "janedoe", self.name, 0.5)])]

    Profile.seen = []
    r = _run(Orchestrator([Local(), Profile()], Config()).run([Identifier(Kind.EMAIL, email)]))
    assert Profile.seen == ["janedoe", "jane_alt"]   # 0.18 lifted to 0.85 by confirmation
    assert any(f.module == "correlate" for f in r.findings)
    print("ok: in-flight avatar confirmation lets a confirmed account's links be searched")


# -- accounts table ---------------------------------------------------------------
def test_accounts_table_merges_engines():
    email = Identifier(Kind.EMAIL, "jane@example.com")
    u = Identifier(Kind.USERNAME, "jdoe")
    r = RunResult(seeds=[email])
    r.findings += [
        Finding("whatsmyname", u, "x", 0.3, url="https://gitlab.com/jdoe", platform="GitLab"),
        Finding("maigret", u, "x", 0.3, url="https://gitlab.com/jdoe/", platform="GitLab"),
        Finding("correlate", email, "x", 0.95, url="https://gitlab.com/jdoe"),
        Finding("holehe", email, "x", 0.8, url="https://instagram.com", platform="instagram.com"),
        Finding("maigret", u, "x", 0.3, url="https://www.instagram.com/jdoe", platform="Instagram"),
        Finding("whatsmyname", u, "x", 0.3, url="https://keybase.io/jdoe", platform="Keybase"),
    ]
    rows = accounts(r)
    got = [(x["status"], x["platform"], x["modules"]) for x in rows]
    assert got == [
        ("CONFIRMED", "GitLab", ["whatsmyname", "maigret"]),
        ("EMAIL REGISTERED", "instagram.com", ["holehe"]),
        ("LEAD + email registered on site", "Instagram", ["maigret"]),
        ("LEAD", "Keybase", ["whatsmyname"]),
    ]
    md = to_markdown(r)
    assert "## Accounts found (4)" in md and "| CONFIRMED | GitLab |" in md
    print("ok: accounts table merges engines, ranks confirmed > email > leads")


def test_sherlock_steps_aside_for_maigret():
    import importlib.util as iu

    from footprint.modules.sherlock_runner import SherlockModule
    real = iu.find_spec
    iu.find_spec = lambda n, *a: object() if n in ("maigret", "sherlock_project") else real(n, *a)
    try:
        assert "maigret" in SherlockModule().skip_reason(Config())
        assert SherlockModule().skip_reason(Config(extra={"sherlock_enabled": True})) is None
    finally:
        iu.find_spec = real
    print("ok: sherlock steps aside when maigret is installed (opt back in)")


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print("\nall engine tests passed")
