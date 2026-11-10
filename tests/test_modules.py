"""Offline module tests: real module code against mocked HTTP / mocked tools.

No network. Each test feeds a module canned responses and checks it parses and,
crucially, CLASSIFIES correctly -- "couldn't check" must never be reported as
"not found".

Run:  python -m pytest -q tests   (or: python tests/test_modules.py)
"""
from __future__ import annotations

import asyncio
import hashlib
import sys
import types
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import httpx

from footprint.config import Config
from footprint.models import Identifier, Kind
from footprint.modules.dns_email import DnsEmailModule, _doh_mx
from footprint.modules.email_localpart import EmailLocalPartModule
from footprint.modules.github_user import GithubUserModule
from footprint.modules.gravatar import GravatarModule
from footprint.modules.xposedornot import XposedOrNotModule

EMAIL = Identifier(Kind.EMAIL, "jane.doe+news@gmail.com")


def _client(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def _run(coro):
    return asyncio.run(coro)


# -- email_localpart ------------------------------------------------------------
def test_localpart_candidates():
    f = _run(EmailLocalPartModule().run(EMAIL, Config(), None))
    # +tag dropped; gmail ignores dots (same mailbox); separator swaps rank lower
    assert f and f[0].data["candidates"] == ["jane.doe", "janedoe", "jane_doe", "jane-doe"]
    conf = {d.value: d.confidence for d in f[0].discovered}
    assert conf["jane.doe"] == conf["janedoe"] == 0.5 and conf["jane_doe"] == 0.4
    assert all(d.kind == Kind.USERNAME and d.confidence <= 0.5 for d in f[0].discovered)
    assert _run(EmailLocalPartModule().run(Identifier(Kind.EMAIL, "info@acme.com"),
                                           Config(), None)) == []
    print("ok: localpart pivot (+tag, gmail dots, generic mailbox skipped)")


# -- gravatar -------------------------------------------------------------------
def test_gravatar_v3_profile_and_404():
    sha = hashlib.sha256(b"jane.doe+news@gmail.com").hexdigest()

    def found(req):
        assert req.url.host == "api.gravatar.com" and sha in req.url.path
        return httpx.Response(200, json={
            "display_name": "Jane Doe", "location": "Pune",
            "profile_url": "https://gravatar.com/janedoe",
            "verified_accounts": [
                {"service_label": "GitHub", "url": "https://github.com/janedoe"},
                {"service_label": "Hidden", "url": "https://x.com/h", "is_hidden": True},
            ]})

    async def go(h):
        async with _client(h) as c:
            return await GravatarModule().run(EMAIL, Config(), c)

    f = _run(go(found))
    assert f and f[0].data["display_name"] == "Jane Doe"
    assert [a["service"] for a in f[0].data["verified_accounts"]] == ["GitHub"]  # hidden skipped
    kinds = {(d.kind, d.value) for d in f[0].discovered}
    assert (Kind.USERNAME, "janedoe") in kinds and (Kind.NAME, "Jane Doe") in kinds

    assert _run(go(lambda req: httpx.Response(404))) == []  # authoritative: no profile
    print("ok: gravatar v3 parse, hidden accounts skipped, 404 -> nothing")


def test_gravatar_falls_back_to_legacy():
    def h(req):
        if req.url.host == "api.gravatar.com":
            return httpx.Response(429)  # v3 rate-limited -> legacy
        return httpx.Response(200, json={"entry": [{"displayName": "J", "preferredUsername": "jd"}]})

    async def go():
        async with _client(h) as c:
            return await GravatarModule().run(EMAIL, Config(), c)

    f = _run(go())
    assert f and f[0].data["username"] == "jd"
    print("ok: gravatar legacy fallback")


# -- xposedornot ----------------------------------------------------------------
def test_xposedornot_analytics_and_none():
    def breached(req):
        return httpx.Response(200, json={"ExposedBreaches": {"breaches_details": [
            {"breach": "Canva", "domain": "canva.com", "xposed_date": "2019",
             "xposed_data": "Email addresses;Names;Passwords", "password_risk": "hardtocrack"},
        ]}})

    async def go(h):
        async with _client(h) as c:
            return await XposedOrNotModule().run(EMAIL, Config(), c)

    f = _run(go(breached))
    assert f[0].data["breaches"] == ["Canva"]
    assert f[0].data["exposed_data_classes"] == ["Email addresses", "Names", "Passwords"]

    f = _run(go(lambda req: httpx.Response(404, json={"Error": "Not found"})))
    assert f[0].title == "No known breaches"
    print("ok: xposedornot analytics parse + not-found")


def test_xposedornot_falls_back_to_check_email():
    def h(req):
        if "breach-analytics" in req.url.path:
            return httpx.Response(500)
        return httpx.Response(200, json={"breaches": [["Canva", "Dubsmash"]]})

    async def go():
        async with _client(h) as c:
            return await XposedOrNotModule().run(EMAIL, Config(), c)

    assert _run(go())[0].data["breaches"] == ["Canva", "Dubsmash"]
    print("ok: xposedornot check-email fallback")


# -- dns ------------------------------------------------------------------------
def test_doh_mx_semantics():
    async def go(h):
        async with _client(h) as c:
            return await _doh_mx("gmail.com", c)

    ok = _run(go(lambda r: httpx.Response(200, json={"Status": 0, "Answer": [
        {"type": 15, "data": "10 alt1.gmail-smtp-in.l.google.com."},
        {"type": 15, "data": "5 gmail-smtp-in.l.google.com."}]})))
    assert ok == ["alt1.gmail-smtp-in.l.google.com", "gmail-smtp-in.l.google.com"]
    assert _run(go(lambda r: httpx.Response(200, json={"Status": 3}))) == []    # NXDOMAIN
    assert _run(go(lambda r: httpx.Response(502))) is None                      # unknown
    print("ok: DoH MX parse; NXDOMAIN=[] vs failure=None")


def test_dns_failure_is_unknown_not_no_mx(monkeypatch=None):
    import footprint.modules.dns_email as dm
    orig = dm._dnspython_mx
    dm._dnspython_mx = lambda d: None  # plain DNS unavailable
    try:
        async def go():
            async with _client(lambda r: httpx.Response(503)) as c:  # DoH down too
                return await DnsEmailModule().run(EMAIL, Config(), c)
        f = _run(go())
    finally:
        dm._dnspython_mx = orig
    assert "has_mx" not in f[0].data and "unknown" in f[0].data["mx_records"]
    print("ok: failed DNS reported as unknown, not 'no MX'")


# -- github ---------------------------------------------------------------------
def test_github_403_is_error_not_absent():
    async def go(h):
        async with _client(h) as c:
            return await GithubUserModule().run(Identifier(Kind.USERNAME, "jd"), Config(), c)

    assert _run(go(lambda r: httpx.Response(404))) == []
    try:
        _run(go(lambda r: httpx.Response(403, json={"message": "rate limited"})))
        raise AssertionError("403 must raise")
    except RuntimeError as e:
        assert "403" in str(e)
    print("ok: github 404=absent, 403=error")


# -- holehe classification (library mocked) ------------------------------------
def test_holehe_classification():
    import footprint.modules.holehe_runner as hr

    def site(name, **res):
        async def fn(email, client, out):
            out.append({"name": name, "domain": f"{name}.com", "method": "register",
                        "rateLimit": False, "exists": False, "emailrecovery": None,
                        "phoneNumber": None, "others": None, **res})
        fn.__name__ = name
        return fn

    fake_mods = {}
    for name, res in {"insta": {"exists": True, "phoneNumber": "+91 ****42"},
                      "spot": {}, "snap": {"rateLimit": True}, "adobe": {"exists": True}}.items():
        fake_mods[f"holehe.modules.cat.{name}"] = types.SimpleNamespace(**{name: site(name, **res)})

    core = types.ModuleType("holehe.core")
    core.import_submodules = lambda pkg: fake_mods

    async def launch_module(fn, email, client, out):
        await fn(email, client, out)
    core.launch_module = launch_module

    saved = sys.modules.get("holehe.core")
    sys.modules["holehe.core"] = core
    try:
        out = _run(hr.HoleheModule().run(EMAIL, Config(), None))
    finally:
        if saved is not None:
            sys.modules["holehe.core"] = saved
        else:
            sys.modules.pop("holehe.core", None)

    summary = out[-1].data
    assert summary["registered_on"] == ["insta.com"]
    assert summary["not_registered_on"] == ["spot.com"]
    assert summary["inconclusive"] == ["snap.com"]          # rate-limited != absent
    assert summary["password_recovery_modules_skipped"] == ["adobe"]  # -NP default
    assert summary["recovery_hints"][0]["phoneNumber"] == "+91 ****42"
    assert out[0].title == "Account registered on insta.com"
    print("ok: holehe registered / not / inconclusive split, recovery modules skipped")


# -- sherlock classification (library mocked) ----------------------------------
def test_sherlock_classification():
    import footprint.modules.sherlock_runner as sr

    def st(label):
        return types.SimpleNamespace(status=types.SimpleNamespace(name=label))

    fake = {
        "GitHub": {"status": st("CLAIMED"), "url_user": "https://www.github.com/jd",
                   "http_status": 200, "response_text": b"<html>jd's profile</html>"},
        "Reddit": {"status": st("AVAILABLE"), "url_user": None},
        "Medium": {"status": st("UNKNOWN"), "url_user": None},
        "Pinterest": {"status": st("WAF"), "url_user": None},
        "Twitter": {"status": st("ILLEGAL"), "url_user": None},
    }
    orig = sr._run_sherlock
    sr._run_sherlock = lambda u, c: (fake, {})
    try:
        out = _run(sr.SherlockModule().run(Identifier(Kind.USERNAME, "jd", confidence=0.5),
                                           Config(), None))
    finally:
        sr._run_sherlock = orig

    d = out[-1].data
    assert [x["site"] for x in d["found"]] == ["GitHub"]
    assert d["absent_on"] == ["Reddit"]
    assert d["inconclusive"] == ["Medium", "Pinterest"]  # WAF/unknown != absent
    assert d["handle_not_valid_on"] == ["Twitter"]
    assert out[0].confidence == 0.3  # lead confidence scales with the handle's own
    print("ok: sherlock claimed / available / inconclusive / illegal split")


def test_sherlock_distrusts_blocks_and_bot_walls():
    from footprint.modules.sherlock_runner import avatar_hashes, classify

    assert classify("AVAILABLE", 404, b"Not Found") == "absent"
    assert classify("AVAILABLE", 403, b"{}") == "inconclusive"            # npm/GitHub case
    assert classify("AVAILABLE", 429, b"") == "inconclusive"
    assert classify("AVAILABLE", 503, b"") == "inconclusive"
    assert classify("CLAIMED", 200, b"<html>profile</html>") == "found"
    assert classify("CLAIMED", 200,
                    b"<title>Security Verification</title> verify-human") == "inconclusive"
    assert classify("CLAIMED", 200, b"<title>Just a moment...</title>") == "inconclusive"
    assert classify("ILLEGAL", "?", "") == "not_valid"
    assert classify("WAF", "?", "") == "inconclusive"
    sha = hashlib.sha256(b"x@y.com").hexdigest()
    assert avatar_hashes(f'"avatar_url":"https://secure.gravatar.com/avatar/{sha}?s=80"'
                         .encode()) == [sha]
    print("ok: sherlock bot walls / 403 / 429 / 5xx downgraded to inconclusive")


def test_sherlock_head_hits_are_rechecked_with_get():
    import footprint.modules.sherlock_runner as sr

    def st(label):
        return types.SimpleNamespace(status=types.SimpleNamespace(name=label))

    sha = hashlib.sha256(b"jane.doe@gmail.com").hexdigest()
    head_only = {"status": st("CLAIMED"), "http_status": 200, "response_text": ""}
    fake = {"Apple": {**head_only, "url_user": "https://apple.example/forums/profile/jd"},
            "Shop": {**head_only, "url_user": "https://shop.example/u/jd"},
            "Forum": {**head_only, "url_user": "https://forum.example/u/jd"}}
    sites = {"Apple": {"url": "https://apple.example/forums/profile/{}"},
             "Shop": {"url": "https://shop.example/u/{}"},
             "Forum": {"url": "https://forum.example/u/{}"}}

    def handler(req):
        if req.url.host == "apple.example" and "verify-human" not in req.url.path:
            return httpx.Response(302, headers={"Location": "/verify-human/verify.html"})
        if req.url.host == "apple.example":
            return httpx.Response(200, text="<title>Security Verification</title>")
        if req.url.host == "shop.example":
            return httpx.Response(302, headers={"Location": "/login?next=/u/jd"})
        if req.url.host == "forum.example":
            return httpx.Response(200, text=f'<img src="https://www.gravatar.com/avatar/{sha}">')
        return httpx.Response(200, text="")  # /login page

    orig = sr._run_sherlock
    sr._run_sherlock = lambda u, c: (fake, sites)
    try:
        async def go():
            async with httpx.AsyncClient(transport=httpx.MockTransport(handler),
                                         follow_redirects=True) as c:
                return await sr.SherlockModule().run(Identifier(Kind.USERNAME, "jd"),
                                                     Config(), c)
        out = _run(go())
    finally:
        sr._run_sherlock = orig

    d = out[-1].data
    assert [x["site"] for x in d["found"]] == ["Forum"]
    assert d["inconclusive"] == ["Apple", "Shop"]          # bot wall + login redirect
    assert any("walled" in x for x in d["verdicts_downgraded_to_inconclusive"])
    assert out[0].data["avatar_hashes"] == [sha]           # hash taken from the GET body
    print("ok: HEAD-only hits re-checked with GET (bot wall, login redirect, avatar)")


def test_holehe_swallowed_errors_are_inconclusive():
    import footprint.modules.holehe_runner as hr

    async def blip(email, client, out):  # upstream bug: error reported as "not registered"
        try:
            await client.post("https://blip.example/signup")
        except Exception:
            out.append({"name": "blip", "domain": "blip.fm", "rateLimit": False, "exists": False})

    async def diigo(email, client, out):  # upstream bug: appends twice on failure
        for _ in range(2):
            out.append({"name": "diigo", "domain": "diigo.com", "rateLimit": True, "exists": False})

    async def clean(email, client, out):  # answers normally: not registered
        r = await client.get("https://clean.example/check")
        out.append({"name": "clean", "domain": "clean.example", "rateLimit": False,
                    "exists": r.json()["taken"]})

    def handler(req):
        if req.url.host == "blip.example":
            raise httpx.ConnectError("blocked", request=req)
        return httpx.Response(200, json={"taken": False})

    fake_mods = {f"holehe.modules.cat.{n}": types.SimpleNamespace(**{n: f})
                 for n, f in {"blip": blip, "diigo": diigo, "clean": clean}.items()}
    core = types.ModuleType("holehe.core")
    core.import_submodules = lambda pkg: fake_mods

    async def launch_module(fn, email, client, out):
        await fn(email, client, out)
    core.launch_module = launch_module

    saved_core, saved_make = sys.modules.get("holehe.core"), hr._make_client
    sys.modules["holehe.core"] = core
    hr._make_client = lambda c: hr._RecordingClient(transport=httpx.MockTransport(handler))
    try:
        out = _run(hr.HoleheModule().run(EMAIL, Config(), None))
    finally:
        hr._make_client = saved_make
        if saved_core is not None:
            sys.modules["holehe.core"] = saved_core
        else:
            sys.modules.pop("holehe.core", None)

    s = out[-1].data
    assert s["inconclusive"] == ["blip.fm", "diigo.com"]   # not "not registered"
    assert s["not_registered_on"] == ["clean.example"]
    assert s["checked"] == 3                               # diigo's double entry merged
    print("ok: holehe swallowed errors -> inconclusive; duplicate entries merged")


def test_dns_lying_resolver_needs_doh_confirmation():
    import footprint.modules.dns_email as dm
    orig = dm._dnspython_mx
    dm._dnspython_mx = lambda d: []  # sandbox resolver: NXDOMAIN for everything
    try:
        async def go(h):
            async with _client(h) as c:
                return await DnsEmailModule().run(EMAIL, Config(), c)
        down = _run(go(lambda r: httpx.Response(503)))
        up = _run(go(lambda r: httpx.Response(200, json={"Status": 0, "Answer": [
            {"type": 15, "data": "5 gmail-smtp-in.l.google.com."}]})))
    finally:
        dm._dnspython_mx = orig
    assert "has_mx" not in down[0].data and "unknown" in down[0].data["mx_records"]
    assert down[0].data["free_mail_provider"] == "Google (Gmail)"
    assert up[0].data["has_mx"] is True and up[0].data["mail_provider"].startswith("Google")
    # the gmail.com domain it surfaced is not re-checked (no duplicate finding)
    dom = Identifier(Kind.DOMAIN, "gmail.com", source="dns_email")
    assert _run(DnsEmailModule().run(dom, Config(), None)) == []
    print("ok: negative plain-DNS answer needs DoH; free-mail provider offline; no dup")


def test_gitlab_user_profile():
    from footprint.modules.gitlab_user import GitlabUserModule

    def h(req):
        if req.url.path == "/api/v4/users":
            return httpx.Response(200, json=[{"id": 7, "username": "jd", "name": "Jane",
                                              "web_url": "https://gitlab.com/jd"}])
        return httpx.Response(200, json={"id": 7, "username": "jd", "name": "Jane",
                                         "location": "Pune", "linkedin": "jane-doe",
                                         "bio": "", "web_url": "https://gitlab.com/jd"})

    async def go(handler):
        async with _client(handler) as c:
            return await GitlabUserModule().run(Identifier(Kind.USERNAME, "jd"), Config(), c)

    f = _run(go(h))
    assert f[0].data["location"] == "Pune" and "bio" not in f[0].data  # empty dropped
    urls = {d.value for d in f[0].discovered if d.kind == Kind.URL}
    assert "https://www.linkedin.com/in/jane-doe" in urls
    assert _run(go(lambda r: httpx.Response(200, json=[]))) == []

    def detail_forbidden(req):  # gitlab.com without a token
        if req.url.path == "/api/v4/users":
            return httpx.Response(200, json=[{"id": 7, "username": "jd", "name": "Jane"}])
        return httpx.Response(403, json={"message": "403 Forbidden - Not authorized!"})
    note = _run(go(detail_forbidden))[0].data["profile_details"]
    assert "HTTP 403" in note and "not checked" in note
    try:
        _run(go(lambda r: httpx.Response(403)))
        raise AssertionError("403 must raise")
    except RuntimeError:
        pass
    print("ok: gitlab_user profile, linkedin url, empty=absent, 403=error")


def test_gravatar_hash_correlation():
    from footprint.models import Finding, RunResult
    from footprint.orchestrator import correlate_gravatar

    email = "jane.doe@gmail.com"
    sha = hashlib.sha256(email.encode()).hexdigest()
    user = Identifier(Kind.USERNAME, "janedoe", "email_localpart", 0.5)
    r = RunResult(seeds=[Identifier(Kind.EMAIL, email)])
    r.identifiers += [Identifier(Kind.EMAIL, email), user]
    r.findings.append(Finding("gitlab_user", user, "Public GitLab profile @janedoe", 0.5,
                              url="https://gitlab.com/janedoe",
                              data={"avatar_url": f"https://secure.gravatar.com/avatar/{sha}"}))
    r.findings.append(Finding("sherlock", user, "Handle on GitLab", 0.3,
                              url="https://gitlab.com/janedoe/",
                              data={"avatar_hashes": [sha]}))
    r.findings.append(Finding("sherlock", user, "Handle elsewhere", 0.3,
                              data={"avatar_hashes": ["0" * 64]}))  # someone else
    correlate_gravatar(r)

    links = [f for f in r.findings if f.module == "correlate"]
    assert len(links) == 1                          # same account from 2 modules -> 1 link
    assert r.findings[0].confidence == 0.95 and r.findings[1].confidence == 0.95
    assert r.findings[2].confidence == 0.3          # non-matching hash untouched
    assert next(i for i in r.identifiers if i.kind == Kind.USERNAME).confidence == 0.9

    # fields a confirmed account published inherit confidence
    name = Identifier(Kind.NAME, "Jane", "gitlab_user", 0.42)
    r2 = RunResult(seeds=[Identifier(Kind.EMAIL, email)])
    r2.identifiers += [Identifier(Kind.EMAIL, email), name]
    r2.findings.append(Finding("gitlab_user", user, "GitLab", 0.5, discovered=[name],
                               data={"avatar_url": f"https://gravatar.com/avatar/{sha}"}))
    correlate_gravatar(r2)
    assert next(i for i in r2.identifiers if i.kind == Kind.NAME).confidence == 0.85
    print("ok: gravatar hash correlation confirms account, dedupes, upgrades username")


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print("\nall module tests passed")
