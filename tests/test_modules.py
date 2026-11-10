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
    assert f and f[0].data["candidates"] == ["jane.doe", "janedoe"]  # +tag dropped, gmail dots
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
        "GitHub": {"status": st("CLAIMED"), "url_user": "https://www.github.com/jd"},
        "Reddit": {"status": st("AVAILABLE"), "url_user": None},
        "Medium": {"status": st("UNKNOWN"), "url_user": None},
        "Pinterest": {"status": st("WAF"), "url_user": None},
        "Twitter": {"status": st("ILLEGAL"), "url_user": None},
    }
    orig = sr._run_sherlock
    sr._run_sherlock = lambda u, c: fake
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


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print("\nall module tests passed")
