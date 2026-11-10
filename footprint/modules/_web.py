"""Shared helpers for the username engines (sherlock, maigret, WhatsMyName).

One place decides when an HTTP answer can be trusted, so every engine applies
the same rules:

  * 401/403/407/429 and 5xx are blocks, rate limits or outages -- never proof
    that an account is absent (or present).
  * bot walls / interstitials (Cloudflare challenge, "Security Verification",
    login redirects) are inconclusive, even when they come back as 200.
  * a hit backed only by a status code (HEAD request, no body) is re-fetched
    once with GET before it is believed.

Also: Gravatar-hash extraction (for correlation) and profile-URL -> handle
parsing (for pivoting from links found on profiles).
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

BLOCKED_STATUSES = frozenset({401, 403, 407, 429})

# Markers of bot walls / interstitials / policy blocks (matched lowercase).
WALL_MARKERS = (
    "just a moment...",                     # Cloudflare challenge
    "attention required! | cloudflare",
    "/cdn-cgi/challenge-platform",
    "checking your browser",
    "security verification",                # Apple and others
    "verify-human",
    "_incapsula_resource",                  # Imperva
    "px-captcha",                           # PerimeterX
    "ddos protection by",
    "this github api path is not available",  # sandboxed GitHub proxy policy
)

# A hit whose GET lands on one of these paths is a soft 404 / wall.
WALL_URL_MARKERS = ("verify-human", "captcha", "/challenge", "/login", "/signin",
                    "/sign_in", "/sign-in", "/auth/", "/accounts/login")

# Same UA sherlock sends, so re-checks see what the original request saw.
UA = "Mozilla/5.0 (X11; Linux x86_64; rv:129.0) Gecko/20100101 Firefox/129.0"

_GRAVATAR_RE = re.compile(r"gravatar\.com/avatar/([0-9a-f]{64}|[0-9a-f]{32})", re.I)


def page_text(raw) -> str:
    if isinstance(raw, bytes):
        return raw[:400_000].decode("utf-8", errors="replace")
    return str(raw or "")[:400_000]


def is_blocked_status(status) -> bool:
    return isinstance(status, int) and (status in BLOCKED_STATUSES or status >= 500)


def is_walled(text: str, final_url: str = "") -> bool:
    t = text.lower()
    u = final_url.lower()
    return any(m in t for m in WALL_MARKERS) or any(m in u for m in WALL_URL_MARKERS)


def classify(label: str, http_status, response_text) -> str:
    """Map an engine's CLAIMED/AVAILABLE/... + raw response to a verdict:
    found / absent / not_valid / inconclusive."""
    walled = is_walled(page_text(response_text))
    blocked = is_blocked_status(http_status)
    if label == "CLAIMED":
        return "inconclusive" if (walled or blocked) else "found"
    if label == "AVAILABLE":
        return "inconclusive" if (walled or blocked) else "absent"
    if label == "ILLEGAL":
        return "not_valid"
    return "inconclusive"  # UNKNOWN, WAF, anything new


def avatar_hashes(response_text) -> list[str]:
    return sorted({h.lower() for h in _GRAVATAR_RE.findall(page_text(response_text))})


async def verify_hit(http, url: str) -> tuple[str, str]:
    """GET a hit that had no body to inspect. Returns (verdict, page text),
    verdict one of ok / walled / blocked / gone."""
    try:
        r = await http.get(url, headers={"User-Agent": UA}, follow_redirects=True)
    except Exception:
        return "blocked", ""
    text = r.text[:400_000]
    if is_walled(text, str(r.url)):
        return "walled", text
    if is_blocked_status(r.status_code):
        return "blocked", text
    if r.status_code >= 400:
        return "gone", text
    return "ok", text


# --- profile URL -> (platform, handle) --------------------------------------
# (platform, host regex, path regex capturing the handle)
_PROFILE_PATTERNS = [
    ("Instagram", r"(?:www\.)?instagram\.com", r"/([A-Za-z0-9._]{1,30})/?"),
    ("X", r"(?:www\.|mobile\.)?(?:twitter|x)\.com", r"/@?([A-Za-z0-9_]{1,15})/?"),
    ("Facebook", r"(?:www\.|m\.)?facebook\.com", r"/([A-Za-z0-9.]{5,50})/?"),
    ("TikTok", r"(?:www\.)?tiktok\.com", r"/@([A-Za-z0-9._]{2,24})/?"),
    ("YouTube", r"(?:www\.|m\.)?youtube\.com", r"/(?:@|c/|user/)([A-Za-z0-9._-]{3,100})/?"),
    ("GitHub", r"(?:www\.)?github\.com", r"/([A-Za-z0-9-]{1,39})/?"),
    ("GitLab", r"(?:www\.)?gitlab\.com", r"/([A-Za-z0-9_.-]{2,255})/?"),
    ("LinkedIn", r"(?:[a-z]{2,3}\.|www\.)?linkedin\.com", r"/in/([A-Za-z0-9_-]{3,100})/?"),
    ("Reddit", r"(?:www\.|old\.)?reddit\.com", r"/(?:user|u)/([A-Za-z0-9_-]{3,20})/?"),
    ("Telegram", r"(?:t|telegram)\.me", r"/([A-Za-z0-9_]{5,32})/?"),
    ("Pinterest", r"(?:[a-z]{2}\.|www\.)?pinterest\.[a-z.]+", r"/([A-Za-z0-9_]{3,30})/?"),
    ("Threads", r"(?:www\.)?threads\.(?:net|com)", r"/@([A-Za-z0-9._]{1,30})/?"),
    ("Medium", r"(?:www\.)?medium\.com", r"/@([A-Za-z0-9._-]{1,50})/?"),
    ("Twitch", r"(?:www\.)?twitch\.tv", r"/([A-Za-z0-9_]{4,25})/?"),
    ("SoundCloud", r"(?:www\.)?soundcloud\.com", r"/([A-Za-z0-9_-]{3,25})/?"),
    ("Snapchat", r"(?:www\.)?snapchat\.com", r"/(?:add/|@)([A-Za-z0-9._-]{3,15})/?"),
    ("DEV", r"dev\.to", r"/([A-Za-z0-9_]{2,30})/?"),
    ("LeetCode", r"(?:www\.)?leetcode\.com", r"/(?:u/)?([A-Za-z0-9_-]{3,30})/?"),
    ("Codeforces", r"(?:www\.)?codeforces\.com", r"/profile/([A-Za-z0-9_.-]{3,24})/?"),
    ("Keybase", r"keybase\.io", r"/([A-Za-z0-9_]{2,16})/?"),
]
_COMPILED = [(p, re.compile(h + r"\Z", re.I), re.compile(pt + r"\Z")) for p, h, pt in _PROFILE_PATTERNS]

# First path segments that are site sections, not users.
_RESERVED = {
    "about", "accounts", "apps", "auth", "blog", "business", "c", "careers", "channel",
    "collections", "company", "contact", "contest", "dashboard", "developers", "direct",
    "discuss", "download", "enterprise", "events", "explore", "features", "feed", "groups",
    "hashtag", "help", "home", "home.php", "i", "intent", "issues", "jobs", "join", "legal",
    "login", "marketplace", "messages", "new", "notifications", "orgs", "p", "pages",
    "policies", "pricing", "privacy", "problems", "problemset", "profile.php", "pulls", "r",
    "reel", "reels", "results", "school", "search", "security", "settings", "share",
    "sharer", "sharer.php", "signup", "site", "sponsors", "status", "stories", "studyplan",
    "submissions", "tag", "tags", "team", "terms", "topics", "tos", "trending", "u", "user",
    "watch", "web",
}


def handle_from_url(url: str) -> tuple[str, str] | None:
    """'https://x.com/jane_doe' -> ('X', 'jane_doe'); None for non-profile URLs."""
    try:
        p = urlparse(url if "://" in url else "https://" + url)
    except ValueError:
        return None
    host = (p.hostname or "").lower()
    for platform, host_re, path_re in _COMPILED:
        if host_re.match(host):
            m = path_re.match(p.path or "/")
            if m and m.group(1).lower() not in _RESERVED:
                return platform, m.group(1)
            return None
    return None
