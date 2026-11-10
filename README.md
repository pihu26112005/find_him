# find_him — footprint auditor

A consent-gated OSINT engine that turns one identifier (email, username, domain,
or profile URL) into a confidence-scored report of what is **publicly**
discoverable about it — breaches, public profiles, linked accounts, leaked
metadata.

This is the defensible core of what paid "reverse email" sites
(behindtheemail.com, Epieos, OSINT Industries) sell. The key insight: **the data
is public.** Those sites mostly charge for convenience, aggregation, and a nice
UI over tools you can run yourself.

> **Scope, up front.** This tool audits an identifier you have standing over:
> your own, a consenting subject's, or an asset in an authorized security
> assessment. It is **not** a people-finder for unmasking or locating strangers.
> It ships with no IP-logger trap links and no face recognition — those are the
> stalking-tool half of this space and are left out on purpose. See
> [Legitimate use](#legitimate-use).

## How the paid sites actually work

There is no magic database. These services run many small public lookups in
parallel and feed the results back in:

1. **Account-existence checks** — many sites leak whether an email is registered
   via their signup / password-reset flow. Fan that out over ~120 sites and you
   learn where someone has accounts (this is `holehe`).
2. **Provider lookups** — Gravatar returns a public profile for an email hash;
   Google resolves a Gmail to account data (GHunt); GitHub exposes public
   profiles.
3. **Username pivoting** — a handle found in step 2 is checked across ~400 sites
   for public profile pages (`Sherlock` / `Maigret`).
4. **Enrichment APIs** — LinkedIn and job history almost never come from live
   scraping; they come from B2B data vendors who sell email→profile lookups.
5. **Breach data** — HIBP gives breach *names* ethically; shadier indexes resell
   the actual leaked records.
6. **Entity resolution** — deciding which hits are the same person (matching
   names, usernames, locations), with a confidence score on each link.

This repo implements 1–3, 5 and a conservative 6, with the hooks to add 4.

## Install

```bash
python3 -m venv .venv
.venv/bin/pip install -U pip setuptools wheel
.venv/bin/pip install -r requirements.txt                  # core: httpx + pyyaml
.venv/bin/pip install -r requirements-optional.txt         # holehe, sherlock, dnspython
cp config.example.yaml config.yaml                         # optional keys (gitignored)
```

Use a virtualenv: `holehe` builds from source and fails against old distro
setuptools. No API key is required — breach names come from the free
XposedOrNot API; an HIBP key is an optional extra.

## Use

```bash
# audit your own address
python -m footprint --basis own me@example.com

# consented subject, write JSON
python -m footprint --basis consent --reference CONSENT-2026-07 \
    subject@example.com --format json --out report.json

# authorized assessment, several seeds at once
python -m footprint --basis authorized --reference SOW-2026-14 \
    alice@target.com alicehandle target.com
```

A legitimate **basis** is required; `consent` and `authorized` also require a
`--reference`. Each run appends a line to `footprint-audit.log` with subjects
**hashed** (not plaintext). Modules whose API key / CLI tool isn't present are
skipped and listed in the report, never fatal.

## Architecture

```
seed identifier(s)
      │
      ▼
 authorization gate ──► append-only audit log (subjects hashed)
      │
      ▼
 orchestrator ──┐  async fan-out, per-module timeouts, depth-limited
      │         │  discovered identifiers fed back in (confidence decays)
      ▼         │
   modules ◄────┘  one public source each: gravatar, xposedornot, hibp,
      │            email_localpart, dns_email, github_user, holehe, sherlock
      ▼
 RunResult ──► report.py ──► Markdown / JSON (+ same-person signals)
```

- `footprint/orchestrator.py` — the fan-out engine (dedup, depth, confidence).
- `footprint/modules/` — one file per source; subclass `Module`.
- `footprint/authorization.py` — the basis gate + hashed audit log.
- `footprint/report.py` — conservative entity resolution + rendering.
- `.claude/skills/footprint-audit/SKILL.md` — the Claude skill: planning,
  workflow, and the full open-source tool catalog.

## Add a source

Subclass `Module`, declare which identifier `kinds` it `accepts`, return
`Finding`s carrying any `discovered` identifiers, and register it in
`orchestrator.default_modules()`. `footprint/modules/gravatar.py` is the
reference example (~60 lines).

## Modules

| module | input | source | key? | what it returns |
|--------|-------|--------|------|-----------------|
| `gravatar` | email | Gravatar API v3 (+ legacy JSON) | no | public profile, verified accounts |
| `xposedornot` | email | XposedOrNot | no | breach names, exposed data classes |
| `hibp` | email | Have I Been Pwned | paid | breach names, exposed data classes |
| `email_localpart` | email | (offline) | no | username candidates from the local part |
| `dns_email` | email/domain | DNS, DoH fallback | no | MX, mail provider, disposable domain |
| `holehe` | email | holehe library | no | sites with an account; masked recovery hints |
| `github_user` | username | GitHub REST API | optional | public profile fields |
| `gitlab_user` | username | GitLab REST API | no | public profile fields, linked socials |
| `sherlock` | username | sherlock library | no | public profile pages across ~480 sites |

Results are split three ways everywhere: **found**, **absent**, and
**inconclusive** (blocked, rate-limited, bot-walled). Inconclusive is never
reported as absent, and Sherlock/holehe verdicts are re-checked against the raw
responses because both tools are too trusting on their own (see the module
docstrings).

**Correlation.** After a run, every avatar served by Gravatar on a found
profile (GitLab, WordPress, Disqus, ...) is hash-compared with the seed
email(s). A match proves the account is registered with that email and is
reported under *Confirmed links*; the username and fields from that account are
upgraded from "lead" to "confirmed".

## Test

```bash
.venv/bin/python tests/test_offline.py   # engine logic, gate, report (no network)
.venv/bin/python tests/test_modules.py   # every module vs mocked HTTP/tools (no network)
```

## Legitimate use

Reverse-lookup / OSINT is dual-use. Keep it on the right side:

- **Do**: audit your own exposure; check a subject who consented; recon assets in
  an engagement you're authorized to assess; fraud/KYC with an audit trail.
- **Don't**: identify, locate, or monitor a specific person who hasn't consented
  and isn't in authorized scope. "Who is behind this account", unmasking an
  anonymous user, or finding someone from a photo is stalking/doxxing.

Profiling a person from their email engages GDPR, India's DPDP Act, CCPA and
similar — you need a lawful basis, and account-existence/scraping breach most
platforms' terms. The shippable product is a self-serve exposure checker (verify
address ownership, show the owner their own footprint) or a B2B fraud tool with
logging — which is the shape this engine is built in.
