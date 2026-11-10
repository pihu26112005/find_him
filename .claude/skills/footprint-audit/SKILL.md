---
name: footprint-audit
description: >
  Audit the PUBLIC digital footprint of an identifier (email, username, domain,
  or profile URL) and produce a confidence-scored report of what is exposed —
  breaches, public profiles, linked accounts, leaked metadata. Use for checking
  YOUR OWN exposure, a subject who has given consent, or an asset inside an
  authorized security assessment. Covers reverse-email / reverse-username /
  "who is behind this account" / OSINT reconnaissance / attack-surface and
  data-broker exposure questions. Does NOT covertly locate or de-anonymize an
  unknown person (no IP-logger trap links, no face recognition of strangers).
---

# Footprint Audit

This skill turns one identifier into a map of what is **publicly** discoverable
about it, using public sources and well-known open-source tools, and writes a
confidence-scored report. It is the defensible core of what paid "reverse email"
sites (behindtheemail, Epieos, OSINT Industries, SpiderFoot HX) sell: the data
is public; those sites mostly charge for convenience and aggregation.

The engine lives in this repo at `footprint/` (see `README.md`). This file tells
you — Claude — how to plan and run an audit responsibly.

## 0. Gate first — establish a legitimate basis (do this before anything else)

Before any lookup, confirm with the user which basis applies. If none does,
**stop and say so**; do not look the subject up.

| Basis | Meaning | What to require |
|-------|---------|-----------------|
| `own` | The user is auditing their own identifier | nothing extra |
| `consent` | The subject gave informed consent | a consent reference |
| `authorized` | Asset in an engagement the user is authorized to assess | engagement/SOW reference |

**Refuse** (politely, and offer the defensible alternative) when the goal is to
find, locate, unmask, monitor, or "get information on" a specific person who has
not consented and is not in scope of an authorized assessment — e.g. an ex, a
date, a stranger from a photo, an anonymous account the user wants named. That
is stalking/doxxing regardless of how it's phrased. The tell is targeting a
*person against their knowledge*, not auditing an *identifier you have standing
over*.

Hard lines, always:
- No IP-grabber / trap-link tooling (silently capturing someone's IP/location).
- No face-recognition identification of unknown people.
- No tools that redistribute leaked credentials (use HIBP's breach *names*, not
  dumps of passwords/phones).
- No scraping that needs a logged-in session or defeats access controls.

## 1. Plan the pivots

OSINT is a graph search: each identifier can reveal others, which you re-query.

```
email ──┬─ Gravatar profile ──► name, username, linked accounts, location
        ├─ XposedOrNot / HIBP ► breach names + exposed data classes
        ├─ holehe ────────────► which sites have an account for this email
        ├─ local part ────────► username candidate ("jane.doe91@" -> jane.doe91)
        └─ domain checks ─────► MX, mail provider, disposable?

username ─┬─ GitHub / GitLab ─► name, company, location, blog, linked socials
          └─ Sherlock/Maigret ► public profile pages on ~480 sites

found profiles ── Gravatar avatar hash == hash(seed email)? ──► confirmed link

name / url / linked accounts ──► feed back in, 1–2 more rounds, then stop
```

Rules of thumb:
- Depth 2 is plenty. Each extra round multiplies noise.
- Confidence decays as you pivot. A username *derived from* an email is less
  certainly the same person than the email itself. Keep the scores.
- Existence ≠ identity. "A `john92` profile exists on site X" does not prove it's
  the same John. Flag it as a lead, not a fact.

## 2. Run the engine

Setup once (virtualenv required — holehe won't build on old distro setuptools):

```bash
python3 -m venv .venv && .venv/bin/pip install -U pip setuptools wheel
.venv/bin/pip install -r requirements.txt -r requirements-optional.txt
```

Then (with `.venv/bin/python -m footprint` if the venv isn't activated):

```bash
# self-audit
python -m footprint --basis own me@example.com

# consented subject, JSON out
python -m footprint --basis consent --reference CONSENT-2026-07 \
    --operator "$(whoami)" subject@example.com --format json --out report.json

# authorized assessment, multiple seeds
python -m footprint --basis authorized --reference SOW-2026-14 \
    alice@target.com alicehandle target.com
```

The engine autodetects seed kind, fans out across configured modules, feeds
discoveries back in up to `max_depth`, and writes the report. Modules without
their key/tool are **skipped and listed**, not failed. Keys go in `config.yaml`
(copy `config.example.yaml`) or env vars `FOOTPRINT_HIBP_API_KEY`,
`FOOTPRINT_GITHUB_TOKEN`.

Every run appends an authorization line to `footprint-audit.log` (subjects
hashed, not plaintext). Don't disable this.

## 3. Interpret & resolve entities

The report groups findings by the identifier they're about and surfaces
"same-person signals" (a name/username seen from >1 source). When you write up
results for the user:
- Lead with **Confirmed links**: an account whose Gravatar avatar hash equals
  the hash of the seed email is provably registered with that email. For a
  self-audit this is also a finding to fix — uploading a custom avatar on that
  site removes the email hash from the public profile.
- Then the **strongest-confidence** items.
- Separate **confirmed** (subject published it: Gravatar, GitHub public profile,
  HIBP) from **leads** (a handle exists somewhere; same-person not proven).
- Say plainly when the result is *empty* — for a careful person with a personal
  address, little or nothing public is the expected, healthy outcome.
- Keep **inconclusive** separate from **absent**. holehe and sherlock mark
  blocked, rate-limited and bot-walled checks as inconclusive; report the count
  and never present them as "no account".
- A username found from the email's *local part* is a guess (confidence 0.5),
  so profiles found under it are leads until corroborated.
- For self-audit, end with concrete remediation (lock down profiles, rotate
  breached passwords, data-broker opt-outs).

## 4. Extending — add a module

Drop a `Module` subclass in `footprint/modules/`, declare `accepts` (which kinds
it queries) and `requires_config`, return `Finding`s with `discovered`
identifiers. Register it in `orchestrator.default_modules()`. Keep each module
single-source and public-only. See `footprint/modules/gravatar.py` as the model.

## 5. Tool catalog — what the paid sites are really using

All open-source or public-API. This is the honest answer to "how do they do it":

**Email → accounts / profile**
- **holehe** — email registered-or-not across ~120 sites (public reset/signup
  responses). The engine shells out to it.
- **Have I Been Pwned** — breach exposure by email (names + data classes). Key.
- **XposedOrNot** — free, keyless, open-source breach checker (names +
  metadata). The engine's default breach source.
- **Gravatar** — public profile + linked accounts by email hash. No key.
- **GHunt** — for Gmail: Google account name, photo, Maps reviews, public
  calendar (needs Google cookies; add as an opt-in module).
- **EmailRep / emailrep.io** — reputation/metadata for an address. Key.

**Username → profiles**
- **Sherlock** — username across ~400 sites. Shelled out by the engine.
- **Maigret** — like Sherlock, richer (extracts profile data, tags). Good upgrade.
- **WhatsMyName** — the community data set those two draw from.

**Name / phone / general aggregation**
- **SpiderFoot** — the big orchestrator: 200+ modules, email/name/domain/IP,
  has its own API you can call instead of re-building fan-out. Your bookmark.
- **recon-ng** — modular recon framework (Metasploit-style) for the same.
- **theHarvester** — emails/subdomains/hosts for a *domain* (recon, not people).

**Domain / infra (for custom-domain emails)**
- **whois / RDAP**, **crt.sh** (cert transparency), **dnspython** (MX/DNS),
  **Wayback/CDX** for historical pages.

**Breach/leak indexes (higher legal risk — breach *names* only, don't resell)**
- **DeHashed**, **LeakCheck**, **IntelX** — paid, index leaked records. The
  engine deliberately uses HIBP (names) instead of these (dumps).

**Face / image / IP (explicitly out of scope for this skill)**
- FaceCheck.ID, PimEyes (stranger face ID), IP-logger trap links — do **not**
  wire these in. They're the stalking-tool half of the space.

## 6. Legal footing (tell the user, don't paper over)

Profiling a person from their email engages GDPR, India's DPDP Act, CCPA, etc.;
you need a lawful basis. Account-existence checks and scraping breach most
platforms' ToS, and LinkedIn/Meta litigate. The shippable product is: verify the
user owns the address (confirmation link) then show *their own* exposure, or sell
to businesses for fraud/KYC with an audit trail — which is exactly the shape of
this engine.
