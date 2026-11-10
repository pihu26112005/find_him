"""footprint — a consent-gated OSINT footprint auditor engine.

This package turns a seed identifier (your own email, a consenting subject's
username, or an asset inside an authorized assessment) into a confidence-scored
report of what is publicly exposed about it, using only public sources and
well-known open-source tools.

It deliberately does NOT include covert tracking (IP-logger trap links),
face-recognition identification of unknown people, or any technique that
locates a specific individual without their knowledge. See README.md.
"""

__version__ = "0.1.0"
