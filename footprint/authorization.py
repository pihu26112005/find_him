"""The legitimate-basis gate.

This is the part that keeps the tool on the right side of the line. Before any
lookups run, the operator must assert *why* they are allowed to audit this
subject. The assertion and a hash of the subject are written to an append-only
audit log. This does not technically prevent misuse, but it (a) forces an
explicit, logged choice, (b) makes the tool unattractive for casual stalking,
and (c) gives organizations a paper trail for DPIA / compliance.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path


class Basis:
    #: You are auditing your own identifiers.
    OWN = "own"
    #: The subject has given informed consent to be audited.
    CONSENT = "consent"
    #: Part of a security assessment you are contractually authorized to run.
    AUTHORIZED = "authorized"

    ALL = {OWN, CONSENT, AUTHORIZED}
    HELP = {
        OWN: "your own email/username/domain",
        CONSENT: "a subject who has given informed consent",
        AUTHORIZED: "an asset inside an engagement you are authorized to assess",
    }


class AuthorizationError(Exception):
    pass


@dataclass
class Authorization:
    basis: str
    reference: str  # consent record id, engagement/SOW ref, or "self"
    operator: str

    def validate(self) -> None:
        if self.basis not in Basis.ALL:
            raise AuthorizationError(
                f"unknown basis {self.basis!r}; must be one of {sorted(Basis.ALL)}"
            )
        if self.basis in (Basis.CONSENT, Basis.AUTHORIZED) and not self.reference.strip():
            raise AuthorizationError(
                f"basis '{self.basis}' requires --reference "
                f"(a consent record id or engagement/authorization reference)"
            )


def record(auth: Authorization, seeds: list[str], log_path: str | Path) -> None:
    """Append one tamper-evident-ish line to the audit log.

    Subjects are stored as salted hashes, not plaintext, so the log itself is
    not a new pile of personal data. The salt is the basis+reference, so the
    same subject under the same authorization is still correlatable for review.
    """
    auth.validate()
    log = Path(log_path)
    log.parent.mkdir(parents=True, exist_ok=True)
    salt = f"{auth.basis}:{auth.reference}".encode()
    entry = {
        "ts": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "operator": auth.operator,
        "basis": auth.basis,
        "reference": auth.reference,
        "subjects": [
            hashlib.sha256(salt + s.strip().lower().encode()).hexdigest()[:16]
            for s in seeds
        ],
        "tool": "footprint",
    }
    with log.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
