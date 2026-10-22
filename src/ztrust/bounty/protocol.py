"""Commit-reveal scheme that makes bounty claims front-running resistant.

1. The researcher computes ``commitment = SHA-256(salt_hex ":" report_bytes)``
   locally and submits *only* the commitment plus a shielded payout address.
   The server timestamps it — nobody, including the maintainer, learns the content.
2. Later the researcher reveals ``(report, salt)``. The server recomputes the hash.
3. When two reports describe the same issue, the one with the earlier
   commitment wins, even if it was revealed second.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets

COMMITMENT_RE = re.compile(r"^[0-9a-f]{64}$")
SALT_RE = re.compile(r"^[0-9a-f]{32,128}$")


def make_salt(nbytes: int = 32) -> str:
    return secrets.token_hex(nbytes)


def compute_commitment(report: bytes | str, salt_hex: str) -> str:
    if not SALT_RE.match(salt_hex):
        raise ValueError("salt must be 32-128 lowercase hex characters")
    body = report.encode("utf-8") if isinstance(report, str) else report
    return hashlib.sha256(salt_hex.encode("ascii") + b":" + body).hexdigest()


def verify_commitment(commitment: str, report: bytes | str, salt_hex: str) -> bool:
    try:
        expected = compute_commitment(report, salt_hex)
    except ValueError:
        return False
    return hmac.compare_digest(expected, commitment.lower())
