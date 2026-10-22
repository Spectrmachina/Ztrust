"""SQLite persistence for bounty programs and findings (stdlib only)."""

from __future__ import annotations

import json
import secrets
import sqlite3
import threading
from datetime import UTC, datetime
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS programs (
    id              TEXT PRIMARY KEY,
    repo            TEXT NOT NULL,
    title           TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    funding_address TEXT NOT NULL,
    viewing_key     TEXT,
    payouts_json    TEXT NOT NULL,
    budget_zats     INTEGER NOT NULL,
    spent_zats      INTEGER NOT NULL DEFAULT 0,
    active          INTEGER NOT NULL DEFAULT 1,
    created_at      TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS findings (
    id             TEXT PRIMARY KEY,
    program_id     TEXT NOT NULL REFERENCES programs(id),
    pseudonym      TEXT NOT NULL,
    payout_address TEXT NOT NULL,
    commitment     TEXT NOT NULL UNIQUE,
    committed_at   TEXT NOT NULL,
    status         TEXT NOT NULL,
    report         TEXT,
    salt           TEXT,
    fingerprint    TEXT,
    revealed_at    TEXT,
    severity       TEXT,
    payout_zats    INTEGER,
    triage_note    TEXT,
    txid           TEXT,
    paid_at        TEXT
);
CREATE INDEX IF NOT EXISTS idx_findings_program ON findings(program_id, fingerprint);
"""

STATUSES = ("committed", "revealed", "accepted", "rejected", "duplicate", "paid")


def utcnow() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def new_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_urlsafe(9)}"


class BountyStore:
    def __init__(self, path: str = "ztrust.db") -> None:
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        with self._lock:
            self._conn.executescript(SCHEMA)
            self._conn.commit()

    def _one(self, sql: str, args: tuple[Any, ...]) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(sql, args).fetchone()
        return dict(row) if row else None

    def _all(self, sql: str, args: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(r) for r in self._conn.execute(sql, args).fetchall()]

    def _exec(self, sql: str, args: tuple[Any, ...]) -> None:
        with self._lock:
            self._conn.execute(sql, args)
            self._conn.commit()

    # ------------------------------------------------------------------ programs

    def create_program(
        self,
        repo: str,
        title: str,
        description: str,
        funding_address: str,
        viewing_key: str | None,
        payouts_zats: dict[str, int],
        budget_zats: int,
    ) -> dict[str, Any]:
        program_id = new_id("prg")
        self._exec(
            "INSERT INTO programs (id, repo, title, description, funding_address, viewing_key, payouts_json,"
            " budget_zats, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (program_id, repo, title, description, funding_address, viewing_key,
             json.dumps(payouts_zats), budget_zats, utcnow()),
        )
        return self.get_program(program_id)  # type: ignore[return-value]

    def get_program(self, program_id: str) -> dict[str, Any] | None:
        row = self._one("SELECT * FROM programs WHERE id = ?", (program_id,))
        if row:
            row["payouts"] = json.loads(row.pop("payouts_json"))
            row["reserved_zats"] = self.reserved_zats(program_id)
        return row

    def list_programs(self) -> list[dict[str, Any]]:
        ids = [r["id"] for r in self._all("SELECT id FROM programs WHERE active = 1 ORDER BY created_at DESC")]
        return [p for p in (self.get_program(i) for i in ids) if p]

    def reserved_zats(self, program_id: str) -> int:
        row = self._one(
            "SELECT COALESCE(SUM(payout_zats), 0) AS total FROM findings WHERE program_id = ? AND status = 'accepted'",
            (program_id,),
        )
        return int(row["total"]) if row else 0

    def add_spent(self, program_id: str, zats: int) -> None:
        self._exec("UPDATE programs SET spent_zats = spent_zats + ? WHERE id = ?", (zats, program_id))

    # ------------------------------------------------------------------ findings

    def create_commitment(self, program_id: str, pseudonym: str, payout_address: str, commitment: str) -> dict[str, Any]:
        finding_id = new_id("fnd")
        self._exec(
            "INSERT INTO findings (id, program_id, pseudonym, payout_address, commitment, committed_at, status)"
            " VALUES (?, ?, ?, ?, ?, ?, 'committed')",
            (finding_id, program_id, pseudonym, payout_address, commitment.lower(), utcnow()),
        )
        return self.get_finding(finding_id)  # type: ignore[return-value]

    def get_finding(self, finding_id: str) -> dict[str, Any] | None:
        return self._one("SELECT rowid AS seq, * FROM findings WHERE id = ?", (finding_id,))

    def commitment_exists(self, commitment: str) -> bool:
        return self._one("SELECT 1 FROM findings WHERE commitment = ?", (commitment.lower(),)) is not None

    def list_findings(self, program_id: str | None = None) -> list[dict[str, Any]]:
        if program_id:
            return self._all(
                "SELECT rowid AS seq, * FROM findings WHERE program_id = ? ORDER BY rowid", (program_id,)
            )
        return self._all("SELECT rowid AS seq, * FROM findings ORDER BY rowid")

    def same_fingerprint(self, program_id: str, fingerprint: str, exclude_id: str) -> list[dict[str, Any]]:
        return self._all(
            "SELECT rowid AS seq, * FROM findings WHERE program_id = ? AND fingerprint = ? AND id != ?"
            " AND status IN ('revealed', 'accepted', 'paid', 'duplicate') ORDER BY rowid",
            (program_id, fingerprint, exclude_id),
        )

    def update_finding(self, finding_id: str, **fields: Any) -> dict[str, Any]:
        allowed = {"status", "report", "salt", "fingerprint", "revealed_at", "severity",
                   "payout_zats", "triage_note", "txid", "paid_at"}
        unknown = set(fields) - allowed
        if unknown:
            raise ValueError(f"cannot update {unknown}")
        if "status" in fields and fields["status"] not in STATUSES:
            raise ValueError(f"bad status {fields['status']}")
        assignments = ", ".join(f"{k} = ?" for k in fields)
        self._exec(f"UPDATE findings SET {assignments} WHERE id = ?", (*fields.values(), finding_id))  # noqa: S608
        return self.get_finding(finding_id)  # type: ignore[return-value]

    def leaderboard(self) -> list[dict[str, Any]]:
        return self._all(
            "SELECT pseudonym, COUNT(*) AS paid_findings, SUM(payout_zats) AS total_zats FROM findings"
            " WHERE status = 'paid' GROUP BY pseudonym ORDER BY total_zats DESC LIMIT 50"
        )
