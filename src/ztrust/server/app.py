"""FastAPI service that runs ZTrust bounty programs.

Roles
-----
* **Maintainer / admin** — creates programs, triages findings, releases payouts.
  Authenticated with the ``X-ZTrust-Admin-Token`` header (``ZTRUST_ADMIN_TOKEN``).
* **Researcher** — anonymous. Identified only by a pseudonym and a shielded
  payout address. Submits a commitment first, reveals the report later.

Interactive docs are served at ``/docs`` once the server is running.
"""

# NOTE: no `from __future__ import annotations` here — FastAPI must resolve the
# locally defined `Admin` dependency alias at runtime.
import hmac
import os
from decimal import Decimal
from typing import Annotated, Any, Literal

try:
    from fastapi import Depends, FastAPI, Header, HTTPException, status
    from pydantic import BaseModel, Field, field_validator
except ImportError as exc:  # pragma: no cover
    raise ImportError("The ZTrust API needs extra dependencies: pip install 'ztrust[server]'") from exc

from ztrust import PROJECT_URL, __version__
from ztrust.bounty.backends import PayoutError, ZcashBackend, backend_from_env
from ztrust.bounty.protocol import COMMITMENT_RE, verify_commitment
from ztrust.bounty.store import BountyStore, utcnow
from ztrust.bounty.zcash import build_payment_uri, classify_address, format_zec, is_viewing_key, zec_to_zats
from ztrust.models import Severity

MAX_REPORT_BYTES = 64 * 1024

# --------------------------------------------------------------------------- schemas


class ProgramCreate(BaseModel):
    repo: str = Field(pattern=r"^[A-Za-z0-9_.\-]+/[A-Za-z0-9_.\-]+$", examples=["acme/widgets"])
    title: str = Field(min_length=3, max_length=120)
    description: str = Field(default="", max_length=4000)
    funding_address: str = Field(description="Shielded (Unified or Sapling) address that holds the bounty pool")
    viewing_key: str | None = Field(
        default=None, description="Optional UFVK so anyone can audit that the pool is really funded"
    )
    payouts: dict[Severity, Decimal] = Field(description="Reward in ZEC per severity")
    budget: Decimal = Field(gt=0, description="Total ZEC committed to the program")

    @field_validator("viewing_key")
    @classmethod
    def _check_vk(cls, value: str | None) -> str | None:
        if value is not None and not is_viewing_key(value):
            raise ValueError("viewing_key must be a Unified (uview1…) or Sapling (zxviews1…) full viewing key")
        return value


class CommitmentCreate(BaseModel):
    pseudonym: str = Field(min_length=2, max_length=40, pattern=r"^[A-Za-z0-9_.\-]+$")
    payout_address: str
    commitment: str = Field(description="hex SHA-256 of `salt:report`, see `ztrust commit`")

    @field_validator("commitment")
    @classmethod
    def _check_commitment(cls, value: str) -> str:
        value = value.lower()
        if not COMMITMENT_RE.match(value):
            raise ValueError("commitment must be 64 hex characters")
        return value


class Reveal(BaseModel):
    report: str = Field(min_length=20)
    salt: str
    fingerprint: str | None = Field(
        default=None,
        max_length=200,
        description="Identifier of the issue (CVE, OSV id, ZTrust fingerprint) used for duplicate detection",
    )


class Triage(BaseModel):
    decision: Literal["accept", "reject"]
    severity: Severity | None = None
    note: str = Field(default="", max_length=2000)


# --------------------------------------------------------------------------- views


def program_view(p: dict[str, Any]) -> dict[str, Any]:
    remaining = p["budget_zats"] - p["spent_zats"] - p["reserved_zats"]
    return {
        "id": p["id"],
        "repo": p["repo"],
        "title": p["title"],
        "description": p["description"],
        "funding_address": p["funding_address"],
        "funding_uri": build_payment_uri(
            p["funding_address"], memo=f"ztrust:fund:{p['id']}", label=f"ZTrust bounty {p['repo']}"
        ),
        "viewing_key": p["viewing_key"],
        "payouts": {sev: format_zec(z) for sev, z in p["payouts"].items()},
        "budget": format_zec(p["budget_zats"]),
        "spent": format_zec(p["spent_zats"]),
        "reserved": format_zec(p["reserved_zats"]),
        "remaining": format_zec(max(remaining, 0)),
        "created_at": p["created_at"],
    }


def finding_view(f: dict[str, Any], admin: bool = False) -> dict[str, Any]:
    view = {
        "id": f["id"],
        "program_id": f["program_id"],
        "pseudonym": f["pseudonym"],
        "status": f["status"],
        "commitment": f["commitment"],
        "committed_at": f["committed_at"],
        "revealed_at": f["revealed_at"],
        "severity": f["severity"],
        "payout": format_zec(f["payout_zats"]) if f["payout_zats"] is not None else None,
        "txid": f["txid"],
        "paid_at": f["paid_at"],
    }
    if admin:
        view.update(
            report=f["report"],
            fingerprint=f["fingerprint"],
            payout_address=f["payout_address"],
            triage_note=f["triage_note"],
        )
    return view


# --------------------------------------------------------------------------- app


def create_app(
    store: BountyStore | None = None,
    backend: ZcashBackend | None = None,
    admin_token: str | None = None,
    network: str | None = None,
) -> FastAPI:
    store = store or BountyStore(os.environ.get("ZTRUST_DB", "ztrust.db"))
    backend = backend or backend_from_env()
    admin_token = admin_token if admin_token is not None else os.environ.get("ZTRUST_ADMIN_TOKEN", "")
    network = network or os.environ.get("ZTRUST_ZCASH_NETWORK", "main")

    app = FastAPI(
        title="ZTrust Bounty API",
        version=__version__,
        description="Privacy-preserving supply-chain security bounties paid in shielded ZEC. "
        f"Source: {PROJECT_URL}",
    )

    def require_admin(x_ztrust_admin_token: Annotated[str | None, Header()] = None) -> None:
        if not admin_token:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "ZTRUST_ADMIN_TOKEN is not configured")
        if not x_ztrust_admin_token or not hmac.compare_digest(x_ztrust_admin_token.encode(), admin_token.encode()):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid admin token")

    Admin = Annotated[None, Depends(require_admin)]

    def check_shielded(address: str, field: str) -> None:
        info = classify_address(address)
        if not info.valid:
            raise HTTPException(422, f"{field}: not a valid Zcash address")
        if not info.shielded:
            raise HTTPException(422, f"{field}: must be a shielded Unified or Sapling address")
        if info.network != network:
            raise HTTPException(422, f"{field}: address is for {info.network}net, server runs on {network}net")

    def load_program(program_id: str) -> dict[str, Any]:
        program = store.get_program(program_id)
        if not program:
            raise HTTPException(404, "program not found")
        return program

    def load_finding(finding_id: str) -> dict[str, Any]:
        finding = store.get_finding(finding_id)
        if not finding:
            raise HTTPException(404, "finding not found")
        return finding

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "version": __version__, "network": network, "payout_backend": backend.name}

    # -------------------------------------------------------------- programs

    @app.post("/api/programs", status_code=201)
    def create_program(body: ProgramCreate, _: Admin) -> dict[str, Any]:
        check_shielded(body.funding_address, "funding_address")
        try:
            payouts = {sev.value: zec_to_zats(amount) for sev, amount in body.payouts.items()}
            budget = zec_to_zats(body.budget)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        if not payouts:
            raise HTTPException(422, "at least one severity payout is required")
        program = store.create_program(
            body.repo, body.title, body.description, body.funding_address, body.viewing_key, payouts, budget
        )
        return program_view(program)

    @app.get("/api/programs")
    def list_programs() -> list[dict[str, Any]]:
        return [program_view(p) for p in store.list_programs()]

    @app.get("/api/programs/{program_id}")
    def get_program(program_id: str) -> dict[str, Any]:
        return program_view(load_program(program_id))

    # -------------------------------------------------------------- researcher flow

    @app.post("/api/programs/{program_id}/commitments", status_code=201)
    def commit(program_id: str, body: CommitmentCreate) -> dict[str, Any]:
        load_program(program_id)
        check_shielded(body.payout_address, "payout_address")
        if store.commitment_exists(body.commitment):
            raise HTTPException(409, "commitment already registered")
        return finding_view(store.create_commitment(program_id, body.pseudonym, body.payout_address, body.commitment))

    @app.post("/api/findings/{finding_id}/reveal")
    def reveal(finding_id: str, body: Reveal) -> dict[str, Any]:
        finding = load_finding(finding_id)
        if finding["status"] != "committed":
            raise HTTPException(409, f"finding is already {finding['status']}")
        if len(body.report.encode()) > MAX_REPORT_BYTES:
            raise HTTPException(413, "report too large")
        if not verify_commitment(finding["commitment"], body.report, body.salt):
            raise HTTPException(422, "report and salt do not match the commitment")

        new_status = "revealed"
        if body.fingerprint:
            for other in store.same_fingerprint(finding["program_id"], body.fingerprint, finding_id):
                if other["seq"] < finding["seq"]:
                    new_status = "duplicate"  # someone committed to the same issue first
                elif other["status"] == "revealed":
                    store.update_finding(other["id"], status="duplicate")  # we committed first
        updated = store.update_finding(
            finding_id,
            status=new_status,
            report=body.report,
            salt=body.salt,
            fingerprint=body.fingerprint,
            revealed_at=utcnow(),
        )
        return finding_view(updated)

    @app.get("/api/findings/{finding_id}")
    def get_finding(finding_id: str) -> dict[str, Any]:
        return finding_view(load_finding(finding_id))

    @app.get("/api/leaderboard")
    def leaderboard() -> list[dict[str, Any]]:
        return [
            {"pseudonym": r["pseudonym"], "paid_findings": r["paid_findings"], "total": format_zec(r["total_zats"])}
            for r in store.leaderboard()
        ]

    # -------------------------------------------------------------- maintainer flow

    @app.get("/api/admin/findings")
    def admin_findings(_: Admin, program_id: str | None = None) -> list[dict[str, Any]]:
        return [finding_view(f, admin=True) for f in store.list_findings(program_id)]

    @app.post("/api/findings/{finding_id}/triage")
    def triage(finding_id: str, body: Triage, _: Admin) -> dict[str, Any]:
        finding = load_finding(finding_id)
        if finding["status"] != "revealed":
            raise HTTPException(409, f"only revealed findings can be triaged (status: {finding['status']})")
        if body.decision == "reject":
            return finding_view(store.update_finding(finding_id, status="rejected", triage_note=body.note), admin=True)
        if body.severity is None:
            raise HTTPException(422, "severity is required to accept a finding")
        program = load_program(finding["program_id"])
        payout = program["payouts"].get(body.severity.value)
        if not payout:
            raise HTTPException(422, f"program pays nothing for severity '{body.severity.value}'")
        remaining = program["budget_zats"] - program["spent_zats"] - program["reserved_zats"]
        if payout > remaining:
            raise HTTPException(409, f"insufficient budget: {format_zec(remaining)} ZEC remaining")
        updated = store.update_finding(
            finding_id, status="accepted", severity=body.severity.value, payout_zats=payout, triage_note=body.note
        )
        return finding_view(updated, admin=True)

    @app.post("/api/findings/{finding_id}/payout")
    def payout(finding_id: str, _: Admin) -> dict[str, Any]:
        finding = load_finding(finding_id)
        if finding["status"] != "accepted":
            raise HTTPException(409, f"only accepted findings can be paid (status: {finding['status']})")
        program = load_program(finding["program_id"])
        memo = f"ZTrust bounty {finding_id} · {program['repo']} · severity {finding['severity']} · thank you!"
        try:
            result = backend.send(finding["payout_address"], finding["payout_zats"], memo)
        except PayoutError as exc:
            raise HTTPException(502, f"payout failed: {exc}") from exc
        store.add_spent(program["id"], finding["payout_zats"])
        updated = store.update_finding(finding_id, status="paid", txid=result.txid, paid_at=utcnow())
        return finding_view(updated, admin=True)

    return app


def __getattr__(name: str) -> Any:
    """Lazily build ``app`` so importing this module has no side effects (``uvicorn ztrust.server.app:app``)."""
    if name == "app":
        globals()["app"] = create_app()
        return globals()["app"]
    raise AttributeError(name)
