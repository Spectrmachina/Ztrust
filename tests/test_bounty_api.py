import pytest
from conftest import make_sapling_address, make_unified_address

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient  # noqa: E402

from ztrust.bounty.backends import MockBackend  # noqa: E402
from ztrust.bounty.protocol import compute_commitment, make_salt, verify_commitment  # noqa: E402
from ztrust.bounty.store import BountyStore  # noqa: E402
from ztrust.server.app import create_app  # noqa: E402

ADMIN = {"X-ZTrust-Admin-Token": "test-admin-token"}


@pytest.fixture
def client_and_backend():
    backend = MockBackend()
    app = create_app(store=BountyStore(":memory:"), backend=backend, admin_token="test-admin-token")
    return TestClient(app), backend


def create_program(client, budget="10"):
    resp = client.post(
        "/api/programs",
        headers=ADMIN,
        json={
            "repo": "acme/widgets",
            "title": "Widgets supply-chain bounty",
            "funding_address": make_unified_address(1),
            "payouts": {"critical": "5", "high": "2", "medium": "0.5"},
            "budget": budget,
        },
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def submit(client, program_id, report, pseudonym="anon", fingerprint=None, seed=2):
    salt = make_salt()
    commitment = compute_commitment(report, salt)
    resp = client.post(
        f"/api/programs/{program_id}/commitments",
        json={"pseudonym": pseudonym, "payout_address": make_sapling_address(seed), "commitment": commitment},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["id"], salt


def test_commitment_roundtrip():
    salt = make_salt()
    c = compute_commitment("report", salt)
    assert verify_commitment(c, "report", salt)
    assert not verify_commitment(c, "report!", salt)


def test_full_bounty_flow(client_and_backend):
    client, backend = client_and_backend
    program = create_program(client)
    assert program["funding_uri"].startswith("zcash:u1")
    assert program["remaining"] == "10"

    report = "Typosquatted dependency `reqeusts` exfiltrates env vars in setup.py"
    finding_id, salt = submit(client, program["id"], report)

    assert client.get(f"/api/findings/{finding_id}").json()["status"] == "committed"
    bad = client.post(f"/api/findings/{finding_id}/reveal", json={"report": report + "x", "salt": salt})
    assert bad.status_code == 422

    ok = client.post(f"/api/findings/{finding_id}/reveal", json={"report": report, "salt": salt, "fingerprint": "MAL-1"})
    assert ok.json()["status"] == "revealed"

    assert client.post(f"/api/findings/{finding_id}/triage", json={"decision": "accept", "severity": "critical"}).status_code == 401
    accepted = client.post(
        f"/api/findings/{finding_id}/triage", headers=ADMIN, json={"decision": "accept", "severity": "critical"}
    )
    assert accepted.json()["payout"] == "5"
    assert client.get(f"/api/programs/{program['id']}").json()["reserved"] == "5"

    paid = client.post(f"/api/findings/{finding_id}/payout", headers=ADMIN).json()
    assert paid["status"] == "paid" and len(paid["txid"]) == 64
    assert backend.sent[0]["amount_zats"] == 500_000_000
    assert client.get(f"/api/programs/{program['id']}").json()["remaining"] == "5"
    assert client.get("/api/leaderboard").json()[0] == {"pseudonym": "anon", "paid_findings": 1, "total": "5"}


def test_first_commitment_wins_duplicates(client_and_backend):
    client, _ = client_and_backend
    program = create_program(client)
    report_a = "Pwn request in release workflow lets forks steal NPM_TOKEN"
    report_b = "Release workflow checks out PR head under pull_request_target"
    first_id, first_salt = submit(client, program["id"], report_a, pseudonym="early", seed=3)
    second_id, second_salt = submit(client, program["id"], report_b, pseudonym="late", seed=4)

    # The later committer reveals first …
    r = client.post(f"/api/findings/{second_id}/reveal", json={"report": report_b, "salt": second_salt, "fingerprint": "pwn-req"})
    assert r.json()["status"] == "revealed"
    # … but the earlier commitment still wins.
    r = client.post(f"/api/findings/{first_id}/reveal", json={"report": report_a, "salt": first_salt, "fingerprint": "pwn-req"})
    assert r.json()["status"] == "revealed"
    assert client.get(f"/api/findings/{second_id}").json()["status"] == "duplicate"


def test_rejects_transparent_payout_and_budget_overrun(client_and_backend):
    from ztrust.bounty.zcash import b58check_encode

    client, _ = client_and_backend
    program = create_program(client, budget="1")
    resp = client.post(
        f"/api/programs/{program['id']}/commitments",
        json={"pseudonym": "x1", "payout_address": b58check_encode(b"\x1c\xb8" + bytes(20)), "commitment": "a" * 64},
    )
    assert resp.status_code == 422

    report = "Leaked npm token in CI logs of the publish job"
    fid, salt = submit(client, program["id"], report)
    client.post(f"/api/findings/{fid}/reveal", json={"report": report, "salt": salt})
    resp = client.post(f"/api/findings/{fid}/triage", headers=ADMIN, json={"decision": "accept", "severity": "critical"})
    assert resp.status_code == 409
