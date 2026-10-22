# REST API

Start the server:

```bash
pip install -e ".[server]"
export ZTRUST_ADMIN_TOKEN=$(python -c "import secrets; print(secrets.token_urlsafe(32))")
export ZTRUST_ZCASH_NETWORK=test
ztrust serve --port 8080
```

OpenAPI / Swagger UI is generated automatically at **`http://127.0.0.1:8080/docs`**.
All amounts are decimal **ZEC strings** (`"0.5"`). Admin endpoints require the
`X-ZTrust-Admin-Token` header.

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `GET` | `/health` | — | Liveness, version, network, payout backend |
| `POST` | `/api/programs` | admin | Create a bounty program |
| `GET` | `/api/programs` | — | List active programs |
| `GET` | `/api/programs/{id}` | — | Program details, funding URI, remaining budget |
| `POST` | `/api/programs/{id}/commitments` | — | Researcher submits a commitment |
| `POST` | `/api/findings/{id}/reveal` | — | Researcher reveals report + salt |
| `GET` | `/api/findings/{id}` | — | Public status of a finding |
| `GET` | `/api/leaderboard` | — | Top pseudonyms by ZEC earned |
| `GET` | `/api/admin/findings?program_id=` | admin | Full findings incl. reports |
| `POST` | `/api/findings/{id}/triage` | admin | Accept (with severity) or reject |
| `POST` | `/api/findings/{id}/payout` | admin | Send the shielded payout |

## Examples

### Create a program

```bash
curl -X POST http://127.0.0.1:8080/api/programs \
  -H "Content-Type: application/json" -H "X-ZTrust-Admin-Token: $ZTRUST_ADMIN_TOKEN" \
  -d '{
    "repo": "acme/widgets",
    "title": "Widgets supply-chain bounty",
    "funding_address": "utest1...",
    "payouts": {"critical": "5", "high": "2", "medium": "0.5"},
    "budget": "20"
  }'
```

```json
{
  "id": "prg_Xk2p9QaLm1c",
  "repo": "acme/widgets",
  "funding_uri": "zcash:utest1...?memo=enRydXN0OmZ1bmQ6cHJnX1hrMnA5UWFMbTFj&label=ZTrust%20bounty%20acme%2Fwidgets",
  "payouts": {"critical": "5", "high": "2", "medium": "0.5"},
  "budget": "20", "spent": "0", "reserved": "0", "remaining": "20"
}
```

### Commit → reveal

```bash
ztrust commit report.md > commit.json
curl -X POST http://127.0.0.1:8080/api/programs/prg_Xk2p9QaLm1c/commitments \
  -H "Content-Type: application/json" \
  -d "{\"pseudonym\":\"night-owl\",\"payout_address\":\"utest1...\",\"commitment\":\"$(jq -r .commitment commit.json)\"}"

jq -n --rawfile report report.md --arg salt "$(jq -r .salt commit.json)" \
   '{report:$report, salt:$salt, fingerprint:"MAL-2026-1234"}' \
 | curl -X POST http://127.0.0.1:8080/api/findings/fnd_.../reveal -H "Content-Type: application/json" -d @-
```

### Error codes

| Code | Meaning |
|---|---|
| 401 | Missing / wrong admin token |
| 404 | Unknown program or finding |
| 409 | Wrong state transition, duplicate commitment, insufficient budget |
| 413 | Report larger than 64 KiB |
| 422 | Validation error (bad address, non-shielded address, wrong network, hash mismatch) |
| 502 | Wallet RPC failed during payout |
| 503 | `ZTRUST_ADMIN_TOKEN` not configured |

A complete scripted walkthrough lives in [`examples/bounty-flow.sh`](../examples/bounty-flow.sh).
