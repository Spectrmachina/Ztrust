#!/usr/bin/env bash
# End-to-end walkthrough of a ZTrust bounty against a local API.
#   pip install -e ".[server]"
#   ZTRUST_ADMIN_TOKEN=dev ZTRUST_ZCASH_NETWORK=test ztrust serve &
#   FUNDING_UA=utest1... PAYOUT_UA=utest1... ./examples/bounty-flow.sh
# Requires: curl, jq. Uses the mock payout backend unless the server is configured for RPC.
set -euo pipefail

API="${API:-http://127.0.0.1:8080}"
ADMIN="${ZTRUST_ADMIN_TOKEN:-dev}"
: "${FUNDING_UA:?set FUNDING_UA to a testnet unified address}"
: "${PAYOUT_UA:?set PAYOUT_UA to the researcher's shielded address}"

echo "1) Maintainer opens a bounty program"
PROGRAM=$(curl -sf -X POST "$API/api/programs" \
  -H "Content-Type: application/json" -H "X-ZTrust-Admin-Token: $ADMIN" \
  -d "{\"repo\":\"acme/widgets\",\"title\":\"Widgets supply-chain bounty\",
       \"funding_address\":\"$FUNDING_UA\",
       \"payouts\":{\"critical\":\"5\",\"high\":\"2\",\"medium\":\"0.5\"},\"budget\":\"20\"}")
PROGRAM_ID=$(echo "$PROGRAM" | jq -r .id)
echo "   program $PROGRAM_ID — fund it with: $(echo "$PROGRAM" | jq -r .funding_uri)"

echo "2) Researcher writes a private report and commits to it"
REPORT=$(mktemp)
cat > "$REPORT" <<'EOF'
# Typosquat in build dependencies
`python-dateutils` (note the trailing s) is installed by tools/requirements.txt.
Its setup.py posts environment variables to a remote host.
EOF
COMMIT_JSON=$(ztrust commit "$REPORT")
COMMITMENT=$(echo "$COMMIT_JSON" | jq -r .commitment)
SALT=$(echo "$COMMIT_JSON" | jq -r .salt)
FINDING_ID=$(curl -sf -X POST "$API/api/programs/$PROGRAM_ID/commitments" \
  -H "Content-Type: application/json" \
  -d "{\"pseudonym\":\"night-owl\",\"payout_address\":\"$PAYOUT_UA\",\"commitment\":\"$COMMITMENT\"}" | jq -r .id)
echo "   finding $FINDING_ID committed (content still private)"

echo "3) Researcher reveals the report"
jq -n --rawfile report "$REPORT" --arg salt "$SALT" '{report:$report, salt:$salt, fingerprint:"typo:python-dateutils"}' \
  | curl -sf -X POST "$API/api/findings/$FINDING_ID/reveal" -H "Content-Type: application/json" -d @- | jq .status

echo "4) Maintainer accepts it as critical"
curl -sf -X POST "$API/api/findings/$FINDING_ID/triage" \
  -H "Content-Type: application/json" -H "X-ZTrust-Admin-Token: $ADMIN" \
  -d '{"decision":"accept","severity":"critical","note":"Confirmed, package removed"}' | jq '{status,payout}'

echo "5) Shielded payout"
curl -sf -X POST "$API/api/findings/$FINDING_ID/payout" -H "X-ZTrust-Admin-Token: $ADMIN" | jq '{status,payout,txid}'
