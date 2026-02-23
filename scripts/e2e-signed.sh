#!/usr/bin/env bash
set -euo pipefail

BASE=${BASE:-http://localhost:8080}
POLICY=${POLICY:-http://localhost:8082}
STATE=${STATE:-http://localhost:8083}

need() { command -v "$1" >/dev/null || { echo "missing $1"; exit 1; }; }
need curl
need jq
need uuidgen

TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

cp docs/examples/intent.json "$TMP_DIR/intent.json"
cp docs/examples/cert.template.json "$TMP_DIR/cert.json"

# setup policy+state
curl -sS -X POST "$POLICY/v1/policysets" -H 'content-type: application/json' -d '{"id":"finance","name":"finance","domain":"finance"}' >/dev/null || true
curl -sS -X POST "$POLICY/v1/policysets/finance/versions" -H 'content-type: application/json' -d '{"version":"v17","dsl":"policyset finance v17:\naxiom Fresh_bank_feed:\n  when action.name == \"pay_invoice\"\n  require source(\"bank\").age_sec <= 30\naxiom Role_guard:\n  when action.name == \"pay_invoice\"\n  require actor.role contains \"FinanceOperator\"\n","created_by":"policy-author","approvals_required":2}' >/dev/null || true
curl -sS -X POST "$POLICY/v1/policysets/finance/versions/v17/submit" -H 'content-type: application/json' -d '{"submitter":"policy-author"}' >/dev/null || true
curl -sS -X POST "$POLICY/v1/policysets/finance/versions/v17/approvals" -H 'content-type: application/json' -d '{"approver":"ops-1"}' >/dev/null
curl -sS -X POST "$POLICY/v1/policysets/finance/versions/v17/approvals" -H 'content-type: application/json' -d '{"approver":"ops-2"}' >/dev/null
curl -sS -X POST "$STATE/v1/state/sources" -H 'content-type: application/json' -d '{"tenant":"acme","domain":"finance","sources":[{"source":"bank","age_sec":5,"health_score":0.99,"lag_sec":1,"jitter_sec":1}]}' >/dev/null
SNAPSHOT_ID=$(curl -sS -X POST "$STATE/v1/state/snapshot" -H 'content-type: application/json' -d '{"tenant":"acme","domain":"finance"}' | jq -r '.snapshot_id')

NONCE=$(uuidgen | tr '[:upper:]' '[:lower:]')
IDEMP=$(uuidgen | tr '[:upper:]' '[:lower:]')
INTENT_ID=$(uuidgen | tr '[:upper:]' '[:lower:]')
CERT_ID=$(uuidgen | tr '[:upper:]' '[:lower:]')

jq --arg nonce "$NONCE" --arg idem "$IDEMP" --arg iid "$INTENT_ID" '.idempotency_key=$idem | .intent_id=$iid' "$TMP_DIR/intent.json" > "$TMP_DIR/intent.patched.json"
mv "$TMP_DIR/intent.patched.json" "$TMP_DIR/intent.json"

HASH=$(go run ./cmd/axiomctl hash-intent --intent "$TMP_DIR/intent.json" --policy-version v17 --nonce "$NONCE")

go run ./cmd/axiomctl gen-key --out-private "$TMP_DIR/private.key" --out-public "$TMP_DIR/public.key"
PUB=$(cat "$TMP_DIR/public.key")
KID=$(uuidgen | tr '[:upper:]' '[:lower:]')

curl -sS -X POST "$POLICY/v1/keys" -H 'content-type: application/json' \
  -d "{\"kid\":\"$KID\",\"signer\":\"agent-key-1\",\"public_key\":\"$PUB\"}" >/dev/null

jq --arg hash "$HASH" --arg nonce "$NONCE" --arg kid "$KID" --arg cid "$CERT_ID" --arg sid "$SNAPSHOT_ID" '.intent_hash=$hash | .nonce=$nonce | .signature.kid=$kid | .cert_id=$cid | .evidence.state_snapshot_refs=[{"source":"state","snapshot_id":$sid,"age_sec":0}]' "$TMP_DIR/cert.json" > "$TMP_DIR/cert.patched.json"
mv "$TMP_DIR/cert.patched.json" "$TMP_DIR/cert.json"

go run ./cmd/axiomctl sign-cert --cert "$TMP_DIR/cert.json" --private "$TMP_DIR/private.key" --out "$TMP_DIR/cert.signed.json"

REQUEST=$(jq -n --argjson intent "$(cat "$TMP_DIR/intent.json")" --argjson cert "$(cat "$TMP_DIR/cert.signed.json")" '{intent:$intent, cert:$cert, tool_payload:{op:"simulate", input:{invoice:"inv-1"}}}')

echo "$REQUEST" | curl -sS -X POST "$BASE/v1/tool/execute" -H 'content-type: application/json' -d @-
