#!/usr/bin/env bash
set -euo pipefail

BASE=${BASE:-http://localhost:8080}
POLICY=${POLICY:-http://localhost:8082}
STATE=${STATE:-http://localhost:8083}

need() { command -v "$1" >/dev/null || { echo "missing $1"; exit 1; }; }
need curl
need jq
need uuidgen
need go

TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

DSL=$(cat <<'POLICY'
policyset finance v17:
axiom Fresh_bank_feed:
  when action.name in ["pay_invoice", "refund"]
  require source("bank").age_sec <= 30
axiom Role_guard:
  when action.name == "pay_invoice"
  require actor.role contains "FinanceOperator"
  else shield("REQUIRE_APPROVAL")
POLICY
)

curl -sS -X POST "$POLICY/v1/policysets" -H 'content-type: application/json' \
  -d '{"id":"finance","name":"finance","domain":"finance"}' >/dev/null || true

jq -n --arg dsl "$DSL" '{version:"v17", dsl:$dsl, created_by:"policy-author", approvals_required:1}' \
  | curl -sS -X POST "$POLICY/v1/policysets/finance/versions" -H 'content-type: application/json' -d @- >/dev/null || true

curl -sS -X POST "$POLICY/v1/policysets/finance/versions/v17/submit" -H 'content-type: application/json' \
  -d '{"submitter":"policy-author"}' >/dev/null || true
curl -sS -X POST "$POLICY/v1/policysets/finance/versions/v17/approvals" -H 'content-type: application/json' \
  -d '{"approver":"ops-1"}' >/dev/null || true

curl -sS -X POST "$STATE/v1/state/sources" -H 'content-type: application/json' \
  -d '{"tenant":"acme","domain":"finance","sources":[{"source":"bank","age_sec":5,"health_score":0.99,"lag_sec":1,"jitter_sec":1}]}' >/dev/null
SNAPSHOT_ID=$(curl -sS -X POST "$STATE/v1/state/snapshot" -H 'content-type: application/json' -d '{"tenant":"acme","domain":"finance"}' | jq -r '.snapshot_id')

NONCE=$(uuidgen | tr '[:upper:]' '[:lower:]')
IDEMP=$(uuidgen | tr '[:upper:]' '[:lower:]')
INTENT_ID=$(uuidgen | tr '[:upper:]' '[:lower:]')
CERT_ID=$(uuidgen | tr '[:upper:]' '[:lower:]')

cp docs/examples/intent.json "$TMP_DIR/intent.json"
cp docs/examples/cert.template.json "$TMP_DIR/cert.json"

jq --arg nonce "$NONCE" --arg idem "$IDEMP" --arg iid "$INTENT_ID" \
  '.idempotency_key=$idem | .intent_id=$iid | .actor.roles=["Viewer"] | .actor.id="operator-1"' \
  "$TMP_DIR/intent.json" > "$TMP_DIR/intent.patched.json"

mv "$TMP_DIR/intent.patched.json" "$TMP_DIR/intent.json"

HASH=$(go run ./cmd/axiomctl hash-intent --intent "$TMP_DIR/intent.json" --policy-version v17 --nonce "$NONCE")

go run ./cmd/axiomctl gen-key --out-private "$TMP_DIR/private.key" --out-public "$TMP_DIR/public.key"
PUB=$(cat "$TMP_DIR/public.key")
KID=$(uuidgen | tr '[:upper:]' '[:lower:]')

curl -sS -X POST "$POLICY/v1/keys" -H 'content-type: application/json' \
  -d "{\"kid\":\"$KID\",\"signer\":\"agent-key-1\",\"public_key\":\"$PUB\"}" >/dev/null

jq --arg hash "$HASH" --arg nonce "$NONCE" --arg kid "$KID" --arg cid "$CERT_ID" --arg sid "$SNAPSHOT_ID" \
  '.intent_hash=$hash
  | .nonce=$nonce
  | .signature.kid=$kid
  | .cert_id=$cid
  | .claims=[{"type":"Approval","statement":"approvals_required >= 1"}]
  | .evidence.state_snapshot_refs=[{"source":"state","snapshot_id":$sid,"age_sec":0}]' \
  "$TMP_DIR/cert.json" > "$TMP_DIR/cert.patched.json"

mv "$TMP_DIR/cert.patched.json" "$TMP_DIR/cert.json"

go run ./cmd/axiomctl sign-cert --cert "$TMP_DIR/cert.json" --private "$TMP_DIR/private.key" --out "$TMP_DIR/cert.signed.json" >/dev/null

REQUEST=$(jq -n --argjson intent "$(cat "$TMP_DIR/intent.json")" --argjson cert "$(cat "$TMP_DIR/cert.signed.json")" \
  '{intent:$intent, cert:$cert, tool_payload:{op:"simulate", input:{invoice:"inv-1"}}}')

RESP=$(echo "$REQUEST" | curl -sS -X POST "$BASE/v1/tool/execute" -H 'content-type: application/json' -d @-)
ESCROW_ID=$(echo "$RESP" | jq -r '.escrow.escrow_id // empty')

if [ -z "$ESCROW_ID" ]; then
  echo "$RESP" >&2
  exit 1
fi

echo "$ESCROW_ID"
