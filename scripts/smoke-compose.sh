#!/usr/bin/env bash
set -euo pipefail

COMPOSE_FILE=${COMPOSE_FILE:-infra/docker-compose/docker-compose.yml}
ENV_FILE=${ENV_FILE:-.env}
if [ ! -f "$ENV_FILE" ]; then
  ENV_FILE=.env.example
fi
AUTH_MODE=${AUTH_MODE:-off}
export AUTH_MODE
ALLOW_INSECURE_AUTH_OFF=${ALLOW_INSECURE_AUTH_OFF:-true}
export ALLOW_INSECURE_AUTH_OFF
TMP_DIR=""
dc() {
  docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" "$@"
}
cleanup() {
  if [ -n "${TMP_DIR:-}" ] && [ -d "$TMP_DIR" ]; then
    rm -rf "$TMP_DIR"
  fi
  dc down -v >/dev/null 2>&1 || true
}
trap cleanup EXIT

wait_for() {
  local url=$1
  local max=${2:-60}
  local i=0
  until curl -fsS "$url" >/dev/null 2>&1; do
    i=$((i+1))
    if [ "$i" -ge "$max" ]; then
      echo "timeout waiting for $url"
      return 1
    fi
    sleep 2
  done
}

echo "bringing up stack"
dc up -d --build

wait_for http://localhost:8080/healthz

echo "running signed happy-path"
./scripts/e2e-signed.sh >/tmp/axiom-e2e.json
cat /tmp/axiom-e2e.json

echo "creating escrow case"
POLICY=http://localhost:8082
STATE=http://localhost:8083
BASE=http://localhost:8080

# policy with approval shield on failure
curl -sS -X POST "$POLICY/v1/policysets" -H 'content-type: application/json' -d '{"id":"finance2","name":"finance2","domain":"finance"}' >/dev/null || true
curl -sS -X POST "$POLICY/v1/policysets/finance2/versions" -H 'content-type: application/json' -d '{"version":"v1","dsl":"policyset finance2 v1:\naxiom Role_guard:\n  when action.name == \"pay_invoice\"\n  require actor.role contains \"FinanceOperator\"\n  else shield(\"REQUIRE_APPROVAL\")\n","created_by":"policy-author","approvals_required":2}' >/dev/null || true
curl -sS -X POST "$POLICY/v1/policysets/finance2/versions/v1/submit" -H 'content-type: application/json' -d '{"submitter":"policy-author"}' >/dev/null || true
SOD_CODE=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$POLICY/v1/policysets/finance2/versions/v1/approvals" -H 'content-type: application/json' -d '{"approver":"policy-author"}')
if [ "$SOD_CODE" != "403" ]; then
  echo "expected SoD rejection for creator approval"
  exit 1
fi
curl -sS -X POST "$POLICY/v1/policysets/finance2/versions/v1/approvals" -H 'content-type: application/json' -d '{"approver":"ops-a"}' >/dev/null
curl -sS -X POST "$POLICY/v1/policysets/finance2/versions/v1/approvals" -H 'content-type: application/json' -d '{"approver":"ops-b"}' >/dev/null
curl -sS -X POST "$STATE/v1/state/sources" -H 'content-type: application/json' -d '{"tenant":"acme","domain":"finance","sources":[{"source":"bank","age_sec":5,"health_score":0.99,"lag_sec":1,"jitter_sec":1},{"source":"erp","age_sec":5,"health_score":0.99,"lag_sec":1,"jitter_sec":1}]}' >/dev/null

TMP_DIR=$(mktemp -d)
cp docs/examples/intent.json "$TMP_DIR/intent.json"
cp docs/examples/cert.template.json "$TMP_DIR/cert.json"
NONCE=$(uuidgen | tr '[:upper:]' '[:lower:]')
IDEMP=$(uuidgen | tr '[:upper:]' '[:lower:]')
INTENT_ID=$(uuidgen | tr '[:upper:]' '[:lower:]')
CERT_ID=$(uuidgen | tr '[:upper:]' '[:lower:]')

jq --arg nonce "$NONCE" --arg idem "$IDEMP" --arg iid "$INTENT_ID" '.idempotency_key=$idem | .intent_id=$iid | .actor.roles=["Viewer"]' "$TMP_DIR/intent.json" > "$TMP_DIR/intent.patched.json"
mv "$TMP_DIR/intent.patched.json" "$TMP_DIR/intent.json"

HASH=$(go run ./cmd/axiomctl hash-intent --intent "$TMP_DIR/intent.json" --policy-version v1 --nonce "$NONCE")
go run ./cmd/axiomctl gen-key --out-private "$TMP_DIR/private.key" --out-public "$TMP_DIR/public.key" >/dev/null
PUB=$(cat "$TMP_DIR/public.key")
KID=$(uuidgen | tr '[:upper:]' '[:lower:]')
curl -sS -X POST "$POLICY/v1/keys" -H 'content-type: application/json' -d "{\"kid\":\"$KID\",\"signer\":\"agent-key-1\",\"public_key\":\"$PUB\"}" >/dev/null
jq --arg hash "$HASH" --arg nonce "$NONCE" --arg kid "$KID" --arg cid "$CERT_ID" '.intent_hash=$hash | .nonce=$nonce | .signature.kid=$kid | .cert_id=$cid | .policy_set_id="finance2" | .policy_version="v1"' "$TMP_DIR/cert.json" > "$TMP_DIR/cert.patched.json"
mv "$TMP_DIR/cert.patched.json" "$TMP_DIR/cert.json"
go run ./cmd/axiomctl sign-cert --cert "$TMP_DIR/cert.json" --private "$TMP_DIR/private.key" --out "$TMP_DIR/cert.signed.json" >/dev/null

REQUEST=$(jq -n --argjson intent "$(cat "$TMP_DIR/intent.json")" --argjson cert "$(cat "$TMP_DIR/cert.signed.json")" '{intent:$intent, cert:$cert, tool_payload:{op:"simulate", input:{invoice:"inv-escrow"}}}')
RESP=$(echo "$REQUEST" | curl -sS -X POST "$BASE/v1/tool/execute" -H 'content-type: application/json' -d @-)
echo "$RESP"
VERDICT=$(echo "$RESP" | jq -r '.verdict')
if [ "$VERDICT" = "ESCROW" ]; then
  ESCROW_ID=$(echo "$RESP" | jq -r '.escrow.escrow_id')
  if [ "$ESCROW_ID" = "null" ] || [ -z "$ESCROW_ID" ]; then
    echo "expected escrow id when verdict is ESCROW"
    exit 1
  fi
  curl -sS -X POST "$BASE/v1/escrow/approve" -H 'content-type: application/json' -d "{\"escrow_id\":\"$ESCROW_ID\",\"approver\":\"manager-1\"}" | jq .
  curl -sS "$BASE/v1/escrow/$ESCROW_ID" | jq .
elif [ "$VERDICT" != "SHIELD" ]; then
  echo "expected ESCROW or SHIELD, got: $RESP"
  exit 1
fi

# P2 fix: strict ALLOW case — validates normal production path
echo "running strict ALLOW-path smoke"
IDEMP_ALLOW=$(uuidgen | tr '[:upper:]' '[:lower:]')
INTENT_ALLOW_ID=$(uuidgen | tr '[:upper:]' '[:lower:]')
NONCE_ALLOW=$(uuidgen | tr '[:upper:]' '[:lower:]')
CERT_ALLOW_ID=$(uuidgen | tr '[:upper:]' '[:lower:]')

jq --arg nonce "$NONCE_ALLOW" --arg idem "$IDEMP_ALLOW" --arg iid "$INTENT_ALLOW_ID" \
  '.idempotency_key=$idem | .intent_id=$iid | .actor.roles=["FinanceOperator"]' \
  "$TMP_DIR/intent.json" > "$TMP_DIR/intent_allow.json"
HASH_ALLOW=$(go run ./cmd/axiomctl hash-intent --intent "$TMP_DIR/intent_allow.json" --policy-version v1 --nonce "$NONCE_ALLOW")
jq --arg hash "$HASH_ALLOW" --arg nonce "$NONCE_ALLOW" --arg kid "$KID" --arg cid "$CERT_ALLOW_ID" \
  '.intent_hash=$hash | .nonce=$nonce | .signature.kid=$kid | .cert_id=$cid | .policy_set_id="finance2" | .policy_version="v1"' \
  "$TMP_DIR/cert.json" > "$TMP_DIR/cert_allow.json"
go run ./cmd/axiomctl sign-cert --cert "$TMP_DIR/cert_allow.json" --private "$TMP_DIR/private.key" --out "$TMP_DIR/cert_allow_signed.json" >/dev/null

REQ_ALLOW=$(jq -n --argjson intent "$(cat "$TMP_DIR/intent_allow.json")" --argjson cert "$(cat "$TMP_DIR/cert_allow_signed.json")" '{intent:$intent, cert:$cert, tool_payload:{op:"simulate", input:{invoice:"inv-allow"}}}')
RESP_ALLOW=$(echo "$REQ_ALLOW" | curl -sS -X POST "$BASE/v1/tool/execute" -H 'content-type: application/json' -d @-)
echo "$RESP_ALLOW"
VERDICT_ALLOW=$(echo "$RESP_ALLOW" | jq -r '.verdict')
if [ "$VERDICT_ALLOW" = "ALLOW" ]; then
  :
elif [ "$VERDICT_ALLOW" = "ESCROW" ] && [ "$(echo "$RESP_ALLOW" | jq -r '.reason_code')" = "SMT_NON_FORMAL" ]; then
  echo "strict ALLOW degraded to ESCROW due non-formal SMT backend"
else
  echo "STRICT ALLOW FAIL: expected ALLOW (or ESCROW with SMT_NON_FORMAL), got $VERDICT_ALLOW"
  echo "$RESP_ALLOW" | jq .
  exit 1
fi
echo "strict ALLOW path passed"

echo "smoke complete"
