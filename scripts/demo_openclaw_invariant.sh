#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT_DIR"

COMPOSE_FILE=${COMPOSE_FILE:-infra/docker-compose/docker-compose.yml}
ENV_FILE=${ENV_FILE:-.env}
if [[ ! -f "$ENV_FILE" ]]; then
  ENV_FILE=.env.example
fi

for bin in curl jq docker go; do
  if ! command -v "$bin" >/dev/null 2>&1; then
    echo "missing required command: $bin"
    exit 1
  fi
done

BASE=${BASE:-http://localhost:8080}
POLICY=${POLICY:-http://localhost:8082}
STATE=${STATE:-http://localhost:8083}
PROXY=${PROXY:-http://localhost:8090}
KEY_DIR=${KEY_DIR:-.invariant/openclaw/dev_keys}

OPENCLAW_GATEWAY_TOKEN=${OPENCLAW_GATEWAY_TOKEN:-openclaw-demo-token}
OPENCLAW_POLICY_SET_ID=${OPENCLAW_POLICY_SET_ID:-finance_openclaw}
OPENCLAW_POLICY_VERSION=${OPENCLAW_POLICY_VERSION:-v1}
AUTH_MODE=${AUTH_MODE:-off}
ALLOW_INSECURE_AUTH_OFF=${ALLOW_INSECURE_AUTH_OFF:-true}
ENVIRONMENT=${ENVIRONMENT:-development}

export OPENCLAW_GATEWAY_TOKEN
export OPENCLAW_POLICY_SET_ID
export OPENCLAW_POLICY_VERSION
export AUTH_MODE
export ALLOW_INSECURE_AUTH_OFF
export ENVIRONMENT

KID=${OPENCLAW_SIGNER_KID:-openclaw-dev-kid}
go run ./cmd/invariant openclaw keys init --dir "$KEY_DIR" --kid "$KID" >/tmp/invariant-openclaw-keys.log

OPENCLAW_SIGNER_PRIVATE_KEY_B64=$(tr -d '\n' < "$KEY_DIR/private.key")
OPENCLAW_SIGNER_KID=$KID
export OPENCLAW_SIGNER_PRIVATE_KEY_B64
export OPENCLAW_SIGNER_KID

dc() {
  docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" --profile openclaw "$@"
}

cleanup() {
  if [[ "${KEEP_STACK_UP:-0}" == "1" ]]; then
    echo "KEEP_STACK_UP=1 set; leaving services running"
    return
  fi
  dc down -v >/dev/null 2>&1 || true
}
trap cleanup EXIT

wait_for() {
  local url=$1
  local max=${2:-90}
  local i=0
  until curl -fsS "$url" >/dev/null 2>&1; do
    i=$((i+1))
    if [[ "$i" -ge "$max" ]]; then
      echo "timeout waiting for $url"
      return 1
    fi
    sleep 2
  done
}

echo "[1/8] starting services"
dc up -d --build

wait_for "$BASE/healthz"
wait_for "$POLICY/healthz"
wait_for "$STATE/healthz"
wait_for "$PROXY/healthz"

echo "[2/8] registering signer key"
PUB=$(tr -d '\n' < "$KEY_DIR/public.key")
curl -sS -X POST "$POLICY/v1/keys" -H 'content-type: application/json' \
  -d "{\"kid\":\"$KID\",\"signer\":\"openclaw-adapter\",\"public_key\":\"$PUB\"}" >/dev/null || true

echo "[3/8] publishing policy"
DSL=$(cat <<'POLICYDSL'
policyset finance_openclaw v1:
axiom OpenClawApproval:
  when action.name == "openclaw.send"
  require actor.role contains "FinanceOperator"
  else shield("REQUIRE_APPROVAL")
POLICYDSL
)

curl -sS -X POST "$POLICY/v1/policysets" -H 'content-type: application/json' \
  -d "{\"id\":\"$OPENCLAW_POLICY_SET_ID\",\"name\":\"$OPENCLAW_POLICY_SET_ID\",\"domain\":\"finance\"}" >/dev/null || true
curl -sS -X POST "$POLICY/v1/policysets/$OPENCLAW_POLICY_SET_ID/versions" -H 'content-type: application/json' \
  -d "$(jq -n --arg version "$OPENCLAW_POLICY_VERSION" --arg dsl "$DSL" '{version:$version,dsl:$dsl,created_by:"policy-author",approvals_required:2}')" >/dev/null || true
curl -sS -X POST "$POLICY/v1/policysets/$OPENCLAW_POLICY_SET_ID/versions/$OPENCLAW_POLICY_VERSION/submit" -H 'content-type: application/json' \
  -d '{"submitter":"policy-author"}' >/dev/null || true
curl -sS -X POST "$POLICY/v1/policysets/$OPENCLAW_POLICY_SET_ID/versions/$OPENCLAW_POLICY_VERSION/approvals" -H 'content-type: application/json' \
  -d '{"approver":"ops-a"}' >/dev/null || true
curl -sS -X POST "$POLICY/v1/policysets/$OPENCLAW_POLICY_SET_ID/versions/$OPENCLAW_POLICY_VERSION/approvals" -H 'content-type: application/json' \
  -d '{"approver":"ops-b"}' >/dev/null || true

echo "[4/8] seeding belief state"
curl -sS -X POST "$STATE/v1/state/sources" -H 'content-type: application/json' \
  -d '{"tenant":"acme","domain":"finance","sources":[{"source":"bank","age_sec":5,"health_score":0.99,"lag_sec":1,"jitter_sec":1}]}' >/dev/null

echo "[5/8] invoke side-effecting OpenClaw action (expected ESCROW)"
TS=$(date +%s)
REQ1=$(jq --arg idem "idem-escrow-$TS" '.idempotency_key=$idem' scripts/demo_payloads/escrow_request.json)
RESP1=$(echo "$REQ1" | curl -sS -X POST "$PROXY/tools/invoke" -H 'content-type: application/json' -d @-)
VERDICT1=$(echo "$RESP1" | jq -r '.verdict')
if [[ "$VERDICT1" != "ESCROW" && "$VERDICT1" != "SHIELD" ]]; then
  echo "unexpected first verdict: $RESP1"
  exit 1
fi
ESCROW_ID=$(echo "$RESP1" | jq -r '.escrow.escrow_id // empty')
if [[ -z "$ESCROW_ID" ]]; then
  ESCROW_ID=$(curl -sS "$BASE/v1/escrows?status=PENDING&limit=1" | jq -r '.items[0].escrow_id // empty')
fi
if [[ -z "$ESCROW_ID" ]]; then
  echo "unable to resolve escrow id"
  echo "$RESP1"
  exit 1
fi

echo "[6/8] approve and execute escrow"
APPROVE_RESP=$(go run ./cmd/invariant escrow approve "$ESCROW_ID" --approver manager-1 --base "$BASE")
STATUS=$(echo "$APPROVE_RESP" | jq -r '.status // empty')
if [[ "$STATUS" == "APPROVED" ]]; then
  EXEC_RESP=$(go run ./cmd/invariant escrow execute "$ESCROW_ID" --base "$BASE")
  STATUS=$(echo "$EXEC_RESP" | jq -r '.status // empty')
fi
if [[ "$STATUS" != "CLOSED" && "$STATUS" != "EXECUTED" && "$STATUS" != "ROLLED_BACK" ]]; then
  echo "unexpected escrow status: $STATUS"
  exit 1
fi

echo "[7/8] invoke authorized action (expected ALLOW)"
REQ2=$(jq --arg idem "idem-allow-$TS" '.idempotency_key=$idem' scripts/demo_payloads/allow_request.json)
RESP2=$(echo "$REQ2" | curl -sS -X POST "$PROXY/tools/invoke" -H 'content-type: application/json' -d @-)
VERDICT2=$(echo "$RESP2" | jq -r '.verdict')
if [[ "$VERDICT2" != "ALLOW" ]]; then
  echo "expected ALLOW, got: $RESP2"
  exit 1
fi

echo "[8/8] audit replay"
DECISION_ID=$(curl -sS "$BASE/v1/verdicts?limit=50" | jq -r '.items[] | select(.verdict=="ALLOW") | .decision_id' | head -n 1)
if [[ -z "$DECISION_ID" ]]; then
  echo "could not find ALLOW decision id"
  exit 1
fi
REPLAY=$(curl -sS -X POST "$BASE/v1/audit/$DECISION_ID/replay")

cat <<OUTPUT
--- Demo Summary ---
First verdict: $VERDICT1
Escrow ID: $ESCROW_ID
Escrow final status: $STATUS
Second verdict: $VERDICT2
Replay decision_id: $DECISION_ID
Replay result: $(echo "$REPLAY" | jq -c '.')
DEMO_SUCCESS
OUTPUT
