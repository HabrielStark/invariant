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
BASE=${BASE:-http://localhost:8080}
POLICY=${POLICY:-http://localhost:8082}
STATE=${STATE:-http://localhost:8083}
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

need() { command -v "$1" >/dev/null || { echo "missing $1"; exit 1; }; }
need curl
need jq
need uuidgen
need go
need docker

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

wait_for_redis() {
  local max=${1:-30}
  local i=0
  until dc exec -T redis redis-cli ping >/dev/null 2>&1; do
    i=$((i+1))
    if [ "$i" -ge "$max" ]; then
      echo "timeout waiting for redis"
      return 1
    fi
    sleep 1
  done
}

echo "bringing up stack"
dc up -d --build
wait_for "$BASE/healthz"

echo "seeding policy + state"
curl -sS -X POST "$POLICY/v1/policysets" -H 'content-type: application/json' -d '{"id":"finance","name":"finance","domain":"finance"}' >/dev/null || true
curl -sS -X POST "$POLICY/v1/policysets/finance/versions" -H 'content-type: application/json' -d '{"version":"v17","dsl":"policyset finance v17:\naxiom Fresh_bank_feed:\n  when action.name == \"pay_invoice\"\n  require source(\"bank\").age_sec <= 30\naxiom Role_guard:\n  when action.name == \"pay_invoice\"\n  require actor.role contains \"FinanceOperator\"\n","created_by":"policy-author","approvals_required":2}' >/dev/null || true
curl -sS -X POST "$POLICY/v1/policysets/finance/versions/v17/submit" -H 'content-type: application/json' -d '{"submitter":"policy-author"}' >/dev/null || true
curl -sS -X POST "$POLICY/v1/policysets/finance/versions/v17/approvals" -H 'content-type: application/json' -d '{"approver":"ops-1"}' >/dev/null || true
curl -sS -X POST "$POLICY/v1/policysets/finance/versions/v17/approvals" -H 'content-type: application/json' -d '{"approver":"ops-2"}' >/dev/null || true
curl -sS -X POST "$STATE/v1/state/sources" -H 'content-type: application/json' -d '{"tenant":"acme","domain":"finance","sources":[{"source":"bank","age_sec":5,"health_score":0.99,"lag_sec":1,"jitter_sec":1}]}' >/dev/null
SNAPSHOT_ID=$(curl -sS -X POST "$STATE/v1/state/snapshot" -H 'content-type: application/json' -d '{"tenant":"acme","domain":"finance"}' | jq -r '.snapshot_id')

TMP_DIR=$(mktemp -d)
cp docs/examples/intent.json "$TMP_DIR/intent.json"
cp docs/examples/cert.template.json "$TMP_DIR/cert.json"
go run ./cmd/axiomctl gen-key --out-private "$TMP_DIR/private.key" --out-public "$TMP_DIR/public.key" >/dev/null
KID=$(uuidgen | tr '[:upper:]' '[:lower:]')
PUB=$(cat "$TMP_DIR/public.key")
curl -sS -X POST "$POLICY/v1/keys" -H 'content-type: application/json' -d "{\"kid\":\"$KID\",\"signer\":\"agent-key-1\",\"public_key\":\"$PUB\"}" >/dev/null

make_request() {
  local nonce=$1
  local idempotency=$2
  local intent_id=$3
  local cert_id=$4
  local max_stale=${5:-30}
  local required=${6:-'["bank"]'}
  local policy_version=${7:-"v17"}
  local roles=${8:-'["FinanceOperator"]'}
  local expires_override=${9:-""}

  jq --arg idem "$idempotency" --arg iid "$intent_id" --argjson req "$required" --argjson stale "$max_stale" --argjson roles "$roles" '.idempotency_key=$idem | .intent_id=$iid | .data_requirements.required_sources=$req | .data_requirements.max_staleness_sec=$stale | .actor.roles=$roles' "$TMP_DIR/intent.json" > "$TMP_DIR/intent.work.json"
  if [ -n "$expires_override" ]; then
    EXP="$expires_override"
  else
    EXP=$(date -u -v+10M +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || python3 - <<'PY'
import datetime
print((datetime.datetime.utcnow()+datetime.timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%SZ"))
PY
)
  fi
  HASH=$(go run ./cmd/axiomctl hash-intent --intent "$TMP_DIR/intent.work.json" --policy-version "$policy_version" --nonce "$nonce")
  jq --arg hash "$HASH" --arg nonce "$nonce" --arg kid "$KID" --arg cid "$cert_id" --arg sid "$SNAPSHOT_ID" --arg exp "$EXP" --arg pv "$policy_version" '.intent_hash=$hash | .nonce=$nonce | .signature.kid=$kid | .cert_id=$cid | .expires_at=$exp | .policy_version=$pv | .evidence.state_snapshot_refs=[{"source":"state","snapshot_id":$sid,"age_sec":0}]' "$TMP_DIR/cert.json" > "$TMP_DIR/cert.work.json"
  go run ./cmd/axiomctl sign-cert --cert "$TMP_DIR/cert.work.json" --private "$TMP_DIR/private.key" --out "$TMP_DIR/cert.signed.json" >/dev/null
  jq -n --argjson intent "$(cat "$TMP_DIR/intent.work.json")" --argjson cert "$(cat "$TMP_DIR/cert.signed.json")" '{intent:$intent, cert:$cert, tool_payload:{op:"simulate", input:{invoice:"inv-chaos"}}}'
}

echo "chaos: stale source should not ALLOW"
curl -sS -X POST "$STATE/v1/state/sources" -H 'content-type: application/json' -d '{"tenant":"acme","domain":"finance","sources":[{"source":"bank","age_sec":600,"health_score":0.99,"lag_sec":1,"jitter_sec":1}]}' >/dev/null
REQ_STALE=$(make_request "$(uuidgen | tr '[:upper:]' '[:lower:]')" "$(uuidgen | tr '[:upper:]' '[:lower:]')" "$(uuidgen | tr '[:upper:]' '[:lower:]')" "$(uuidgen | tr '[:upper:]' '[:lower:]')" 30 '["bank"]')
RESP_STALE=$(echo "$REQ_STALE" | curl -sS -X POST "$BASE/v1/tool/execute" -H 'content-type: application/json' -d @-)
V_STALE=$(echo "$RESP_STALE" | jq -r '.verdict')
if [ "$V_STALE" = "ALLOW" ]; then
  echo "stale state must not ALLOW: $RESP_STALE"
  exit 1
fi

echo "chaos: missing required source should not ALLOW"
curl -sS -X POST "$STATE/v1/state/sources" -H 'content-type: application/json' -d '{"tenant":"acme","domain":"finance","sources":[{"source":"bank","age_sec":5,"health_score":0.99,"lag_sec":1,"jitter_sec":1}]}' >/dev/null
REQ_MISSING=$(make_request "$(uuidgen | tr '[:upper:]' '[:lower:]')" "$(uuidgen | tr '[:upper:]' '[:lower:]')" "$(uuidgen | tr '[:upper:]' '[:lower:]')" "$(uuidgen | tr '[:upper:]' '[:lower:]')" 30 '["bank","erp"]')
RESP_MISSING=$(echo "$REQ_MISSING" | curl -sS -X POST "$BASE/v1/tool/execute" -H 'content-type: application/json' -d @-)
V_MISSING=$(echo "$RESP_MISSING" | jq -r '.verdict')
if [ "$V_MISSING" = "ALLOW" ]; then
  echo "missing required source must not ALLOW: $RESP_MISSING"
  exit 1
fi

echo "chaos: expired cert should DENY"
EXP_PAST=$(date -u -v-5M +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || python3 - <<'PY'
import datetime
print((datetime.datetime.utcnow()-datetime.timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ"))
PY
)
REQ_EXPIRED=$(make_request "$(uuidgen | tr '[:upper:]' '[:lower:]')" "$(uuidgen | tr '[:upper:]' '[:lower:]')" "$(uuidgen | tr '[:upper:]' '[:lower:]')" "$(uuidgen | tr '[:upper:]' '[:lower:]')" 30 '["bank"]' "v17" '["FinanceOperator"]' "$EXP_PAST")
RESP_EXPIRED=$(echo "$REQ_EXPIRED" | curl -sS -X POST "$BASE/v1/tool/execute" -H 'content-type: application/json' -d @-)
V_EXPIRED=$(echo "$RESP_EXPIRED" | jq -r '.verdict')
R_EXPIRED=$(echo "$RESP_EXPIRED" | jq -r '.reason_code')
if [ "$V_EXPIRED" != "DENY" ] || [ "$R_EXPIRED" != "CERT_EXPIRED" ]; then
  echo "expired cert should DENY with CERT_EXPIRED: $RESP_EXPIRED"
  exit 1
fi

echo "chaos: redis unavailable should not ALLOW"
dc stop redis >/dev/null
REQ_REDIS=$(make_request "$(uuidgen | tr '[:upper:]' '[:lower:]')" "$(uuidgen | tr '[:upper:]' '[:lower:]')" "$(uuidgen | tr '[:upper:]' '[:lower:]')" "$(uuidgen | tr '[:upper:]' '[:lower:]')" 30 '["bank"]')
RESP_REDIS=$(echo "$REQ_REDIS" | curl -sS -X POST "$BASE/v1/tool/execute" -H 'content-type: application/json' -d @-)
V_REDIS=$(echo "$RESP_REDIS" | jq -r '.verdict')
if [ "$V_REDIS" = "ALLOW" ]; then
  echo "redis down must not ALLOW: $RESP_REDIS"
  exit 1
fi
dc start redis >/dev/null
wait_for_redis 30

echo "chaos: concurrent approvals should settle escrow"
curl -sS -X POST "$POLICY/v1/policysets/finance/versions" -H 'content-type: application/json' -d '{"version":"v18","dsl":"policyset finance v18:\naxiom Require_approval:\n  when action.name == \"pay_invoice\"\n  require actor.role contains \"FinanceOperator\"\n  else shield(\"REQUIRE_APPROVAL\")\n","created_by":"policy-author","approvals_required":2}' >/dev/null || true
curl -sS -X POST "$POLICY/v1/policysets/finance/versions/v18/submit" -H 'content-type: application/json' -d '{"submitter":"policy-author"}' >/dev/null || true
curl -sS -X POST "$POLICY/v1/policysets/finance/versions/v18/approvals" -H 'content-type: application/json' -d '{"approver":"ops-1"}' >/dev/null || true
curl -sS -X POST "$POLICY/v1/policysets/finance/versions/v18/approvals" -H 'content-type: application/json' -d '{"approver":"ops-2"}' >/dev/null || true
REQ_ESCROW=$(make_request "$(uuidgen | tr '[:upper:]' '[:lower:]')" "$(uuidgen | tr '[:upper:]' '[:lower:]')" "$(uuidgen | tr '[:upper:]' '[:lower:]')" "$(uuidgen | tr '[:upper:]' '[:lower:]')" 30 '["bank"]' "v18" '["Requester"]')
RESP_ESCROW=$(echo "$REQ_ESCROW" | curl -sS -X POST "$BASE/v1/tool/execute" -H 'content-type: application/json' -d @-)
V_ESCROW=$(echo "$RESP_ESCROW" | jq -r '.verdict')
if [ "$V_ESCROW" = "ESCROW" ]; then
  ESCROW_ID=$(echo "$RESP_ESCROW" | jq -r '.escrow.escrow_id')
  if [ -z "$ESCROW_ID" ] || [ "$ESCROW_ID" = "null" ]; then
    echo "expected escrow id when verdict is ESCROW: $RESP_ESCROW"
    exit 1
  fi
  curl -sS -X POST "$BASE/v1/escrow/approve" -H 'content-type: application/json' -d "{\"escrow_id\":\"$ESCROW_ID\",\"approver\":\"ops-1\"}" >/dev/null &
  curl -sS -X POST "$BASE/v1/escrow/approve" -H 'content-type: application/json' -d "{\"escrow_id\":\"$ESCROW_ID\",\"approver\":\"ops-2\"}" >/dev/null &
  wait
  ESCROW_STATUS=$(curl -sS "$BASE/v1/escrow/$ESCROW_ID" | jq -r '.status')
  if [ "$ESCROW_STATUS" != "CLOSED" ] && [ "$ESCROW_STATUS" != "EXECUTED" ]; then
    echo "escrow did not close: $ESCROW_STATUS"
    exit 1
  fi
elif [ "$V_ESCROW" != "SHIELD" ]; then
  echo "expected escrow or shield verdict for approvals: $RESP_ESCROW"
  exit 1
fi

echo "chaos: verifier outage should degrade without ALLOW"
dc stop verifier >/dev/null
REQ_DEG=$(make_request "$(uuidgen | tr '[:upper:]' '[:lower:]')" "$(uuidgen | tr '[:upper:]' '[:lower:]')" "$(uuidgen | tr '[:upper:]' '[:lower:]')" "$(uuidgen | tr '[:upper:]' '[:lower:]')" 30 '["bank"]')
RESP_DEG=$(echo "$REQ_DEG" | curl -sS -X POST "$BASE/v1/tool/execute" -H 'content-type: application/json' -d @-)
V_DEG=$(echo "$RESP_DEG" | jq -r '.verdict')
if [ "$V_DEG" = "ALLOW" ]; then
  echo "degraded mode violation: $RESP_DEG"
  exit 1
fi
if [ "$V_DEG" != "SHIELD" ] && [ "$V_DEG" != "DEFER" ] && [ "$V_DEG" != "ESCROW" ]; then
  echo "unexpected degraded verdict: $RESP_DEG"
  exit 1
fi

echo "chaos checks passed"
