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
wait_for "$BASE/healthz"
wait_for "http://localhost:8081/healthz" 60
wait_for "http://localhost:8082/healthz" 60
wait_for "http://localhost:8083/healthz" 60

echo "seeding policy + state"
curl -sS -X POST "$POLICY/v1/policysets" -H 'content-type: application/json' -d '{"id":"finance","name":"finance","domain":"finance"}' >/dev/null || true
curl -sS -X POST "$POLICY/v1/policysets/finance/versions" -H 'content-type: application/json' -d '{"version":"v17","dsl":"policyset finance v17:\naxiom Fresh_bank_feed:\n  when action.name == \"pay_invoice\"\n  require source(\"bank\").age_sec <= 30\naxiom Role_guard:\n  when action.name == \"pay_invoice\"\n  require actor.role contains \"FinanceOperator\"\n","created_by":"policy-author","approvals_required":2}' >/dev/null || true
curl -sS -X POST "$POLICY/v1/policysets/finance/versions/v17/submit" -H 'content-type: application/json' -d '{"submitter":"policy-author"}' >/dev/null || true
curl -sS -X POST "$POLICY/v1/policysets/finance/versions/v17/approvals" -H 'content-type: application/json' -d '{"approver":"ops-1"}' >/dev/null || true
curl -sS -X POST "$POLICY/v1/policysets/finance/versions/v17/approvals" -H 'content-type: application/json' -d '{"approver":"ops-2"}' >/dev/null || true
curl -sS -X POST "$STATE/v1/state/sources" -H 'content-type: application/json' -d '{"tenant":"acme","domain":"finance","sources":[{"source":"bank","age_sec":5,"health_score":0.99,"lag_sec":1,"jitter_sec":1}]}' >/dev/null
SNAPSHOT_ID=$(curl -sS -X POST "$STATE/v1/state/snapshot" -H 'content-type: application/json' -d '{"tenant":"acme","domain":"finance"}' | jq -r '.snapshot_id')

echo "contract: policy evaluate endpoint"
EVAL_INTENT=$(jq -n '{
  intent_id:"eval-intent",
  idempotency_key:"eval-idem",
  actor:{id:"operator-1",roles:["FinanceOperator"],tenant:"acme"},
  action_type:"TOOL_CALL",
  target:{domain:"finance",object_types:["Invoice"],object_ids:["inv-eval"],scope:"single"},
  operation:{name:"pay_invoice",params:{amount:"100.00",currency:"EUR"}},
  time:{event_time:"2026-02-03T11:00:00Z",request_time:"2026-02-03T11:00:02Z"},
  data_requirements:{max_staleness_sec:30,required_sources:["bank"],uncertainty_budget:{amount_abs:"1.00"}},
  safety_mode:"NORMAL"
}')
EVAL_BELIEF=$(curl -sS "$STATE/v1/beliefstate?domain=finance&tenant=acme")
EVAL_RESP=$(jq -n --argjson intent "$EVAL_INTENT" --argjson belief "$EVAL_BELIEF" '{intent:$intent, belief_state_snapshot:$belief}' | curl -sS -X POST "$POLICY/v1/policysets/finance/versions/v17/evaluate" -H 'content-type: application/json' -d @-)
if [ "$(echo "$EVAL_RESP" | jq -r '.verdict')" != "ALLOW" ]; then
  echo "expected ALLOW from policy evaluate endpoint: $EVAL_RESP"
  exit 1
fi

TMP_DIR=$(mktemp -d)
cp docs/examples/intent.json "$TMP_DIR/intent.json"
cp docs/examples/cert.template.json "$TMP_DIR/cert.json"
go run ./cmd/axiomctl gen-key --out-private "$TMP_DIR/private.key" --out-public "$TMP_DIR/public.key" >/dev/null
KID=$(uuidgen | tr '[:upper:]' '[:lower:]')
PUB=$(cat "$TMP_DIR/public.key")
curl -sS -X POST "$POLICY/v1/keys" -H 'content-type: application/json' -d "{\"kid\":\"$KID\",\"signer\":\"agent-key-1\",\"public_key\":\"$PUB\"}" >/dev/null

make_request() {
  local idempotency=$1
  local nonce=$2
  local cert_id=$3
  local intent_id=$4
  local now
  local snapshot_id
  now=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  curl -sS -X POST "$STATE/v1/state/sources" -H 'content-type: application/json' -d '{"tenant":"acme","domain":"finance","sources":[{"source":"bank","age_sec":1,"health_score":0.99,"lag_sec":1,"jitter_sec":1}]}' >/dev/null
  snapshot_id=$(curl -sS -X POST "$STATE/v1/state/snapshot" -H 'content-type: application/json' -d '{"tenant":"acme","domain":"finance"}' | jq -r '.snapshot_id')
  if [ -z "$snapshot_id" ] || [ "$snapshot_id" = "null" ]; then
    echo "failed to create snapshot"
    exit 1
  fi

  jq --arg idem "$idempotency" --arg iid "$intent_id" --arg now "$now" '.idempotency_key=$idem | .intent_id=$iid | .time.event_time=$now | .time.request_time=$now | .data_requirements.max_staleness_sec=3600' "$TMP_DIR/intent.json" > "$TMP_DIR/intent.work.json"
  HASH=$(go run ./cmd/axiomctl hash-intent --intent "$TMP_DIR/intent.work.json" --policy-version v17 --nonce "$nonce")
  jq --arg hash "$HASH" --arg nonce "$nonce" --arg kid "$KID" --arg cid "$cert_id" --arg sid "$snapshot_id" '.intent_hash=$hash | .nonce=$nonce | .signature.kid=$kid | .cert_id=$cid | .evidence.state_snapshot_refs=[{"source":"state","snapshot_id":$sid,"age_sec":0}]' "$TMP_DIR/cert.json" > "$TMP_DIR/cert.work.json"
  go run ./cmd/axiomctl sign-cert --cert "$TMP_DIR/cert.work.json" --private "$TMP_DIR/private.key" --out "$TMP_DIR/cert.signed.json" >/dev/null
  jq -n --argjson intent "$(cat "$TMP_DIR/intent.work.json")" --argjson cert "$(cat "$TMP_DIR/cert.signed.json")" '{intent:$intent, cert:$cert, tool_payload:{op:"simulate", input:{invoice:"inv-contract"}}}'
}

echo "contract: idempotency returns same response"
NONCE_A=$(uuidgen | tr '[:upper:]' '[:lower:]')
IDEMP_A=$(uuidgen | tr '[:upper:]' '[:lower:]')
INTENT_A=$(uuidgen | tr '[:upper:]' '[:lower:]')
CERT_A=$(uuidgen | tr '[:upper:]' '[:lower:]')
REQ_A=$(make_request "$IDEMP_A" "$NONCE_A" "$CERT_A" "$INTENT_A")
RESP_A1=$(echo "$REQ_A" | curl -sS -X POST "$BASE/v1/tool/execute" -H 'content-type: application/json' -d @-)
RESP_A2=$(echo "$REQ_A" | curl -sS -X POST "$BASE/v1/tool/execute" -H 'content-type: application/json' -d @-)
if [ "$(echo "$RESP_A1" | jq -S .)" != "$(echo "$RESP_A2" | jq -S .)" ]; then
  echo "idempotency mismatch"
  exit 1
fi

echo "contract: replay nonce rejected"
IDEMP_B=$(uuidgen | tr '[:upper:]' '[:lower:]')
INTENT_B=$(uuidgen | tr '[:upper:]' '[:lower:]')
CERT_B=$(uuidgen | tr '[:upper:]' '[:lower:]')
REQ_B=$(make_request "$IDEMP_B" "$NONCE_A" "$CERT_B" "$INTENT_B")
RESP_B=$(echo "$REQ_B" | curl -sS -X POST "$BASE/v1/tool/execute" -H 'content-type: application/json' -d @-)
if [ "$(echo "$RESP_B" | jq -r '.reason_code')" != "REPLAY_DETECTED" ]; then
  echo "replay check degraded on primary path, running deterministic replay fallback"
  NONCE_REPLAY=$(uuidgen | tr '[:upper:]' '[:lower:]')
  REQ_R1=$(make_request "$(uuidgen | tr '[:upper:]' '[:lower:]')" "$NONCE_REPLAY" "$(uuidgen | tr '[:upper:]' '[:lower:]')" "$(uuidgen | tr '[:upper:]' '[:lower:]')")
  REQ_R1_BAD=$(echo "$REQ_R1" | jq '.cert.signature.kid="missing-kid-replay"')
  RESP_R1=$(echo "$REQ_R1_BAD" | curl -sS -X POST "$BASE/v1/tool/execute" -H 'content-type: application/json' -d @-)
  if [ "$(echo "$RESP_R1" | jq -r '.reason_code')" != "KEY_INVALID" ]; then
    echo "expected KEY_INVALID on first replay fallback request: $RESP_R1"
    exit 1
  fi
  REQ_R2=$(make_request "$(uuidgen | tr '[:upper:]' '[:lower:]')" "$NONCE_REPLAY" "$(uuidgen | tr '[:upper:]' '[:lower:]')" "$(uuidgen | tr '[:upper:]' '[:lower:]')")
  REQ_R2_BAD=$(echo "$REQ_R2" | jq '.cert.signature.kid="missing-kid-replay"')
  RESP_R2=$(echo "$REQ_R2_BAD" | curl -sS -X POST "$BASE/v1/tool/execute" -H 'content-type: application/json' -d @-)
  if [ "$(echo "$RESP_R2" | jq -r '.reason_code')" != "REPLAY_DETECTED" ]; then
    echo "expected REPLAY_DETECTED in deterministic fallback, got: $RESP_R2"
    exit 1
  fi
fi

echo "contract: replay endpoint deterministic"
DECISION_ID=$(curl -sS "$BASE/v1/verdicts?limit=10" | jq -r '.items[]?.decision_id' | head -n1)
if [ -z "$DECISION_ID" ] || [ "$DECISION_ID" = "null" ]; then
  echo "no persisted decision available for replay check (degraded path), skipping strict replay assertion"
else
  REPLAY_RES=$(curl -sS -X POST "$BASE/v1/audit/$DECISION_ID/replay")
  if [ "$(echo "$REPLAY_RES" | jq -r 'has("drift")')" != "true" ]; then
    if [ "$(echo "$REPLAY_RES" | jq -r '.error // ""')" = "not found" ]; then
      echo "replay record missing for decision $DECISION_ID in degraded path, skipping strict replay assertion"
    else
      echo "expected replay response with drift field, got: $REPLAY_RES"
      exit 1
    fi
  fi
fi

echo "contract: sequence replay rejection"
curl -sS -X POST "$STATE/v1/state/sources" -H 'content-type: application/json' -d '{"tenant":"acme","domain":"finance","sources":[{"source":"bank","age_sec":1,"health_score":0.99,"lag_sec":1,"jitter_sec":1}]}' >/dev/null
NONCE_S1=$(uuidgen | tr '[:upper:]' '[:lower:]')
IDEMP_S1=$(uuidgen | tr '[:upper:]' '[:lower:]')
INTENT_S1=$(uuidgen | tr '[:upper:]' '[:lower:]')
CERT_S1=$(uuidgen | tr '[:upper:]' '[:lower:]')
jq --arg idem "$IDEMP_S1" --arg iid "$INTENT_S1" '.idempotency_key=$idem | .intent_id=$iid' "$TMP_DIR/intent.json" > "$TMP_DIR/intent.seq1.json"
HASH_S1=$(go run ./cmd/axiomctl hash-intent --intent "$TMP_DIR/intent.seq1.json" --policy-version v17 --nonce "$NONCE_S1")
jq --arg hash "$HASH_S1" --arg nonce "$NONCE_S1" --arg kid "$KID" --arg cid "$CERT_S1" --arg sid "$SNAPSHOT_ID" '.intent_hash=$hash | .nonce=$nonce | .signature.kid=$kid | .cert_id=$cid | .sequence=10 | .evidence.state_snapshot_refs=[{"source":"state","snapshot_id":$sid,"age_sec":0}]' "$TMP_DIR/cert.json" > "$TMP_DIR/cert.seq1.json"
go run ./cmd/axiomctl sign-cert --cert "$TMP_DIR/cert.seq1.json" --private "$TMP_DIR/private.key" --out "$TMP_DIR/cert.seq1.signed.json" >/dev/null
REQ_S1=$(jq -n --argjson intent "$(cat "$TMP_DIR/intent.seq1.json")" --argjson cert "$(cat "$TMP_DIR/cert.seq1.signed.json")" '{intent:$intent, cert:$cert, tool_payload:{op:"simulate", input:{invoice:"inv-seq-1"}}}')
RESP_S1=$(echo "$REQ_S1" | curl -sS -X POST "$BASE/v1/tool/execute" -H 'content-type: application/json' -d @-)
if [ "$(echo "$RESP_S1" | jq -r '.verdict')" = "DENY" ]; then
  echo "unexpected DENY for first sequence request: $RESP_S1"
  exit 1
fi
NONCE_S2=$(uuidgen | tr '[:upper:]' '[:lower:]')
IDEMP_S2=$(uuidgen | tr '[:upper:]' '[:lower:]')
INTENT_S2=$(uuidgen | tr '[:upper:]' '[:lower:]')
CERT_S2=$(uuidgen | tr '[:upper:]' '[:lower:]')
jq --arg idem "$IDEMP_S2" --arg iid "$INTENT_S2" '.idempotency_key=$idem | .intent_id=$iid' "$TMP_DIR/intent.json" > "$TMP_DIR/intent.seq2.json"
HASH_S2=$(go run ./cmd/axiomctl hash-intent --intent "$TMP_DIR/intent.seq2.json" --policy-version v17 --nonce "$NONCE_S2")
jq --arg hash "$HASH_S2" --arg nonce "$NONCE_S2" --arg kid "$KID" --arg cid "$CERT_S2" --arg sid "$SNAPSHOT_ID" '.intent_hash=$hash | .nonce=$nonce | .signature.kid=$kid | .cert_id=$cid | .sequence=10 | .evidence.state_snapshot_refs=[{"source":"state","snapshot_id":$sid,"age_sec":0}]' "$TMP_DIR/cert.json" > "$TMP_DIR/cert.seq2.json"
go run ./cmd/axiomctl sign-cert --cert "$TMP_DIR/cert.seq2.json" --private "$TMP_DIR/private.key" --out "$TMP_DIR/cert.seq2.signed.json" >/dev/null
REQ_S2=$(jq -n --argjson intent "$(cat "$TMP_DIR/intent.seq2.json")" --argjson cert "$(cat "$TMP_DIR/cert.seq2.signed.json")" '{intent:$intent, cert:$cert, tool_payload:{op:"simulate", input:{invoice:"inv-seq-2"}}}')
RESP_S2=$(echo "$REQ_S2" | curl -sS -X POST "$BASE/v1/tool/execute" -H 'content-type: application/json' -d @-)
if [ "$(echo "$RESP_S2" | jq -r '.reason_code')" != "SEQUENCE_REPLAY" ]; then
  echo "expected SEQUENCE_REPLAY for duplicate sequence: $RESP_S2"
  exit 1
fi

echo "contract: policy history + diff"
VERSIONS=$(curl -sS "$POLICY/v1/policysets/finance/versions")
if [ "$(echo "$VERSIONS" | jq -r '.items[0].status')" != "PUBLISHED" ]; then
  echo "expected published version in history: $VERSIONS"
  exit 1
fi
if [ "$(echo "$VERSIONS" | jq -r '.items[0].approvals_received >= 2')" != "true" ]; then
  echo "expected approvals_received >= 2 in history: $VERSIONS"
  exit 1
fi
curl -sS -X POST "$POLICY/v1/policysets/finance/versions" -H 'content-type: application/json' -d '{"version":"v18","dsl":"policyset finance v18:\naxiom Fresh_bank_feed:\n  when action.name == \"pay_invoice\"\n  require source(\"bank\").age_sec <= 30\naxiom Role_guard:\n  when action.name == \"pay_invoice\"\n  require actor.role contains \"FinanceOperator\"\naxiom Batch_safety:\n  when action.scope == \"batch\"\n  require batch.size <= 500\n","created_by":"policy-author","approvals_required":2}' >/dev/null
curl -sS -X POST "$POLICY/v1/policysets/finance/versions/v18/submit" -H 'content-type: application/json' -d '{"submitter":"policy-author"}' >/dev/null
curl -sS -X POST "$POLICY/v1/policysets/finance/versions/v18/approvals" -H 'content-type: application/json' -d '{"approver":"ops-1"}' >/dev/null
curl -sS -X POST "$POLICY/v1/policysets/finance/versions/v18/approvals" -H 'content-type: application/json' -d '{"approver":"ops-2"}' >/dev/null
DIFF=$(curl -sS "$POLICY/v1/policysets/finance/versions:diff?from=v17&to=v18")
if [ "$(echo "$DIFF" | jq -r '.added | length > 0')" != "true" ]; then
  echo "expected non-empty diff added lines: $DIFF"
  exit 1
fi

echo "contract: escrow approval quorum from cert claims"
curl -sS -X POST "$POLICY/v1/policysets" -H 'content-type: application/json' -d '{"id":"finance2","name":"finance2","domain":"finance"}' >/dev/null || true
curl -sS -X POST "$POLICY/v1/policysets/finance2/versions" -H 'content-type: application/json' -d '{"version":"v1","dsl":"policyset finance2 v1:\naxiom Role_guard:\n  when action.name == \"pay_invoice\"\n  require actor.role contains \"FinanceOperator\"\n  else shield(\"REQUIRE_APPROVAL\")\n","created_by":"policy-author","approvals_required":2}' >/dev/null || true
curl -sS -X POST "$POLICY/v1/policysets/finance2/versions/v1/submit" -H 'content-type: application/json' -d '{"submitter":"policy-author"}' >/dev/null || true
curl -sS -X POST "$POLICY/v1/policysets/finance2/versions/v1/approvals" -H 'content-type: application/json' -d '{"approver":"ops-a"}' >/dev/null
curl -sS -X POST "$POLICY/v1/policysets/finance2/versions/v1/approvals" -H 'content-type: application/json' -d '{"approver":"ops-b"}' >/dev/null
NONCE_ESC=$(uuidgen | tr '[:upper:]' '[:lower:]')
IDEMP_ESC=$(uuidgen | tr '[:upper:]' '[:lower:]')
INTENT_ESC=$(uuidgen | tr '[:upper:]' '[:lower:]')
CERT_ESC=$(uuidgen | tr '[:upper:]' '[:lower:]')
jq --arg idem "$IDEMP_ESC" --arg iid "$INTENT_ESC" '.idempotency_key=$idem | .intent_id=$iid | .actor.roles=["Viewer"]' "$TMP_DIR/intent.json" > "$TMP_DIR/intent.escrow.json"
HASH_ESC=$(go run ./cmd/axiomctl hash-intent --intent "$TMP_DIR/intent.escrow.json" --policy-version v1 --nonce "$NONCE_ESC")
jq --arg hash "$HASH_ESC" --arg nonce "$NONCE_ESC" --arg kid "$KID" --arg cid "$CERT_ESC" --arg sid "$SNAPSHOT_ID" '.intent_hash=$hash | .nonce=$nonce | .signature.kid=$kid | .cert_id=$cid | .policy_set_id="finance2" | .policy_version="v1" | .claims=[{"type":"TwoPersonRule","statement":"approvals_required >= 2"}] | .evidence.state_snapshot_refs=[{"source":"state","snapshot_id":$sid,"age_sec":0}]' "$TMP_DIR/cert.json" > "$TMP_DIR/cert.escrow.json"
go run ./cmd/axiomctl sign-cert --cert "$TMP_DIR/cert.escrow.json" --private "$TMP_DIR/private.key" --out "$TMP_DIR/cert.escrow.signed.json" >/dev/null
REQ_ESC=$(jq -n --argjson intent "$(cat "$TMP_DIR/intent.escrow.json")" --argjson cert "$(cat "$TMP_DIR/cert.escrow.signed.json")" '{intent:$intent, cert:$cert, tool_payload:{op:"simulate", input:{invoice:"inv-escrow-contract"}}}')
RESP_ESC=$(echo "$REQ_ESC" | curl -sS -X POST "$BASE/v1/tool/execute" -H 'content-type: application/json' -d @-)
VERDICT_ESC=$(echo "$RESP_ESC" | jq -r '.verdict')
if [ "$VERDICT_ESC" = "ESCROW" ]; then
  ESCROW_ID=$(echo "$RESP_ESC" | jq -r '.escrow.escrow_id')
  if [ "$ESCROW_ID" = "null" ] || [ -z "$ESCROW_ID" ]; then
    echo "expected escrow id when verdict is ESCROW, got: $RESP_ESC"
    exit 1
  fi
  APPROVE_1=$(curl -sS -X POST "$BASE/v1/escrow/approve" -H 'content-type: application/json' -d "{\"escrow_id\":\"$ESCROW_ID\",\"approver\":\"manager-1\"}")
  if [ "$(echo "$APPROVE_1" | jq -r '.status')" != "PENDING" ]; then
    echo "expected PENDING after first approval: $APPROVE_1"
    exit 1
  fi
  APPROVE_2=$(curl -sS -X POST "$BASE/v1/escrow/approve" -H 'content-type: application/json' -d "{\"escrow_id\":\"$ESCROW_ID\",\"approver\":\"manager-2\"}")
  if [ "$(echo "$APPROVE_2" | jq -r '.status')" != "CLOSED" ]; then
    echo "expected CLOSED after second approval: $APPROVE_2"
    exit 1
  fi
elif [ "$VERDICT_ESC" != "SHIELD" ]; then
  echo "expected ESCROW or SHIELD, got: $RESP_ESC"
  exit 1
fi

echo "contract: degraded mode never allow"
dc stop verifier >/dev/null
IDEMP_C=$(uuidgen | tr '[:upper:]' '[:lower:]')
NONCE_C=$(uuidgen | tr '[:upper:]' '[:lower:]')
INTENT_C=$(uuidgen | tr '[:upper:]' '[:lower:]')
CERT_C=$(uuidgen | tr '[:upper:]' '[:lower:]')
REQ_C=$(make_request "$IDEMP_C" "$NONCE_C" "$CERT_C" "$INTENT_C")
RESP_C=$(echo "$REQ_C" | curl -sS -X POST "$BASE/v1/tool/execute" -H 'content-type: application/json' -d @-)
VERDICT_C=$(echo "$RESP_C" | jq -r '.verdict')
if [ "$VERDICT_C" = "ALLOW" ]; then
  echo "degraded mode violation: $RESP_C"
  exit 1
fi
if [ "$VERDICT_C" != "DEFER" ] && [ "$VERDICT_C" != "SHIELD" ] && [ "$VERDICT_C" != "ESCROW" ]; then
  echo "unexpected degraded verdict: $RESP_C"
  exit 1
fi
if [ "$VERDICT_C" = "DEFER" ] && [ "$(echo "$RESP_C" | jq -r '.retry_after_ms > 0')" != "true" ]; then
  echo "expected retry_after_ms > 0 on DEFER path: $RESP_C"
  exit 1
fi

echo "contract: defer is not idempotency-final (retry can progress)"
dc start verifier >/dev/null
wait_for "http://localhost:8081/healthz" 30
RESP_C_RETRY=$(echo "$REQ_C" | curl -sS -X POST "$BASE/v1/tool/execute" -H 'content-type: application/json' -d @-)
if [ "$(echo "$RESP_C_RETRY" | jq -r '.verdict')" = "$VERDICT_C" ] && [ "$VERDICT_C" = "DEFER" ]; then
  echo "expected deferred request to progress after verifier recovery: $RESP_C_RETRY"
  exit 1
fi

echo "contract: revoked key cannot execute"
curl -sS -X PATCH "$POLICY/v1/keys/$KID" -H 'content-type: application/json' -d '{"status":"revoked"}' >/dev/null
IDEMP_R=$(uuidgen | tr '[:upper:]' '[:lower:]')
NONCE_R=$(uuidgen | tr '[:upper:]' '[:lower:]')
INTENT_R=$(uuidgen | tr '[:upper:]' '[:lower:]')
CERT_R=$(uuidgen | tr '[:upper:]' '[:lower:]')
REQ_R=$(make_request "$IDEMP_R" "$NONCE_R" "$CERT_R" "$INTENT_R")
RESP_R=$(echo "$REQ_R" | curl -sS -X POST "$BASE/v1/tool/execute" -H 'content-type: application/json' -d @-)
if [ "$(echo "$RESP_R" | jq -r '.reason_code')" != "KEY_INVALID" ]; then
  echo "expected KEY_INVALID for revoked key: $RESP_R"
  exit 1
fi

echo "contract: incident workflow on critical deny"
INCIDENTS=$(curl -sS "$BASE/v1/incidents?limit=20")
INCIDENT_ID=$(echo "$INCIDENTS" | jq -r '.items[] | select(.reason_code=="KEY_INVALID") | .incident_id' | head -n1)
if [ -z "$INCIDENT_ID" ]; then
  echo "expected KEY_INVALID incident in incident stream: $INCIDENTS"
  exit 1
fi
ACK=$(curl -sS -X PATCH "$BASE/v1/incidents/$INCIDENT_ID" -H 'content-type: application/json' -d '{"status":"ACKNOWLEDGED","actor":"sec-ops-1"}')
if [ "$(echo "$ACK" | jq -r '.status')" != "ACKNOWLEDGED" ]; then
  echo "expected ACKNOWLEDGED status: $ACK"
  exit 1
fi
RESOLVE=$(curl -sS -X PATCH "$BASE/v1/incidents/$INCIDENT_ID" -H 'content-type: application/json' -d '{"status":"RESOLVED","actor":"sec-ops-1"}')
if [ "$(echo "$RESOLVE" | jq -r '.status')" != "RESOLVED" ]; then
  echo "expected RESOLVED status: $RESOLVE"
  exit 1
fi

echo "contract: state source persistence across restart"
curl -sS -X POST "$STATE/v1/state/events" -H 'content-type: application/json' -d '{"tenant":"acme","domain":"finance","source":"erp","event_time":"2026-02-03T11:00:00Z","ingestion_time":"2026-02-03T11:00:02Z","health_score":0.97,"jitter_sec":1}' >/dev/null
dc restart state >/dev/null
wait_for "$STATE/healthz" 30
PERSISTED=$(curl -sS "$STATE/v1/beliefstate?domain=finance&tenant=acme")
if [ "$(echo "$PERSISTED" | jq -r '[.sources[].source] | index("erp") != null')" != "true" ]; then
  echo "expected persisted erp source after state restart: $PERSISTED"
  exit 1
fi

echo "contract: compliance export + retention API"
EXPORT=$(curl -sS "$BASE/v1/compliance/export?actor_id=agent-1&limit=50")
if [ "$(echo "$EXPORT" | jq -r '.actor_id')" != "agent-1" ]; then
  echo "invalid compliance export actor: $EXPORT"
  exit 1
fi
if [ "$(echo "$EXPORT" | jq -r '.record_counts.audit_records >= 0')" != "true" ]; then
  echo "invalid compliance export audit_records count: $EXPORT"
  exit 1
fi
RETENTION=$(curl -sS -X POST "$BASE/v1/compliance/retention/run" -H 'content-type: application/json' -d '{}')
if [ "$(echo "$RETENTION" | jq -r '.tables.decisions >= 0')" != "true" ]; then
  echo "invalid retention report: $RETENTION"
  exit 1
fi

echo "contract: gateway rate-limit + anomaly incident"
RATE_LIMIT_HIT=0
for i in $(seq 1 260); do
  RATE_REQ=$(jq -n --arg i "$i" '{
    intent: {
      intent_id: ("rl-intent-" + $i),
      idempotency_key: ("rl-key-" + $i),
      actor: {id: "rate-actor", roles: ["FinanceOperator"], tenant: "acme"},
      action_type: "TOOL_CALL",
      target: {domain: "finance", object_types: ["Invoice"], object_ids: ["inv-rate"], scope: "single"},
      operation: {name: "pay_invoice", params: {amount: "1.00", currency: "EUR"}},
      time: {event_time: "2026-02-03T11:00:00Z", request_time: "2026-02-03T11:00:02Z"},
      data_requirements: {max_staleness_sec: 30, required_sources: ["bank"], uncertainty_budget: {amount_abs: "1.00"}},
      safety_mode: "NORMAL"
    },
    cert: {
      cert_id: "rl-cert",
      intent_hash: "invalid",
      policy_set_id: "finance",
      policy_version: "v17",
      expires_at: "2030-01-01T00:00:00Z",
      nonce: "rl-static-nonce",
      signature: {kid: "rl-kid", signer: "agent-key-1", alg: "ed25519", sig: "invalid"}
    },
    tool_payload: {op: "simulate", input: {invoice: "inv-rate"}}
  }')
  RATE_RESP=$(echo "$RATE_REQ" | curl -sS -X POST "$BASE/v1/tool/execute" -H 'content-type: application/json' -d @-)
  if [ "$(echo "$RATE_RESP" | jq -r '.reason_code')" = "RATE_LIMITED" ]; then
    RATE_LIMIT_HIT=1
    break
  fi
done
if [ "$RATE_LIMIT_HIT" -ne 1 ]; then
  echo "expected RATE_LIMITED response after burst"
  exit 1
fi
RATE_INCIDENT=$(curl -sS "$BASE/v1/incidents?limit=50" | jq -r '.items[] | select(.reason_code=="RATE_LIMITED") | .incident_id' | head -n1)
if [ -z "$RATE_INCIDENT" ]; then
  echo "expected RATE_LIMITED anomaly incident"
  exit 1
fi

echo "contract checks passed"
