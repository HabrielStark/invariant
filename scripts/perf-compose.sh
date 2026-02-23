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
VERIFY_URL=${VERIFY_URL:-http://localhost:8081/v1/verify}
SAMPLES=${SAMPLES:-200}
WARMUP=${WARMUP:-20}
P95_BUDGET_MS=${P95_BUDGET_MS:-150}
P99_BUDGET_MS=${P99_BUDGET_MS:-250}
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
need python3
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

load_env_value() {
  local key=$1
  local file=$2
  if [ ! -f "$file" ]; then
    return 0
  fi
  grep -E "^${key}=" "$file" | tail -n1 | cut -d'=' -f2-
}

if [ -z "${VERIFIER_AUTH_HEADER:-}" ]; then
  VERIFIER_AUTH_HEADER=$(load_env_value VERIFIER_AUTH_HEADER "$ENV_FILE")
fi
if [ -z "${VERIFIER_AUTH_TOKEN:-}" ]; then
  VERIFIER_AUTH_TOKEN=$(load_env_value VERIFIER_AUTH_TOKEN "$ENV_FILE")
fi
VERIFY_AUTH_ARGS=()
if [ -n "${VERIFIER_AUTH_HEADER:-}" ] && [ -n "${VERIFIER_AUTH_TOKEN:-}" ]; then
  VERIFY_AUTH_ARGS=(-H "${VERIFIER_AUTH_HEADER}: ${VERIFIER_AUTH_TOKEN}")
fi

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
BELIEF=$(curl -sS "$STATE/v1/beliefstate?domain=finance&tenant=acme")

TMP_DIR=$(mktemp -d)
cp docs/examples/intent.json "$TMP_DIR/intent.json"
cp docs/examples/cert.template.json "$TMP_DIR/cert.json"
NOW=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
jq --arg now "$NOW" '.time.event_time=$now | .time.request_time=$now | .data_requirements.max_staleness_sec=3600' "$TMP_DIR/intent.json" > "$TMP_DIR/intent.work.json"
mv "$TMP_DIR/intent.work.json" "$TMP_DIR/intent.json"
go run ./cmd/axiomctl gen-key --out-private "$TMP_DIR/private.key" --out-public "$TMP_DIR/public.key" >/dev/null
KID=$(uuidgen | tr '[:upper:]' '[:lower:]')
PUB=$(cat "$TMP_DIR/public.key")
curl -sS -X POST "$POLICY/v1/keys" -H 'content-type: application/json' -d "{\"kid\":\"$KID\",\"signer\":\"agent-key-1\",\"public_key\":\"$PUB\"}" >/dev/null

NONCE=$(uuidgen | tr '[:upper:]' '[:lower:]')
EXP=$(date -u -v+10M +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || python3 - <<'PY'
import datetime
print((datetime.datetime.utcnow()+datetime.timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%SZ"))
PY
)
HASH=$(go run ./cmd/axiomctl hash-intent --intent "$TMP_DIR/intent.json" --policy-version v17 --nonce "$NONCE")
jq --arg hash "$HASH" --arg nonce "$NONCE" --arg kid "$KID" --arg exp "$EXP" '.intent_hash=$hash | .nonce=$nonce | .expires_at=$exp | .signature.kid=$kid' "$TMP_DIR/cert.json" > "$TMP_DIR/cert.work.json"
go run ./cmd/axiomctl sign-cert --cert "$TMP_DIR/cert.work.json" --private "$TMP_DIR/private.key" --out "$TMP_DIR/cert.signed.json" >/dev/null

VERIFY_PAYLOAD=$(jq -n --argjson intent "$(cat "$TMP_DIR/intent.json")" --argjson cert "$(cat "$TMP_DIR/cert.signed.json")" --argjson belief "$BELIEF" '{intent:$intent, cert:$cert, belief_state_snapshot:$belief}')

echo "warmup ($WARMUP requests)"
for _ in $(seq 1 "$WARMUP"); do
  attempts=0
  while true; do
    attempts=$((attempts+1))
    if ! curl -sS -o "$TMP_DIR/warmup.json" -X POST "$VERIFY_URL" -H 'content-type: application/json' "${VERIFY_AUTH_ARGS[@]}" -d "$VERIFY_PAYLOAD"; then
      if [ "$attempts" -ge 20 ]; then
        echo "warmup verify failed after retries"
        exit 1
      fi
      sleep 0.2
      continue
    fi
    if [ "$(jq -r '.error // ""' "$TMP_DIR/warmup.json")" = "verifier unavailable" ]; then
      if [ "$attempts" -ge 20 ]; then
        echo "warmup verifier unavailable after retries: $(cat "$TMP_DIR/warmup.json")"
        exit 1
      fi
      sleep 0.2
      continue
    fi
    break
  done
 done

LAT_FILE="$TMP_DIR/latencies_ms.txt"
: > "$LAT_FILE"

echo "measuring verify latency ($SAMPLES requests)"
for _ in $(seq 1 "$SAMPLES"); do
  attempts=0
  while true; do
    attempts=$((attempts+1))
    if ! ms=$(curl -sS -o "$TMP_DIR/resp.json" -w '%{time_total}' -X POST "$VERIFY_URL" -H 'content-type: application/json' "${VERIFY_AUTH_ARGS[@]}" -d "$VERIFY_PAYLOAD"); then
      if [ "$attempts" -ge 20 ]; then
        echo "verify request failed after retries"
        exit 1
      fi
      sleep 0.2
      continue
    fi
    if [ "$(jq -r '.error // ""' "$TMP_DIR/resp.json")" = "verifier unavailable" ]; then
      if [ "$attempts" -ge 20 ]; then
        echo "verifier unavailable after retries during perf sample: $(cat "$TMP_DIR/resp.json")"
        exit 1
      fi
      sleep 0.2
      continue
    fi
    verdict=$(jq -r '.verdict // ""' "$TMP_DIR/resp.json")
    if [ -z "$verdict" ]; then
      echo "expected verifier verdict during perf run, got: $(cat "$TMP_DIR/resp.json")"
      exit 1
    fi
    python3 - "$ms" >> "$LAT_FILE" <<'PY'
import sys
print(round(float(sys.argv[1]) * 1000.0, 3))
PY
    break
  done
done

python3 - "$LAT_FILE" "$P95_BUDGET_MS" "$P99_BUDGET_MS" <<'PY'
import sys
from statistics import mean
path = sys.argv[1]
p95_budget = float(sys.argv[2])
p99_budget = float(sys.argv[3])
values = []
with open(path, 'r', encoding='utf-8') as f:
    for line in f:
        line = line.strip()
        if line:
            values.append(float(line))
if not values:
    raise SystemExit('no samples')
values.sort()
def pct(p):
    i = int((p/100.0) * len(values))
    if i >= len(values):
        i = len(values)-1
    return values[i]
print(f"samples={len(values)} avg_ms={mean(values):.3f} p50_ms={pct(50):.3f} p95_ms={pct(95):.3f} p99_ms={pct(99):.3f} max_ms={max(values):.3f}")
if pct(95) > p95_budget:
    raise SystemExit(f"p95 budget failed: {pct(95):.3f} > {p95_budget}")
if pct(99) > p99_budget:
    raise SystemExit(f"p99 budget failed: {pct(99):.3f} > {p99_budget}")
PY

echo "perf checks passed"
