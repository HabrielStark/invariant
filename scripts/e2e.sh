#!/usr/bin/env bash
set -euo pipefail

BASE=${BASE:-http://localhost:8080}
POLICY=${POLICY:-http://localhost:8082}
STATE=${STATE:-http://localhost:8083}

if ! command -v curl >/dev/null; then
  echo "curl is required"
  exit 1
fi

# create policyset
curl -sS -X POST "$POLICY/v1/policysets" -H 'content-type: application/json' -d '{"id":"finance","name":"finance","domain":"finance"}' >/dev/null || true

# publish draft policy
curl -sS -X POST "$POLICY/v1/policysets/finance/versions" -H 'content-type: application/json' -d '{"version":"v17","dsl":"policyset finance v17:\naxiom Fresh_bank_feed:\n  when action.name == \"pay_invoice\"\n  require source(\"bank\").age_sec <= 30\naxiom Role_guard:\n  when action.name == \"pay_invoice\"\n  require actor.role contains \"FinanceOperator\"\n","created_by":"policy-author","approvals_required":2}' >/dev/null
curl -sS -X POST "$POLICY/v1/policysets/finance/versions/v17/submit" -H 'content-type: application/json' -d '{"submitter":"policy-author"}' >/dev/null
curl -sS -X POST "$POLICY/v1/policysets/finance/versions/v17/approvals" -H 'content-type: application/json' -d '{"approver":"ops-1"}' >/dev/null
curl -sS -X POST "$POLICY/v1/policysets/finance/versions/v17/approvals" -H 'content-type: application/json' -d '{"approver":"ops-2"}' >/dev/null

# ingest state
curl -sS -X POST "$STATE/v1/state/sources" -H 'content-type: application/json' -d '{"tenant":"acme","domain":"finance","sources":[{"source":"bank","age_sec":5,"health_score":0.99,"lag_sec":1,"jitter_sec":1}]}' >/dev/null

echo "E2E setup complete. To execute signed requests, register key and submit certs via gateway APIs."
