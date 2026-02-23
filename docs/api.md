# AxiomOS API (MVP)

## Health
- `GET /healthz` on each service (`gateway`, `verifier`, `policy`, `state`, `tool-mock`, `mock-ontology`)

## Gateway
- `GET /metrics`
- `GET /metrics/prometheus`
- `GET /v1/stream` (WebSocket event stream)
- `POST /v1/tool/execute`
- `POST /v1/ontology/actions/execute`
- `POST /v1/verify` (proxy only)
- `POST /v1/escrow/approve`
- `POST /v1/escrow/cancel`
- `POST /v1/escrow/rollback`
- `GET /v1/escrow/{escrow_id}`
- `GET /v1/escrows?status=&limit=`
- `GET /v1/beliefstate?domain=...` (gateway proxy to state)
- `GET /v1/verdicts?limit=`
- `GET /v1/incidents?status=&limit=`
- `PATCH /v1/incidents/{incident_id}`
- `GET /v1/compliance/export?actor_id=&limit=`
  - includes `subject_restrictions` and `record_counts.active_subject_restrictions`
- `GET /v1/compliance/subjects/restrictions?actor_id=&limit=`
- `POST /v1/compliance/subjects/restrict`
- `POST /v1/compliance/subjects/unrestrict`
- `POST /v1/compliance/retention/run`
- `GET /v1/audit/{decision_id}`
- `POST /v1/audit/{decision_id}/replay`

Gateway ABAC runtime guards (when auth enabled):
- actor binding (`principal.sub == intent.actor.id`) unless elevated role
- tenant match (`principal.tenant == intent.actor.tenant`) unless elevated role
- domain role allow-list by env `ABAC_DOMAIN_ROLES`
- policy ABAC rules (`abac allow/deny`) evaluated before verification
- dynamic attribute resolution via `ABAC_ATTR_URL` with cache TTL `ABAC_ATTR_CACHE_TTL_SEC`

`GatewayResponse` fields:
- `verdict`, `reason_code`
- optional `retry_after_ms` (for `DEFER` and `RATE_LIMITED`)
- optional `result`, `shield`, `escrow`, `counterexample`

`GET /metrics` returns JSON counters for:
- endpoint count/error/latency aggregates
- verdict distribution
- reason-code distribution

### Ontology adapter payloads
For the default HTTP/mock adapter, `action_payload` is passed through to `ONTOLOGY_URL + /actions/execute`.

For Foundry adapter (`ONTOLOGY_ADAPTER=foundry`), `action_payload` accepts:
```json
{
  "ontology": "finance",
  "action": "pay_invoice",
  "parameters": { "invoice_id": "inv-1", "amount": "10.00" },
  "mode": "DRY_RUN"
}
```
Batch execution uses:
```json
{
  "ontology": "finance",
  "action": "change_status",
  "batch": [
    { "id": "inv-1", "status": "PAID" },
    { "id": "inv-2", "status": "PAID" }
  ]
}
```
`mode=DRY_RUN` or `READ_ONLY` sets `dryRun` / `previewOnly` for Foundry apply requests.

## Verifier
- `POST /v1/verify`
- Verifier runtime SMT options (env):
  - `SMT_ENABLED=true|false`
  - `SMT_BACKEND=z3cgo|z3|z3exec|go`
  - `SMT_TIMEOUT_MS=50`
  - `Z3_PATH=/usr/bin/z3`

## Policy
- `POST /v1/policysets`
- `POST /v1/policysets/{id}/versions`
- `GET /v1/policysets/{id}/versions`
- `GET /v1/policysets/{id}/versions:diff?from=vX&to=vY`
- `POST /v1/policysets/{id}/versions/{version}/submit`
- `POST /v1/policysets/{id}/versions/{version}/approvals`
- `POST /v1/policysets/{id}/versions/{version}/approve` (alias, compatibility)
- `GET /v1/policysets/{id}/versions/{version}/approvals`
- `POST /v1/policysets/{id}/versions/{version}/evaluate`
- `GET /v1/policysets/{id}/versions/{version}`

Policy versions are created as `DRAFT`, then `PENDING_APPROVAL`, then `PUBLISHED` after quorum.
`created_by` cannot approve the same version (SoD).
Create version payload fields:
- `version`, `dsl`, `created_by`, optional `approvals_required` (default `2`).
`GET /v1/policysets/{id}/versions` returns version history with status and approval counters.
`GET /v1/policysets/{id}/versions:diff` returns normalized line-level `added` / `removed`.
- `POST /v1/keys`
- `GET /v1/keys?status=&limit=`
- `GET /v1/keys/{kid}`
- `PATCH /v1/keys/{kid}`

## State
- `POST /v1/state/sources` (test ingest)
- `POST /v1/state/events` (event-time ingest)
- `POST /v1/state/snapshot`
- `GET /v1/state/snapshot/{snapshot_id}`
- `GET /v1/beliefstate?domain=...`

`POST /v1/audit/{decision_id}/replay` re-runs verifier with `replay=true` and the stored intent/cert plus snapshot refs from cert evidence (if available). Response includes `original`, `replay`, and `drift`.

## Canonical Hash
- Intent hash = `sha256( Canonical(ActionIntent) + "|" + policy_version + "|" + cert.nonce )`
- Canonical JSON uses RFC 8785.
- Floating-point JSON tokens are rejected; non-integers must be encoded as decimal strings.

## Models
See `pkg/models/models.go`.
DSL grammar reference: `pkg/axiomdsl/grammar.ebnf`

Key requirements:
- `ActionIntent.idempotency_key` is required; gateway scopes it by `actor.id` for dedupe.
- `ActionCert.expires_at` and `ActionCert.nonce` are required.
- `ActionCert.sequence` is optional; when present it must be monotonic per `(kid, actor.id, policy_set_id)` stream.
- `DEFER` decisions are not persisted in idempotency storage to allow retry progression.
- Gateway action endpoints enforce rate-limit by actor/domain/action stream:
  - `RATE_LIMIT_ENABLED=true|false`
  - `RATE_LIMIT_PER_MINUTE=<int>`
  - `RATE_LIMIT_WINDOW_SEC=<int>`
  - Redis-backed distributed counter when Redis is available, memory fallback otherwise
  - exceeding returns `DENY` + `reason_code=RATE_LIMITED`

## Shields (MVP behavior)
- `READ_ONLY` and `DRY_RUN` execute upstream with a `{ "mode": "<TYPE>", "payload": <original> }` wrapper.
- `REQUIRE_APPROVAL` creates escrow and returns `ESCROW`.
- `SMALL_BATCH` chunks `ids` (batch) into size 100 and executes sequentially.

## Expression support (current evaluator)
- string predicates: `==`, `!=`, `contains`, `in [..]`
- numeric predicates: `<=`, `>=`, `<`, `>`, `==`, `!=`
- numeric terms:
  - literals (`30`, `0.95`, `"123.45"`)
  - `action.params.<name>`
  - `source("<name>").age_sec|health_score|lag_sec`
  - `budget.remaining("<CODE>")` from params like `budget_ap_remaining` or `budget_remaining_AP`
  - `eps(1.00)`
  - `+` / `-` arithmetic combinations

When `SMT_BACKEND=z3`, `z3cgo`, or `z3exec`, numeric constraints are sent to Z3 with named assertions and unsat-core extraction. `go` is non-formal and verifier will return `ESCROW` on would-be-ALLOW.
If Z3 is unavailable/timeout, verifier returns `DEFER` with `reason_code=SMT_UNAVAILABLE`.

## Escrow FSM
- Main path: `PENDING -> APPROVED -> EXECUTED -> CLOSED`
- Side paths: `PENDING -> EXPIRED`, `PENDING -> CANCELLED`, `APPROVED -> FAILED`, `FAILED -> ROLLED_BACK`, `EXECUTED -> ROLLED_BACK`

## Incident API
- Incident statuses: `OPEN`, `ACKNOWLEDGED`, `RESOLVED`
- `PATCH /v1/incidents/{incident_id}` body:
  - `{ "status": "ACKNOWLEDGED|RESOLVED", "actor": "security-admin-1" }`
- Critical conditions that auto-open incidents in gateway:
  - `DENY` (except `CERT_EXPIRED`)
  - `SOD_*`, `ACCESS_*`
  - `BAD_SIGNATURE`, `KEY_INVALID`, `REPLAY_DETECTED`, `SEQUENCE_REPLAY`, `INTENT_HASH_MISMATCH`, `SUBJECT_RESTRICTED`
  - anomaly condition: repeated `RATE_LIMITED` (deduped per actor/domain per minute)
