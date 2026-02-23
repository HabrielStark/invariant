# Invariant + OpenClaw Incident Response Runbook

## Scope

This runbook covers production and local incidents for the OpenClaw adapter path that routes side-effecting operations through Invariant Gateway.

## Signals and Dashboards

Primary Prometheus metrics:

- `invariant_verdict_total{verdict,reason}`
- `invariant_verify_latency_ms{stat}`
- `invariant_shield_total{type}`
- `invariant_escrow_total{state}`
- `openclaw_adapter_requests_total`

Primary APIs:

- `GET /metrics/prometheus`
- `GET /v1/escrows`
- `POST /v1/escrow/approve`
- `POST /v1/escrow/execute`
- `POST /v1/audit/{decision_id}/replay`

## 1) Stuck Escrows

Symptoms:

- Escrows remain `PENDING`/`APPROVED` beyond policy TTL.
- `invariant_escrow_total{state="PENDING"}` grows steadily.

Immediate actions:

1. List escrows:

```bash
invariant escrow list --base http://localhost:8080 --status PENDING --limit 200
```

2. For eligible requests, apply SoD-compliant approval:

```bash
invariant escrow approve <escrow_id> --approver manager-1 --base http://localhost:8080
```

3. If approval is separate from execution, execute explicitly:

```bash
invariant escrow execute <escrow_id> --base http://localhost:8080
```

4. If execution fails, inspect rollback/compensation events in logs and incident table.

Recovery criteria:

- pending queue drains
- escrow transitions reach `CLOSED` or explicit terminal state

## 2) Verifier Down / Degraded Mode

Symptoms:

- increased `DEFER` or `SHIELD` with `reason="DEGRADED_MODE"` or `VERIFY_TIMEOUT`
- rising `invariant_verify_latency_ms{stat="max"}`

Immediate actions:

1. Confirm verifier health:

```bash
curl -sS http://localhost:8081/healthz
```

2. Confirm gateway configuration keeps degraded mode safe:

- `DEGRADED_NO_ALLOW=true`

3. Restart verifier and dependent services:

```bash
docker compose -f infra/docker-compose/docker-compose.yml restart verifier gateway
```

4. Re-run one blocked intent with a fresh nonce/idempotency key.

Recovery criteria:

- verifier health restored
- degraded reasons stop increasing
- ALLOW path resumes for valid requests

## 3) Replay Mismatch / Determinism Drift

Symptoms:

- replay endpoint drift for same decision snapshot
- `REPLAY_DETECTED` spikes despite expected dedupe

Immediate actions:

1. Fetch original decision and replay:

```bash
curl -sS -X POST http://localhost:8080/v1/audit/<decision_id>/replay | jq .
```

2. Verify cert fields:

- nonce
- policy_version
- intent_hash
- snapshot references

3. Verify adapter canonicalization path has not changed:

- `adapters/openclaw/mapper.go`
- `adapters/openclaw/sanitize.go`

4. If drift is unexpected, freeze deployments and compare image digests + policy version.

Recovery criteria:

- replay drift eliminated for fixed snapshot/policy inputs

## 4) High SHIELD Rate

Symptoms:

- rapid increase in `invariant_shield_total{type}`
- drop in ALLOW for previously healthy operations

Immediate actions:

1. Break down by reason and operation:

- `invariant_verdict_total{verdict="SHIELD",reason=...}`
- query adapter logs for `operation.name`

2. Validate state freshness source latencies (`/v1/beliefstate`).

3. Validate policy changes around shield clauses.

4. If needed, temporarily require manual approvals for affected operation classes.

Recovery criteria:

- shield rate returns to baseline
- no unsafe ALLOW introduced

## 5) Suspected Bypass Attempt

Symptoms:

- side effects observed without matching Invariant decisions/audit records
- unauthorized direct tool execution paths

Immediate actions:

1. Contain:

- remove direct upstream credentials from non-gateway paths
- block egress route that bypasses gateway

2. Validate all side effects map to decision ids and audit records.

3. Rotate exposed credentials/tokens and signer keys if compromise is possible.

4. Enforce strict routing via adapter + gateway only.

5. Open incident with category `SECURITY_POLICY` and preserve logs.

Recovery criteria:

- every side effect has corresponding decision + audit chain
- bypass route removed and tested

## Post-Incident Checklist

1. Root cause documented with exact commit/policy versions.
2. Replay of representative decisions validated.
3. Additional test added for the failure mode.
4. Dashboard alert thresholds adjusted if needed.
