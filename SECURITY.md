# Security Policy

## Reporting
Report vulnerabilities privately to security@axiomos.local with:
- affected endpoint/module
- reproduction steps
- impact and potential blast radius

Do not open public issues for active vulnerabilities.

## Response Targets
- Acknowledge: 24h
- Initial triage: 72h
- Mitigation patch: 7 days for critical, 30 days for high

## Key Rotation
- Agent signing keys: rotate every 90 days
- Emergency rotation: immediate revoke via `PATCH /v1/keys/{kid}`
- Redis nonce cache is ephemeral and not used as long-term trust material

## Hardening Baseline
- Gateway is mandatory choke point
- Replay defense with `nonce + expires_at`
- Append-only audit table enforced by DB trigger
- Network policies deny direct tool/ontology ingress except from gateway
- HSTS enforced: `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`
- `Cache-Control: no-store` on all API responses
- CSP: `default-src 'none'; frame-ancestors 'none'; base-uri 'none'`

## GDPR Data Subject Rights
- **Subject Access Request**: `GET /v1/gdpr/export?requested_by={actor}&subject_id={subject}` — exports only subject-scoped audit decisions, escrows, and incidents
- **Right to Erasure**: `POST /v1/gdpr/erasure` — pseudonymizes mutable stores (`subject_restrictions`, `incidents`) and records immutable audit-table exception (`audit_records`)
- **Access Request Logging**: `POST /v1/gdpr/access-request` — creates a compliance trail entry for audit purposes
- All GDPR actions require `complianceofficer` or `securityadmin` role
- Compliance events stored in `compliance_events` table with full audit trail

## Observability
- Prometheus P50/P95/P99 latency histograms via `/metrics/prometheus`
- Alerts fire at P95 > 200ms (high) and P99 > 500ms (critical)
- Verdict, reason, and gauge counters for decision monitoring

## Static Analysis
- `gosec` integrated into CI (`make gosec`)
- Race detection enabled in all test targets (`-race`)
