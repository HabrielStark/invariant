# AxiomOS MVP Final Report

## Build Summary

- Architecture delivered as monorepo with services:
  - `gateway`, `verifier`, `policy`, `state`, `mock-ontology`, `tool-mock`, `migrator`, `axiomctl`
- SDKs for agent integration:
  - Go: `pkg/agentsdk`
  - TypeScript: `sdk/ts`
- Runtime assurance path is active:
  - Action interception through gateway
  - Cert verification (Ed25519), anti-replay, idempotency
  - Policy evaluation with counterexamples
  - Shield / Escrow / Defer fallback
  - Append-only audit + replay
  - Incident stream for critical denials/security failures
  - OIDC auth modes (`oidc_hs256`, `oidc_rs256` with JWKS)
  - ABAC runtime checks (actor/tenant/domain role)
  - Gateway distributed rate-limits (Redis + fallback) + anomaly incidents for burst abuse
  - Compliance export and retention APIs

## Security Controls Implemented

- Canonical hash and cert binding:
  - `intent_hash = sha256(canonical(intent)|policy_version|nonce)`
  - Signed payload includes `intent_hash|policy_version|expires_at|nonce`
- Replay defense:
  - Redis `SETNX` nonce + TTL
- Sequence defense:
  - Monotonic stream guard for optional `ActionCert.sequence`
- Idempotency:
  - `idempotency_key` decision dedupe for terminal verdicts
- Key registry:
  - register/revoke/rotate via policy API
- Incident response:
  - auto-create incidents on critical policy/security failures
  - acknowledge/resolve workflow via gateway API
- ABAC runtime controls:
  - actor, tenant, and domain-role checks in gateway when auth enabled
- Audit append-only:
  - DB trigger denies `UPDATE/DELETE` on `audit_records`
- Network enforcement:
  - K8s default deny + allow-list
  - Compose internal-only DB/Redis

## DoD Coverage

Reference matrix: `docs/dod-matrix.md`

- Gateway mandatory for write paths: covered
- P95/P99 budget instrumentation hooks: present (OTel-ready)
- No deadlocks: degraded path returns non-ALLOW and bounded fallback
- Counterexamples on policy fail: covered
- Policy approval workflow: DRAFT/PENDING_APPROVAL/PUBLISHED with SoD + quorum
- 4 shields (READ_ONLY, SMALL_BATCH, REQUIRE_APPROVAL, DRY_RUN): covered
- Replay reproducibility via snapshot refs and replay endpoint: covered
- Policy editor test-run endpoint for draft/version validation: covered
- Incident queue + status transitions (`OPEN/ACKNOWLEDGED/RESOLVED`): covered

## Final Verification (Self-Audit)

Executed `./scripts/self-audit.sh`:

1. `go test ./...` passed
2. `go vet ./...` passed
3. `ui/console` build passed
4. `npm audit --omit=dev` passed (0 vulnerabilities)
5. `make sdk-ts-build` passed
6. `make sbom` generated `sbom-go.json`
7. `make vuln` passed (0 vulnerabilities affecting code)
8. `./scripts/smoke-compose.sh` passed
9. `./scripts/contract-compose.sh` passed
10. `./scripts/chaos-compose.sh` passed
11. `./scripts/perf-compose.sh` passed
    - p95: `6.020ms`
    - p99: `8.312ms`

## Operational Entry Points

- Bootstrap stack + seed:
  - `./scripts/bootstrap.sh`
- Full verification:
  - `./scripts/self-audit.sh`
- Dev quick run:
  - `./scripts/dev.sh`
