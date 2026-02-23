# Threat Model (STRIDE) - 2026-02-12

## Objective

Document attacker paths, trust boundaries, and mitigations for AxiomOS Runtime Assurance services:

- gateway
- verifier
- policy
- state
- postgres/redis
- tool/ontology adapters

## System and Trust Boundaries

1. External caller -> Gateway API boundary
2. Gateway -> internal services (verifier/policy/state) service-token boundary
3. Services -> data stores (postgres/redis) persistence boundary
4. Policy/cert cryptographic boundary (Ed25519 certs + key lifecycle)
5. Human approval boundary (escrow/compliance operations)

## Critical Assets

1. Policy versions and approvals history
2. ActionCert signatures, nonces, idempotency keys
3. Service-to-service auth tokens
4. Audit trail records and replay evidence
5. Tenant/domain-scoped belief state snapshots
6. Escrow queue and approval decisions

## STRIDE Register

| ID | STRIDE | Threat | Current controls | Residual risk | Priority |
|---|---|---|---|---|---|
| TM-01 | S | JWT spoofing for user APIs | HS256 validation, exp/nbf checks, auth middleware, role checks | Secret leakage compromises model | High |
| TM-02 | S | Service identity spoofing to internal endpoints | Static service header/token checks, constant-time compare | Token reuse risk if leaked | High |
| TM-03 | T | ActionCert tampering in transit | Intent hash binding + signature verification + nonce checks | Depends on key hygiene and rotation rigor | High |
| TM-04 | T | Replay of valid cert/sequence | Nonce replay + sequence replay controls | Distributed cache/store outage can degrade posture | High |
| TM-05 | R | Repudiation of policy changes | Versioned policy state + approval workflow + audit trail | Audit retention/immutability config drift | Medium |
| TM-06 | R | Repudiation of runtime decisions | Decision/audit replay endpoints + persisted decision IDs | Requires reliable DB durability and backups | Medium |
| TM-07 | I | Sensitive data leakage in logs/audit | Redaction/masking, hashed actor identifiers, data minimization patterns | Misconfigured custom logs can reintroduce leakage | Medium |
| TM-08 | I | Cross-tenant data disclosure | Tenant resolution checks, RBAC, actor binding | Broken tenant claims in upstream IdP mapping | High |
| TM-09 | D | Verifier unavailable causes outage | Degraded mode with SHIELD/DEFER/ESCROW, bounded wait | Large-scale dependency outage still impacts throughput | Medium |
| TM-10 | D | Request flood / abuse | Rate limiting, retry controls, timeouts | Non-uniform limits across all endpoints | Medium |
| TM-11 | D | Oversized payload exhaustion | Max body size middleware + timeout caps | Upstream proxies must mirror limits | Medium |
| TM-12 | E | RBAC escalation to compliance/security operations | withRoles per route, strict role checks | Role mapping errors in IdP claim issuance | High |
| TM-13 | E | Bypass Gateway via direct internal APIs | Service-token requirements on internal paths, auth on service APIs | Network exposure misconfig can increase attack surface | High |
| TM-14 | T/I | Supply-chain compromise in build/runtime dependencies | pinned scanners/CI checks/SBOM/vuln gates | New malicious releases between scans | High |
| TM-15 | I/D | Secret exfiltration from CI/runtime | env/KMS patterns, no hardcoded secrets, secret scans | Human operational mistakes remain possible | High |

## Attack Scenarios (Most Credible)

1. Stolen service token used against policy internal endpoint
   - Impact: policy/version data exposure, bypass of intended service path.
   - Mitigation in place: dedicated internal token gate.
   - Next: rotate tokens regularly; move to mTLS/SPIFFE identity for east-west traffic.

2. Valid JWT with wrong role attempts compliance action
   - Impact: unauthorized governance operations.
   - Mitigation in place: route-level role checks with explicit allowed roles.
   - Next: add authorization decision logs with policy reason for every `403`.

3. Replay of signed cert under degraded conditions
   - Impact: duplicated or out-of-order actions.
   - Mitigation in place: nonce + sequence replay detection, idempotency handling.
   - Next: periodic replay-attack chaos tests under datastore partial failure.

4. Dependency compromise introduces runtime backdoor
   - Impact: full control or data exfiltration.
   - Mitigation in place: SBOM + vulnerability scans + pinned security tooling.
   - Next: provenance verification/SLSA-level artifact attestations.

## Controls Coverage vs. Acceptance Criteria

- Gateway-only execution path: covered by auth/routing + contract tests.
- Deterministic verdict and replayability: covered by audit/replay endpoints and decision records.
- No deadlock on stale/missing state: covered by degraded decisions and chaos checks.
- Policy change governance: covered by submit/approval flow with SoD checks.

## Gaps and Residual Work

1. Independent third-party pentest is still required for formal external assurance.
2. Network policy hardening must be enforced in production cluster (not only compose).
3. Token-based east-west auth should evolve to short-lived identity (mTLS/SPIFFE).
4. Add periodic red-team scenario for CI secret theft and key compromise.

## Immediate Hardening Delta Completed

1. Compose host-exposed ports bound to loopback by default:
   - `infra/docker-compose/docker-compose.yml`
2. Reproducible external pentest script added:
   - `scripts/pentest-external.sh`
3. Make target added:
   - `make pentest-external`

