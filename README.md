# Invariant

[![CI](https://github.com/HabrielStark/invariant/actions/workflows/ci.yml/badge.svg)](https://github.com/HabrielStark/invariant/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-See%20LICENSES-blue)](./LICENSES.txt)

Invariant is a runtime assurance kernel that sits between an agent decision and real-world execution.

Input: `ActionIntent + ActionCert`  
Output: `ALLOW | SHIELD | DEFER | ESCROW | DENY`

Designed for deterministic, replayable, auditable enforcement in high-risk agent workflows.

## Why Invariant

- Deterministic policy evaluation with canonical JSON hashing
- Anti-replay and idempotency as first-class controls
- Escrow approvals with SoD and explicit state machine
- Policy/version governance with publish and approval flow
- Full audit trail and replay endpoint
- Local-first dev stack (Docker Compose), no paid services required

## Core Verdict Model

- `ALLOW`: execute side effect
- `SHIELD`: safe degradation (`READ_ONLY | SMALL_BATCH | REQUIRE_APPROVAL | DRY_RUN`)
- `DEFER`: retry later, never commit
- `ESCROW`: explicit human approval path
- `DENY`: hard stop with minimal counterexample

## Architecture

```text
Agent/Tool/Node
   -> Invariant Gateway (8080)
      -> Verifier (8081) + Policy (8082) + State (8083)
      -> Escrow + Audit + Replay + Metrics
   -> Upstream executors (mock-ontology/tool-mock or real adapters)
```

## OpenClaw Integration (First-Class)

Invariant includes a production-ready OpenClaw adapter under `adapters/openclaw`:

- HTTP Proxy Mode: `adapters/openclaw/http-proxy`
- WS Node Mode (`role=node`): `adapters/openclaw/ws-node`

OpenClaw integration details and exact hook points are documented in:

- `adapters/openclaw/README.md`

### End-to-End Demo (OpenClaw -> Invariant -> Escrow -> Approve -> Allow -> Replay)

```bash
./scripts/demo_openclaw_invariant.sh
```

Expected flow:

1. First side-effecting action returns `ESCROW`
2. Approval executes escrow and closes it
3. Second authorized action returns `ALLOW`
4. Replay returns `drift:false` for same decision context

## Quickstart (Local, Docker Compose)

```bash
./scripts/bootstrap.sh
```

Services:

- `gateway` `:8080`
- `verifier` `:8081`
- `policy` `:8082`
- `state` `:8083`
- `mock-ontology` `:8084`
- `tool-mock` `:8085`
- `openclaw-http-proxy` `:8090`
- `openclaw-ws-node` `:8091`
- `openclaw` `:18789` (local OpenClaw dev mode)

## Developer Commands

```bash
make fmt
make lint
make test
make build
make gosec
make vuln
make sbom
make trivy
make smoke
make contract
make chaos
make perf
make self-audit
```

Coverage gate:

```bash
./scripts/check-go-coverage.sh 85.0 coverage_all.out -race
```

## Security and Reliability Controls

- Canonical JSON (`RFC 8785`) intent hashing
- ed25519 cert verification and signed intent binding
- Nonce + TTL replay protection
- Actor-scoped idempotency key dedupe
- SoD on escrow approvals
- Degraded mode safety: no `ALLOW` on verifier outage
- Rate-limit anomaly incidents
- Compliance export + retention APIs

## Metrics

Prometheus metrics include:

- `invariant_verdict_total{verdict,reason}`
- `invariant_verify_latency_ms`
- `invariant_shield_total{type}`
- `invariant_escrow_total{state}`
- `openclaw_adapter_requests_total`

Dashboards:

- `infra/grafana/dashboards/openclaw-invariant.json`
- `infra/grafana/dashboards/axiomos.json`

## API and Docs

- API: `docs/api.md`
- OpenClaw Adapter: `adapters/openclaw/README.md`
- Deployment: `docs/deployment.md`
- Incident Runbook: `docs/runbook_incident_response.md`
- Security Policy: `SECURITY.md`
- Secrets: `docs/secrets.md`
- Threat Model: `docs/threat-model-2026-02-12.md`
- Final Audit: `docs/final-audit-2026-02-12.md`
- Final Report: `docs/final-report.md`

## Repository Standards

- Pinned tool versions in CI and security scanning
- CycloneDX SBOM generation for Go and UI
- Critical vulnerability gate in CI
- Race tests, smoke, contract, chaos, perf pipelines

## License and Attribution

- Dependency licensing: `LICENSES.txt`
- Attribution: `ATTRIBUTION.md`

