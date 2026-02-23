# AxiomOS MVP DoD Matrix

## Acceptance Mapping

| Requirement | Implementation | Validation |
| --- | --- | --- |
| All write actions pass gateway | `cmd/gateway/main.go` routes `/v1/tool/execute`, `/v1/ontology/actions/execute` only | `scripts/smoke-compose.sh`, `scripts/contract-compose.sh` |
| Replay protection | `nonce` + `SETNX` in gateway | `scripts/contract-compose.sh` (`REPLAY_DETECTED`) |
| Sequence replay prevention | monotonic `(kid, actor, policy_set)` check in `cert_sequences` | `scripts/contract-compose.sh` (`SEQUENCE_REPLAY`) |
| Idempotency | `decision_by_key` + cache/db lookup in gateway | `scripts/contract-compose.sh` (same response on repeated request) |
| Canonical intent hash | `pkg/models/canonical.go` + gateway/verifier checks | `pkg/models/canonical_test.go`, signed E2E scripts |
| Liveness no deadlock | RTA fallback `SHIELD/ESCROW/DEFER`, bounded verifier timeout | `pkg/rta/decision_test.go`, degraded contract scenario |
| Degraded mode never ALLOW | `rta.Decide` + gateway config `DEGRADED_NO_ALLOW=true` | `pkg/rta/decision_test.go`, `scripts/contract-compose.sh` |
| Escrow FSM with lifecycle | `pkg/escrowfsm/fsm.go`, gateway transitions | `pkg/escrowfsm/fsm_test.go`, smoke escrow path |
| Policy changes require approval | policy workflow `DRAFT->PENDING_APPROVAL->PUBLISHED` | policy API tests + contract policy history checks |
| Counterexample with failed axiom | verifier emits minimal facts/failed axioms | smoke + contract replay output |
| Snapshot-based replay | state snapshot API + cert evidence refs + replay endpoint | `scripts/contract-compose.sh` replay deterministic check |
| Policy dry-run test runner | `POST /v1/policysets/{id}/versions/{version}/evaluate` | `pkg/policyeval/eval_test.go`, console Axiom Test-Run |
| Key registry + revoke | policy key APIs + gateway/verifier key status checks | contract revoked key scenario |
| Incident response workflow | gateway auto-opens incidents on critical failures; `/v1/incidents` acknowledge/resolve | `cmd/gateway/main_test.go` + compose E2E manual flow |
| State continuity on restart | `source_states` upsert + state warmup from DB on boot | `cmd/state/main.go` logic + smoke/contract snapshots |
| Append-only audit | DB trigger blocks update/delete of `audit_records` | migration DDL + replay endpoint uses persisted records |
| Network bypass prevention | k8s network policies + compose no host bind for internal deps | infra manifests + smoke/contract run using gateway exposed ports only |
| ABAC runtime enforcement | gateway actor/tenant/domain checks (`ABAC_*` env) | `cmd/gateway/main_test.go` |
| Action rate-limits + anomaly alerts | gateway distributed Redis limiter with memory fallback (`RATE_LIMIT_*` env) and incident dedupe | `pkg/ratelimit/limiter_test.go`, `cmd/gateway/main_test.go` |
| Chaos/liveness coverage | degraded verifier, stale/missing source scenarios | `scripts/chaos-compose.sh` |
| Latency budget evidence | p50/p95/p99 measurement against `/v1/verify` | `scripts/perf-compose.sh` |
| Compliance data export | actor-scoped audit/escrow/incident export endpoint | `scripts/contract-compose.sh` |
| Retention controls | configurable retention purge for non-immutable tables | `POST /v1/compliance/retention/run` + contract |

## Final Gates

Run these before release:

```bash
go test ./...
go vet ./...
cd ui/console && npm run build && npm audit --omit=dev
cd ../..
make sbom
make vuln
./scripts/smoke-compose.sh
./scripts/contract-compose.sh
```
