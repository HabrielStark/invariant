# Invariant Roadmap

## v0.1.x (Stabilization)

- Harden CI reliability and keep all required checks green
- Expand replay determinism test matrix across adapters
- Add migration docs for policy/version lifecycle changes
- Improve onboarding docs for operators and security teams

## v0.2.0 (Adapter Expansion)

- Add first-class adapters for additional agent runtimes
- Add contract-test harness for third-party adapter conformance
- Add policy bundle signing and verification pipeline
- Add deterministic replay fixtures for cross-version compatibility

## v0.3.0 (Enterprise Guardrails)

- Fine-grained RBAC for escrow operations and policy publishing
- Multi-tenant isolation validation suite and load tests
- Incident response automation playbooks and escalation hooks
- Release provenance attestations and dependency policy enforcement

## Open Issues to Tackle

- Improve degraded-mode operator UX in dashboards
- Add richer minimal counterexample visualization
- Add multi-region state snapshot consistency checks
- Add benchmark suite for p95/p99 verification latency under stress
