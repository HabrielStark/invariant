# Changelog

## 0.1.0
- Added gateway/verifier/policy/state services
- Added anti-replay (`nonce`, `expires_at`) and idempotency
- Added escrow FSM with approval/cancel/rollback endpoints
- Added snapshot API and audit replay endpoint
- Added policy key registry and policy approval workflow
- Added Docker Compose + Kubernetes manifests + network policies
- Added CI pipeline with tests, vuln scan, and SBOM generation
