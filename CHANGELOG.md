# Changelog

## 0.1.1

### Fixed
- Match TypeScript intent canonicalization to the existing Go wire format for HTML-sensitive strings, Unicode separators and supplementary-plane keys; reject unsafe JavaScript integers.
- Reject trailing JSON documents and garbage in canonicalization and numeric validation.
- Return errors instead of panicking on invalid Ed25519 public/private key lengths.
- Propagate Go SDK response read failures instead of accepting partial JSON responses.
- Honor context cancellation during upstream and Vault retry waits; bound buffered responses to 16 MiB.
- Retry transient Vault failures with zero delay, avoid retrying permanent authorization errors, and validate returned key lengths.

### Security dependencies
- Pin the build toolchain to Go 1.26.8 and update pgx, gRPC, OpenTelemetry, x/net and x/text to versions fixing reachable vulnerability findings.
- The module now requires Go 1.25 or newer because of these dependency updates. Use the pinned Go 1.26.8 toolchain for builds.

### Developer experience
- Add shared Go/TypeScript canonicalization and hash fixtures plus regression tests for cancellation, partial responses, response limits and invalid keys.
- Make the TypeScript SDK independently buildable with its own lockfile and test command; run its tests in CI.
- Include adapters in formatting checks and use Node 22 in CI for the existing Vite 7 console.
- Document wire-format compatibility, response limits and retry semantics.

No database migration or server signature-format change is required. See
[SDK compatibility notes](docs/sdk.md#v011-compatibility-and-response-handling).

## 0.1.0
- Added gateway/verifier/policy/state services
- Added anti-replay (`nonce`, `expires_at`) and idempotency
- Added escrow FSM with approval/cancel/rollback endpoints
- Added snapshot API and audit replay endpoint
- Added policy key registry and policy approval workflow
- Added Docker Compose + Kubernetes manifests + network policies
- Added CI pipeline with tests, vuln scan, and SBOM generation
