# Invariant 0.1.1 patch validation

Base: `65298bb5f5857e06ae767c963f90ae867b653a1f` (v0.1.0/main).
This patch hardens client response handling, cancellation, canonical hash
interoperability and key validation. It does not certify the whole system as
production-ready.

## Reproduced defect

`TestClientRejectsPartialResponse` was run against the unchanged base in an
isolated worktree. All four subtests failed: Verify, ExecuteTool,
ExecuteOntology and ApproveEscrow returned success after their response reader
returned both valid-looking JSON bytes and a transport error. All four pass
with this patch, returning the wrapped read error and closing the response.

## Completed local checks

| Check | Result |
| --- | --- |
| `go test -race -count=1 -json ./...` | 939 tests/subtests passed, 1 skipped; no failures |
| `scripts/check-go-coverage.sh 85.0 /tmp/invariant-final-coverage.out -race -count=1` | 87.7%; gate passed (packages with tests) |
| `go vet ./...` | Passed |
| `go build ./...` | Passed |
| `go mod verify` | All modules verified |
| `gofmt -l cmd pkg adapters` | No unformatted files |
| `govulncheck@v1.1.4 ./...` | 0 reachable vulnerabilities after updates; baseline had 25 |
| `gosec@v2.22.0 -quiet ./cmd/... ./pkg/...` | Passed, no findings |
| `npm test --prefix sdk/ts` | Build and all 5 tests passed |
| `npm run build --prefix ui/console` | Passed |
| `npm audit --prefix ui/console --omit=dev --audit-level=critical` | 0 vulnerabilities |
| `scripts/check-ui-budget.sh` | Passed: entry JS 171,777 bytes / 53,396 gzip bytes |
| `git diff --check` | Passed |

Tests used Go 1.26.8, verified against the official download checksum. The
Docker builder image is pinned to the registry-resolved digest for
`golang:1.26.8-bookworm`.

## Remaining validation limits

- Docker is unavailable in the editing environment. Compose smoke, contract,
  chaos, performance, container image execution and Trivy checks were not run
  locally. The existing CI still contains those Compose/Trivy gates.
- `TestE2EDemoScript` was skipped because the opt-in external demo environment
  was not enabled. Default Go test success does not include this scenario or
  the build-tagged PostgreSQL integration tests.
- Z3 CGO container builds and real PostgreSQL/Redis/Kafka/Vault deployments
  have not been validated locally by this patch.
- Govulncheck also reports 2 findings in imported packages and 3 in required
  modules without reachable calls. Zero reachable findings is not a claim
  that every transitive dependency or container image is vulnerability-free.
- CI results must be checked for the published commit before declaring a
  production release fully validated.

## Upgrade and rollback

Use Go 1.26.8 for builds; updated dependencies raise the module minimum to Go
1.25. No database migration or server signature-format change is introduced.
TypeScript callers must use safe integer numbers or decimal strings. Shared
upstream clients, Vault lookup and the Go SDK now reject responses over 16 MiB.
See `docs/sdk.md` for compatibility and retry semantics. Roll back by deploying
the previous source revision and its dependency lockfiles together; no data
rollback is required by these code changes.
