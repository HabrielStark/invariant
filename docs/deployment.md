# Deployment Guide

## Local
1. Start Postgres + Redis.
2. `./scripts/migrate.sh`
3. `./scripts/dev.sh`
4. Start console: `cd ui/console && npm run dev`
5. Optional gates: `./scripts/chaos-compose.sh` and `./scripts/perf-compose.sh`

### Upstream Connector Settings

- `UPSTREAM_TIMEOUT_MS` request timeout for verifier/state/tool/ontology calls.
- `UPSTREAM_RETRIES` and `UPSTREAM_RETRY_DELAY_MS` transient retry policy.
- Optional auth header/token pairs per upstream:
  - `VERIFIER_AUTH_HEADER` + `VERIFIER_AUTH_TOKEN`
  - `POLICY_AUTH_HEADER` + `POLICY_AUTH_TOKEN`
  - `STATE_AUTH_HEADER` + `STATE_AUTH_TOKEN`
  - `TOOL_AUTH_HEADER` + `TOOL_AUTH_TOKEN`
  - `ONTOLOGY_AUTH_HEADER` + `ONTOLOGY_AUTH_TOKEN`

## Docker Compose
- `docker compose -f infra/docker-compose/docker-compose.yml up --build`
- Kafka profile: `docker compose -f infra/docker-compose/docker-compose.yml --profile kafka up --build`
- or one-command bootstrap: `./scripts/bootstrap.sh`
- Postgres/Redis are internal-only (no host port publish).
- API services are loopback-bound in compose by default (`127.0.0.1:8080-8083`) to reduce accidental LAN exposure.
- Compose defaults are dev-safe and set `DATABASE_REQUIRE_TLS=false`, `REDIS_REQUIRE_TLS=false`.
- External black-box pentest pack: `make pentest-external` (report output under `reports/pentest/<timestamp>/`).

## Kubernetes
- Build/push image `axiom:<release-tag>` and pin deployments to immutable digest (`axiom@sha256:...`)
- `kubectl apply -f infra/k8s/axiomos.yaml`
- Includes default-deny network policy with explicit allow-lists for gateway/verifier/state/policy and mocks.
- Requires TLS secrets:
  - `axiomos-db-tls` with `server.crt`, `server.key`, `ca.crt`
  - `axiomos-redis-tls` with `tls.crt`, `tls.key`, `ca.crt`
- Production runtime enforces secure transport:
  - `DATABASE_REQUIRE_TLS=true` for migrator/gateway/policy/state/verifier
  - `REDIS_TLS=true` and `REDIS_REQUIRE_TLS=true` for gateway

## Monitoring
Track:
- gateway/verifier p95 latency
- verdict distribution
- reason_code distribution
- escrow pending count
- replay detection rate
- source age/health

Gateway runtime counters are exposed at `GET /metrics`.

## Auth + Security Runtime Flags
- `AUTH_MODE=off|oidc_hs256|oidc_rs256` (gateway/policy)
- `ENVIRONMENT=development|dev|local|test|staging|production`
 - `STRICT_PROD_SECURITY=true|false` (default `true`; enforces production startup hardening gates)
   - requires `DATABASE_REQUIRE_TLS=true`
   - requires HTTPS-only explicit `CORS_ALLOWED_ORIGINS` (no wildcard/localhost)
   - gateway additionally requires `REDIS_REQUIRE_TLS=true` and forbids insecure Redis TLS flags
   - service internal auth headers/tokens must be configured per service role
  - `AUTH_MODE=off` is allowed only with `ALLOW_INSECURE_AUTH_OFF=true` and explicit non-production `ENVIRONMENT=development|dev|local|test`
  - `AUTH_MODE=off` is blocked for `staging|stage|production|prod`
- `CORS_ALLOWED_ORIGINS=https://console.example.com` (comma-separated exact origins)
- `DATABASE_REQUIRE_TLS=true|false` (all DB-backed services)
- `REDIS_REQUIRE_TLS=true|false` and Redis TLS files/server-name (gateway)
- `REDIS_ALLOW_INSECURE_TLS=false` (must be explicitly `true` if `REDIS_TLS_INSECURE=true` for local diagnostics)
- `SHIELD_STRICT_NO_COMMIT=true` (gateway enforces local no-commit reports for READ_ONLY/DRY_RUN shields)
- `DB_TENANT_SCOPE=all|tenant` and optional `DB_TENANT_STATIC=<tenant-id>` (Postgres runtime params used by tenant RLS policies)
- external key store (gateway/verifier):
  - `KEYSTORE_PROVIDER=db|vault_transit`
  - `VAULT_ADDR`, `VAULT_TOKEN`, `VAULT_NAMESPACE`
  - `VAULT_TRANSIT_MOUNT`, `VAULT_KEY_PREFIX`
  - `VAULT_KEY_LOOKUP_TIMEOUT_MS`, `VAULT_KEY_LOOKUP_RETRIES`, `VAULT_KEY_LOOKUP_RETRY_DELAY_MS`
- HS256 mode: `OIDC_HS256_SECRET=<shared-secret>`
- RS256 mode: `OIDC_JWKS_URL`, `OIDC_ISSUER`, `OIDC_AUDIENCE`
- ABAC guard config (gateway):
  - `ABAC_DOMAIN_ROLES=finance:financeoperator,financemanager;security:securityadmin`
  - `ABAC_STRICT_ACTOR_BINDING=true|false`
- Retention controls (gateway):
  - `RETENTION_ENABLED=true|false`
  - `RETENTION_DAYS=90`
  - `RETENTION_INTERVAL_SEC=3600`
- `SMT_BACKEND=z3exec|z3cgo|go`, `SMT_TIMEOUT_MS=50`, `Z3_PATH=/usr/bin/z3` (verifier)
- Ontology adapter (gateway):
  - `ONTOLOGY_ADAPTER=mock|foundry`
  - Foundry config: `FOUNDRY_BASE_URL`, `FOUNDRY_TOKEN`, `FOUNDRY_ONTOLOGY_ID`, `FOUNDRY_ALLOW_BATCH`, `FOUNDRY_ALLOW_DRY_RUN`, `FOUNDRY_ALLOW_PREVIEW`
- `KAFKA_ENABLED=true|false`, `KAFKA_BROKERS`, `KAFKA_TOPIC`, `KAFKA_GROUP_ID` (state)

## TCO Note
Managed-first recommendation:
- Managed Postgres/Redis/Kafka reduces patching burden and downtime risk.
- Self-hosted requires monthly OS patching, daily backup verification, and incident on-call.
