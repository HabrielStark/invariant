# Secrets Report

## Required Secrets
- `DATABASE_URL` (scope: backend services; rotate 90d)
- `DATABASE_REQUIRE_TLS` (scope: backend services; set `true` in production)
- `REDIS_ADDR` (scope: gateway/state/verifier; rotate 90d)
- `REDIS_PASSWORD` (scope: gateway/state/verifier; rotate 90d)
- `REDIS_REQUIRE_TLS` (scope: gateway; set `true` in production)
- `REDIS_ALLOW_INSECURE_TLS` (scope: gateway; keep `false`; only temporary local debugging with `REDIS_TLS_INSECURE=true`)
- Redis TLS material when `REDIS_TLS=true`:
  - `REDIS_TLS_CA_CERT_FILE`
  - `REDIS_TLS_CERT_FILE` (optional mTLS)
  - `REDIS_TLS_KEY_FILE` (optional mTLS)
  - `REDIS_TLS_SERVER_NAME`
- `AUDIT_HASH_SALT` (scope: gateway; rotate 180d)
- Upstream auth tokens (optional, if external adapters require auth):
  - `VERIFIER_AUTH_TOKEN`
  - `POLICY_AUTH_TOKEN`
  - `STATE_AUTH_TOKEN`
  - `TOOL_AUTH_TOKEN`
  - `ONTOLOGY_AUTH_TOKEN`
- Internal auth headers (non-secret config):
  - `POLICY_AUTH_HEADER`
  - `VERIFIER_AUTH_HEADER`
  - `STATE_AUTH_HEADER`
  - `CORS_ALLOWED_ORIGINS`
  - `SHIELD_STRICT_NO_COMMIT`
  - `ENVIRONMENT`
  - `DB_TENANT_SCOPE`
  - `DB_TENANT_STATIC`
  - `KEYSTORE_PROVIDER`
  - `VAULT_TRANSIT_MOUNT`
  - `VAULT_KEY_PREFIX`
- Foundry adapter token (if enabled):
  - `FOUNDRY_TOKEN`
- OIDC client id/secret (scope: gateway+console auth, when enabled)
- OIDC auth settings (scope: gateway/policy):
  - HS256 mode: `OIDC_HS256_SECRET`
  - RS256 mode: `OIDC_JWKS_URL`, `OIDC_ISSUER`, `OIDC_AUDIENCE`
  - Trusted proxy CIDRs: `TRUSTED_PROXY_CIDRS` (gateway)
- KMS/Vault credentials (scope: signer key operations, when enabled):
  - `VAULT_ADDR`
  - `VAULT_TOKEN`
  - `VAULT_NAMESPACE` (optional)

## Key Material
- Agent private signing keys must never be stored in repository.
- Public keys are registered via `POST /v1/keys`.
- Revoke via `PATCH /v1/keys/{kid}`.
- Kubernetes TLS secret objects:
  - `axiomos-db-tls`: `server.crt`, `server.key`, `ca.crt`
  - `axiomos-redis-tls`: `tls.crt`, `tls.key`, `ca.crt`

## Rotation Schedule
- Agent keypair: 90 days
- DB credentials: 90 days
- Emergency rotation: immediate on leak indication

## Logging Rules
- Never log full cert signatures, raw private keys, or unmasked PII.
- Audit entries should keep IDs/hashes only.
