ALTER TABLE decisions
  ADD COLUMN IF NOT EXISTS tenant TEXT NOT NULL DEFAULT '';

ALTER TABLE escrows
  ADD COLUMN IF NOT EXISTS tenant TEXT NOT NULL DEFAULT '';

ALTER TABLE incidents
  ADD COLUMN IF NOT EXISTS tenant TEXT NOT NULL DEFAULT '';

ALTER TABLE audit_records
  ADD COLUMN IF NOT EXISTS tenant TEXT NOT NULL DEFAULT '';

DROP INDEX IF EXISTS decisions_idempotency_uq;
CREATE UNIQUE INDEX IF NOT EXISTS decisions_tenant_idempotency_uq
  ON decisions(tenant, idempotency_key);

CREATE INDEX IF NOT EXISTS decisions_tenant_created_idx
  ON decisions(tenant, created_at DESC);

CREATE INDEX IF NOT EXISTS escrows_tenant_created_idx
  ON escrows(tenant, created_at DESC);

CREATE INDEX IF NOT EXISTS incidents_tenant_created_idx
  ON incidents(tenant, created_at DESC);

CREATE INDEX IF NOT EXISTS audit_records_tenant_created_idx
  ON audit_records(tenant, created_at DESC);
