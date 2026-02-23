-- Add actor_id_hash column for GDPR data-subject lookups.
-- Populated at INSERT time by gateway's audit middleware.
ALTER TABLE audit_records
  ADD COLUMN IF NOT EXISTS actor_id_hash TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS audit_records_actor_hash_idx
  ON audit_records(actor_id_hash);

CREATE INDEX IF NOT EXISTS audit_records_actor_tenant_idx
  ON audit_records(actor_id_hash, tenant);
