CREATE TABLE IF NOT EXISTS policy_sets (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  domain TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS policy_versions (
  id SERIAL PRIMARY KEY,
  policy_set_id TEXT NOT NULL REFERENCES policy_sets(id) ON DELETE CASCADE,
  version TEXT NOT NULL,
  dsl TEXT NOT NULL,
  effective_from TIMESTAMPTZ,
  effective_to TIMESTAMPTZ,
  status TEXT NOT NULL DEFAULT 'DRAFT',
  approved_by TEXT,
  approved_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS policy_version_uq ON policy_versions(policy_set_id, version);

CREATE TABLE IF NOT EXISTS key_registry (
  kid TEXT PRIMARY KEY,
  signer TEXT NOT NULL,
  public_key BYTEA NOT NULL,
  status TEXT NOT NULL DEFAULT 'active',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS decisions (
  decision_id TEXT PRIMARY KEY,
  idempotency_key TEXT NOT NULL,
  verdict TEXT NOT NULL,
  reason_code TEXT NOT NULL,
  response_json JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS decisions_idempotency_uq ON decisions(idempotency_key);

CREATE TABLE IF NOT EXISTS escrows (
  escrow_id TEXT PRIMARY KEY,
  status TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL,
  approvals_required INT NOT NULL,
  approvals_received INT NOT NULL DEFAULT 0,
  intent_raw JSONB NOT NULL,
  cert_raw JSONB NOT NULL,
  payload_raw JSONB,
  action_type TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS escrow_approvals (
  id SERIAL PRIMARY KEY,
  escrow_id TEXT NOT NULL REFERENCES escrows(escrow_id) ON DELETE CASCADE,
  approver TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS escrow_approvals_uq ON escrow_approvals(escrow_id, approver);

CREATE TABLE IF NOT EXISTS audit_records (
  decision_id TEXT PRIMARY KEY,
  intent_raw JSONB NOT NULL,
  cert_raw JSONB NOT NULL,
  policy_version TEXT NOT NULL,
  verdict TEXT NOT NULL,
  reason_code TEXT NOT NULL,
  counterexample JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Prevent UPDATE/DELETE on audit_records
CREATE OR REPLACE FUNCTION prevent_audit_modifications() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'audit_records is append-only';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS audit_no_update ON audit_records;
CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit_records
  FOR EACH ROW EXECUTE FUNCTION prevent_audit_modifications();

DROP TRIGGER IF EXISTS audit_no_delete ON audit_records;
CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit_records
  FOR EACH ROW EXECUTE FUNCTION prevent_audit_modifications();

CREATE TABLE IF NOT EXISTS belief_snapshots (
  snapshot_id TEXT PRIMARY KEY,
  domain TEXT NOT NULL,
  payload JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
