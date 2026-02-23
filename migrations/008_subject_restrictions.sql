CREATE TABLE IF NOT EXISTS subject_restrictions (
  tenant TEXT NOT NULL DEFAULT '',
  actor_id_hash TEXT NOT NULL,
  reason TEXT NOT NULL DEFAULT '',
  created_by TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  lifted_by TEXT,
  lifted_at TIMESTAMPTZ,
  PRIMARY KEY (tenant, actor_id_hash)
);

CREATE INDEX IF NOT EXISTS subject_restrictions_active_idx
  ON subject_restrictions(tenant, created_at DESC)
  WHERE lifted_at IS NULL;

ALTER TABLE subject_restrictions ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS subject_restrictions_tenant_policy ON subject_restrictions;
CREATE POLICY subject_restrictions_tenant_policy ON subject_restrictions
  USING (
    axiom_tenant_scope_all()
    OR tenant = axiom_current_tenant()
  )
  WITH CHECK (
    axiom_tenant_scope_all()
    OR tenant = axiom_current_tenant()
  );
