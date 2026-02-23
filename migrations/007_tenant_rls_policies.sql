-- Tenant-aware row level security baseline.
-- Enforcement uses session settings:
--   SET app.current_tenant = '<tenant-id>'
--   SET app.current_tenant_scope = 'all'   -- elevated read/write scope

CREATE OR REPLACE FUNCTION axiom_current_tenant() RETURNS TEXT
LANGUAGE sql
STABLE
AS $$
  SELECT NULLIF(current_setting('app.current_tenant', true), '');
$$;

CREATE OR REPLACE FUNCTION axiom_tenant_scope_all() RETURNS BOOLEAN
LANGUAGE sql
STABLE
AS $$
  SELECT current_setting('app.current_tenant_scope', true) = 'all';
$$;

-- decisions
ALTER TABLE decisions ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS decisions_tenant_policy ON decisions;
CREATE POLICY decisions_tenant_policy ON decisions
  USING (axiom_tenant_scope_all() OR tenant = axiom_current_tenant())
  WITH CHECK (axiom_tenant_scope_all() OR tenant = axiom_current_tenant());

-- escrows
ALTER TABLE escrows ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS escrows_tenant_policy ON escrows;
CREATE POLICY escrows_tenant_policy ON escrows
  USING (axiom_tenant_scope_all() OR tenant = axiom_current_tenant())
  WITH CHECK (axiom_tenant_scope_all() OR tenant = axiom_current_tenant());

-- incidents
ALTER TABLE incidents ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS incidents_tenant_policy ON incidents;
CREATE POLICY incidents_tenant_policy ON incidents
  USING (axiom_tenant_scope_all() OR tenant = axiom_current_tenant())
  WITH CHECK (axiom_tenant_scope_all() OR tenant = axiom_current_tenant());

-- audit records
ALTER TABLE audit_records ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS audit_records_tenant_policy ON audit_records;
CREATE POLICY audit_records_tenant_policy ON audit_records
  USING (axiom_tenant_scope_all() OR tenant = axiom_current_tenant())
  WITH CHECK (axiom_tenant_scope_all() OR tenant = axiom_current_tenant());

-- belief snapshots
ALTER TABLE belief_snapshots ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS belief_snapshots_tenant_policy ON belief_snapshots;
CREATE POLICY belief_snapshots_tenant_policy ON belief_snapshots
  USING (axiom_tenant_scope_all() OR tenant = axiom_current_tenant())
  WITH CHECK (axiom_tenant_scope_all() OR tenant = axiom_current_tenant());

-- source states
ALTER TABLE source_states ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS source_states_tenant_policy ON source_states;
CREATE POLICY source_states_tenant_policy ON source_states
  USING (axiom_tenant_scope_all() OR tenant = axiom_current_tenant())
  WITH CHECK (axiom_tenant_scope_all() OR tenant = axiom_current_tenant());
