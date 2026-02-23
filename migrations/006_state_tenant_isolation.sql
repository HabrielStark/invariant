ALTER TABLE belief_snapshots
  ADD COLUMN IF NOT EXISTS tenant TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS belief_snapshots_tenant_created_idx
  ON belief_snapshots(tenant, created_at DESC);

CREATE INDEX IF NOT EXISTS belief_snapshots_tenant_domain_idx
  ON belief_snapshots(tenant, domain);

ALTER TABLE source_states
  ADD COLUMN IF NOT EXISTS tenant TEXT NOT NULL DEFAULT '';

DROP INDEX IF EXISTS source_states_domain_idx;

ALTER TABLE source_states
  DROP CONSTRAINT IF EXISTS source_states_pkey;

ALTER TABLE source_states
  ADD PRIMARY KEY (tenant, domain, source);

CREATE INDEX IF NOT EXISTS source_states_tenant_domain_idx
  ON source_states(tenant, domain);
