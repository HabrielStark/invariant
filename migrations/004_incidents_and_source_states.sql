CREATE TABLE IF NOT EXISTS incidents (
  incident_id TEXT PRIMARY KEY,
  decision_id TEXT,
  severity TEXT NOT NULL,
  category TEXT NOT NULL,
  reason_code TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'OPEN',
  title TEXT NOT NULL,
  details JSONB NOT NULL DEFAULT '{}'::jsonb,
  acknowledged_by TEXT,
  resolved_by TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  resolved_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS incidents_status_created_idx
  ON incidents(status, created_at DESC);

CREATE INDEX IF NOT EXISTS incidents_reason_created_idx
  ON incidents(reason_code, created_at DESC);

CREATE OR REPLACE FUNCTION touch_incident_updated_at() RETURNS trigger AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS incidents_touch_updated_at ON incidents;
CREATE TRIGGER incidents_touch_updated_at
  BEFORE UPDATE ON incidents
  FOR EACH ROW EXECUTE FUNCTION touch_incident_updated_at();

CREATE TABLE IF NOT EXISTS source_states (
  domain TEXT NOT NULL,
  source TEXT NOT NULL,
  event_time TIMESTAMPTZ NOT NULL,
  ingestion_time TIMESTAMPTZ NOT NULL,
  health_score DOUBLE PRECISION NOT NULL,
  lag_sec INT NOT NULL,
  jitter_sec INT NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (domain, source)
);

CREATE INDEX IF NOT EXISTS source_states_domain_idx
  ON source_states(domain);
