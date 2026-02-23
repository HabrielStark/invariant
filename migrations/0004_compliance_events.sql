-- compliance_events table for GDPR audit trail
CREATE TABLE IF NOT EXISTS compliance_events (
    id              BIGSERIAL PRIMARY KEY,
    event_type      TEXT NOT NULL,
    subject_hash    TEXT NOT NULL,
    requested_by    TEXT NOT NULL,
    reason          TEXT NOT NULL DEFAULT '',
    records_affected BIGINT NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_compliance_events_type ON compliance_events(event_type);
CREATE INDEX IF NOT EXISTS idx_compliance_events_subject ON compliance_events(subject_hash);
