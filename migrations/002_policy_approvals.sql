ALTER TABLE policy_versions
  ADD COLUMN IF NOT EXISTS approvals_required INT NOT NULL DEFAULT 2;

ALTER TABLE policy_versions
  ADD COLUMN IF NOT EXISTS created_by TEXT;

ALTER TABLE policy_versions
  ADD COLUMN IF NOT EXISTS submitted_at TIMESTAMPTZ;

CREATE TABLE IF NOT EXISTS policy_version_approvals (
  id SERIAL PRIMARY KEY,
  policy_set_id TEXT NOT NULL,
  version TEXT NOT NULL,
  approver TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS policy_version_approvals_uq
  ON policy_version_approvals(policy_set_id, version, approver);
