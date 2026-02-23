CREATE TABLE IF NOT EXISTS cert_sequences (
  stream_key TEXT PRIMARY KEY,
  last_seq INT NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
