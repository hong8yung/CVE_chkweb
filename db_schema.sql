CREATE TABLE IF NOT EXISTS cve (
  id                text PRIMARY KEY,
  published_at      timestamptz NOT NULL,
  last_modified_at  timestamptz NOT NULL,
  cvss_score        numeric(3,1),
  cvss_version      text,
  severity          text,
  source_identifier text,
  raw               jsonb NOT NULL,
  created_at        timestamptz NOT NULL DEFAULT now(),
  updated_at        timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_cve_published_at ON cve (published_at DESC);
CREATE INDEX IF NOT EXISTS idx_cve_last_modified_at ON cve (last_modified_at DESC);
CREATE INDEX IF NOT EXISTS idx_cve_cvss_score ON cve (cvss_score DESC);
CREATE INDEX IF NOT EXISTS idx_cve_raw_gin ON cve USING gin (raw);

CREATE TABLE IF NOT EXISTS ingest_job_log (
  id              bigserial PRIMARY KEY,
  job_type        text NOT NULL,
  window_start    timestamptz,
  window_end      timestamptz,
  requested_count int,
  upserted_count  int,
  failed_count    int,
  status          text NOT NULL,
  error_message   text,
  started_at      timestamptz NOT NULL DEFAULT now(),
  finished_at     timestamptz
);

CREATE TABLE IF NOT EXISTS ingest_checkpoint (
  key        text PRIMARY KEY,
  value_ts   timestamptz NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);
