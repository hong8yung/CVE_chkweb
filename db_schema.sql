CREATE TABLE IF NOT EXISTS cve (
  id                text PRIMARY KEY,
  published_at      timestamptz NOT NULL,
  last_modified_at  timestamptz NOT NULL,
  cvss_score        numeric(3,1),
  cvss_version      text,
  severity          text,
  impact_type       text,
  classification_version text,
  source_identifier text,
  raw               jsonb NOT NULL,
  created_at        timestamptz NOT NULL DEFAULT now(),
  updated_at        timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_cve_published_at ON cve (published_at DESC);
CREATE INDEX IF NOT EXISTS idx_cve_last_modified_at ON cve (last_modified_at DESC);
CREATE INDEX IF NOT EXISTS idx_cve_cvss_score ON cve (cvss_score DESC);
CREATE INDEX IF NOT EXISTS idx_cve_impact_type ON cve (impact_type);
CREATE INDEX IF NOT EXISTS idx_cve_raw_gin ON cve USING gin (raw);

ALTER TABLE cve ADD COLUMN IF NOT EXISTS impact_type text;
ALTER TABLE cve ADD COLUMN IF NOT EXISTS classification_version text;

CREATE TABLE IF NOT EXISTS cve_cpe (
  cve_id      text NOT NULL REFERENCES cve (id) ON DELETE CASCADE,
  part        text NOT NULL,
  vendor      text NOT NULL,
  product     text NOT NULL,
  version     text,
  criteria    text NOT NULL,
  vulnerable  boolean NOT NULL DEFAULT true,
  created_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (cve_id, criteria)
);

CREATE INDEX IF NOT EXISTS idx_cve_cpe_product ON cve_cpe (product);
CREATE INDEX IF NOT EXISTS idx_cve_cpe_vendor_product ON cve_cpe (vendor, product);
CREATE INDEX IF NOT EXISTS idx_cve_cpe_vulnerable ON cve_cpe (vulnerable);

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

CREATE TABLE IF NOT EXISTS user_profile_settings (
  profile_key   text PRIMARY KEY,
  settings_json jsonb NOT NULL,
  updated_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS daily_review_item (
  profile_key  text NOT NULL,
  review_date  date NOT NULL,
  cve_id       text NOT NULL REFERENCES cve (id) ON DELETE CASCADE,
  status       text NOT NULL DEFAULT 'pending',
  note         text NOT NULL DEFAULT '',
  reviewed_at  timestamptz,
  updated_at   timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (profile_key, review_date, cve_id)
);

CREATE TABLE IF NOT EXISTS daily_review_backlog (
  profile_key                 text NOT NULL,
  cve_id                      text NOT NULL REFERENCES cve (id) ON DELETE CASCADE,
  status                      text NOT NULL DEFAULT 'pending',
  note                        text NOT NULL DEFAULT '',
  first_seen_at               timestamptz NOT NULL DEFAULT now(),
  last_seen_at                timestamptz NOT NULL DEFAULT now(),
  cve_last_modified_at        timestamptz,
  last_processed_modified_at  timestamptz,
  needs_recheck               boolean NOT NULL DEFAULT false,
  reviewed_at                 timestamptz,
  updated_at                  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (profile_key, cve_id)
);

CREATE INDEX IF NOT EXISTS idx_daily_review_backlog_status
  ON daily_review_backlog (profile_key, status, last_seen_at DESC);
CREATE INDEX IF NOT EXISTS idx_daily_review_backlog_needs_recheck
  ON daily_review_backlog (profile_key, needs_recheck, last_seen_at DESC);

CREATE TABLE IF NOT EXISTS user_profile_preset (
  profile_key  text NOT NULL,
  preset_name  text NOT NULL,
  rule_json    jsonb NOT NULL,
  is_enabled   boolean NOT NULL DEFAULT true,
  updated_at   timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (profile_key, preset_name)
);
