CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    host TEXT NOT NULL,
    port INTEGER NOT NULL DEFAULT 443,
    addresses JSONB NOT NULL DEFAULT '[]'::jsonb,
    status TEXT NOT NULL DEFAULT 'queued',
    progress_percent INTEGER NOT NULL DEFAULT 0,
    progress_stage TEXT NOT NULL DEFAULT 'queued',
    progress_detail TEXT NOT NULL DEFAULT 'Ожидаем worker',
    error TEXT NOT NULL DEFAULT '',
    grade TEXT,
    score INTEGER,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS scans_host_created_idx ON scans (host, created_at DESC);
CREATE INDEX IF NOT EXISTS scans_status_created_idx ON scans (status, created_at DESC);
CREATE INDEX IF NOT EXISTS scans_retention_idx ON scans (status, created_at);

CREATE TABLE IF NOT EXISTS reports (
    scan_id TEXT PRIMARY KEY REFERENCES scans(id) ON DELETE CASCADE,
    report JSONB NOT NULL,
    raw JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS findings (
    id BIGSERIAL PRIMARY KEY,
    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    severity TEXT NOT NULL,
    code TEXT NOT NULL,
    category TEXT NOT NULL,
    title TEXT NOT NULL,
    detail TEXT NOT NULL,
    grade_cap TEXT,
    score_penalty INTEGER NOT NULL DEFAULT 0,
    recommendation JSONB NOT NULL DEFAULT '{}'::jsonb,
    evidence JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS findings_scan_severity_idx ON findings (scan_id, severity);
CREATE INDEX IF NOT EXISTS findings_code_idx ON findings (code);

CREATE TABLE IF NOT EXISTS monitored_domains (
    id BIGSERIAL PRIMARY KEY,
    host TEXT NOT NULL,
    port INTEGER NOT NULL DEFAULT 443,
    enabled BOOLEAN NOT NULL DEFAULT true,
    scan_interval_seconds INTEGER NOT NULL DEFAULT 86400,
    last_scan_at TIMESTAMPTZ,
    next_scan_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    notes TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (host, port)
);

CREATE INDEX IF NOT EXISTS monitored_domains_due_idx
ON monitored_domains (enabled, next_scan_at);

CREATE TABLE IF NOT EXISTS monitoring_snapshots (
    id BIGSERIAL PRIMARY KEY,
    monitored_domain_id BIGINT NOT NULL REFERENCES monitored_domains(id) ON DELETE CASCADE,
    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    grade TEXT,
    score INTEGER,
    certificate_not_after TIMESTAMPTZ,
    certificate_expires_in_days INTEGER,
    supported_protocols JSONB NOT NULL DEFAULT '[]'::jsonb,
    hsts JSONB NOT NULL DEFAULT '{}'::jsonb,
    findings JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (monitored_domain_id, scan_id)
);

CREATE INDEX IF NOT EXISTS monitoring_snapshots_domain_created_idx
ON monitoring_snapshots (monitored_domain_id, created_at DESC);

CREATE TABLE IF NOT EXISTS monitoring_events (
    id BIGSERIAL PRIMARY KEY,
    monitored_domain_id BIGINT NOT NULL REFERENCES monitored_domains(id) ON DELETE CASCADE,
    snapshot_id BIGINT REFERENCES monitoring_snapshots(id) ON DELETE CASCADE,
    scan_id TEXT REFERENCES scans(id) ON DELETE SET NULL,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'info',
    title TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT '',
    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS monitoring_events_domain_created_idx
ON monitoring_events (monitored_domain_id, created_at DESC);

CREATE INDEX IF NOT EXISTS monitoring_events_type_idx
ON monitoring_events (event_type);

CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS scans_set_updated_at ON scans;
CREATE TRIGGER scans_set_updated_at
BEFORE UPDATE ON scans
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

DROP TRIGGER IF EXISTS monitored_domains_set_updated_at ON monitored_domains;
CREATE TRIGGER monitored_domains_set_updated_at
BEFORE UPDATE ON monitored_domains
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();
