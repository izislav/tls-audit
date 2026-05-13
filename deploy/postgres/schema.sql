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
