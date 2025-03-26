CREATE DATABASE dev;
CREATE TABLE IF NOT EXISTS dev (
    id SERIAL PRIMARY KEY,
    cve_id VARCHAR(50),
    package_url VARCHAR,
    affected_version VARCHAR,
    severity VARCHAR,
    cvss_score VARCHAR,
    fix_version VARCHAR,
    short_description TEXT,
    recommendation TEXT,
    insights TEXT,
    scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP 
);

CREATE TABLE IF NOT EXISTS scan_result (
    id SERIAL PRIMARY KEY,
    cve_id VARCHAR(50) ,
    scan_id VARCHAR ,
    package_url VARCHAR,
    affected_version VARCHAR,
    severity VARCHAR,
    cvss_score VARCHAR,
    fix_version VARCHAR,
    short_description TEXT,
    recommendation TEXT,
    insights TEXT,
    scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP 
);


CREATE TABLE IF NOT EXISTS dependency_scan (
    id SERIAL PRIMARY KEY,
    scan_id VARCHAR,
    package_name VARCHAR,
    current_version VARCHAR,
    latest_version VARCHAR,
    latest_publish_date VARCHAR,
    weekly_downloads VARCHAR,
    insights TEXT,
    scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_dev
    BEFORE UPDATE ON dev
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE INDEX idx_scan_date_dev ON dev(scan_date);
CREATE INDEX idx_severity_dev ON dev(severity);


CREATE TRIGGER update_scan_result
    BEFORE UPDATE ON scan_result
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE INDEX idx_scan_date_scan_result ON scan_result(scan_date);
CREATE INDEX idx_severity_scan_result ON scan_result(severity);
CREATE INDEX idx_scan_date_dependency_scan ON dependency_scan(scan_date);