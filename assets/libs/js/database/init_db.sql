CREATE TABLE IF NOT EXISTS vulnerabilities_test (
    id VARCHAR(50) PRIMARY KEY,
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

CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_vulnerabilities_updated_at
    BEFORE UPDATE ON vulnerabilities_test
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE INDEX idx_scan_date ON vulnerabilities_test(scan_date);
CREATE INDEX idx_severity ON vulnerabilities_test(severity);