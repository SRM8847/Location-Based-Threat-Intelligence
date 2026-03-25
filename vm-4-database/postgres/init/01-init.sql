-- Enable PostGIS extension
CREATE EXTENSION IF NOT EXISTS postgis;

-- Alerts table
CREATE TABLE IF NOT EXISTS alerts (
    id SERIAL PRIMARY KEY,
    event_id VARCHAR(255),
    timestamp TIMESTAMP NOT NULL,
    event_type VARCHAR(50),
    
    -- Network details
    src_ip INET,
    src_port INTEGER,
    dest_ip INET,
    dest_port INTEGER,
    protocol VARCHAR(10),
    
    -- Alert details
    signature TEXT,
    signature_id INTEGER,
    category VARCHAR(100),
    severity VARCHAR(20),
    
    -- Risk scoring
    risk_score INTEGER,
    
    -- Location details
    site_id VARCHAR(50),
    site_name VARCHAR(255),
    location GEOMETRY(Point, 4326),
    
    -- Enrichment and raw data
    enrichment_data JSONB,
    raw_event JSONB,
    
    -- Status tracking
    status VARCHAR(20) DEFAULT 'new',
    acknowledged_by VARCHAR(100),
    acknowledged_at TIMESTAMP,
    resolved_by VARCHAR(100),
    resolved_at TIMESTAMP,
    notes TEXT,
    
    -- Timestamps
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Sites table (from CMDB)
CREATE TABLE IF NOT EXISTS sites (
    id SERIAL PRIMARY KEY,
    site_id VARCHAR(50) UNIQUE NOT NULL,
    site_name VARCHAR(255) NOT NULL,
    ip_range CIDR,
    city VARCHAR(100),
    country VARCHAR(100),
    location GEOMETRY(Point, 4326),
    datacenter_type VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Threat intelligence cache
CREATE TABLE IF NOT EXISTS threat_intel (
    id SERIAL PRIMARY KEY,
    ip_address INET UNIQUE NOT NULL,
    source VARCHAR(50),
    score INTEGER,
    categories JSONB,
    tags JSONB,
    last_seen TIMESTAMP,
    expires_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Audit log
CREATE TABLE IF NOT EXISTS audit_log (
    id SERIAL PRIMARY KEY,
    alert_id INTEGER REFERENCES alerts(id),
    action VARCHAR(50),
    performed_by VARCHAR(100),
    details JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_src_ip ON alerts(src_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_dest_ip ON alerts(dest_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_site_id ON alerts(site_id);
CREATE INDEX IF NOT EXISTS idx_alerts_risk_score ON alerts(risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_location ON alerts USING GIST(location);

CREATE INDEX IF NOT EXISTS idx_sites_location ON sites USING GIST(location);
CREATE INDEX IF NOT EXISTS idx_sites_ip_range ON sites USING GIST(ip_range inet_ops);

CREATE INDEX IF NOT EXISTS idx_threat_intel_ip ON threat_intel(ip_address);
CREATE INDEX IF NOT EXISTS idx_threat_intel_expires ON threat_intel(expires_at);

-- Create updated_at trigger
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_alerts_updated_at
    BEFORE UPDATE ON alerts
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Create materialized view for dashboard summary
CREATE MATERIALIZED VIEW IF NOT EXISTS alert_summary AS
SELECT 
    site_id,
    site_name,
    location,
    severity,
    COUNT(*) as alert_count,
    AVG(risk_score) as avg_risk_score,
    MAX(timestamp) as last_alert_time
FROM alerts
WHERE status = 'new'
GROUP BY site_id, site_name, location, severity;

CREATE INDEX IF NOT EXISTS idx_alert_summary_site ON alert_summary(site_id);

-- Insert sample sites (optional - for testing)
INSERT INTO sites (site_id, site_name, ip_range, city, country, location, datacenter_type)
VALUES 
    ('site-001', 'Azure US East', '10.0.0.0/16', 'Virginia', 'USA', 
     ST_SetSRID(ST_MakePoint(-78.6569, 37.4316), 4326), 'cloud'),
    ('site-002', 'Azure West Europe', '10.1.0.0/16', 'Amsterdam', 'Netherlands',
     ST_SetSRID(ST_MakePoint(4.9041, 52.3676), 4326), 'cloud')
ON CONFLICT (site_id) DO NOTHING;

-- Grant permissions
GRANT ALL PRIVILEGES ON DATABASE threat_intel TO tiuser;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO tiuser;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO tiuser;
