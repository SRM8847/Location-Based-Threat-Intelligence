# VM-4: Persistent Storage

This VM runs PostgreSQL with PostGIS extension for storing enriched security alerts and asset inventory.

## Components

- **PostgreSQL 16**: Relational database
- **PostGIS 3.4**: Geospatial extension for location queries

## Database Schema

### Tables

**alerts** - Stores all security alerts with enrichment
- Primary key: `id` (auto-increment)
- Indexes: timestamp, severity, status, src_ip, location (GIST)
- JSONB field: `enrichment_data` (flexible TI storage)

**sites** - Configuration Management Database (CMDB)
- Maps IP ranges to business assets
- Contains: site_id, site_name, city, country, location

**audit_log** - Tracks analyst actions
- Records: acknowledge, resolve, notes
- For compliance and auditing

## Setup

### Prerequisites
- Docker and Docker Compose installed
- At least 8GB RAM (PostgreSQL buffer cache)
- 50GB disk space

### Installation

1. **Copy environment template**
```bash
cp .env.example .env
```

2. **Edit `.env` file**
```bash
nano .env
```

Update these values:
```bash
POSTGRES_DB=threat_intel
POSTGRES_USER=tiuser
POSTGRES_PASSWORD=your-strong-password-here
```

3. **Deploy database**
```bash
cd /opt/project
docker-compose up -d
```

4. **Wait for initialization** (30-60 seconds)
```bash
docker logs postgres -f
# Wait for: "database system is ready to accept connections"
```

5. **Verify deployment**
```bash
docker exec -it postgres psql -U tiuser -d threat_intel -c "SELECT version();"
```

## Database Initialization

### Automatic Setup (First Run)

On first deployment, the following happens automatically:

1. Create database `threat_intel`
2. Enable PostGIS extension
3. Create tables (alerts, sites, audit_log)
4. Create indexes
5. Load CMDB data from `sites.csv`

**Scripts location**: `init-scripts/`
- `01-create-database.sql`
- `02-create-tables.sql`
- `03-load-cmdb.sql`

### Manual Setup (If Needed)

If auto-initialization fails:
```bash
# Connect to database
docker exec -it postgres psql -U tiuser -d threat_intel

# Create tables manually
\i /docker-entrypoint-initdb.d/02-create-tables.sql

# Load CMDB
COPY sites FROM '/docker-entrypoint-initdb.d/sites.csv' CSV HEADER;
```

## Verification

### Check Database Exists
```bash
docker exec -it postgres psql -U tiuser -d threat_intel -c "\l"
```

### Check Tables Created
```bash
docker exec -it postgres psql -U tiuser -d threat_intel -c "\dt"
# Should show: alerts, sites, audit_log
```

### Check PostGIS Extension
```bash
docker exec -it postgres psql -U tiuser -d threat_intel -c "\dx"
# Should show: postgis
```

### Check CMDB Data
```bash
docker exec -it postgres psql -U tiuser -d threat_intel -c \
  "SELECT COUNT(*) FROM sites;"
# Should return number of sites (e.g., 9)
```

### Check Alerts Table
```bash
docker exec -it postgres psql -U tiuser -d threat_intel -c \
  "SELECT COUNT(*) FROM alerts;"
```

## Queries

### Recent Alerts
```sql
SELECT 
  id, 
  timestamp, 
  severity, 
  signature, 
  src_ip, 
  site_name 
FROM alerts 
ORDER BY timestamp DESC 
LIMIT 10;
```

### Alerts by Severity
```sql
SELECT 
  severity, 
  COUNT(*) as count 
FROM alerts 
GROUP BY severity 
ORDER BY 
  CASE severity 
    WHEN 'critical' THEN 1 
    WHEN 'high' THEN 2 
    WHEN 'medium' THEN 3 
    WHEN 'low' THEN 4 
  END;
```

### Alerts by Site
```sql
SELECT 
  site_name, 
  COUNT(*) as attacks,
  AVG(risk_score) as avg_risk
FROM alerts 
WHERE site_name IS NOT NULL
GROUP BY site_name 
ORDER BY attacks DESC;
```

### Geographic Distribution
```sql
SELECT 
  enrichment_data->'src_location'->>'country' as country,
  COUNT(*) as attacks
FROM alerts
WHERE enrichment_data->'src_location' IS NOT NULL
GROUP BY enrichment_data->'src_location'->>'country'
ORDER BY attacks DESC
LIMIT 10;
```

### Spatial Query (Attacks Near Location)
```sql
SELECT 
  id, 
  src_ip, 
  signature,
  ST_Distance(
    location::geography,
    ST_SetSRID(ST_MakePoint(72.8777, 19.0760), 4326)::geography
  ) / 1000 as distance_km
FROM alerts
WHERE ST_DWithin(
  location::geography,
  ST_SetSRID(ST_MakePoint(72.8777, 19.0760), 4326)::geography,
  100000  -- 100km radius
)
ORDER BY distance_km;
```

### Recent Activity Timeline
```sql
SELECT 
  date_trunc('hour', timestamp) as hour,
  COUNT(*) as alerts,
  COUNT(DISTINCT src_ip) as unique_attackers
FROM alerts
WHERE timestamp > NOW() - INTERVAL '24 hours'
GROUP BY hour
ORDER BY hour DESC;
```

## Maintenance

### Backup Database
```bash
# Full backup
docker exec -it postgres pg_dump -U tiuser threat_intel > backup_$(date +%Y%m%d).sql

# Compress backup
gzip backup_$(date +%Y%m%d).sql
```

### Restore Database
```bash
# Restore from backup
gunzip backup_20260318.sql.gz
docker exec -i postgres psql -U tiuser -d threat_intel < backup_20260318.sql
```

### Vacuum Database (Reclaim Space)
```bash
docker exec -it postgres psql -U tiuser -d threat_intel -c "VACUUM ANALYZE;"
```

### View Database Size
```bash
docker exec -it postgres psql -U tiuser -d threat_intel -c \
  "SELECT pg_size_pretty(pg_database_size('threat_intel'));"
```

### View Table Sizes
```bash
docker exec -it postgres psql -U tiuser -d threat_intel -c \
  "SELECT 
     schemaname,
     tablename,
     pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) AS size
   FROM pg_tables 
   WHERE schemaname = 'public'
   ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC;"
```

### Archive Old Alerts
```bash
# Archive alerts older than 90 days
docker exec -it postgres psql -U tiuser -d threat_intel -c \
  "DELETE FROM alerts WHERE timestamp < NOW() - INTERVAL '90 days';"

# Or move to archive table
docker exec -it postgres psql -U tiuser -d threat_intel -c \
  "INSERT INTO alerts_archive SELECT * FROM alerts WHERE timestamp < NOW() - INTERVAL '90 days';
   DELETE FROM alerts WHERE timestamp < NOW() - INTERVAL '90 days';"
```

## Performance Tuning

### Check Index Usage
```bash
docker exec -it postgres psql -U tiuser -d threat_intel -c \
  "SELECT * FROM pg_stat_user_indexes WHERE schemaname = 'public';"
```

### Slow Query Log
Edit `postgresql.conf` to enable slow query logging:
```
log_min_duration_statement = 1000  # Log queries taking > 1 second
```

### Connection Pool Stats
```bash
docker exec -it postgres psql -U tiuser -d threat_intel -c \
  "SELECT * FROM pg_stat_activity;"
```

## Troubleshooting

### Connection refused from VM-3 or VM-5
```bash
# Check PostgreSQL is running
docker ps | grep postgres

# Check listening on port 5432
docker exec postgres netstat -tuln | grep 5432

# Check NSG allows inbound 5432 from VM-3 and VM-5 IPs
# Azure Portal → NSG → Inbound Rules

# Test from VM-3
telnet <VM-4-IP> 5432
```

### Out of disk space
```bash
# Check disk usage
df -h /var/lib/docker

# Check database size
docker exec -it postgres psql -U tiuser -d threat_intel -c \
  "SELECT pg_database_size('threat_intel') / 1024 / 1024 as size_mb;"

# Archive old data (see Maintenance section)
```

### Slow queries
```bash
# Check current queries
docker exec -it postgres psql -U tiuser -d threat_intel -c \
  "SELECT pid, now() - query_start as duration, query 
   FROM pg_stat_activity 
   WHERE state = 'active' 
   ORDER BY duration DESC;"

# Kill long-running query
docker exec -it postgres psql -U tiuser -d threat_intel -c \
  "SELECT pg_terminate_backend(PID);"
```

### PostGIS not working
```bash
# Verify extension is installed
docker exec -it postgres psql -U tiuser -d threat_intel -c "\dx"

# Reinstall if needed
docker exec -it postgres psql -U tiuser -d threat_intel -c \
  "CREATE EXTENSION IF NOT EXISTS postgis;"
```

## Security

- Password authentication required
- No superuser access for application
- NSG restricts access to VM-3 and VM-5 only
- SSL/TLS not enabled (private network)
- Regular backups recommended

## Performance Metrics

- **Write throughput**: 1,000+ inserts/second
- **Read latency**: < 10ms for indexed queries
- **Storage**: ~5GB for 100,000 alerts
- **Memory**: Uses ~2GB for buffer cache

## CMDB Format

`sites.csv` format:
```csv
site_id,site_name,ip_range,city,country,latitude,longitude,datacenter_type
site-001,Azure US East,10.0.0.0/16,Virginia,USA,37.4316,-78.6569,cloud
site-002,HQ Office,192.168.1.0/24,New York,USA,40.7128,-74.0060,office
```

Update CMDB:
```bash
# Edit sites.csv locally
nano /opt/cmdb/sites.csv

# Reload into database
docker exec -i postgres psql -U tiuser -d threat_intel -c \
  "TRUNCATE sites; COPY sites FROM STDIN CSV HEADER;" < /opt/cmdb/sites.csv
```