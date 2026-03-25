# VM-3: Event Processing Pipeline

This VM runs the three-stage processing pipeline that transforms raw alerts into enriched, correlated security events.

## Components

- **Normalizer**: Validates and structures events
- **Enricher**: Adds threat intelligence and geolocation
- **Correlator**: Applies correlation rules and stores final alerts

## Architecture
```
Redis Stream (VM-2) → Normalizer → Enricher → Correlator → PostgreSQL (VM-4)
                          ↓            ↓           ↓
                    Validation    TI Lookup   Filtering
                                  GeoIP       Deduplication
                                  CMDB        Database Insert
```

## Setup

### Prerequisites
- Docker and Docker Compose installed
- VM-2 must be running (Redis)
- VM-4 must be running (PostgreSQL)
- Network access to VM-2 (port 6379) and VM-4 (port 5432)

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
REDIS_HOST=<VM-2-PUBLIC-IP>
REDIS_PORT=6379
REDIS_PASSWORD=your-redis-password

POSTGRES_HOST=<VM-4-PUBLIC-IP>
POSTGRES_PORT=5432
POSTGRES_DB=threat_intel
POSTGRES_USER=tiuser
POSTGRES_PASSWORD=your-postgres-password
```

3. **Deploy services**
```bash
cd /opt/project
docker-compose up -d
```

4. **Verify deployment**
```bash
docker-compose ps
# Should show: normalizer, enricher, correlator all "Up"
```

## Pipeline Stages

### Stage 1: Normalizer

**Purpose**: Validate event schema and extract key fields

**Operations**:
- Schema validation (required fields present)
- Field extraction (src_ip, dest_ip, signature, etc.)
- Initial risk score assignment based on severity
- Event ID generation

**Input**: `normalized-events` stream from VM-2
**Output**: `enriched-events` stream

**Configuration**: `normalizer/normalizer.py`

**Verify**:
```bash
docker logs normalizer --tail 20
# Should show: "Normalized event from {ip}"
```

### Stage 2: Enricher

**Purpose**: Add threat intelligence, geolocation, and asset context

**Operations**:
- **Source IP (Attacker)**:
  - Query Redis for cached TI data (VirusTotal, AbuseIPDB, OTX)
  - Fallback to ip-api.com for GeoIP
  - Add: country, city, lat/lon, reputation, malicious flags
  
- **Destination IP (Target)**:
  - Query CMDB (VM-4) for asset mapping
  - Add: site_id, site_name, datacenter_type
  
**Input**: `enriched-events` stream
**Output**: `correlated-events` stream

**Configuration**: `enricher/enricher.py`

**Verify**:
```bash
docker logs enricher --tail 20
# Should show: "Enriched event from {ip}"
```

### Stage 3: Correlator

**Purpose**: Filter and store final alerts in PostgreSQL

**Operations**:
- Filter: Only store event_type='alert' (skip flows, stats)
- Correlation rules (future enhancement)
- Insert into PostgreSQL alerts table
- Audit logging

**Input**: `correlated-events` stream
**Output**: PostgreSQL database

**Configuration**: `correlator/correlator.py`

**Verify**:
```bash
docker logs correlator --tail 20
# Should show: "Stored alert: {severity} - {src_ip} -> {site_name}"
```

## Verification

### Check All Services Running
```bash
docker-compose ps
```

### Watch Pipeline in Real-Time
```bash
# Terminal 1
docker logs normalizer -f

# Terminal 2
docker logs enricher -f

# Terminal 3
docker logs correlator -f
```

### Check Event Counts
```bash
# On VM-2
docker exec -it redis redis-cli -a "password" XLEN enriched-events
docker exec -it redis redis-cli -a "password" XLEN correlated-events

# On VM-4
docker exec -it postgres psql -U tiuser -d threat_intel -c "SELECT COUNT(*) FROM alerts;"
```

### Test End-to-End
```bash
# Generate test attack (from your PC)
curl "http://<VM-1-IP>:3000/?test=<script>alert(1)</script>"

# Wait 30 seconds, check database
docker exec -it postgres psql -U tiuser -d threat_intel -c \
  "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 1;"
```

## Configuration

### Normalizer Settings
Edit `normalizer/normalizer.py`:
- Severity mapping rules
- Risk score calculation
- Stream MAXLEN (default: 5000)

### Enricher Settings
Edit `enricher/enricher.py`:
- TI lookup priority (VirusTotal → AbuseIPDB → OTX → GeoIP)
- GeoIP fallback API
- CMDB query logic

### Correlator Settings
Edit `correlator/correlator.py`:
- Event type filtering
- Correlation rules
- Database insert logic

## Troubleshooting

### Normalizer stuck/not processing
```bash
# Check Redis connection
docker logs normalizer | grep -i "error\|connection"

# Verify consumer group exists
docker exec -it redis redis-cli -a "password" XINFO GROUPS normalized-events

# Restart normalizer
docker-compose restart normalizer
```

### Enricher returning null locations
```bash
# Check TI cache
docker exec -it redis redis-cli -a "password" KEYS "ti:*" | wc -l
# Should be > 0

# Check GeoIP API is working
docker exec enricher curl "http://ip-api.com/json/8.8.8.8"
# Should return JSON with location data

# Check logs for API errors
docker logs enricher | grep -i "geoip\|error"
```

### Correlator not inserting to database
```bash
# Test PostgreSQL connection
docker exec correlator python3 -c "import psycopg2; \
  conn = psycopg2.connect(host='<VM-4-IP>', port=5432, \
  database='threat_intel', user='tiuser', password='<password>'); \
  print('Connected!')"

# Check NSG allows VM-3 → VM-4 on port 5432

# Check correlator logs
docker logs correlator | grep -i "error\|database"
```

### Pipeline performance degradation
```bash
# Check stream consumer lag
docker exec -it redis redis-cli -a "password" XPENDING normalized-events parsers

# Check service CPU/memory
docker stats

# Reduce stream MAXLEN if needed
# Edit respective .py files and rebuild
```

## Performance

- **Throughput**: 100-200 events/second per stage
- **Latency**: 1-2 seconds end-to-end (VM-2 → PostgreSQL)
- **Memory**: ~500MB per service
- **CPU**: 10-20% per service under normal load

## Data Flow Example

**Input (from Suricata)**:
```json
{
  "timestamp": "2026-03-18T10:00:00Z",
  "event_type": "alert",
  "src_ip": "1.2.3.4",
  "dest_ip": "172.18.0.4",
  "alert": {"signature": "XSS Attack", "severity": 1}
}
```

**After Normalizer**:
```json
{
  ...previous fields...,
  "event_id": "123456789",
  "severity": "high",
  "risk_score": 75
}
```

**After Enricher**:
```json
{
  ...previous fields...,
  "enrichment": {
    "src_location": {
      "country": "United States",
      "city": "New York",
      "latitude": 40.7128,
      "longitude": -74.0060
    },
    "src_threats": [{
      "source": "virustotal",
      "malicious": 3
    }],
    "dest_site": {
      "site_id": "site-007",
      "site_name": "VM-1 Internal Network"
    }
  }
}
```

**After Correlator**:
Stored in PostgreSQL `alerts` table with full enrichment.

## Maintenance

### Update Pipeline Code
```bash
# Edit any .py file
nano enricher/enricher.py

# Rebuild specific service
docker-compose stop enricher
docker-compose build enricher
docker-compose up -d enricher
```

### Reset Consumer Groups (if stuck)
```bash
# On VM-2
docker exec -it redis redis-cli -a "password" \
  XGROUP DESTROY normalized-events parsers

docker exec -it redis redis-cli -a "password" \
  XGROUP CREATE normalized-events parsers $ MKSTREAM

# Restart VM-3 services
docker-compose restart
```

### View Pending Messages
```bash
docker exec -it redis redis-cli -a "password" \
  XPENDING normalized-events parsers
```

## Security

- Read-only access to Redis (no write to input stream)
- Write-only access to PostgreSQL (no admin privileges)
- No external network access except ip-api.com (GeoIP)
- Environment variables for all credentials