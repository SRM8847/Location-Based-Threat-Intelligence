# VM-2: Ingestion Queue & Threat Intelligence

This VM acts as the ingestion layer, buffering incoming events and fetching external threat intelligence.

## Components

- **Redis**: In-memory queue and cache for events and threat intelligence
- **TI Fetcher**: Periodic fetcher for VirusTotal, AbuseIPDB, and AlienVault OTX
- **Log Parser**: Validates and normalizes incoming Suricata events

## Architecture
```
Filebeat (VM-1) → Redis LIST → Log Parser → Redis STREAM → VM-3 Pipeline
                    ↓
              TI Fetcher (hourly)
                    ↓
              Cached TI Data (24hr TTL)
```

## Setup

### Prerequisites
- Docker and Docker Compose installed
- VM-1 must be running (Suricata + Filebeat)
- API keys for VirusTotal, AbuseIPDB, OTX

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
REDIS_PASSWORD=your-strong-password-here
ABUSEIPDB_API_KEY=your-abuseipdb-key
OTX_API_KEY=your-otx-key
VIRUSTOTAL_API_KEY=your-virustotal-key
```

3. **Deploy services**
```bash
cd /opt/project
docker-compose up -d
```

4. **Verify deployment**
```bash
docker-compose ps
# Should show: redis, ti-fetcher, log-parser all "Up"
```

## Configuration

### Redis Configuration
- **Port**: 6379 (exposed to VM-1 and VM-3)
- **Password**: Set in `.env` file
- **Persistence**: Disabled (in-memory only)
- **Max Memory**: Uses available RAM

### TI Fetcher Configuration
Edit `ti-fetcher/fetcher.py` to adjust:
- Fetch interval (default: 3600 seconds / 1 hour)
- Cache TTL (default: 86400 seconds / 24 hours)
- Blacklist limits

### Log Parser Configuration
Edit `log-parser/parser.py` to adjust:
- Stream MAXLEN (default: 5000 events)
- Validation rules
- Event schema

## Verification

### Check Redis is Running
```bash
docker exec -it redis redis-cli -a "your-password" ping
# Expected: PONG
```

### Check Incoming Events Queue
```bash
docker exec -it redis redis-cli -a "your-password" LLEN suricata-events
# Shows number of queued events from Filebeat
```

### Check Stream Processing
```bash
docker exec -it redis redis-cli -a "your-password" XLEN normalized-events
# Shows number of normalized events
```

### Check Cached Threat Intelligence
```bash
docker exec -it redis redis-cli -a "your-password" KEYS "ti:*" | wc -l
# Shows number of cached TI entries
```

### Check TI Fetcher Logs
```bash
docker logs ti-fetcher --tail 50
# Should show periodic fetches from AbuseIPDB, OTX, VirusTotal
```

### Check Log Parser Logs
```bash
docker logs log-parser --tail 50
# Should show events being parsed and forwarded
```

## Data Structures

### Redis Keys

**Lists (FIFO Queue):**
- `suricata-events` - Raw events from Filebeat

**Streams (Ordered Processing):**
- `normalized-events` - Validated events from log-parser
- `enriched-events` - TI-enriched events (written by VM-3)
- `correlated-events` - Final alerts (written by VM-3)

**Hashes (Cached Threat Intel):**
- `ti:abuseipdb:{ip}` - AbuseIPDB data for IP
- `ti:otx:{ip}` - AlienVault OTX data for IP
- `ti:virustotal:{ip}` - VirusTotal data for IP

### Event Flow
```
1. Filebeat: RPUSH suricata-events "{json}"
2. Log Parser: BLPOP suricata-events
3. Log Parser: XADD normalized-events "{validated_json}"
4. VM-3 reads from: XREADGROUP normalized-events
```

## Troubleshooting

### Redis connection refused
```bash
# Check Redis is running
docker ps | grep redis

# Check NSG allows port 6379 from VM-1 and VM-3
# Azure Portal → NSG → Inbound Rules

# Test connection from VM-1
telnet <VM-2-IP> 6379
```

### TI Fetcher API errors
```bash
# Check API keys are set
docker exec ti-fetcher env | grep API_KEY

# Check rate limits
docker logs ti-fetcher | grep -i "rate limit\|429"

# Wait for cooldown period, then restart
docker-compose restart ti-fetcher
```

### Log Parser not processing
```bash
# Check if events are in queue
docker exec -it redis redis-cli -a "password" LLEN suricata-events

# Check log-parser logs
docker logs log-parser --tail 100

# Restart if stuck
docker-compose restart log-parser
```

### Streams filling up (>8000 events)
```bash
# Trim streams manually
docker exec -it redis redis-cli -a "password" XTRIM normalized-events MAXLEN 3000
docker exec -it redis redis-cli -a "password" XTRIM enriched-events MAXLEN 3000
docker exec -it redis redis-cli -a "password" XTRIM correlated-events MAXLEN 3000

# Or automate with cron (see deployment guide)
```

## Maintenance

### View Redis Memory Usage
```bash
docker exec -it redis redis-cli -a "password" INFO memory
```

### Clear All Data (Use Carefully!)
```bash
docker exec -it redis redis-cli -a "password" FLUSHALL
```

### Restart All Services
```bash
docker-compose restart
```

### Update TI Fetcher Code
```bash
# Edit fetcher.py
nano ti-fetcher/fetcher.py

# Rebuild and restart
docker-compose stop ti-fetcher
docker-compose build ti-fetcher
docker-compose up -d ti-fetcher
```

## Performance

- **Throughput**: 50,000+ operations/second
- **Memory**: ~800MB for typical workload
- **Network**: Outbound to TI APIs (HTTPS)
- **Disk**: Minimal (in-memory only)

## Security

- Redis password authentication required
- No external Redis access (NSG restricted)
- API keys stored in environment variables
- TLS for external API calls

## API Rate Limits

- **AbuseIPDB**: 1000 requests/day (free tier)
- **AlienVault OTX**: Unlimited (rate limited)
- **VirusTotal**: 4 requests/minute, 500/day (free tier)

Strategy: Cache aggressively, fetch in batches, respect rate limits.