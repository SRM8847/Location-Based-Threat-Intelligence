# VM-5: User Interface & API

This VM provides the web interface for security analysts to view, investigate, and manage alerts.

## Components

- **FastAPI Backend**: RESTful API serving enriched alerts
- **React Frontend**: Interactive dashboard with map visualization
- **Nginx**: Reverse proxy and static file server
- **Notifier**: Alert notification service (placeholder)

## Architecture
```
User Browser → Nginx (80/443) → React Frontend
                  ↓
               FastAPI (/api/*) → PostgreSQL (VM-4)
                  ↓
            VirusTotal API (detailed analysis)
```

## Setup

### Prerequisites
- Docker and Docker Compose installed
- VM-4 must be running (PostgreSQL)
- VirusTotal API key (for detailed analysis feature)
- Ports 80 and 443 open in NSG

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
POSTGRES_HOST=<VM-4-PUBLIC-IP>
POSTGRES_PORT=5432
POSTGRES_DB=threat_intel
POSTGRES_USER=tiuser
POSTGRES_PASSWORD=your-postgres-password

VIRUSTOTAL_API_KEY=your-virustotal-api-key
```

3. **Deploy services**
```bash
cd /opt/project
docker-compose up -d
```

4. **Wait for frontend build** (2-3 minutes)
```bash
docker logs frontend -f
# Wait for: "Compiled successfully!"
```

5. **Verify deployment**
```bash
docker-compose ps
# Should show: backend, frontend, nginx all "Up"
```

## Components Details

### FastAPI Backend

**Port**: 8000 (internal only, accessed via Nginx)

**API Endpoints**:
- `GET /` - API health check
- `GET /api/alerts` - List alerts (with filters)
- `GET /api/alerts/{id}` - Single alert details
- `GET /api/alerts/{id}/detailed-analysis` - VirusTotal deep dive
- `POST /api/alerts/{id}/acknowledge` - Mark alert as reviewed
- `POST /api/alerts/{id}/resolve` - Close alert
- `GET /api/stats` - Dashboard statistics
- `GET /api/sites` - CMDB asset list

**Configuration**: `backend/main.py`

**Dependencies**: `backend/requirements.txt`

### React Frontend

**Technology**: React 18, Leaflet.js, Axios

**Features**:
- Interactive world map with attack markers
- Filterable alert list (severity, status)
- Quick investigation panel
- Detailed VirusTotal analysis
- Alert management (acknowledge, resolve)
- Real-time updates (30-second polling)

**Configuration**: `frontend/src/App.js`

**Styling**: Custom CSS with violet-blue neon theme

### Nginx

**Port**: 80 (HTTP), 443 (HTTPS - optional)

**Routes**:
- `/` → React frontend static files
- `/api/*` → FastAPI backend proxy

**Configuration**: `nginx/nginx.conf`

**Static Files**: Served from `/usr/share/nginx/html`

## Verification

### Check All Services Running
```bash
docker-compose ps
```

### Test Backend API
```bash
# Health check
curl http://localhost:8000/

# Get alerts
curl http://localhost:8000/api/alerts?limit=5

# Get stats
curl http://localhost:8000/api/stats
```

### Test Frontend
```bash
# Check Nginx is serving frontend
curl -I http://localhost:80
# Should return: 200 OK
```

### Access Dashboard
Open browser: `http://<VM-5-PUBLIC-IP>`

Expected: Dashboard loads with map and alert list

### Test Detailed Analysis
1. Click any alert → "🔍 Investigate"
2. Click "🔬 Detailed Analysis"
3. Should load VirusTotal data (requires API key)

## API Documentation

### GET /api/alerts

**Parameters**:
- `severity` (optional): critical, high, medium, low
- `status` (optional): new, acknowledged, resolved
- `site_id` (optional): Filter by site
- `limit` (default: 100): Max results

**Example**:
```bash
curl "http://localhost:8000/api/alerts?severity=critical&status=new&limit=10"
```

**Response**:
```json
{
  "alerts": [
    {
      "id": 123,
      "timestamp": "2026-03-18T10:00:00Z",
      "severity": "critical",
      "signature": "SQL Injection - UNION SELECT",
      "src_ip": "1.2.3.4",
      "dest_ip": "172.18.0.4",
      "risk_score": 100,
      "site_name": "VM-1 Internal Network",
      "latitude": 40.7128,
      "longitude": -74.0060
    }
  ],
  "count": 1
}
```

### GET /api/stats

**Response**:
```json
{
  "recent_1h": 25,
  "severity_counts": [
    {"severity": "critical", "count": 10},
    {"severity": "high", "count": 15}
  ],
  "site_stats": [
    {
      "site_name": "VM-1 Internal Network",
      "alert_count": 50,
      "avg_risk_score": 75.5
    }
  ]
}
```

### POST /api/alerts/{id}/acknowledge

**Body**:
```json
{
  "acknowledged_by": "analyst_name",
  "notes": "Investigating potential false positive"
}
```

**Response**:
```json
{
  "message": "Alert acknowledged",
  "alert_id": 123
}
```

## UI Features

### Dashboard Header
- Statistics cards (recent alerts, severity breakdown)
- Map toggle button
- Auto-refresh every 30 seconds

### Interactive Map
- CartoDB dark theme base layer
- Color-coded markers (severity)
- Circle radius = risk score
- Click marker to see alert details
- Popup with signature and severity

### Alert List
- Scrollable sidebar
- Severity badge with color coding
- Timestamp in IST
- Source → Target display
- Action buttons per alert

### Investigation Panel
- Alert ID, signature, severity
- Risk score (0-100)
- Source and target details
- Protocol and timestamp
- Acknowledge/Resolve buttons
- Link to detailed analysis

### Detailed Analysis Page
- Full-screen overlay
- VirusTotal API integration
- Geolocation (country, continent, RIR)
- Network info (ASN, AS owner, network range)
- Reputation breakdown (malicious/suspicious/harmless)
- WHOIS data
- Tags and categories
- Our internal enrichment data

## Customization

### Change Dashboard Theme
Edit `frontend/src/App.css`:
```css
:root {
  --primary-dark: #0a0e27;      /* Background color */
  --accent-violet: #6366f1;     /* Primary accent */
  --accent-blue: #3b82f6;       /* Secondary accent */
}
```

### Adjust Auto-Refresh Interval
Edit `frontend/src/App.js`:
```javascript
const interval = setInterval(() => {
  fetchAlerts();
  fetchStats();
}, 30000); // Change to desired milliseconds
```

### Add New API Endpoint
1. Edit `backend/main.py`
2. Add new route with `@app.get()` or `@app.post()`
3. Rebuild backend: `docker-compose build backend`
4. Restart: `docker-compose up -d backend`

### Enable HTTPS
1. Obtain SSL certificate (Let's Encrypt)
2. Edit `nginx/nginx.conf` to add SSL configuration
3. Update `docker-compose.yml` to expose port 443
4. Rebuild: `docker-compose up -d nginx`

## Troubleshooting

### Dashboard shows white screen
```bash
# Check browser console (F12)
# Look for JavaScript errors

# Check if frontend built successfully
docker logs frontend | grep -i error

# Rebuild frontend
docker-compose stop frontend
docker-compose build frontend
docker-compose up -d frontend
```

### API returns 500 errors
```bash
# Check backend logs
docker logs backend --tail 50

# Test database connection
docker exec backend python3 -c "import psycopg2; \
  conn = psycopg2.connect(host='<VM-4-IP>', port=5432, \
  database='threat_intel', user='tiuser', password='<password>'); \
  print('Connected!')"

# Restart backend
docker-compose restart backend
```

### Map not loading
```bash
# Check browser console for errors
# Common issue: Leaflet CSS not loading

# Verify internet connectivity (CDN access)
curl https://unpkg.com/leaflet@1.9.4/dist/leaflet.css

# Clear browser cache: Ctrl + Shift + R
```

### Detailed analysis returns "API key not configured"
```bash
# Check environment variable is set
docker exec backend env | grep VIRUSTOTAL

# Update .env file
nano .env
# Add: VIRUSTOTAL_API_KEY=your-key-here

# Restart backend
docker-compose restart backend
```

### Nginx 502 Bad Gateway
```bash
# Check backend is running
docker ps | grep backend

# Check backend is listening on port 8000
docker exec backend netstat -tuln | grep 8000

# Check nginx can reach backend
docker exec nginx curl http://backend:8000/
# Should return API response

# Restart all services
docker-compose restart
```

## Performance

- **Dashboard load time**: < 2 seconds (100 alerts)
- **API response time**: < 100ms (indexed queries)
- **Map rendering**: < 1 second (100 markers)
- **Concurrent users**: 50+ (single VM)

## Security

- No authentication (add OAuth2 for production)
- CORS enabled for dashboard origin
- SQL injection prevented (parameterized queries)
- Input validation via Pydantic models
- HTTPS recommended for production

## Maintenance

### Update Backend Code
```bash
# Edit Python files
nano backend/main.py

# Rebuild
docker-compose stop backend
docker-compose build backend
docker-compose up -d backend
```

### Update Frontend Code
```bash
# Edit React files
nano frontend/src/App.js

# Rebuild (takes 2-3 minutes)
docker-compose stop frontend
docker-compose build frontend
docker-compose up -d frontend

# Clear browser cache
# Press Ctrl + Shift + R in browser
```

### View Access Logs
```bash
docker logs nginx | tail -100
```

### Monitor Resource Usage
```bash
docker stats backend frontend nginx
```

## Browser Compatibility

- Chrome/Edge: ✅ Fully supported
- Firefox: ✅ Fully supported
- Safari: ✅ Fully supported
- Mobile: ⚠️ Responsive but optimized for desktop

## Recommended Screen Resolution

- Minimum: 1366x768
- Optimal: 1920x1080 or higher
- Ultra-wide: Supported (map scales nicely)