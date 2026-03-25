# 🛡️ Location-Aware Threat Intelligence Platform

A distributed threat intelligence platform deployed across VMs, featuring real-time attack detection, geolocation enrichment, and VirusTotal integration.



## 🏗️ Architecture

Multi-VM distributed architecture:
| VM | Role | Docs |
|---|---|---|
| VM-1 | Attack Sensor (Suricata + Filebeat + Juice Shop) | [README](./vm-1-sensor/readme.md) |
| VM-2 | Ingestion Queue & Threat Intelligence | [README](./vm-2-ingest-queue/readme.md) |
| VM-3 | Event Processing Pipeline | [README](./vm-3-processor/readme.md) |
| VM-4 | Persistent Storage (PostgreSQL + PostGIS) | [README](./vm-4-database/readme.md) |
| VM-5 | UI & API (FastAPI + React + Nginx) | [README](./vm-5-ui-notifier/readme.md) |

## ✨ Features

✅ Real-time threat detection with Suricata IDS  
✅ Geolocation enrichment via VirusTotal, AbuseIPDB, OTX  
✅ Interactive map visualization with Leaflet  
✅ Detailed threat intelligence analysis  
✅ Professional neon-themed dashboard  
✅ Multi-stage event processing pipeline  


### Prerequisites
- 5 VMs (Ubuntu 24.04, 2vCPU/4GB RAM each)
- Docker & Docker Compose installed on all VMs
- API keys: VirusTotal, AbuseIPDB, AlienVault OTX
### The architecture was developed in Azure, because of free student credit availability and multiple VMs were used to accomodate the project within different accounts and to prevent the credit exhaustion. If your VM has sufficient capacity you can run it in single VM.


### Basic Setup

1. Clone this repository
2. Copy `.env.example` to `.env` in each VM folder
3. Update `.env` with your VM IPs and API keys
4. Deploy each VM in order (VM-1 → VM-5)
```bash
# On each VM
cd /opt/project
docker-compose up -d
```

## 🛠️ Tech Stack

**Security**: Suricata, Custom Detection Rules  
**Backend**: Python, FastAPI, Redis, PostgreSQL/PostGIS  
**Frontend**: React, Leaflet, Axios  
**Infrastructure**: Docker, Azure VMs, Nginx  

## 🔒 Security Note

This is an educational/portfolio project. For production use:
- Enable HTTPS
- Implement authentication
- Use private VNet instead of public IPs
- Rotate secrets regularly


# 🔷 Deployment Order (IMPORTANT)

Run in this order:

```bash
# VM-2 (Redis)
docker-compose up -d

# VM-4 (Database)
docker-compose up -d

# VM-3 (Processor)
docker-compose up -d

# VM-1 (Sensor)
docker-compose up -d

# VM-5 (UI/API)
docker-compose up -d
```

---

⭐ Star this repo if you find it useful!
