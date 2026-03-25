# 🛡️ Location-Aware Threat Intelligence Platform

A distributed threat intelligence platform deployed across Azure VMs, featuring real-time attack detection, geolocation enrichment, and VirusTotal integration.



## 🏗️ Architecture

Multi-VM distributed architecture:
- **VM-1**: Suricata IDS + Filebeat + OWASP Juice Shop
- **VM-2**: Redis Queue + TI Fetcher (AbuseIPDB/OTX/VirusTotal)
- **VM-3**: Event Processing Pipeline (Normalizer → Enricher → Correlator)
- **VM-4**: PostgreSQL + PostGIS
- **VM-5**: FastAPI Backend + React Frontend + Nginx

## ✨ Features

✅ Real-time threat detection with Suricata IDS  
✅ Geolocation enrichment via VirusTotal, AbuseIPDB, OTX  
✅ Interactive map visualization with Leaflet  
✅ Detailed threat intelligence analysis  
✅ Professional neon-themed dashboard  
✅ Multi-stage event processing pipeline  


### Prerequisites
- 5 Azure VMs (Ubuntu 24.04, 2vCPU/4GB RAM each)
- Docker & Docker Compose installed on all VMs
- API keys: VirusTotal, AbuseIPDB, AlienVault OTX

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

### The architecture was developed in azure, because of free student credit availability and multiple VMs were used to accomodate the project within different accounts and to prevent the credit exhaustion. If your VM has sufficient capacity you can run it in single VM


---

⭐ Star this repo if you find it useful!