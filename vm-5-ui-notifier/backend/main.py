#!/usr/bin/env python3
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
import psycopg2
import psycopg2.extras
import os
import requests
import json
from datetime import datetime

app = FastAPI(title="Threat Intelligence API")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Database connection
POSTGRES_HOST = os.getenv('POSTGRES_HOST', 'localhost')
POSTGRES_PORT = int(os.getenv('POSTGRES_PORT', 5432))
POSTGRES_DB = os.getenv('POSTGRES_DB', 'threat_intel')
POSTGRES_USER = os.getenv('POSTGRES_USER', 'tiuser')
POSTGRES_PASSWORD = os.getenv('POSTGRES_PASSWORD', '')

def get_db_conn():
    return psycopg2.connect(
        host=POSTGRES_HOST,
        port=POSTGRES_PORT,
        database=POSTGRES_DB,
        user=POSTGRES_USER,
        password=POSTGRES_PASSWORD
    )

# Models
class AlertAcknowledge(BaseModel):
    acknowledged_by: str
    notes: Optional[str] = None

class AlertResolve(BaseModel):
    resolved_by: str
    notes: Optional[str] = None

# Routes
@app.get("/")
def root():
    return {"message": "Threat Intelligence API", "status": "running"}

@app.get("/api/alerts")
def get_alerts(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    site_id: Optional[str] = None,
    limit: int = 100
):
    """Get alerts with optional filters"""
    try:
        conn = get_db_conn()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        query = """
            SELECT 
                id, event_id, timestamp, event_type,
                src_ip, src_port, dest_ip, dest_port, protocol,
                signature, signature_id, category, severity, risk_score,
                site_id, site_name,
                ST_X(location) as longitude,
                ST_Y(location) as latitude,
                enrichment_data, status,
                acknowledged_by, acknowledged_at,
                resolved_by, resolved_at, notes,
                created_at
            FROM alerts
            WHERE 1=1
        """
        params = []
        
        if severity:
            query += " AND severity = %s"
            params.append(severity)
        
        if status:
            query += " AND status = %s"
            params.append(status)
        
        if site_id:
            query += " AND site_id = %s"
            params.append(site_id)
        
        query += " ORDER BY timestamp DESC LIMIT %s"
        params.append(limit)
        
        cur.execute(query, params)
        alerts = cur.fetchall()
        
        cur.close()
        conn.close()
        
        return {"alerts": alerts, "count": len(alerts)}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/alerts/{alert_id}")
def get_alert(alert_id: int):
    """Get single alert by ID"""
    try:
        conn = get_db_conn()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        cur.execute("""
            SELECT 
                id, event_id, timestamp, event_type,
                src_ip, src_port, dest_ip, dest_port, protocol,
                signature, signature_id, category, severity, risk_score,
                site_id, site_name,
                ST_X(location) as longitude,
                ST_Y(location) as latitude,
                enrichment_data, raw_event, status,
                acknowledged_by, acknowledged_at,
                resolved_by, resolved_at, notes,
                created_at
            FROM alerts
            WHERE id = %s
        """, (alert_id,))
        
        alert = cur.fetchone()
        
        cur.close()
        conn.close()
        
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")
        
        return alert
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/alerts/{alert_id}/acknowledge")
def acknowledge_alert(alert_id: int, data: AlertAcknowledge):
    """Acknowledge an alert"""
    try:
        conn = get_db_conn()
        cur = conn.cursor()
        
        cur.execute("""
            UPDATE alerts
            SET status = 'acknowledged',
                acknowledged_by = %s,
                acknowledged_at = %s,
                notes = COALESCE(notes || E'\n', '') || %s
            WHERE id = %s
        """, (
            data.acknowledged_by,
            datetime.utcnow(),
            f"[{datetime.utcnow().isoformat()}] Acknowledged by {data.acknowledged_by}: {data.notes or 'No notes'}",
            alert_id
        ))
        
        # Log to audit
        cur.execute("""
            INSERT INTO audit_log (alert_id, action, performed_by, details)
            VALUES (%s, %s, %s, %s)
        """, (
            alert_id,
            'acknowledge',
            data.acknowledged_by,
            json.dumps({'notes': data.notes})
        ))
        
        conn.commit()
        cur.close()
        conn.close()
        
        return {"message": "Alert acknowledged", "alert_id": alert_id}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/alerts/{alert_id}/resolve")
def resolve_alert(alert_id: int, data: AlertResolve):
    """Resolve an alert"""
    try:
        conn = get_db_conn()
        cur = conn.cursor()
        
        cur.execute("""
            UPDATE alerts
            SET status = 'resolved',
                resolved_by = %s,
                resolved_at = %s,
                notes = COALESCE(notes || E'\n', '') || %s
            WHERE id = %s
        """, (
            data.resolved_by,
            datetime.utcnow(),
            f"[{datetime.utcnow().isoformat()}] Resolved by {data.resolved_by}: {data.notes or 'No notes'}",
            alert_id
        ))
        
        # Log to audit
        cur.execute("""
            INSERT INTO audit_log (alert_id, action, performed_by, details)
            VALUES (%s, %s, %s, %s)
        """, (
            alert_id,
            'resolve',
            data.resolved_by,
            json.dumps({'notes': data.notes})
        ))
        
        conn.commit()
        cur.close()
        conn.close()
        
        return {"message": "Alert resolved", "alert_id": alert_id}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/stats")
def get_stats():
    """Get dashboard statistics"""
    try:
        conn = get_db_conn()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        # Total alerts by severity
        cur.execute("""
            SELECT severity, COUNT(*) as count
            FROM alerts
            WHERE status = 'new'
            GROUP BY severity
        """)
        severity_counts = cur.fetchall()
        
        # Alerts by site
        cur.execute("""
            SELECT 
                site_id, site_name,
                ST_X(location) as longitude,
                ST_Y(location) as latitude,
                COUNT(*) as alert_count,
                AVG(risk_score) as avg_risk_score
            FROM alerts
            WHERE status = 'new' AND site_id IS NOT NULL
            GROUP BY site_id, site_name, location
        """)
        site_stats = cur.fetchall()
        
        # Recent alerts
        cur.execute("""
            SELECT COUNT(*) as count
            FROM alerts
            WHERE timestamp > NOW() - INTERVAL '1 hour'
        """)
        recent = cur.fetchone()
        
        cur.close()
        conn.close()
        
        return {
            "severity_counts": severity_counts,
            "site_stats": site_stats,
            "recent_1h": recent['count']
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/sites")
def get_sites():
    """Get all sites"""
    try:
        conn = get_db_conn()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        cur.execute("""
            SELECT 
                site_id, site_name, city, country,
                ST_X(location) as longitude,
                ST_Y(location) as latitude,
                datacenter_type
            FROM sites
        """)
        sites = cur.fetchall()
        
        cur.close()
        conn.close()
        
        return {"sites": sites}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
#####
@app.get("/api/alerts/{alert_id}/detailed-analysis")
def get_detailed_analysis(alert_id: int):
    """Get detailed threat intelligence analysis for an alert"""
    try:
        # Get alert from database
        conn = get_db_conn()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        cur.execute("""
            SELECT src_ip, dest_ip, enrichment_data, raw_event
            FROM alerts
            WHERE id = %s
        """, (alert_id,))
        
        alert = cur.fetchone()
        cur.close()
        conn.close()
        
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")
        
        src_ip = alert['src_ip']
        
        # Call VirusTotal API for detailed analysis
        vt_api_key = os.getenv('VIRUSTOTAL_API_KEY', '')
        
        if not vt_api_key or vt_api_key == 'your-virustotal-api-key-here':
            return {
                "error": "VirusTotal API key not configured",
                "src_ip": src_ip,
                "basic_data": alert['enrichment_data']
            }
        
        headers = {'x-apikey': vt_api_key}
        
        # Get IP analysis from VirusTotal
        vt_url = f"https://www.virustotal.com/api/v3/ip_addresses/{src_ip}"
        vt_response = requests.get(vt_url, headers=headers, timeout=10)
        
        if vt_response.status_code == 200:
            vt_data = vt_response.json()
            attributes = vt_data.get('data', {}).get('attributes', {})
            
            analysis = {
                "alert_id": alert_id,
                "src_ip": src_ip,
                "dest_ip": alert['dest_ip'],
                
                # Geolocation
                "geolocation": {
                    "country": attributes.get('country', 'Unknown'),
                    "continent": attributes.get('continent', 'Unknown'),
                    "regional_internet_registry": attributes.get('regional_internet_registry', 'Unknown')
                },
                
                # Network Information
                "network": {
                    "asn": attributes.get('asn', 0),
                    "as_owner": attributes.get('as_owner', 'Unknown'),
                    "network": attributes.get('network', 'Unknown')
                },
                
                # Reputation & Analysis
                "reputation": {
                    "reputation_score": attributes.get('reputation', 0),
                    "last_analysis_stats": attributes.get('last_analysis_stats', {}),
                    "malicious_count": attributes.get('last_analysis_stats', {}).get('malicious', 0),
                    "suspicious_count": attributes.get('last_analysis_stats', {}).get('suspicious', 0),
                    "harmless_count": attributes.get('last_analysis_stats', {}).get('harmless', 0),
                    "undetected_count": attributes.get('last_analysis_stats', {}).get('undetected', 0)
                },
                
                # WHOIS
                "whois": attributes.get('whois', 'No WHOIS data available'),
                
                # Historical Data
                "historical": {
                    "last_analysis_date": attributes.get('last_analysis_date', 0),
                    "last_modification_date": attributes.get('last_modification_date', 0)
                },
                
                # Tags and Categories
                "tags": attributes.get('tags', []),
                
                # Detected URLs and Files
                "total_votes": attributes.get('total_votes', {}),
                
                # Raw enrichment from our system
                "our_enrichment": alert['enrichment_data']
            }
            
            return analysis
        else:
            return {
                "error": f"VirusTotal API error: {vt_response.status_code}",
                "src_ip": src_ip,
                "basic_data": alert['enrichment_data']
            }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
####
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
