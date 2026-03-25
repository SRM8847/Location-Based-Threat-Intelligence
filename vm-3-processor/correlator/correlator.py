#!/usr/bin/env python3
import os
import json
import redis
import psycopg2
import logging
from datetime import datetime, timedelta
from collections import defaultdict

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Configuration
REDIS_HOST = os.getenv('REDIS_HOST', 'localhost')
REDIS_PORT = int(os.getenv('REDIS_PORT', 6379))
REDIS_PASSWORD = os.getenv('REDIS_PASSWORD', '')
INPUT_STREAM = os.getenv('INPUT_STREAM', 'correlated-events')

POSTGRES_HOST = os.getenv('POSTGRES_HOST', 'localhost')
POSTGRES_PORT = int(os.getenv('POSTGRES_PORT', 5432))
POSTGRES_DB = os.getenv('POSTGRES_DB', 'threat_intel')
POSTGRES_USER = os.getenv('POSTGRES_USER', 'tiuser')
POSTGRES_PASSWORD = os.getenv('POSTGRES_PASSWORD', '')

# Redis connection
r = redis.Redis(
    host=REDIS_HOST,
    port=REDIS_PORT,
    password=REDIS_PASSWORD,
    decode_responses=False
)

# PostgreSQL connection
def get_db_conn():
    return psycopg2.connect(
        host=POSTGRES_HOST,
        port=POSTGRES_PORT,
        database=POSTGRES_DB,
        user=POSTGRES_USER,
        password=POSTGRES_PASSWORD
    )

# In-memory correlation state
event_window = defaultdict(list)
WINDOW_SIZE = 300  # 5 minutes

def calculate_risk_score(event):
    """Calculate location-based risk score"""
    score = 0
    
    # Base alert severity
    if event.get('alert'):
        severity = event['alert'].get('severity', 0)
        score += severity * 10
    
    # Threat intelligence
    enrichment = event.get('enrichment', {})
    
    if enrichment.get('src_threats'):
        for threat in enrichment['src_threats']:
            if threat['source'] == 'abuseipdb':
                score += threat.get('score', 0) / 10
    
    if enrichment.get('dest_threats'):
        score += 20  # Internal asset communicating with known bad IP
    
    # Multiple events from same source
    src_ip = event.get('src_ip')
    if src_ip:
        recent_events = event_window.get(src_ip, [])
        score += len(recent_events) * 5
    
    # External vs internal attacker
    if not enrichment.get('src_site'):
        score += 15  # External attacker
    
    # Target is critical infrastructure
    if enrichment.get('dest_site', {}).get('datacenter_type') == 'datacenter':
        score += 20
    
    return min(score, 100)  # Cap at 100

def get_severity_level(score):
    """Convert score to severity level"""
    if score >= 75:
        return 'critical'
    elif score >= 50:
        return 'high'
    elif score >= 25:
        return 'medium'
    else:
        return 'low'

def store_alert(event, risk_score, severity):
    """Store alert in PostgreSQL"""
    try:
        conn = get_db_conn()
        cur = conn.cursor()
        
        enrichment = event.get('enrichment', {}) or {}
        dest_site = enrichment.get('dest_site') or {}
        src_site = enrichment.get('src_site') or {}
        
        # Prefer dest_site, fallback to src_site
        site = dest_site if dest_site else src_site
        
        # Get location coordinates
        lat = site.get('latitude', 0.0) if site else 0.0
        lon = site.get('longitude', 0.0) if site else 0.0
        
        # Get alert info
        alert_info = event.get('alert', {}) or {}
        
        cur.execute("""
            INSERT INTO alerts (
                event_id, timestamp, event_type, src_ip, src_port, dest_ip, dest_port, protocol,
                signature, signature_id, category, risk_score, severity,
                site_id, site_name, location, enrichment_data, raw_event
            ) VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                ST_SetSRID(ST_MakePoint(%s, %s), 4326), %s, %s
            )
        """, (
            event.get('event_id', ''),
            event.get('timestamp'),
            event.get('event_type'),
            event.get('src_ip'),
            event.get('src_port', 0),
            event.get('dest_ip'),
            event.get('dest_port', 0),
            event.get('protocol', ''),
            alert_info.get('signature', 'Unknown'),
            alert_info.get('signature_id', 0),
            alert_info.get('category', 'Unknown'),
            risk_score,
            severity,
            site.get('site_id') if site else None,
            site.get('site_name', 'Unknown Location') if site else 'Unknown Location',
            lon,  # longitude first for PostGIS
            lat,  # latitude second
            json.dumps(enrichment),
            json.dumps(event)
        ))
        
        conn.commit()
        cur.close()
        conn.close()
        
        site_name = site.get('site_name', 'Unknown') if site else 'Unknown'
        logger.info(f"Stored alert: {severity} - {event.get('src_ip')} -> {site_name}")
        
    except Exception as e:
        logger.error(f"Error storing alert: {e}")

def process_event(event):
    """Correlate and score event"""
    try:
        # ONLY process actual alert events
        if event.get('event_type') != 'alert':
            return True  # Skip non-alert events
        
        # Make sure we have alert data
        if not event.get('alert'):
            return True  # Skip if no alert info
        
        # Update event window
        src_ip = event.get('src_ip')
        if src_ip:
            now = datetime.utcnow()
            event_window[src_ip].append(now)
            
            # Clean old events
            event_window[src_ip] = [
                t for t in event_window[src_ip]
                if (now - t).total_seconds() < WINDOW_SIZE
            ]
        
        # Calculate risk
        risk_score = calculate_risk_score(event)
        severity = get_severity_level(risk_score)
        
        # Store alert (all alerts, even low risk ones)
        store_alert(event, risk_score, severity)
        
        return True
        
    except Exception as e:
        logger.error(f"Error processing event: {e}")
        return False

def main():
    logger.info("Correlator starting...")
    logger.info(f"Redis: {REDIS_HOST}:{REDIS_PORT}")
    logger.info(f"PostgreSQL: {POSTGRES_HOST}:{POSTGRES_PORT}")
    
    # Test connections
    try:
        r.ping()
        logger.info("Redis connection successful")
    except Exception as e:
        logger.error(f"Redis connection failed: {e}")
        import time
        time.sleep(5)
        return main()
    
    try:
        conn = get_db_conn()
        conn.close()
        logger.info("PostgreSQL connection successful")
    except Exception as e:
        logger.error(f"PostgreSQL connection failed: {e}")
        logger.warning("Will retry when processing events...")
    
    # Create consumer group
    try:
        r.xgroup_create(INPUT_STREAM, 'correlator-group', id='0', mkstream=True)
        logger.info("Created consumer group")
    except redis.exceptions.ResponseError as e:
        if 'BUSYGROUP' not in str(e):
            logger.error(f"Error creating group: {e}")
    
    logger.info("Waiting for events...")
    
    while True:
        try:
            messages = r.xreadgroup(
                'correlator-group',
                'correlator-1',
                {INPUT_STREAM: '>'},
                count=10,
                block=1000
            )
            
            if not messages:
                continue
            
            for stream_name, stream_messages in messages:
                for message_id, message_data in stream_messages:
                    try:
                        event_data = message_data[b'data'].decode('utf-8')
                        event = json.loads(event_data)
                        
                        # Process
                        if process_event(event):
                            # Acknowledge
                            r.xack(INPUT_STREAM, 'correlator-group', message_id)
                        
                    except Exception as e:
                        logger.error(f"Error processing message: {e}")
                        continue
        
        except Exception as e:
            logger.error(f"Error in main loop: {e}")
            continue

if __name__ == "__main__":
    main()
