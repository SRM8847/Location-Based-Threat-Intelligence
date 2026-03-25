#!/usr/bin/env python3
import os
import json
import redis
import logging
import csv
import ipaddress
import geoip2.database
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Configuration
REDIS_HOST = os.getenv('REDIS_HOST', 'localhost')
REDIS_PORT = int(os.getenv('REDIS_PORT', 6379))
REDIS_PASSWORD = os.getenv('REDIS_PASSWORD', '')
INPUT_STREAM = os.getenv('INPUT_STREAM', 'enriched-events')
OUTPUT_STREAM = os.getenv('OUTPUT_STREAM', 'correlated-events')
CMDB_PATH = os.getenv('CMDB_PATH', '/cmdb/sites.csv')
GEOIP_DB_PATH = os.getenv('GEOIP_DB_PATH', '/geoip/GeoLite2-City.mmdb')

# Redis connection
r = redis.Redis(
    host=REDIS_HOST,
    port=REDIS_PORT,
    password=REDIS_PASSWORD,
    decode_responses=False
)

# Load CMDB
cmdb_sites = []

def load_cmdb():
    """Load CMDB site mappings"""
    global cmdb_sites
    try:
        with open(CMDB_PATH, 'r') as f:
            reader = csv.DictReader(f)
            cmdb_sites = list(reader)
        logger.info(f"Loaded {len(cmdb_sites)} sites from CMDB")
    except Exception as e:
        logger.error(f"Error loading CMDB: {e}")

def get_site_from_ip(ip):
    """Map IP to site using CMDB"""
    try:
        ip_obj = ipaddress.ip_address(ip)
        for site in cmdb_sites:
            network = ipaddress.ip_network(site['ip_range'])
            if ip_obj in network:
                return {
                    'site_id': site['site_id'],
                    'site_name': site['site_name'],
                    'city': site['city'],
                    'country': site['country'],
                    'latitude': float(site['latitude']),
                    'longitude': float(site['longitude']),
                    'datacenter_type': site['datacenter_type']
                }
    except Exception as e:
        logger.debug(f"Error mapping IP {ip} to site: {e}")
    return None
###########################
def get_geoip(ip):
    """Get GeoIP information using free API"""
    try:
        # Use ip-api.com (free, no key needed, 45 requests/minute)
        url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,lat,lon,isp,as"
        response = requests.get(url, timeout=5)
        
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'success':
                return {
                    'city': data.get('city', ''),
                    'country': data.get('country', ''),
                    'country_code': data.get('countryCode', ''),
                    'latitude': data.get('lat', 0),
                    'longitude': data.get('lon', 0),
                    'isp': data.get('isp', ''),
                    'asn': data.get('as', '')
                }
    except Exception as e:
        logger.debug(f"GeoIP lookup failed for {ip}: {e}")
        
    return None

#################################
def get_threat_intel(ip):
    """Check if IP is in threat intelligence feeds and get location"""
    threats = []
    location = None
    
    # Check AbuseIPDB
    abuseipdb_key = f"ti:abuseipdb:{ip}"
    if r.exists(abuseipdb_key):
        data = json.loads(r.get(abuseipdb_key))
        threats.append({
            'source': 'abuseipdb',
            'score': data.get('score', 0),
            'categories': data.get('categories', [])
        })
        # Extract location from AbuseIPDB
        if data.get('country_code'):
            location = {
                'source': 'abuseipdb',
                'country_code': data.get('country_code', ''),
                'country': data.get('country_name', ''),
                'isp': data.get('isp', ''),
                'usage_type': data.get('usage_type', '')
            }
    
    # Check OTX
    otx_key = f"ti:otx:{ip}"
    if r.exists(otx_key):
        data = json.loads(r.get(otx_key))
        threats.append({
            'source': 'otx',
            'pulse': data.get('pulse', ''),
            'tags': data.get('tags', [])
        })
        # Extract location from OTX if available and not already found
        if not location and data.get('country'):
            location = {
                'source': 'otx',
                'country': data.get('country', ''),
                'city': data.get('city', ''),
                'latitude': data.get('latitude', 0),
                'longitude': data.get('longitude', 0)
            }
    
    # Check VirusTotal
    vt_key = f"ti:virustotal:{ip}"
    if r.exists(vt_key):
        data = json.loads(r.get(vt_key))
        threats.append({
            'source': 'virustotal',
            'reputation': data.get('reputation', 0),
            'malicious': data.get('malicious_count', 0),
            'suspicious': data.get('suspicious_count', 0),
            'asn': data.get('asn', 0),
            'as_owner': data.get('as_owner', '')
        })
        # Extract location from VirusTotal if not already found
        if not location and data.get('country'):
            location = {
                'source': 'virustotal',
                'country': data.get('country', ''),
                'continent': data.get('continent', ''),
                'asn': data.get('asn', 0),
                'as_owner': data.get('as_owner', '')
            }
    
    return {
        'threats': threats if threats else None,
        'location': location
    }
##################################
def enrich_event(event):
    """Enrich event with GeoIP, CMDB, and TI data"""
    try:
        src_ip = event.get('src_ip')
        dest_ip = event.get('dest_ip')
        
        enrichment = {
            'enriched_at': datetime.utcnow().isoformat(),
            'processor': 'vm3-enricher'
        }
        
        # Enrich SOURCE IP (attacker)
# Enrich SOURCE IP (attacker)
        if src_ip:
            logger.info(f"Enriching src_ip: {src_ip}")  # ADD THIS
            # Get threat intel (includes location from TI feeds)
            ti_result = get_threat_intel(src_ip)
            logger.info(f"TI result for {src_ip}: {ti_result}")  # ADD THIS
            
            if ti_result['threats']:
                enrichment['src_threats'] = ti_result['threats']
            
            # Use TI location if available
            if ti_result['location']:
                logger.info(f"Using TI location for {src_ip}")  # ADD THIS
                enrichment['src_location'] = ti_result['location']
            else:
                logger.info(f"Falling back to GeoIP for {src_ip}")  # ADD THIS
                # Fallback to GeoIP if no TI location
                geoip = get_geoip(src_ip)
                logger.info(f"GeoIP result for {src_ip}: {geoip}")  # ADD THIS
                if geoip:
                    enrichment['src_location'] = {
                        'source': 'geoip',
                        **geoip
                    }
        
        # Enrich DESTINATION IP (target/asset)
        if dest_ip:
            # CMDB lookup for your assets
            site = get_site_from_ip(dest_ip)
            if site:
                enrichment['dest_site'] = site
            else:
                # If not in CMDB, still try to get location
                geoip = get_geoip(dest_ip)
                if geoip:
                    enrichment['dest_location'] = {
                        'source': 'geoip',
                        **geoip
                    }
            
            # Also check if destination is a known threat (unusual but possible)
            ti_result = get_threat_intel(dest_ip)
            if ti_result['threats']:
                enrichment['dest_threats'] = ti_result['threats']
        
        event['enrichment'] = enrichment
        return event
        
    except Exception as e:
        logger.error(f"Error enriching event: {e}")
        return event

############################################
def main():
    logger.info("Enricher starting...")
    logger.info(f"Redis: {REDIS_HOST}:{REDIS_PORT}")
    
    # Load CMDB
    load_cmdb()
    
    # Test Redis connection
    try:
        r.ping()
        logger.info("Redis connection successful")
    except Exception as e:
        logger.error(f"Redis connection failed: {e}")
        import time
        time.sleep(5)
        return main()
    
    # Create consumer group
    try:
        r.xgroup_create(INPUT_STREAM, 'enricher-group', id='0', mkstream=True)
        logger.info("Created consumer group")
    except redis.exceptions.ResponseError as e:
        if 'BUSYGROUP' not in str(e):
            logger.error(f"Error creating group: {e}")
    
    logger.info("Waiting for events...")
    
    while True:
        try:
            messages = r.xreadgroup(
                'enricher-group',
                'enricher-1',
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
                        
                        # Enrich
                        enriched = enrich_event(event)
                        
                        # Send to output
                        r.xadd(
                            OUTPUT_STREAM,
                            {'data': json.dumps(enriched)},
                            maxlen=10000
                        )
                        
                        logger.info(f"Enriched event from {enriched.get('src_ip')}")
                        
                        # Acknowledge
                        r.xack(INPUT_STREAM, 'enricher-group', message_id)
                        
                    except Exception as e:
                        logger.error(f"Error processing message: {e}")
                        continue
        
        except Exception as e:
            logger.error(f"Error in main loop: {e}")
            continue

if __name__ == "__main__":
    main()
