#!/usr/bin/env python3
import os
import json
import time
import redis
import requests
import schedule
from datetime import datetime, timedelta
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Configuration
REDIS_HOST = os.getenv('REDIS_HOST', 'redis')
REDIS_PORT = int(os.getenv('REDIS_PORT', 6379))
REDIS_PASSWORD = os.getenv('REDIS_PASSWORD', '')
ABUSEIPDB_API_KEY = os.getenv('ABUSEIPDB_API_KEY', '')
OTX_API_KEY = os.getenv('OTX_API_KEY', '')
FETCH_INTERVAL = int(os.getenv('FETCH_INTERVAL', 3600))  # 1 hour default

# Redis connection
r = redis.Redis(
    host=REDIS_HOST,
    port=REDIS_PORT,
    password=REDIS_PASSWORD,
    decode_responses=True
)
##########################
def fetch_abuseipdb():
    """Fetch threat intelligence from AbuseIPDB"""
    if not ABUSEIPDB_API_KEY or ABUSEIPDB_API_KEY == 'your-abuseipdb-api-key-here':
        logger.warning("AbuseIPDB API key not configured, skipping...")
        return
    
    try:
        logger.info("Fetching AbuseIPDB blacklist...")
        url = "https://api.abuseipdb.com/api/v2/blacklist"
        headers = {
            'Key': ABUSEIPDB_API_KEY,
            'Accept': 'application/json'
        }
        params = {
            'confidenceMinimum': 90,
            'limit': 10000
        }
        
        response = requests.get(url, headers=headers, params=params, timeout=30)
        response.raise_for_status()
        
        data = response.json()
        blacklist = data.get('data', [])
        
        # Store in Redis with TTL
        pipeline = r.pipeline()
        for entry in blacklist:
            ip = entry.get('ipAddress')
            score = entry.get('abuseConfidenceScore', 0)
            key = f"ti:abuseipdb:{ip}"
            
            threat_data = {
                'ip': ip,
                'score': score,
                'source': 'abuseipdb',
                'timestamp': datetime.utcnow().isoformat(),
                'categories': entry.get('categories', []),
                # NEW: Store location data
                'country_code': entry.get('countryCode', ''),
                'country_name': entry.get('countryName', ''),
                'isp': entry.get('isp', ''),
                'usage_type': entry.get('usageType', '')
            }
            
            pipeline.setex(
                key,
                86400,  # 24 hour TTL
                json.dumps(threat_data)
            )
        
        pipeline.execute()
        logger.info(f"Stored {len(blacklist)} IPs from AbuseIPDB")
        
    except Exception as e:
        logger.error(f"Error fetching AbuseIPDB: {e}")
##########################
##########################
def fetch_otx():
    """Fetch threat intelligence from AlienVault OTX"""
    if not OTX_API_KEY or OTX_API_KEY == 'your-otx-api-key-here':
        logger.warning("OTX API key not configured, skipping...")
        return
    
    try:
        logger.info("Fetching AlienVault OTX pulses...")
        url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
        headers = {
            'X-OTX-API-KEY': OTX_API_KEY
        }
        params = {
            'limit': 50,
            'modified_since': (datetime.utcnow() - timedelta(days=7)).isoformat()
        }
        
        response = requests.get(url, headers=headers, params=params, timeout=30)
        response.raise_for_status()
        
        data = response.json()
        pulses = data.get('results', [])
        
        # Extract and store indicators
        pipeline = r.pipeline()
        indicator_count = 0
        
        for pulse in pulses:
            pulse_name = pulse.get('name', 'Unknown')
            indicators = pulse.get('indicators', [])
            
            for indicator in indicators:
                if indicator.get('type') == 'IPv4':
                    ip = indicator.get('indicator')
                    key = f"ti:otx:{ip}"
                    
                    # Try to get location from indicator details
                    # OTX sometimes includes this in additional fields
                    threat_data = {
                        'ip': ip,
                        'pulse': pulse_name,
                        'source': 'otx',
                        'timestamp': datetime.utcnow().isoformat(),
                        'tags': pulse.get('tags', []),
                        # NEW: Store any location data if available
                        'country': indicator.get('country', ''),
                        'city': indicator.get('city', ''),
                        'latitude': indicator.get('latitude', 0),
                        'longitude': indicator.get('longitude', 0)
                    }
                    
                    pipeline.setex(
                        key,
                        86400,  # 24 hour TTL
                        json.dumps(threat_data)
                    )
                    indicator_count += 1
        
        pipeline.execute()
        logger.info(f"Stored {indicator_count} indicators from OTX")
        
    except Exception as e:
        logger.error(f"Error fetching OTX: {e}")
#################################
def fetch_virustotal():
    """Fetch threat intelligence from VirusTotal"""
    if not os.getenv('VIRUSTOTAL_API_KEY') or os.getenv('VIRUSTOTAL_API_KEY') == 'your-virustotal-api-key-here':
        logger.warning("VirusTotal API key not configured, skipping...")
        return
    
    try:
        logger.info("Fetching VirusTotal threat data...")
        
        vt_api_key = os.getenv('VIRUSTOTAL_API_KEY')
        headers = {
            'x-apikey': vt_api_key
        }
        
        # Get IPs from AbuseIPDB or OTX to check in VT
        sample_ips = []
        
        # Try AbuseIPDB IPs first
        for key in r.scan_iter("ti:abuseipdb:*", count=100):
            # key is already a string (decode_responses=True)
            ip = key.split(':')[-1]  # REMOVED .decode()
            sample_ips.append(ip)
            if len(sample_ips) >= 50:
                break
        
        # If no AbuseIPDB IPs, try OTX
        if not sample_ips:
            for key in r.scan_iter("ti:otx:*", count=100):
                ip = key.split(':')[-1]  # REMOVED .decode()
                sample_ips.append(ip)
                if len(sample_ips) >= 50:
                    break
        
        if not sample_ips:
            logger.warning("No IPs found to enrich with VirusTotal")
            return
        
        enriched_count = 0
        for ip in sample_ips:
            try:
                # VT API endpoint for IP addresses
                url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
                response = requests.get(url, headers=headers, timeout=10)
                
                if response.status_code == 200:
                    data = response.json()
                    attributes = data.get('data', {}).get('attributes', {})
                    
                    key = f"ti:virustotal:{ip}"
                    threat_data = {
                        'ip': ip,
                        'source': 'virustotal',
                        'timestamp': datetime.utcnow().isoformat(),
                        # Location data
                        'country': attributes.get('country', ''),
                        'continent': attributes.get('continent', ''),
                        # Network info
                        'asn': attributes.get('asn', 0),
                        'as_owner': attributes.get('as_owner', ''),
                        'network': attributes.get('network', ''),
                        # Reputation data
                        'reputation': attributes.get('reputation', 0),
                        'last_analysis_stats': attributes.get('last_analysis_stats', {}),
                        'malicious_count': attributes.get('last_analysis_stats', {}).get('malicious', 0),
                        'suspicious_count': attributes.get('last_analysis_stats', {}).get('suspicious', 0)
                    }
                    
                    r.setex(key, 86400, json.dumps(threat_data))
                    enriched_count += 1
                    logger.info(f"Enriched {ip} with VirusTotal data")
                    
                elif response.status_code == 404:
                    logger.debug(f"IP {ip} not found in VirusTotal")
                elif response.status_code == 429:
                    logger.warning("VirusTotal rate limit hit, stopping enrichment")
                    break
                    
                # Rate limiting: VT free tier is 4 requests/minute
                time.sleep(15)  # 15 seconds between requests = 4/min
                
            except Exception as e:
                logger.debug(f"Error fetching VT data for {ip}: {e}")
                continue
        
        logger.info(f"Enriched {enriched_count} IPs with VirusTotal data")
        
    except Exception as e:
        logger.error(f"Error in VirusTotal fetch: {e}")
#################################
def fetch_all_ti():
    """Fetch all threat intelligence sources"""
    logger.info("Starting TI fetch cycle...")
    fetch_abuseipdb()
    fetch_otx()
    fetch_virustotal()  # ADD THIS LINE
    logger.info("TI fetch cycle complete")
    
    # Store fetch metadata
    r.set(
        'ti:last_fetch',
        json.dumps({
            'timestamp': datetime.utcnow().isoformat(),
            'status': 'success'
        })
    )
####################################
def main():
    logger.info("TI Fetcher starting...")
    logger.info(f"Redis: {REDIS_HOST}:{REDIS_PORT}")
    logger.info(f"Fetch interval: {FETCH_INTERVAL} seconds")
    
    # Test Redis connection
    try:
        r.ping()
        logger.info("Redis connection successful")
    except Exception as e:
        logger.error(f"Redis connection failed: {e}")
        time.sleep(5)
        return main()
    
    # Fetch immediately on startup
    fetch_all_ti()
    
    # Schedule periodic fetches
    schedule.every(FETCH_INTERVAL).seconds.do(fetch_all_ti)
    
    # Run scheduler
    while True:
        schedule.run_pending()
        time.sleep(60)

if __name__ == "__main__":
    main()
