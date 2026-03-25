#!/usr/bin/env python3
import os
import json
import redis
import logging
from datetime import datetime
import time

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
INPUT_LIST = os.getenv('INPUT_STREAM', 'suricata-events')  # Now a list
OUTPUT_STREAM = os.getenv('OUTPUT_STREAM', 'normalized-events')

# Redis connection
r = redis.Redis(
    host=REDIS_HOST,
    port=REDIS_PORT,
    password=REDIS_PASSWORD,
    decode_responses=False
)

def normalize_suricata_event(raw_event):
    """Normalize Suricata EVE JSON to common format"""
    try:
        event = json.loads(raw_event) if isinstance(raw_event, (str, bytes)) else raw_event
        
        # Extract common fields
        normalized = {
            'event_id': event.get('flow_id', ''),
            'timestamp': event.get('timestamp', datetime.utcnow().isoformat()),
            'event_type': event.get('event_type', 'unknown'),
            'sensor_id': event.get('sensor_id', 'vm1-sensor'),
            'sensor_location': event.get('sensor_location', 'azure-region-1'),
            
            # Network information
            'src_ip': event.get('src_ip', ''),
            'src_port': event.get('src_port', 0),
            'dest_ip': event.get('dest_ip', ''),
            'dest_port': event.get('dest_port', 0),
            'protocol': event.get('proto', ''),
            
            # Alert information (if present)
            'alert': None,
            
            # HTTP information (if present)
            'http': None,
            
            # Original event
            'raw_event': event
        }
        
        # Extract alert details
        if 'alert' in event:
            alert = event['alert']
            normalized['alert'] = {
                'signature': alert.get('signature', ''),
                'signature_id': alert.get('signature_id', 0),
                'category': alert.get('category', ''),
                'severity': alert.get('severity', 0),
                'action': alert.get('action', '')
            }
        
        # Extract HTTP details
        if 'http' in event:
            http = event['http']
            normalized['http'] = {
                'hostname': http.get('hostname', ''),
                'url': http.get('url', ''),
                'method': http.get('http_method', ''),
                'user_agent': http.get('http_user_agent', ''),
                'status': http.get('status', 0)
            }
        
        return normalized
        
    except Exception as e:
        logger.error(f"Error normalizing event: {e}")
        return None

def process_events():
    """Process events from Redis list"""
    logger.info(f"Starting log parser...")
    logger.info(f"Input list: {INPUT_LIST}")
    logger.info(f"Output stream: {OUTPUT_STREAM}")
    logger.info("Waiting for events...")
    
    while True:
        try:
            # BLPOP with 1 second timeout
            result = r.blpop(INPUT_LIST, timeout=1)
            
            if not result:
                continue
            
            list_name, raw_event = result
            
            try:
                # Decode the event
                event_str = raw_event.decode('utf-8')
                
                # Parse and normalize
                normalized = normalize_suricata_event(event_str)
                
                if normalized:
                    # Push to output stream
                    r.xadd(
                        OUTPUT_STREAM,
                        {'data': json.dumps(normalized)},
                        maxlen=10000
                    )
                    
                    logger.info(f"Processed event: {normalized.get('event_type')} from {normalized.get('src_ip')}")
                
            except Exception as e:
                logger.error(f"Error processing message: {e}")
                continue
        
        except Exception as e:
            logger.error(f"Error in main loop: {e}")
            time.sleep(1)
            continue

def main():
    logger.info("Log Parser starting...")
    
    # Test Redis connection
    try:
        r.ping()
        logger.info("Redis connection successful")
    except Exception as e:
        logger.error(f"Redis connection failed: {e}")
        time.sleep(5)
        return main()
    
    # Start processing
    process_events()

if __name__ == "__main__":
    main()
