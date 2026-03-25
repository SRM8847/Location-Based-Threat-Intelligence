#!/usr/bin/env python3
import os
import json
import redis
import logging
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
INPUT_STREAM = os.getenv('INPUT_STREAM', 'normalized-events')
OUTPUT_STREAM = os.getenv('OUTPUT_STREAM', 'enriched-events')

# Redis connection
r = redis.Redis(
    host=REDIS_HOST,
    port=REDIS_PORT,
    password=REDIS_PASSWORD,
    decode_responses=False
)

def process_event(event_data):
    """Further normalize and prepare for enrichment"""
    try:
        event = json.loads(event_data) if isinstance(event_data, (str, bytes)) else event_data
        
        # Add processing metadata
        event['processing'] = {
            'normalized_at': datetime.utcnow().isoformat(),
            'processor': 'vm3-normalizer'
        }
        
        # Ensure required fields exist
        if not event.get('src_ip'):
            logger.warning("Event missing src_ip, skipping")
            return None
            
        return event
        
    except Exception as e:
        logger.error(f"Error processing event: {e}")
        return None

def main():
    logger.info("Normalizer starting...")
    logger.info(f"Redis: {REDIS_HOST}:{REDIS_PORT}")
    logger.info(f"Input: {INPUT_STREAM}, Output: {OUTPUT_STREAM}")
    
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
        r.xgroup_create(INPUT_STREAM, 'normalizer-group', id='0', mkstream=True)
        logger.info("Created consumer group")
    except redis.exceptions.ResponseError as e:
        if 'BUSYGROUP' not in str(e):
            logger.error(f"Error creating group: {e}")
    
    logger.info("Waiting for events...")
    
    while True:
        try:
            messages = r.xreadgroup(
                'normalizer-group',
                'normalizer-1',
                {INPUT_STREAM: '>'},
                count=10,
                block=1000
            )
            
            if not messages:
                continue
            
            for stream_name, stream_messages in messages:
                for message_id, message_data in stream_messages:
                    try:
                        # Get event data
                        if b'data' in message_data:
                            event_data = message_data[b'data'].decode('utf-8')
                        else:
                            event_data = json.dumps({k.decode('utf-8'): v.decode('utf-8') 
                                                   for k, v in message_data.items()})
                        
                        # Process
                        processed = process_event(event_data)
                        
                        if processed:
                            # Send to output stream
                            r.xadd(
                                OUTPUT_STREAM,
                                {'data': json.dumps(processed)},
                                maxlen=10000
                            )
                            
                            logger.info(f"Normalized event from {processed.get('src_ip')}")
                        
                        # Acknowledge
                        r.xack(INPUT_STREAM, 'normalizer-group', message_id)
                        
                    except Exception as e:
                        logger.error(f"Error processing message: {e}")
                        continue
        
        except Exception as e:
            logger.error(f"Error in main loop: {e}")
            continue

if __name__ == "__main__":
    main()
