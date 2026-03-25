#!/usr/bin/env python3
import os
import json
import time
import psycopg2
import psycopg2.extras
import requests
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Configuration
POSTGRES_HOST = os.getenv('POSTGRES_HOST', 'localhost')
POSTGRES_PORT = int(os.getenv('POSTGRES_PORT', 5432))
POSTGRES_DB = os.getenv('POSTGRES_DB', 'threat_intel')
POSTGRES_USER = os.getenv('POSTGRES_USER', 'tiuser')
POSTGRES_PASSWORD = os.getenv('POSTGRES_PASSWORD', '')

SLACK_WEBHOOK_URL = os.getenv('SLACK_WEBHOOK_URL', '')
SMTP_HOST = os.getenv('SMTP_HOST', '')
SMTP_PORT = int(os.getenv('SMTP_PORT', 587))
SMTP_USER = os.getenv('SMTP_USER', '')
SMTP_PASSWORD = os.getenv('SMTP_PASSWORD', '')
EMAIL_FROM = os.getenv('EMAIL_FROM', 'alerts@localhost')
EMAIL_TO = os.getenv('EMAIL_TO', '')

CHECK_INTERVAL = 60  # Check every 60 seconds
notified_alerts = set()

def get_db_conn():
    return psycopg2.connect(
        host=POSTGRES_HOST,
        port=POSTGRES_PORT,
        database=POSTGRES_DB,
        user=POSTGRES_USER,
        password=POSTGRES_PASSWORD
    )

def get_new_high_severity_alerts():
    """Get new high/critical alerts that haven't been notified"""
    try:
        conn = get_db_conn()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        cur.execute("""
            SELECT *
            FROM alerts
            WHERE severity IN ('high', 'critical')
            AND status = 'new'
            AND created_at > NOW() - INTERVAL '5 minutes'
            ORDER BY created_at DESC
        """)
        
        alerts = cur.fetchall()
        cur.close()
        conn.close()
        
        # Filter out already notified
        new_alerts = [a for a in alerts if a['id'] not in notified_alerts]
        return new_alerts
        
    except Exception as e:
        logger.error(f"Error fetching alerts: {e}")
        return []

def send_slack_notification(alert):
    """Send notification to Slack"""
    if not SLACK_WEBHOOK_URL or SLACK_WEBHOOK_URL == 'https://hooks.slack.com/services/YOUR/WEBHOOK/URL':
        logger.debug("Slack webhook not configured")
        return
    
    try:
        severity_emoji = {
            'critical': '🔴',
            'high': '🟠',
            'medium': '🟡',
            'low': '🟢'
        }
        
        message = {
            "text": f"{severity_emoji.get(alert['severity'], '⚪')} *{alert['severity'].upper()} Alert*",
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": f"{severity_emoji.get(alert['severity'], '⚪')} {alert['severity'].upper()} Security Alert"
                    }
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Signature:*\n{alert['signature']}"},
                        {"type": "mrkdwn", "text": f"*Risk Score:*\n{alert['risk_score']}/100"},
                        {"type": "mrkdwn", "text": f"*Source:*\n{alert['src_ip']}"},
                        {"type": "mrkdwn", "text": f"*Site:*\n{alert['site_name'] or 'Unknown'}"},
                    ]
                },
                {
                    "type": "context",
                    "elements": [
                        {
                            "type": "mrkdwn",
                            "text": f"Alert ID: {alert['id']} | {alert['timestamp']}"
                        }
                    ]
                }
            ]
        }
        
        response = requests.post(SLACK_WEBHOOK_URL, json=message, timeout=10)
        response.raise_for_status()
        logger.info(f"Sent Slack notification for alert {alert['id']}")
        
    except Exception as e:
        logger.error(f"Error sending Slack notification: {e}")

def send_email_notification(alert):
    """Send email notification"""
    if not all([SMTP_HOST, SMTP_USER, SMTP_PASSWORD, EMAIL_TO]):
        logger.debug("Email not configured")
        return
    
    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = f"[{alert['severity'].upper()}] Security Alert - {alert['signature']}"
        msg['From'] = EMAIL_FROM
        msg['To'] = EMAIL_TO
        
        text = f"""
Security Alert Notification

Severity: {alert['severity'].upper()}
Risk Score: {alert['risk_score']}/100

Signature: {alert['signature']}
Category: {alert['category']}

Source: {alert['src_ip']}:{alert['src_port']}
Destination: {alert['dest_ip']}:{alert['dest_port']}
Protocol: {alert['protocol']}

Site: {alert['site_name'] or 'Unknown'}
Time: {alert['timestamp']}

Alert ID: {alert['id']}
        """
        
        msg.attach(MIMEText(text, 'plain'))
        
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.send_message(msg)
        
        logger.info(f"Sent email notification for alert {alert['id']}")
        
    except Exception as e:
        logger.error(f"Error sending email: {e}")

def process_notifications():
    """Main notification processing loop"""
    logger.info("Notifier starting...")
    logger.info(f"PostgreSQL: {POSTGRES_HOST}:{POSTGRES_PORT}")
    logger.info(f"Check interval: {CHECK_INTERVAL} seconds")
    
    # Test database connection
    try:
        conn = get_db_conn()
        conn.close()
        logger.info("PostgreSQL connection successful")
    except Exception as e:
        logger.error(f"PostgreSQL connection failed: {e}")
        time.sleep(5)
        return process_notifications()
    
    while True:
        try:
            alerts = get_new_high_severity_alerts()
            
            for alert in alerts:
                logger.info(f"Processing alert {alert['id']}: {alert['severity']} - {alert['signature']}")
                
                # Send notifications
                send_slack_notification(alert)
                send_email_notification(alert)
                
                # Mark as notified
                notified_alerts.add(alert['id'])
            
            # Clean old entries from notified set
            if len(notified_alerts) > 10000:
                notified_alerts.clear()
            
            time.sleep(CHECK_INTERVAL)
            
        except Exception as e:
            logger.error(f"Error in notification loop: {e}")
            time.sleep(CHECK_INTERVAL)

if __name__ == "__main__":
    process_notifications()
