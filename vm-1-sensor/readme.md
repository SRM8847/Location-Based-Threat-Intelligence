# VM-1: Attack Detection & Log Shipping

This VM runs the front-line sensor components.

## Components

- **Suricata IDS**: Network intrusion detection
- **Filebeat**: Log shipping to Redis
- **OWASP Juice Shop**: Vulnerable web application (attack target)

## Setup

1. Copy `.env.example` to `.env`
2. Update VM-2 IP address in `.env`
3. Update Redis password
4. Deploy:
```bash
cd /opt/project
docker-compose up -d
```

## Configuration

- Suricata rules: `suricata/rules/custom.rules`
- Suricata config: `suricata.yaml`
- Filebeat config: `filebeat/filebeat.yml`

## Verify
```bash
# Check Suricata is running
docker logs suricata

# Check alerts are being generated
tail -f suricata/logs/eve.json
```

## Custom Detection Rules

15+ custom rules for:
- SQL Injection
- XSS
- Directory Traversal
- Brute Force