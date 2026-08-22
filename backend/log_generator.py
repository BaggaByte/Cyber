import os
import time
import json
import random
import datetime
from opensearchpy import OpenSearch

# OpenSearch Configuration
OPENSEARCH_URL = os.environ.get("OPENSEARCH_URL", "http://localhost:9200")
INDEX_NAME = "sentinel-telemetry"

# Data generation parameters
EVENT_TYPES = [
    {"type": "failed_ssh_login", "severity": "MEDIUM", "message": "Failed SSH login attempt from unknown IP"},
    {"type": "waf_block", "severity": "HIGH", "message": "WAF blocked SQL Injection attempt on /login"},
    {"type": "malware_detected", "severity": "CRITICAL", "message": "Antivirus detected generic trojan signature"},
    {"type": "excessive_rate_limit", "severity": "LOW", "message": "API rate limit exceeded by client"},
    {"type": "port_scan_detected", "severity": "HIGH", "message": "Horizontal port scan detected on external interface"},
    {"type": "unauthorized_access", "severity": "CRITICAL", "message": "Unauthorized access attempt to /admin dashboard"},
]

TARGETS = ["web-server-01", "db-cluster-eu", "api-gateway-01", "internal-vault"]
SOURCE_IPS = ["192.168.1.55", "45.33.12.99", "185.60.216.35", "10.0.0.14", "103.22.200.1"]

def get_opensearch_client():
    try:
        client = OpenSearch(
            hosts=[OPENSEARCH_URL],
            use_ssl=False,
            verify_certs=False
        )
        return client
    except Exception as e:
        print(f"Failed to initialize OpenSearch client: {e}")
        return None

def generate_event():
    event_template = random.choice(EVENT_TYPES)
    return {
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "event_type": event_template["type"],
        "severity": event_template["severity"],
        "message": event_template["message"],
        "target_host": random.choice(TARGETS),
        "source_ip": random.choice(SOURCE_IPS),
        "sensor": "sentinel-agent-v1"
    }

def main():
    print("========================================")
    print("  SentinelAI - Telemetry Log Generator  ")
    print("========================================")
    
    client = get_opensearch_client()
    if not client:
        print("[-] Exiting due to connection failure.")
        return
        
    print(f"[*] Connected to OpenSearch at {OPENSEARCH_URL}")
    print(f"[*] Beginning live telemetry stream into index: {INDEX_NAME}...")
    
    count = 0
    try:
        while True:
            event = generate_event()
            
            client.index(
                index=INDEX_NAME,
                body=event
            )
            
            count += 1
            print(f"[+] Indexed event {count}: [{event['severity']}] {event['event_type']} on {event['target_host']}")
            
            # Sleep for a random interval between 1 and 4 seconds
            time.sleep(random.uniform(1.0, 4.0))
            
    except KeyboardInterrupt:
        print("\n[*] Telemetry generation stopped by user.")
        print(f"[*] Total events generated: {count}")

if __name__ == "__main__":
    main()
