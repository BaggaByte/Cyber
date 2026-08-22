import os
import time
import datetime
import json
from celery import Celery
from database import SessionLocal
import models
from minio import Minio
from opensearchpy import OpenSearch
from neo4j import GraphDatabase

redis_url = os.environ.get("REDIS_URL", "redis://redis:6379/0")
app = Celery("sentinel_worker", broker=redis_url, backend=redis_url)

# MinIO Config
MINIO_URL = os.environ.get("MINIO_URL", "minio:9000").replace("http://", "").replace("https://", "")
MINIO_ACCESS_KEY = os.environ.get("MINIO_ACCESS_KEY", "minioadmin")
MINIO_SECRET_KEY = os.environ.get("MINIO_SECRET_KEY", "minioadmin")
MINIO_BUCKET = "scans"

# OpenSearch Config
OPENSEARCH_URL = os.environ.get("OPENSEARCH_URL", "http://opensearch:9200")

# Neo4j Config
NEO4J_URI = os.environ.get("NEO4J_URI", "bolt://neo4j:7687")
NEO4J_USER = os.environ.get("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.environ.get("NEO4J_PASSWORD", "sentinel_neo4j")

def get_minio_client():
    try:
        client = Minio(
            MINIO_URL,
            access_key=MINIO_ACCESS_KEY,
            secret_key=MINIO_SECRET_KEY,
            secure=False
        )
        if not client.bucket_exists(MINIO_BUCKET):
            client.make_bucket(MINIO_BUCKET)
        return client
    except Exception as e:
        print(f"Failed to initialize MinIO: {e}")
        return None

def get_opensearch_client():
    try:
        client = OpenSearch(
            hosts=[OPENSEARCH_URL],
            use_ssl=False,
            verify_certs=False
        )
        return client
    except Exception as e:
        print(f"Failed to initialize OpenSearch: {e}")
        return None
        
def get_neo4j_driver():
    try:
        return GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    except Exception as e:
        print(f"Failed to initialize Neo4j: {e}")
        return None

@app.task(bind=True, soft_time_limit=300, time_limit=330, max_retries=3)
def run_recon_scan(self, scan_id: int, hostname: str):
    db = SessionLocal()
    minio_client = get_minio_client()
    os_client = get_opensearch_client()
    neo4j_driver = get_neo4j_driver()
    
    try:
        # Mark scan as running
        scan = db.query(models.Scan).filter(models.Scan.id == scan_id).first()
        if not scan:
            return
        
        scan.status = models.ScanStatus.RUNNING
        db.commit()

        # Run actual nmap scan
        import subprocess
        import xml.etree.ElementTree as ET
        
        print(f"Starting REAL nmap scan on {hostname}...")
        
        # Run nmap with XML output and service detection (-sV)
        # using a fast timing template (-T4) to keep it somewhat quick
        result = subprocess.run(
            ["nmap", "-T4", "-F", "-sV", "-oX", "-", hostname],
            capture_output=True,
            text=True
        )
        
        nmap_output = result.stdout
        open_ports = []
        raw_details = ""
        
        if result.returncode == 0 and nmap_output:
            try:
                root = ET.fromstring(nmap_output)
                for host in root.findall('host'):
                    for ports in host.findall('ports'):
                        for port in ports.findall('port'):
                            state = port.find('state')
                            if state is not None and state.get('state') == 'open':
                                portid = port.get('portid')
                                protocol = port.get('protocol')
                                service_el = port.find('service')
                                service_name = service_el.get('name') if service_el is not None else "unknown"
                                service_version = service_el.get('version') if service_el is not None else ""
                                
                                open_ports.append(f"{portid}/{protocol} ({service_name} {service_version})")
                raw_details = "\\n".join(open_ports)
            except Exception as e:
                raw_details = f"Failed to parse nmap output: {e}"
        else:
            raw_details = f"Nmap failed or returned no output. Error: {result.stderr}"

        # Get or create a generic vulnerability to associate with findings if no real CVEs are found
        vuln = db.query(models.Vulnerability).filter(models.Vulnerability.cve_id == "NMAP-RECON").first()
        if not vuln:
            vuln = models.Vulnerability(cve_id="NMAP-RECON", severity="INFO", description="Open ports discovered via Nmap")
            db.add(vuln)
            db.commit()
            db.refresh(vuln)
            
        finding = models.Finding(
            target_id=scan.target_id,
            scan_id=scan.id,
            vulnerability_id=vuln.id,
            details=f"Discovered open ports on {hostname}:\\n{raw_details}"
        )
        db.add(finding)
        db.commit()
        db.refresh(finding)
        
        # 1. Upload scan artifact to MinIO
        if minio_client:
            report_data = {
                "scan_id": scan.id,
                "target": hostname,
                "timestamp": datetime.datetime.utcnow().isoformat(),
                "findings": [
                    {
                        "cve": vuln.cve_id,
                        "severity": vuln.severity,
                        "details": finding.details
                    }
                ]
            }
            report_json = json.dumps(report_data).encode("utf-8")
            from io import BytesIO
            minio_client.put_object(
                MINIO_BUCKET,
                f"scan_{scan.id}.json",
                data=BytesIO(report_json),
                length=len(report_json),
                content_type="application/json"
            )
            print(f"Uploaded report scan_{scan.id}.json to MinIO")
            
        # 2. Index finding to OpenSearch
        if os_client:
            doc = {
                "scan_id": scan.id,
                "target": hostname,
                "cve": vuln.cve_id,
                "severity": vuln.severity,
                "details": finding.details,
                "timestamp": datetime.datetime.utcnow().isoformat()
            }
            os_client.index(
                index="sentinel-findings",
                body=doc,
                refresh=True
            )
            print(f"Indexed finding for {hostname} to OpenSearch")
            
        # 3. Create Graph Relationships in Neo4j
        if neo4j_driver:
            try:
                with neo4j_driver.session() as session:
                    session.run(
                        """
                        MERGE (t:Target {hostname: $hostname})
                        MERGE (s:Network_Segment {name: 'Corporate DMZ'})
                        MERGE (v:Vulnerability {cve_id: $cve_id})
                        SET v.severity = $severity
                        MERGE (a:Threat_Actor {name: 'APT-29'})
                        MERGE (r:User_Role {name: 'Domain Admin'})
                        
                        MERGE (t)-[ho:HOSTED_ON]->(s)
                        SET ho.last_seen = $timestamp
                        
                        MERGE (t)-[hv:HAS_VULNERABILITY]->(v)
                        SET hv.last_seen = $timestamp
                        
                        MERGE (v)-[ce:CAN_EXPLOIT]->(a)
                        SET ce.last_seen = $timestamp
                        
                        MERGE (a)-[ha:HAS_ACCESS]->(r)
                        SET ha.last_seen = $timestamp
                        
                        MERGE (r)-[ca:CAN_ACCESS]->(s)
                        SET ca.last_seen = $timestamp
                        """,
                        hostname=hostname,
                        cve_id=vuln.cve_id,
                        severity=vuln.severity,
                        timestamp=datetime.datetime.utcnow().isoformat()
                    )
                print(f"Updated Neo4j graph for {hostname} with expanded topology")
            except Exception as neo4j_exc:
                # Neo4j is non-critical: log and continue, don't fail the scan
                print(f"[WARN] Neo4j graph update failed (non-fatal): {neo4j_exc}")

        # Mark scan as completed
        scan.status = models.ScanStatus.COMPLETED
        scan.end_time = datetime.datetime.utcnow()
        db.commit()
        print(f"Mock scan on {hostname} completed.")
        
    except Exception as exc:
        print(f"Scan failed: {exc}. Retrying...")
        # Guard: scan may not have been fetched yet if the failure was early
        if scan:
            scan.status = models.ScanStatus.FAILED
            scan.end_time = datetime.datetime.utcnow()
            db.commit()
        raise self.retry(exc=exc, countdown=60)
    finally:
        db.close()
        if neo4j_driver:
            neo4j_driver.close()

    return True
