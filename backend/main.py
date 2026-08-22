from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from typing import List, Optional
from pydantic import BaseModel
import database
import models
from worker import run_recon_scan

app = FastAPI(title="Sentinel API")

# CORS: allow Next.js frontend on port 3000 and Nexus frontend on port 5173
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:5173",
        "http://sentinel_frontend:3000",
        "http://nexus_frontend:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Pydantic request/response schemas
class TargetCreate(BaseModel):
    hostname: str

class TargetResponse(BaseModel):
    id: int
    hostname: str

class ScanCreate(BaseModel):
    target_id: int

class ScanResponse(BaseModel):
    scan_id: int
    status: str

@app.get("/health")
def health_check():
    return {"status": "ok"}

@app.post("/targets/", response_model=TargetResponse, status_code=201)
def create_target(body: TargetCreate, db: Session = Depends(database.get_db)):
    existing = db.query(models.Target).filter(models.Target.hostname == body.hostname).first()
    if existing:
        raise HTTPException(status_code=409, detail="Target already exists")
    db_target = models.Target(hostname=body.hostname)
    db.add(db_target)
    db.commit()
    db.refresh(db_target)
    return {"id": db_target.id, "hostname": db_target.hostname}

@app.get("/targets/", response_model=List[dict])
def read_targets(skip: int = 0, limit: int = 100, db: Session = Depends(database.get_db)):
    targets = db.query(models.Target).offset(skip).limit(limit).all()
    return [{"id": t.id, "hostname": t.hostname} for t in targets]

@app.post("/scans/", response_model=ScanResponse, status_code=202)
def trigger_scan(body: ScanCreate, db: Session = Depends(database.get_db)):
    target = db.query(models.Target).filter(models.Target.id == body.target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    
    db_scan = models.Scan(target_id=target.id, status=models.ScanStatus.PENDING)
    db.add(db_scan)
    db.commit()
    db.refresh(db_scan)
    
    # Trigger Celery task asynchronously
    run_recon_scan.delay(db_scan.id, target.hostname)
    
    return {"scan_id": db_scan.id, "status": db_scan.status.value}

@app.get("/scans/", response_model=List[dict])
def list_scans(skip: int = 0, limit: int = 100, db: Session = Depends(database.get_db)):
    scans = db.query(models.Scan).offset(skip).limit(limit).all()
    return [{
        "id": scan.id, 
        "target_id": scan.target_id, 
        "status": scan.status.value,
        "findings_count": len(scan.findings)
    } for scan in scans]

@app.get("/scans/{scan_id}")
def get_scan(scan_id: int, db: Session = Depends(database.get_db)):
    scan = db.query(models.Scan).filter(models.Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {
        "id": scan.id, 
        "target_id": scan.target_id, 
        "status": scan.status.value,
        "findings_count": len(scan.findings)
    }

from neo4j import GraphDatabase
import os

NEO4J_URI = os.environ.get("NEO4J_URI", "bolt://neo4j:7687")
NEO4J_USER = os.environ.get("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.environ.get("NEO4J_PASSWORD", "sentinel_neo4j")

try:
    neo4j_driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
except Exception as e:
    print(f"Failed to connect to Neo4j: {e}")
    neo4j_driver = None

@app.get("/graph/")
def get_graph_data():
    if not neo4j_driver:
        return {"nodes": [], "links": []}
        
    def get_node_group(labels):
        if "Target" in labels: return 1
        if "Vulnerability" in labels: return 2
        if "Network_Segment" in labels: return 3
        if "Threat_Actor" in labels: return 4
        if "User_Role" in labels: return 5
        return 6
        
    try:
        with neo4j_driver.session() as session:
            # Query all nodes and relationships
            result = session.run("""
                MATCH (n)
                OPTIONAL MATCH (n)-[r]->(m)
                RETURN n, r, m
            """)
            
            nodes_dict = {}
            links = []
            
            for record in result:
                n = record["n"]
                if n:
                    node_id = str(n.element_id)
                    if node_id not in nodes_dict:
                        nodes_dict[node_id] = {
                            "id": node_id,
                            "name": n.get("name", n.get("hostname", n.get("cve_id", "Unknown"))),
                            "group": get_node_group(n.labels)
                        }
                
                r = record["r"]
                m = record["m"]
                
                if r and m:
                    target_id = str(m.element_id)
                    if target_id not in nodes_dict:
                        nodes_dict[target_id] = {
                            "id": target_id,
                            "name": m.get("name", m.get("hostname", m.get("cve_id", "Unknown"))),
                            "group": get_node_group(m.labels)
                        }
                        
                    links.append({
                        "source": str(n.element_id),
                        "target": target_id,
                        "value": 1,
                        "type": r.type  # correct neo4j relationship type accessor
                    })
                    
            return {
                "nodes": list(nodes_dict.values()),
                "links": links
            }
    except Exception as e:
        print(f"Error querying Neo4j: {e}")
        return {"nodes": [], "links": []}

@app.get("/analytics/")
def get_analytics(db: Session = Depends(database.get_db)):
    """Returns aggregate metrics for the SOC dashboard."""
    import models
    total_targets = db.query(models.Target).count()
    total_scans = db.query(models.Scan).count()
    completed = db.query(models.Scan).filter(models.Scan.status == models.ScanStatus.COMPLETED).count()
    failed = db.query(models.Scan).filter(models.Scan.status == models.ScanStatus.FAILED).count()
    running = db.query(models.Scan).filter(models.Scan.status == models.ScanStatus.RUNNING).count()
    critical_findings = db.query(models.Finding).join(models.Vulnerability).filter(
        models.Vulnerability.severity == "CRITICAL"
    ).count()
    return {
        "totalTargets": total_targets,
        "totalScans": total_scans,
        "completedScans": completed,
        "failedScans": failed,
        "activeScans": running,
        "criticalVulns": critical_findings,
        "playbooks": 0  # Populated by Aegis AI service
    }
