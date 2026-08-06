from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, JSON, Enum, Boolean, Float
from sqlalchemy.orm import relationship
from datetime import datetime
from database import Base
import enum
try:
    from pgvector.sqlalchemy import Vector
except ImportError:
    # pgvector is only available inside Docker; use String as fallback for local IDE
    from sqlalchemy import String as Vector  # type: ignore

class ScanStatus(str, enum.Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

# --- NEW: The Multi-Tenant Anchor ---
class Organization(Base):
    __tablename__ = "organizations"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True)
    tier = Column(String, default="enterprise") # e.g., free, pro, enterprise
    created_at = Column(DateTime, default=datetime.utcnow)

    # An organization owns many users and assets
    users = relationship("User", back_populates="organization")
    assets = relationship("Asset", back_populates="organization")

# --- UPGRADED: The User Model ---
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"))
    email = Column(String, unique=True, index=True)
    first_name = Column(String, nullable=True)
    last_name = Column(String, nullable=True)
    job_title = Column(String, nullable=True)
    hashed_password = Column(String) # Never store plaintext!
    role = Column(String, default="analyst") # Role-Based Access Control (admin, operator, analyst)
    created_at = Column(DateTime, default=datetime.utcnow)

    organization = relationship("Organization", back_populates="users")

# --- UPGRADED: The Asset Model ---
class Asset(Base):
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id")) # Isolated to a specific Org
    target = Column(String, index=True)
    asset_type = Column(String)
    discovered_at = Column(DateTime, default=datetime.utcnow)
    
    organization = relationship("Organization", back_populates="assets")
    scans = relationship("Scan", back_populates="asset")

class Mission(Base):
    __tablename__ = "missions"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"))
    target = Column(String, index=True)
    goal = Column(String)
    status = Column(String, default="running")
    decision_log = Column(JSON, default=list)
    created_at = Column(DateTime, default=datetime.utcnow)

    organization = relationship("Organization")
    scans = relationship("Scan", back_populates="mission")

class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id"))
    mission_id = Column(Integer, ForeignKey("missions.id", ondelete="CASCADE"), nullable=True)
    status = Column(Enum(ScanStatus), default=ScanStatus.QUEUED)
    risk_score = Column(String, nullable=True)
    findings = Column(JSON, nullable=True) 
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    tool_used = Column(String, nullable=True)
    confidence_score = Column(Integer, nullable=True)
    cross_validated = Column(Boolean, default=False)
    evidence_links = Column(JSON, nullable=True)
    
    asset = relationship("Asset", back_populates="scans")
    mission = relationship("Mission", back_populates="scans")
    
# --- NEW: PGVector Embedding Table ---
class ScanFindingEmbedding(Base):
    __tablename__ = "scan_finding_embeddings"
    
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"))
    org_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"))
    target = Column(String, index=True)
    tool = Column(String)
    risk = Column(String)
    text_content = Column(String) # The raw string that was embedded
    embedding = Column(Vector(384)) # 384 matches all-MiniLM-L6-v2 dimension
    
    scan = relationship("Scan")

# --- NEW: Action & Response Engine ---
class ResponseAction(Base):
    __tablename__ = "response_actions"
    
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"))
    status = Column(String, default="pending") # pending, generated, ticket_created, resolved
    script = Column(String, nullable=True) # Auto-generated bash/python script
    ticket_payload = Column(JSON, nullable=True) # Simulated Jira/ServiceNow payload
    slack_notified = Column(Integer, default=0) # 0/1 boolean flag
    created_at = Column(DateTime, default=datetime.utcnow)
    
    scan = relationship("Scan")

# --- NEW: Scheduled Scanning Engine ---
class ScheduledScan(Base):
    __tablename__ = "scheduled_scans"
    
    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"))
    target = Column(String, index=True)
    tool = Column(String)
    cron_expression = Column(String) # e.g., "0 0 * * *" for daily
    last_run = Column(DateTime, nullable=True)
    next_run = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    organization = relationship("Organization")

# --- NEW: Vulnerability Engine & Threat Intel Enrichment ---
class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"))
    asset_id = Column(Integer, ForeignKey("assets.id", ondelete="CASCADE"))
    
    cve_id = Column(String, index=True)
    title = Column(String)
    severity = Column(String)
    description = Column(String)
    tool_detected = Column(String)
    discovered_at = Column(DateTime, default=datetime.utcnow)
    
    # Enrichment fields (Threat Intel)
    epss_score = Column(Float, nullable=True)
    cisa_kev = Column(Boolean, default=False)
    mitre_tactics = Column(JSON, nullable=True)
    circl_summary = Column(String, nullable=True)
    
    scan = relationship("Scan")
    asset = relationship("Asset")