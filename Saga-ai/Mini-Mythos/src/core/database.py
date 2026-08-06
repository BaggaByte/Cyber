# src/core/database.py
"""
Enterprise Database Schema — SQLAlchemy ORM
Tables:
  - scans                  : One record per audit run
  - vulnerability_findings : Individual vulnerabilities discovered per scan
  - threat_intel_events    : Blocked prompt injections / malicious inputs
  - audit_events           : Structured audit trail for every action taken
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import (
    Boolean, Column, DateTime, ForeignKey,
    Integer, String, Text, create_engine, Index, event
)
from sqlalchemy.orm import DeclarativeBase, Session, relationship, sessionmaker

from core.config import get_settings

settings = get_settings()

# ── Engine ────────────────────────────────────────────────────
_is_sqlite = "sqlite" in settings.database_url

engine = create_engine(
    settings.database_url,
    connect_args={"check_same_thread": False} if _is_sqlite else {},
    # pool_size / max_overflow only valid for non-SQLite engines
    **({} if _is_sqlite else {"pool_size": 5, "max_overflow": 10, "pool_pre_ping": True}),
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


# ── ORM Base ──────────────────────────────────────────────────
class Base(DeclarativeBase):
    pass


# ── Tables ────────────────────────────────────────────────────

class ScanRecord(Base):
    """One record per full audit run."""
    __tablename__ = "scans"

    id              = Column(Integer, primary_key=True, index=True)
    target          = Column(String(2048), index=True, nullable=False)
    status          = Column(String(20), default="QUEUED", index=True)
    # QUEUED | ENGAGED | COMPLETED | FAILED | CANCELLED

    progress_pct    = Column(Integer, default=0)         # 0–100
    current_phase   = Column(String(100), nullable=True) # "RECON", "NUCLEI", etc.
    vulns_found     = Column(Integer, default=0)
    critical_count  = Column(Integer, default=0)
    high_count      = Column(Integer, default=0)
    medium_count    = Column(Integer, default=0)
    low_count       = Column(Integer, default=0)
    pages_crawled   = Column(Integer, default=0)
    endpoints_found = Column(Integer, default=0)

    report_path     = Column(String(512), nullable=True)
    report_filename = Column(String(256), nullable=True)

    error_message   = Column(Text, nullable=True)
    started_at      = Column(DateTime, nullable=True)
    completed_at    = Column(DateTime, nullable=True)
    timestamp       = Column(DateTime, default=datetime.utcnow, index=True)

    # Relationships
    findings  = relationship("VulnerabilityFinding", back_populates="scan",
                             cascade="all, delete-orphan")
    events    = relationship("AuditEvent", back_populates="scan",
                             cascade="all, delete-orphan")

    @property
    def duration_seconds(self) -> Optional[float]:
        if self.started_at and self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None

    def to_dict(self) -> dict:
        return {
            "id":              self.id,
            "target":          self.target,
            "status":          self.status,
            "progress_pct":    self.progress_pct,
            "current_phase":   self.current_phase,
            "vulns_found":     self.vulns_found,
            "critical_count":  self.critical_count,
            "high_count":      self.high_count,
            "medium_count":    self.medium_count,
            "low_count":       self.low_count,
            "pages_crawled":   self.pages_crawled,
            "endpoints_found": self.endpoints_found,
            "report_filename": self.report_filename,
            "error_message":   self.error_message,
            "started_at":      self.started_at.isoformat() if self.started_at else None,
            "completed_at":    self.completed_at.isoformat() if self.completed_at else None,
            "timestamp":       self.timestamp.isoformat() if self.timestamp else None,
            "duration_seconds":self.duration_seconds,
        }


class VulnerabilityFinding(Base):
    """One row per vulnerability discovered during a scan."""
    __tablename__ = "vulnerability_findings"

    id               = Column(Integer, primary_key=True, index=True)
    scan_id          = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"),
                              nullable=False, index=True)

    vuln_name        = Column(String(256), nullable=False)
    cwe              = Column(String(20),  nullable=True, index=True)
    severity         = Column(String(20),  nullable=False, index=True)
    # critical | high | medium | low | info
    confidence       = Column(String(20),  nullable=False)
    # confirmed | likely | unconfirmed

    endpoint         = Column(String(2048), nullable=False)
    method           = Column(String(10),   default="GET")
    payload_used     = Column(Text, nullable=True)
    request_sent     = Column(Text, nullable=True)
    response_snippet = Column(Text, nullable=True)
    notes            = Column(Text, nullable=True)

    source           = Column(String(50), default="custom_fuzzer")
    # custom_fuzzer | nuclei | manual

    is_false_positive = Column(Boolean, default=False)
    timestamp         = Column(DateTime, default=datetime.utcnow)

    # Relationship
    scan = relationship("ScanRecord", back_populates="findings")

    def to_dict(self) -> dict:
        return {
            "id":               self.id,
            "scan_id":          self.scan_id,
            "vuln_name":        self.vuln_name,
            "cwe":              self.cwe,
            "severity":         self.severity,
            "confidence":       self.confidence,
            "endpoint":         self.endpoint,
            "method":           self.method,
            "payload_used":     self.payload_used,
            "notes":            self.notes,
            "source":           self.source,
            "is_false_positive":self.is_false_positive,
            "timestamp":        self.timestamp.isoformat() if self.timestamp else None,
        }


class ThreatEvent(Base):
    """Blocked prompt injections and malicious inputs."""
    __tablename__ = "threat_intel_events"

    id                = Column(Integer, primary_key=True, index=True)
    timestamp         = Column(DateTime, default=datetime.utcnow, index=True)
    event_type        = Column(String(100), index=True)
    source_target     = Column(String(2048))
    malicious_payload = Column(Text)
    mitigation_action = Column(String(256))

    def to_dict(self) -> dict:
        return {
            "id":                self.id,
            "timestamp":         self.timestamp.isoformat() if self.timestamp else None,
            "event_type":        self.event_type,
            "source_target":     self.source_target,
            "malicious_payload": self.malicious_payload,
            "mitigation_action": self.mitigation_action,
        }


class AuditEvent(Base):
    """Structured audit trail for every significant action."""
    __tablename__ = "audit_events"

    id           = Column(Integer, primary_key=True, index=True)
    scan_id      = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"),
                          nullable=True, index=True)
    timestamp    = Column(DateTime, default=datetime.utcnow, index=True)
    log_level    = Column(String(20), default="INFO")       # INFO | WARNING | ERROR | CRITICAL
    component    = Column(String(100), nullable=True)       # RECON | NUCLEI | FUZZER | GRC
    message      = Column(Text, nullable=False)
    extra_data   = Column(Text, nullable=True)              # JSON string of extra context
    # NOTE: 'metadata' is RESERVED by SQLAlchemy — never use it as a column name

    # Relationship
    scan = relationship("ScanRecord", back_populates="events")

    def to_dict(self) -> dict:
        return {
            "id":        self.id,
            "scan_id":   self.scan_id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "level":     self.log_level,
            "component": self.component,
            "message":   self.message,
        }


# ── Indexes for query performance ─────────────────────────────
Index("ix_findings_scan_severity", VulnerabilityFinding.scan_id, VulnerabilityFinding.severity)
Index("ix_events_scan_level",      AuditEvent.scan_id,           AuditEvent.log_level)

# Auto-create all tables on startup
Base.metadata.create_all(bind=engine)


# ── Schema Migration (ALTER TABLE for existing DBs) ───────────
def run_migrations() -> None:
    """
    Add any missing columns to existing tables.
    Safe to call on every startup — skips columns that already exist.
    This prevents 'no such column' errors when the schema evolves.
    """
    # New columns added to 'scans' table in v2.0
    _scans_new_columns = [
        ("progress_pct",    "INTEGER DEFAULT 0"),
        ("current_phase",   "TEXT"),
        ("critical_count",  "INTEGER DEFAULT 0"),
        ("high_count",      "INTEGER DEFAULT 0"),
        ("medium_count",    "INTEGER DEFAULT 0"),
        ("low_count",       "INTEGER DEFAULT 0"),
        ("pages_crawled",   "INTEGER DEFAULT 0"),
        ("endpoints_found", "INTEGER DEFAULT 0"),
        ("report_filename", "TEXT"),
        ("started_at",      "DATETIME"),
        ("completed_at",    "DATETIME"),
        ("error_message",   "TEXT"),
    ]

    with engine.connect() as conn:
        # Get existing column names for 'scans'
        existing = {
            row[1]
            for row in conn.execute(
                __import__("sqlalchemy").text("PRAGMA table_info(scans)")
            )
        }
        for col_name, col_type in _scans_new_columns:
            if col_name not in existing:
                conn.execute(
                    __import__("sqlalchemy").text(
                        f"ALTER TABLE scans ADD COLUMN {col_name} {col_type}"
                    )
                )
        conn.commit()


run_migrations()


# ── Dependency / Helpers ──────────────────────────────────────

def get_db():
    """FastAPI dependency that yields a DB session per request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def update_scan_counts(db: Session, scan_id: int) -> None:
    """Recalculate severity counts on ScanRecord from its findings."""
    scan = db.query(ScanRecord).filter(ScanRecord.id == scan_id).first()
    if not scan:
        return

    findings = (
        db.query(VulnerabilityFinding)
        .filter(
            VulnerabilityFinding.scan_id == scan_id,
            VulnerabilityFinding.is_false_positive == False,
        )
        .all()
    )

    scan.vulns_found    = len(findings)
    scan.critical_count = sum(1 for f in findings if f.severity == "critical")
    scan.high_count     = sum(1 for f in findings if f.severity == "high")
    scan.medium_count   = sum(1 for f in findings if f.severity == "medium")
    scan.low_count      = sum(1 for f in findings if f.severity in ("low", "info"))
    db.commit()