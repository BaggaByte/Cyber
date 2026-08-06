"""
Layer 6: Intelligence & Data Layer — Embeddings Engine (PGVector)
Converts scan findings into vector embeddings and stores them natively in Postgres
for semantic similarity search (RAG retrieval).
"""
import json
import hashlib
from typing import Optional
from observability import get_logger, EMBEDDINGS_STORED
from database import SessionLocal
from models import ScanFindingEmbedding

log = get_logger(__name__)

# Lazy-load the sentence transformer model
_embedder = None

def _get_embedder():
    global _embedder
    if _embedder is None:
        log.info("Loading sentence-transformers model (first run may download ~90MB)...")
        from sentence_transformers import SentenceTransformer
        _embedder = SentenceTransformer("all-MiniLM-L6-v2")
        log.info("Embedding model loaded")
    return _embedder

def _findings_to_text(findings: dict, tool_used: str) -> str:
    """Converts a findings dict into a human-readable text for embedding."""
    parts = [f"Tool: {tool_used}"]

    open_ports = findings.get("open_ports", [])
    if open_ports:
        port_strs = [f"{p.get('port')}/{p.get('protocol')} ({p.get('service', '?')})" for p in open_ports]
        parts.append(f"Open ports: {', '.join(port_strs)}")

    subdomains = findings.get("discovered_subdomains", [])
    if subdomains:
        parts.append(f"Subdomains: {', '.join(s.get('subdomain', '') for s in subdomains)}")

    risk = findings.get("risk_level", "")
    if risk:
        parts.append(f"Risk level: {risk}")

    raw = findings.get("raw_output", "")
    if raw and len(raw) > 10:
        parts.append(f"Output summary: {raw[:500]}")

    return " | ".join(parts)

def embed_and_store(scan_id: int, target: str, tool_used: str,
                    findings: dict, risk_level: str, org_id: int) -> bool:
    """
    Generates an embedding for scan findings and stores it in PGVector.
    Returns True on success, False on failure.
    """
    try:
        text = _findings_to_text(findings, tool_used)
        if not text.strip():
            return False

        embedder = _get_embedder()
        vector = embedder.encode(text).tolist()

        db = SessionLocal()
        try:
            # Check if embedding already exists for this scan to avoid duplicates on retry
            existing = db.query(ScanFindingEmbedding).filter(ScanFindingEmbedding.scan_id == scan_id).first()
            if existing:
                existing.embedding = vector
                existing.text_content = text
            else:
                new_embed = ScanFindingEmbedding(
                    scan_id=scan_id,
                    org_id=org_id,
                    target=target,
                    tool=tool_used,
                    risk=risk_level,
                    text_content=text,
                    embedding=vector
                )
                db.add(new_embed)
            db.commit()
            
            EMBEDDINGS_STORED.inc()
            log.info("Embedding stored in PGVector", extra={"scan_id": scan_id, "tool": tool_used})
            return True
        except Exception as db_e:
            db.rollback()
            raise db_e
        finally:
            db.close()

    except Exception as e:
        log.error("Failed to store embedding", extra={"scan_id": scan_id, "error": str(e)})
        return False
