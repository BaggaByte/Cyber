"""
Layer 6: Intelligence & Data Layer — RAG Query Engine
Retrieves semantically similar past scan findings from Postgres (PGVector).
Used to give the AI Remediation Engine historical context (RAG pattern).
"""
from typing import List, Dict, Optional
from observability import get_logger, RAG_QUERIES
from database import SessionLocal
from models import ScanFindingEmbedding

log = get_logger(__name__)


def find_similar_findings(
    query_text: str,
    org_id: Optional[int] = None,
    n_results: int = 3,
) -> List[Dict]:
    """
    Retrieves the N most semantically similar past scan findings using PGVector cosine distance.
    Optionally scoped to a specific organization for tenant isolation.

    Returns a list of dicts: [{scan_id, target, tool, risk, text, distance}, ...]
    """
    try:
        from intelligence.embeddings import _get_embedder
        embedder = _get_embedder()
        query_vector = embedder.encode(query_text).tolist()

        db = SessionLocal()
        try:
            # Determine the cosine distance to our query
            distance_expr = ScanFindingEmbedding.embedding.cosine_distance(query_vector)
            
            # Query the database, ordering by closest distance
            query = db.query(ScanFindingEmbedding, distance_expr.label("distance"))
            
            if org_id:
                query = query.filter(ScanFindingEmbedding.org_id == org_id)
                
            results = query.order_by(distance_expr).limit(n_results).all()

            RAG_QUERIES.inc()

            similar = []
            for record, distance in results:
                similar.append({
                    "scan_id":  record.scan_id,
                    "target":   record.target,
                    "tool":     record.tool,
                    "risk":     record.risk,
                    "text":     record.text_content,
                    "distance": round(distance, 4),
                })

            log.info("RAG query executed via PGVector", extra={"n_results": len(similar), "org_id": org_id})
            return similar
        finally:
            db.close()

    except Exception as e:
        log.error("RAG query failed", extra={"error": str(e)})
        return []


def build_rag_context(findings: dict, tool_used: str, org_id: int) -> str:
    """
    Generates a RAG context string from similar past findings.
    Injected into the Groq remediation prompt for richer, context-aware analysis.
    """
    from intelligence.embeddings import _findings_to_text
    query = _findings_to_text(findings, tool_used)
    similar = find_similar_findings(query, org_id=org_id, n_results=3)

    if not similar:
        return ""

    lines = ["## Relevant Historical Findings (from past scans in your organization):\n"]
    for s in similar:
        lines.append(
            f"- [{s['tool'].upper()} on {s['target']}] Risk: {s['risk']} | {s['text'][:200]}"
        )
    return "\n".join(lines)
