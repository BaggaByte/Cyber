# observability/__init__.py
from observability.logger import get_logger
from observability.metrics import (
    SCANS_TOTAL, SCAN_DURATION_SECONDS, SCANS_IN_FLIGHT,
    RISK_FINDINGS, EMBEDDINGS_STORED, RAG_QUERIES,
    AUTH_ATTEMPTS, ORCHESTRATIONS_TOTAL,
)

__all__ = [
    "get_logger",
    "SCANS_TOTAL", "SCAN_DURATION_SECONDS", "SCANS_IN_FLIGHT",
    "RISK_FINDINGS", "EMBEDDINGS_STORED", "RAG_QUERIES",
    "AUTH_ATTEMPTS", "ORCHESTRATIONS_TOTAL",
]
