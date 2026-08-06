"""
SentinelAI Custom Prometheus Metrics (Layer 12 — Observability)
All application-level metrics defined here are auto-exposed on /metrics.
"""
from prometheus_client import Counter, Histogram, Gauge

# ── Scan Metrics ──────────────────────────────────────────────────────────────
SCANS_TOTAL = Counter(
    "sentinel_scans_total",
    "Total number of scans dispatched",
    ["tool", "status"],  # labels: tool=nmap, status=completed/failed
)

SCAN_DURATION_SECONDS = Histogram(
    "sentinel_scan_duration_seconds",
    "Time taken to complete a scan (seconds)",
    ["tool"],
    buckets=[5, 10, 30, 60, 120, 300, 600],
)

SCANS_IN_FLIGHT = Gauge(
    "sentinel_scans_in_flight",
    "Number of scans currently running",
)

# ── Risk Metrics ───────────────────────────────────────────────────────────────
RISK_FINDINGS = Counter(
    "sentinel_risk_findings_total",
    "Total findings by risk level",
    ["risk_level"],  # CRITICAL, HIGH, MEDIUM, LOW, INFO
)

# ── Intelligence Metrics ───────────────────────────────────────────────────────
EMBEDDINGS_STORED = Counter(
    "sentinel_embeddings_stored_total",
    "Total number of scan findings embedded into the vector store",
)

RAG_QUERIES = Counter(
    "sentinel_rag_queries_total",
    "Total number of RAG similarity queries executed",
)

# ── Auth Metrics ───────────────────────────────────────────────────────────────
AUTH_ATTEMPTS = Counter(
    "sentinel_auth_attempts_total",
    "Login/register attempts",
    ["endpoint", "result"],  # endpoint=login/register, result=success/failure
)

# ── Orchestrator Metrics ───────────────────────────────────────────────────────
ORCHESTRATIONS_TOTAL = Counter(
    "sentinel_orchestrations_total",
    "Total agentic orchestration runs",
    ["planner"],  # keyword / ai
)
