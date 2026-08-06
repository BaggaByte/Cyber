"""
SentinelAI Structured Logger (Layer 12 — Observability)
Outputs JSON-formatted logs compatible with Loki / ELK / Datadog ingestion.
"""
import logging
import sys
from pythonjsonlogger import jsonlogger

# ── Custom JSON formatter ─────────────────────────────────────────────────────
class SentinelFormatter(jsonlogger.JsonFormatter):
    def add_fields(self, log_record, record, message_dict):
        super().add_fields(log_record, record, message_dict)
        log_record["service"] = "sentinelai-backend"
        log_record["level"] = record.levelname
        log_record.pop("levelname", None)  # avoid duplication


def get_logger(name: str) -> logging.Logger:
    """
    Returns a structured JSON logger for the given module name.

    Usage:
        from observability.logger import get_logger
        log = get_logger(__name__)
        log.info("Scan started", extra={"scan_id": 42, "tool": "nmap"})
    """
    logger = logging.getLogger(name)

    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        formatter = SentinelFormatter(
            fmt="%(asctime)s %(name)s %(level)s %(message)s"
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        logger.propagate = False

    return logger
