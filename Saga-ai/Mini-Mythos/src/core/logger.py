# src/core/logger.py
"""
Enterprise Structured Logger
- Per-scan asyncio queues so multiple concurrent scans don't mix logs
- Structured JSON message format with level, component, scan_id
- Python logging integration
- Global broadcast queue for system-level messages
"""
from __future__ import annotations

import asyncio
import json
import logging
import sys
from datetime import datetime, timezone
from typing import Optional

# ── Python stdlib logger ──────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)

_py_logger = logging.getLogger("nexus")


# ── Per-scan async queues ─────────────────────────────────────
# scan_id → asyncio.Queue[str]
_scan_queues: dict[int, asyncio.Queue] = {}

# Global system queue (scan_id=None messages)
_global_queue: asyncio.Queue = asyncio.Queue(maxsize=2000)


def get_scan_queue(scan_id: int) -> asyncio.Queue:
    """Return or create the asyncio queue for a given scan."""
    if scan_id not in _scan_queues:
        _scan_queues[scan_id] = asyncio.Queue(maxsize=2000)
    return _scan_queues[scan_id]


def remove_scan_queue(scan_id: int) -> None:
    """Clean up queue after scan completes."""
    _scan_queues.pop(scan_id, None)


# ── Core streaming function ───────────────────────────────────

async def stream_log(
    message: str,
    *,
    scan_id: Optional[int] = None,
    level: str = "INFO",
    component: Optional[str] = None,
) -> None:
    """
    Emit a log message to:
      1. Python stdout (via stdlib logging)
      2. The per-scan asyncio queue (for WebSocket streaming)
      3. The global queue (for system-level consumers)

    Args:
        message:   Human-readable log text
        scan_id:   Associate with a specific scan (None = system message)
        level:     INFO | WARNING | ERROR | CRITICAL | DEBUG
        component: RECON | NUCLEI | FUZZER | ORCHESTRATOR | GRC | SYSTEM
    """
    # 1. Python logging
    log_fn = {
        "DEBUG":    _py_logger.debug,
        "INFO":     _py_logger.info,
        "WARNING":  _py_logger.warning,
        "ERROR":    _py_logger.error,
        "CRITICAL": _py_logger.critical,
    }.get(level.upper(), _py_logger.info)

    prefix = f"[{component}] " if component else ""
    log_fn(f"scan={scan_id} {prefix}{message}")

    # 2. Build structured payload for WebSocket clients
    payload = json.dumps({
        "scan_id":   scan_id,
        "level":     level.upper(),
        "component": component or "SYSTEM",
        "message":   message,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })

    # 3. Push to per-scan queue
    if scan_id is not None:
        q = get_scan_queue(scan_id)
        try:
            q.put_nowait(payload)
        except asyncio.QueueFull:
            pass  # drop oldest if full — never block the scan engine

    # 4. Push to global queue
    try:
        _global_queue.put_nowait(payload)
    except asyncio.QueueFull:
        pass


# ── Convenience wrappers ──────────────────────────────────────

async def log_info(msg: str, scan_id: int | None = None, component: str | None = None):
    await stream_log(msg, scan_id=scan_id, level="INFO", component=component)

async def log_warning(msg: str, scan_id: int | None = None, component: str | None = None):
    await stream_log(msg, scan_id=scan_id, level="WARNING", component=component)

async def log_error(msg: str, scan_id: int | None = None, component: str | None = None):
    await stream_log(msg, scan_id=scan_id, level="ERROR", component=component)

async def log_critical(msg: str, scan_id: int | None = None, component: str | None = None):
    await stream_log(msg, scan_id=scan_id, level="CRITICAL", component=component)

async def log_debug(msg: str, scan_id: int | None = None, component: str | None = None):
    await stream_log(msg, scan_id=scan_id, level="DEBUG", component=component)


# ── Legacy compatibility ──────────────────────────────────────
# The old logger exposed `log_queue` directly. Keep this working.
log_queue = _global_queue
