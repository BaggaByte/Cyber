# src/main.py
"""
Nexus AI — Enterprise FastAPI Backend
======================================
Endpoints:
  GET  /api/health                   - System health check
  POST /api/scan                     - Launch a new scan
  GET  /api/scan/{scan_id}           - Get scan details
  GET  /api/scan/{scan_id}/report    - Serve the GRC HTML report
  GET  /api/scans                    - Paginated scan history
  GET  /api/findings                 - All vulnerability findings (paginated)
  GET  /api/findings/{scan_id}       - Findings for one scan
  GET  /api/stats                    - Aggregate stats for the dashboard
  WS   /ws/scan/{scan_id}            - Per-scan live log stream
  WS   /ws/global                    - System-level log stream
"""
from __future__ import annotations

import asyncio
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import (
    BackgroundTasks, Depends, FastAPI, HTTPException,
    Query, WebSocket, WebSocketDisconnect, status
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from pydantic import BaseModel, HttpUrl, field_validator
from sqlalchemy.orm import Session

# Core infrastructure
from core.auth import verify_api_key
from core.config import get_settings
from core.database import (
    AuditEvent, SessionLocal, ScanRecord, VulnerabilityFinding,
    get_db, update_scan_counts
)
from core.logger import (
    get_scan_queue, log_error, log_info, log_queue,
    remove_scan_queue, stream_log
)

# Orchestrator
from orchestrator.mcp_orchestrator import run_enterprise_audit

settings = get_settings()

# ── Active scan tracking ──────────────────────────────────────
_active_scans: set[int] = set()


# ── Lifespan ─────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    await log_info("Nexus AI Enterprise Backend starting up...", component="SYSTEM")
    yield
    await log_info("Nexus AI shutting down...", component="SYSTEM")


# ── App ───────────────────────────────────────────────────────
app = FastAPI(
    title="Nexus AI Enterprise API",
    description="Autonomous DevSecOps & GRC Orchestration Platform",
    version="2.0.0",
    lifespan=lifespan,
)

from fastapi import Request
from fastapi.responses import JSONResponse
import traceback

@app.exception_handler(Exception)
async def debug_exception_handler(request: Request, exc: Exception):
    err = traceback.format_exc()
    with open("crash.log", "a") as f:
        f.write(err + "\n")
    # SECURITY FIX: Do not leak raw stack traces to the client in production!
    return JSONResponse(status_code=500, content={"detail": "An internal server error occurred. Please contact an administrator."})

app.add_middleware(
    CORSMiddleware,
    # Explicit origins instead of "*" so credentials can work if needed.
    # Also covers both Vite dev server ports (5173 + 5174).
    allow_origins=[
        "http://localhost:5173",
        "http://localhost:5174",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:5174",
        "http://localhost:3000",
        *([o for o in settings.cors_origins if o != "*"]),
    ],
    allow_credentials=False,   # Must be False when using wildcard/broad origins
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Request / Response Models ─────────────────────────────────
class ScanRequest(BaseModel):
    target: str

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Target URL cannot be empty")
        if not (v.startswith("http://") or v.startswith("https://")):
            raise ValueError("Target must start with http:// or https://")
        return v


class ScanResponse(BaseModel):
    status: str
    scan_id: int
    target: str
    message: str


# ── Background Worker ─────────────────────────────────────────
async def run_enterprise_worker(target: str, scan_id: int) -> None:
    """Runs the full Groq MCP agentic loop in a background task."""
    _active_scans.add(scan_id)
    db = SessionLocal()
    try:
        scan = db.query(ScanRecord).filter(ScanRecord.id == scan_id).first()
        if scan:
            scan.status = "ENGAGED"
            scan.started_at = datetime.utcnow()
            db.commit()

        await run_enterprise_audit(target, scan_id=scan_id)

        scan = db.query(ScanRecord).filter(ScanRecord.id == scan_id).first()
        if scan:
            scan.status = "COMPLETED"
            scan.completed_at = datetime.utcnow()
            scan.progress_pct = 100
            db.commit()
            update_scan_counts(db, scan_id)

        await log_info("Audit completed successfully.", scan_id=scan_id, component="SYSTEM")

    except Exception as e:
        await log_error(f"Engine failure: {e}", scan_id=scan_id, component="SYSTEM")
        db2 = SessionLocal()
        try:
            scan = db2.query(ScanRecord).filter(ScanRecord.id == scan_id).first()
            if scan:
                scan.status = "FAILED"
                scan.error_message = str(e)
                scan.completed_at = datetime.utcnow()
                db2.commit()
        finally:
            db2.close()
    finally:
        db.close()
        _active_scans.discard(scan_id)
        # Keep queue alive for a moment so client can drain remaining messages
        await asyncio.sleep(3)
        remove_scan_queue(scan_id)


# ══════════════════════════════════════════════════════════════
# WEBSOCKET ENDPOINTS
# ══════════════════════════════════════════════════════════════

@app.websocket("/ws/scan/{scan_id}")
async def websocket_scan(websocket: WebSocket, scan_id: int):
    """Per-scan real-time log stream."""
    await websocket.accept()
    await websocket.send_text(json.dumps({
        "level": "INFO",
        "component": "SYSTEM",
        "message": f"WebSocket connected for scan #{scan_id}",
        "timestamp": datetime.utcnow().isoformat(),
    }))

    q = get_scan_queue(scan_id)
    try:
        while True:
            try:
                message = await asyncio.wait_for(q.get(), timeout=30.0)
                await websocket.send_text(message)

                # Parse to check for completion signal
                try:
                    data = json.loads(message)
                    msg = data.get("message", "")
                    if "Audit Cycle Completed" in msg or "FAILED" in msg:
                        await asyncio.sleep(0.5)
                        break
                except Exception:
                    pass

            except asyncio.TimeoutError:
                # Send keepalive ping
                try:
                    await websocket.send_text(json.dumps({
                        "level": "DEBUG",
                        "component": "SYSTEM",
                        "message": "keepalive",
                        "timestamp": datetime.utcnow().isoformat(),
                    }))
                except Exception:
                    break

    except WebSocketDisconnect:
        pass


@app.websocket("/ws/global")
async def websocket_global(websocket: WebSocket):
    """Global system-level log stream."""
    await websocket.accept()
    try:
        while True:
            try:
                message = await asyncio.wait_for(log_queue.get(), timeout=30.0)
                await websocket.send_text(message)
            except asyncio.TimeoutError:
                try:
                    await websocket.send_text(json.dumps({"level": "DEBUG", "message": "keepalive"}))
                except Exception:
                    break
    except WebSocketDisconnect:
        pass


# ══════════════════════════════════════════════════════════════
# REST ENDPOINTS
# ══════════════════════════════════════════════════════════════

# ── Health ────────────────────────────────────────────────────
@app.get("/api/health", tags=["System"])
async def health_check(db: Session = Depends(get_db)):
    """System health check — verifies DB and configuration."""
    try:
        # Quick DB ping
        db.execute(__import__("sqlalchemy").text("SELECT 1"))
        db_status = "ok"
    except Exception as e:
        db_status = f"error: {e}"

    return {
        "status": "ok" if db_status == "ok" else "degraded",
        "version": "2.0.0",
        "database": db_status,
        "active_scans": len(_active_scans),
        "model": settings.model_name,
        "timestamp": datetime.utcnow().isoformat(),
    }


# ── Launch Scan ───────────────────────────────────────────────
@app.post("/api/scan", response_model=ScanResponse, tags=["Scans"])
async def launch_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    _: str = Depends(verify_api_key),
):
    """Launch a new autonomous security audit."""
    # Concurrency gate
    if len(_active_scans) >= settings.max_concurrent_scans:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Max concurrent scans ({settings.max_concurrent_scans}) reached. Try again shortly.",
        )

    new_scan = ScanRecord(
        target=request.target,
        status="QUEUED",
        timestamp=datetime.utcnow(),
    )
    db.add(new_scan)
    db.commit()
    db.refresh(new_scan)
    scan_id = new_scan.id

    # Audit event
    db.add(AuditEvent(
        scan_id=scan_id,
        log_level="INFO",
        component="API",
        message=f"Scan queued for target: {request.target}",
    ))
    db.commit()

    await log_info(
        f"Scan #{scan_id} queued for target: {request.target}",
        scan_id=scan_id,
        component="API",
    )

    background_tasks.add_task(run_enterprise_worker, request.target, scan_id)

    return ScanResponse(
        status="Queued",
        scan_id=scan_id,
        target=request.target,
        message=f"Audit queued. Connect to /ws/scan/{scan_id} for live output.",
    )


# ── Get Single Scan ───────────────────────────────────────────
@app.get("/api/scan/{scan_id}", tags=["Scans"])
async def get_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    _: str = Depends(verify_api_key),
):
    """Get full details of a scan, including its findings."""
    scan = db.query(ScanRecord).filter(ScanRecord.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan #{scan_id} not found")

    findings = [f.to_dict() for f in scan.findings]
    result = scan.to_dict()
    result["findings"] = findings
    return result


# ── GRC Report ────────────────────────────────────────────────
@app.get("/api/scan/{scan_id}/report", tags=["Reports"])
async def get_report(scan_id: int, db: Session = Depends(get_db)):
    """Serve the HTML GRC compliance report for a completed scan."""
    scan = db.query(ScanRecord).filter(ScanRecord.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan #{scan_id} not found")
    if not scan.report_path:
        raise HTTPException(status_code=404, detail="Report not generated yet for this scan")

    report_path = Path(scan.report_path)
    if not report_path.exists():
        raise HTTPException(status_code=404, detail="Report file not found on disk")

    return FileResponse(report_path, media_type="text/html")


# ── Scan History (Paginated) ──────────────────────────────────
@app.get("/api/scans", tags=["Scans"])
async def list_scans(
    page: int = Query(default=1, ge=1),
    limit: int = Query(default=20, ge=1, le=100),
    status_filter: Optional[str] = Query(default=None),
    db: Session = Depends(get_db),
    _: str = Depends(verify_api_key),
):
    """Paginated list of all scan records, newest first."""
    q = db.query(ScanRecord)
    if status_filter:
        q = q.filter(ScanRecord.status == status_filter.upper())

    total = q.count()
    scans = (
        q.order_by(ScanRecord.timestamp.desc())
        .offset((page - 1) * limit)
        .limit(limit)
        .all()
    )

    return {
        "total":   total,
        "page":    page,
        "limit":   limit,
        "pages":   (total + limit - 1) // limit,
        "scans":   [s.to_dict() for s in scans],
    }


# ── Findings ──────────────────────────────────────────────────
@app.get("/api/findings", tags=["Findings"])
async def list_all_findings(
    page: int = Query(default=1, ge=1),
    limit: int = Query(default=50, ge=1, le=200),
    severity: Optional[str] = Query(default=None),
    db: Session = Depends(get_db),
    _: str = Depends(verify_api_key),
):
    """Paginated list of all vulnerability findings across all scans."""
    q = db.query(VulnerabilityFinding).filter(
        VulnerabilityFinding.is_false_positive == False
    )
    if severity:
        q = q.filter(VulnerabilityFinding.severity == severity.lower())

    total = q.count()
    findings = (
        q.order_by(VulnerabilityFinding.timestamp.desc())
        .offset((page - 1) * limit)
        .limit(limit)
        .all()
    )

    return {
        "total":    total,
        "page":     page,
        "limit":    limit,
        "findings": [f.to_dict() for f in findings],
    }


@app.get("/api/findings/{scan_id}", tags=["Findings"])
async def get_findings_for_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    _: str = Depends(verify_api_key),
):
    """All vulnerability findings for a specific scan."""
    findings = (
        db.query(VulnerabilityFinding)
        .filter(VulnerabilityFinding.scan_id == scan_id)
        .order_by(VulnerabilityFinding.severity)
        .all()
    )
    return {"scan_id": scan_id, "findings": [f.to_dict() for f in findings]}


# ── Aggregate Stats ───────────────────────────────────────────
@app.get("/api/stats", tags=["Dashboard"])
async def get_stats(db: Session = Depends(get_db)):
    """Aggregate statistics for the dashboard."""
    total_scans     = db.query(ScanRecord).count()
    completed_scans = db.query(ScanRecord).filter(ScanRecord.status == "COMPLETED").count()
    failed_scans    = db.query(ScanRecord).filter(ScanRecord.status == "FAILED").count()
    active_scans    = len(_active_scans)

    total_findings  = db.query(VulnerabilityFinding).filter(
        VulnerabilityFinding.is_false_positive == False
    ).count()
    critical_count  = db.query(VulnerabilityFinding).filter(
        VulnerabilityFinding.severity == "critical",
        VulnerabilityFinding.is_false_positive == False,
    ).count()
    high_count      = db.query(VulnerabilityFinding).filter(
        VulnerabilityFinding.severity == "high",
        VulnerabilityFinding.is_false_positive == False,
    ).count()

    # Last 10 scans for trend chart
    recent_scans = (
        db.query(ScanRecord)
        .order_by(ScanRecord.timestamp.desc())
        .limit(10)
        .all()
    )

    return {
        "total_scans":     total_scans,
        "completed_scans": completed_scans,
        "failed_scans":    failed_scans,
        "active_scans":    active_scans,
        "total_findings":  total_findings,
        "critical_count":  critical_count,
        "high_count":      high_count,
        "risk_score":      min(100, (critical_count * 15) + (high_count * 5)),
        "recent_scans":    [s.to_dict() for s in recent_scans],
    }


# ── Legacy History (compatibility) ───────────────────────────
@app.get("/api/history", tags=["Scans"])
async def get_scan_history(db: Session = Depends(get_db)):
    """Legacy endpoint — returns last 10 scans."""
    scans = (
        db.query(ScanRecord)
        .order_by(ScanRecord.timestamp.desc())
        .limit(10)
        .all()
    )
    return [s.to_dict() for s in scans]


# ── Delete Scan ───────────────────────────────────────────────
@app.delete("/api/scan/{scan_id}", tags=["Scans"])
async def delete_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    _: str = Depends(verify_api_key),
):
    """Delete a scan record and all associated findings from the database."""
    scan = db.query(ScanRecord).filter(ScanRecord.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan #{scan_id} not found")
    if scan_id in _active_scans:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Scan #{scan_id} is currently running. Cancel it first.",
        )
    db.delete(scan)
    db.commit()
    return {"status": "deleted", "scan_id": scan_id}


# ── Cancel Scan ───────────────────────────────────────────────
@app.post("/api/scan/{scan_id}/cancel", tags=["Scans"])
async def cancel_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    _: str = Depends(verify_api_key),
):
    """Mark a running scan as CANCELLED (best-effort; the worker will stop at next checkpoint)."""
    if scan_id not in _active_scans:
        raise HTTPException(status_code=404, detail=f"Scan #{scan_id} is not currently running")
    scan = db.query(ScanRecord).filter(ScanRecord.id == scan_id).first()
    if scan:
        scan.status = "CANCELLED"
        scan.completed_at = datetime.utcnow()
        db.commit()
    await log_info(f"Scan #{scan_id} cancellation requested by user.", scan_id=scan_id, component="API")
    _active_scans.discard(scan_id)
    return {"status": "cancelled", "scan_id": scan_id}


# ── Reports Library ────────────────────────────────────────────
@app.get("/api/reports", tags=["Reports"])
async def list_reports(db: Session = Depends(get_db)):
    """List all GRC report files with their metadata, newest first."""
    scans = (
        db.query(ScanRecord)
        .filter(ScanRecord.report_path.isnot(None))
        .order_by(ScanRecord.timestamp.desc())
        .all()
    )
    reports = []
    for s in scans:
        rp = Path(s.report_path) if s.report_path else None
        reports.append({
            "scan_id":    s.id,
            "target":     s.target,
            "status":     s.status,
            "filename":   s.report_filename or (rp.name if rp else None),
            "exists":     rp.exists() if rp else False,
            "timestamp":  s.timestamp.isoformat() if s.timestamp else None,
            "completed_at": s.completed_at.isoformat() if s.completed_at else None,
            "vulns_found":  s.vulns_found,
            "critical_count": s.critical_count,
            "high_count": s.high_count,
        })
    return {"total": len(reports), "reports": reports}


# ── Scan Trend (14-day) ────────────────────────────────────────
@app.get("/api/stats/trend", tags=["Dashboard"])
async def get_trend(db: Session = Depends(get_db)):
    """Return scan counts grouped by day for the last 14 days."""
    from sqlalchemy import func, cast, Date as SQLDate
    from datetime import timedelta

    today = datetime.utcnow().date()
    start = today - timedelta(days=13)

    rows = (
        db.query(
            func.date(ScanRecord.timestamp).label("day"),
            func.count(ScanRecord.id).label("total"),
            func.sum(
                __import__("sqlalchemy").case(
                    (ScanRecord.status == "COMPLETED", 1), else_=0
                )
            ).label("completed"),
            func.sum(
                __import__("sqlalchemy").case(
                    (ScanRecord.status == "FAILED", 1), else_=0
                )
            ).label("failed"),
        )
        .filter(ScanRecord.timestamp >= datetime.combine(start, datetime.min.time()))
        .group_by(func.date(ScanRecord.timestamp))
        .all()
    )

    # Build a full 14-day series (fill zeros for days with no scans)
    data_map = {str(r.day): {"total": r.total, "completed": int(r.completed or 0), "failed": int(r.failed or 0)} for r in rows}
    series = []
    for i in range(14):
        day = str(start + timedelta(days=i))
        entry = data_map.get(day, {"total": 0, "completed": 0, "failed": 0})
        series.append({"date": day, **entry})

    return {"series": series}


# ── Export Findings ────────────────────────────────────────────
@app.get("/api/findings/{scan_id}/export", tags=["Findings"])
async def export_findings(
    scan_id: int,
    fmt: str = Query(default="json", pattern="^(json|csv)$"),
    db: Session = Depends(get_db),
    _: str = Depends(verify_api_key),
):
    """Export findings for a scan as JSON or CSV."""
    from fastapi.responses import PlainTextResponse
    findings = (
        db.query(VulnerabilityFinding)
        .filter(VulnerabilityFinding.scan_id == scan_id)
        .all()
    )
    if fmt == "csv":
        lines = ["severity,vuln_type,url,description,cwe"]
        for f in findings:
            desc = (f.description or "").replace('"', "'")
            lines.append(f'{f.severity},{f.vuln_type},{f.url},"{desc}",{f.cwe or ""}')
        return PlainTextResponse(
            "\n".join(lines),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=findings_scan{scan_id}.csv"},
        )
    return {"scan_id": scan_id, "findings": [f.to_dict() for f in findings]}