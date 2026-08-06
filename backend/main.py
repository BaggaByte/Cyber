from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy.orm import Session
from prometheus_fastapi_instrumentator import Instrumentator
import redis as redis_client

# Database and Task Architecture Imports
from database import get_db, engine
from models import Asset, Scan, ScanStatus, Organization, User, ScheduledScan, Mission
from auth import get_password_hash, verify_password, create_access_token, get_current_user
from worker import run_scan_job
from orchestrator import orchestrator
from observability import get_logger, AUTH_ATTEMPTS, ORCHESTRATIONS_TOTAL
from fastapi.responses import FileResponse
import os
from report_generator import generate_executive_pdf

log = get_logger(__name__)

app = FastAPI(title="SentinelAI API", version="1.0.0")

# ── Layer 12: Auto-instrument all HTTP endpoints for Prometheus ────────────────
Instrumentator().instrument(app).expose(app, endpoint="/metrics")

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
class ScanRequest(BaseModel):
    target: str
    tool: str = "nmap"  # Defaults to our new Nmap plugin

class ScheduleScanRequest(BaseModel):
    target: str
    tool: str
    cron_expression: str

class UserRegister(BaseModel):
    email: str
    password: str
    org_name: str
    first_name: str
    last_name: str
    job_title: str

class UserLogin(BaseModel):
    email: str
    password: str

class OrchestrationRequest(BaseModel):
    goal: str   # Natural language, e.g. "map the attack surface of example.com"
    target: str # Primary target to operate against

@app.get("/")
def read_root():
    return {"status": "SentinelAI Core is Online", "layer": "Layer 1 Access / API"}

@app.get("/health")
def health_check(db: Session = Depends(get_db)):
    """
    Layer 12: Liveness + readiness check.
    Verifies DB, Redis, and Celery worker connectivity.
    """
    health: dict = {"status": "ok", "components": {}}

    # ── Database check ──────────────────────────────────────────────────────
    try:
        db.execute(__import__("sqlalchemy").text("SELECT 1"))
        health["components"]["postgres"] = {"status": "ok"}
    except Exception as e:
        health["components"]["postgres"] = {"status": "error", "detail": str(e)}
        health["status"] = "degraded"

    # ── Redis check ─────────────────────────────────────────────────────────
    try:
        r = redis_client.Redis(host="redis", port=6379, db=0, socket_connect_timeout=2)
        r.ping()
        health["components"]["redis"] = {"status": "ok"}
    except Exception as e:
        health["components"]["redis"] = {"status": "error", "detail": str(e)}
        health["status"] = "degraded"

    # ── Celery worker check (ping) ──────────────────────────────────────────
    try:
        from worker import celery_app
        inspect = celery_app.control.inspect(timeout=2.0)
        active = inspect.ping()
        if active:
            health["components"]["celery"] = {"status": "ok", "workers": list(active.keys())}
        else:
            health["components"]["celery"] = {"status": "no_workers"}
            health["status"] = "degraded"
    except Exception as e:
        health["components"]["celery"] = {"status": "error", "detail": str(e)}
        health["status"] = "degraded"

    log.info("Health check", extra={"health": health})
    return health

@app.post("/api/register")
def register_user(request: UserRegister, db: Session = Depends(get_db)):
    # 1. Check if the user already exists
    if db.query(User).filter(User.email == request.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")

    # 2. Handle the Organization (Multi-Tenancy)
    org = db.query(Organization).filter(Organization.name == request.org_name).first()
    if not org:
        # If the org doesn't exist, create it!
        org = Organization(name=request.org_name)
        db.add(org)
        db.commit()
        db.refresh(org)

    # 3. Hash the password and save the User, tying them to the Organization
    hashed_pw = get_password_hash(request.password)
    new_user = User(
        email=request.email,
        hashed_password=hashed_pw,
        organization_id=org.id,
        first_name=request.first_name,
        last_name=request.last_name,
        job_title=request.job_title,
        role="admin" # The first user in an org becomes the admin
    )
    db.add(new_user)
    db.commit()

    return {"message": f"Successfully registered user in organization: {org.name}"}

@app.post("/api/login")
def login_user(request: UserLogin, db: Session = Depends(get_db)):
    # 1. Find the user
    user = db.query(User).filter(User.email == request.email).first()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # 2. Verify the password
    if not verify_password(request.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # 3. Generate the Key (JWT Token)
    # We pack the payload with everything we need for RBAC and Tenant Isolation
    token_payload = {
        "sub": user.email,
        "user_id": user.id,
        "org_id": user.organization_id,
        "role": user.role
    }
    
    access_token = create_access_token(data=token_payload)

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "org_id": user.organization_id
    }

@app.get("/api/verify_token")
def verify_token(current_user: dict = Depends(get_current_user)):
    return {"status": "ok", "user_id": current_user.get("user_id")}

@app.post("/api/recon")
def launch_recon(
    request: ScanRequest, 
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    org_id = current_user['org_id']
    target_clean = request.target.strip().lower()
    
    if not target_clean:
        raise HTTPException(status_code=400, detail="Target cannot be empty")

    # 1. Ensure Asset exists
    asset = db.query(Asset).filter(Asset.target == target_clean, Asset.organization_id == org_id).first()
    if not asset:
        asset = Asset(target=target_clean, asset_type="domain_or_ip", organization_id=org_id)
        db.add(asset)
        db.commit()
        db.refresh(asset)

    # 2. Initialize a new Scan
    new_scan = Scan(
        asset_id=asset.id,
        status=ScanStatus.QUEUED,
        tool_used=request.tool.lower()
    )
    db.add(new_scan)
    db.commit()
    db.refresh(new_scan)

    # 3. Offload to Celery
    run_scan_job.delay(new_scan.id, asset.target, new_scan.tool_used)

    # THIS is what the frontend is looking for!
    return {
        "message": "Scan job successfully orchestrated",
        "scan_id": new_scan.id,
        "target": asset.target,
        "status": new_scan.status.value,
        "tool": new_scan.tool_used
    }

@app.post("/api/scans/schedule")
def schedule_scan(
    request: ScheduleScanRequest,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    from datetime import datetime
    from croniter import croniter
    
    org_id = current_user['org_id']
    target_clean = request.target.strip().lower()
    
    if not croniter.is_valid(request.cron_expression):
        raise HTTPException(status_code=400, detail="Invalid cron expression")
        
    cron = croniter(request.cron_expression, datetime.utcnow())
    next_run = cron.get_next(datetime)
    
    scheduled_scan = ScheduledScan(
        organization_id=org_id,
        target=target_clean,
        tool=request.tool.lower(),
        cron_expression=request.cron_expression,
        next_run=next_run
    )
    db.add(scheduled_scan)
    db.commit()
    db.refresh(scheduled_scan)
    
    return {"message": "Scan scheduled", "id": scheduled_scan.id, "next_run": scheduled_scan.next_run}

@app.get("/api/scans/schedule")
def list_scheduled_scans(
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    org_id = current_user['org_id']
    schedules = db.query(ScheduledScan).filter(ScheduledScan.organization_id == org_id).all()
    
    return [
        {
            "id": s.id,
            "target": s.target,
            "tool": s.tool,
            "cron_expression": s.cron_expression,
            "last_run": s.last_run,
            "next_run": s.next_run,
        }
        for s in schedules
    ]

@app.get("/api/scans/{scan_id}")
def get_scan_status(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan job not found")

    asset = scan.asset
    return {
        "scan_id": scan.id,
        "status": scan.status.value,
        "tool_used": scan.tool_used,
        "risk_score": scan.risk_score,
        "confidence_score": scan.confidence_score,
        "cross_validated": scan.cross_validated,
        "evidence_links": scan.evidence_links,
        "target": asset.target if asset else None,
        "findings": scan.findings,
        "started_at": scan.started_at,
        "completed_at": scan.completed_at,
    }

@app.get("/api/scans/{scan_id}/report/pdf")
def get_scan_report_pdf(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan job not found")

    if scan.status != ScanStatus.COMPLETED:
        raise HTTPException(status_code=400, detail="Scan must be completed to generate a report")

    asset = scan.asset
    pdf_path = generate_executive_pdf(scan, asset)
    
    return FileResponse(
        path=pdf_path, 
        filename=f"SentinelAI_Report_{asset.target}_{scan_id}.pdf",
        media_type="application/pdf"
    )

@app.get("/api/scans")
def list_scans(
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
    limit: int = 50,
    offset: int = 0,
):
    """List all scans for the authenticated user's organization."""
    org_id = current_user['org_id']
    # Join Scan → Asset to filter by org
    scans = (
        db.query(Scan)
        .join(Asset, Scan.asset_id == Asset.id)
        .filter(Asset.organization_id == org_id)
        .order_by(Scan.id.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    return [
        {
            "scan_id": s.id,
            "status": s.status.value,
            "tool_used": s.tool_used,
            "risk_score": s.risk_score,
            "confidence_score": s.confidence_score,
            "cross_validated": s.cross_validated,
            "evidence_links": s.evidence_links,
            "target": s.asset.target if s.asset else None,
            "started_at": s.started_at,
            "completed_at": s.completed_at,
        }
        for s in scans
    ]


@app.get("/api/assets")
def list_assets(
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """List all assets for the authenticated user's organization."""
    org_id = current_user['org_id']
    assets = db.query(Asset).filter(Asset.organization_id == org_id).all()
    return [
        {
            "asset_id": a.id,
            "target": a.target,
            "asset_type": a.asset_type,
            "discovered_at": a.discovered_at,
            "scan_count": len(a.scans),
            "last_risk_score": a.scans[-1].risk_score if a.scans else None,
        }
        for a in assets
    ]

@app.get("/api/dashboard/summary")
def dashboard_summary(
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Returns high-level stats for the dashboard overview."""
    org_id = current_user['org_id']
    assets = db.query(Asset).filter(Asset.organization_id == org_id).all()
    all_scans = (
        db.query(Scan)
        .join(Asset, Scan.asset_id == Asset.id)
        .filter(Asset.organization_id == org_id)
        .all()
    )
    risk_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for s in all_scans:
        if s.risk_score in risk_counts:
            risk_counts[s.risk_score] += 1

    return {
        "total_assets": len(assets),
        "total_scans": len(all_scans),
        "completed_scans": sum(1 for s in all_scans if s.status.value == "completed"),
        "failed_scans": sum(1 for s in all_scans if s.status.value == "failed"),
        "risk_breakdown": risk_counts,
    }

@app.post("/api/orchestrate")
def run_autonomous_goal(
    request: OrchestrationRequest,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Accepts a natural-language security goal and autonomously sequences scan tasks via LangGraph."""
    org_id = current_user['org_id']
    target_clean = request.target.strip().lower()

    if not target_clean or not request.goal:
        raise HTTPException(status_code=400, detail="Goal and target are required.")

    # 1. Initialize the Mission and Decision Log
    from datetime import datetime
    initial_log = [
        {
            "timestamp": datetime.utcnow().isoformat(),
            "action": "Objective received",
            "reason": request.goal,
            "confidence": ""
        }
    ]
    
    new_mission = Mission(
        organization_id=org_id,
        target=target_clean,
        goal=request.goal,
        decision_log=initial_log
    )
    db.add(new_mission)
    db.commit()
    db.refresh(new_mission)

    # 2. Run the LangGraph orchestrator — returns the final AgentState
    plan = orchestrator.invoke({
        "target": target_clean,
        "goal": request.goal,
        "tasks": [],
        "reasoning": "",
    })

    # New format: tasks = [{"tool": "nmap", "args": {"speed": 4, ...}}, ...]
    tasks = plan.get("tasks", [{"tool": "nmap", "args": {}}, {"tool": "subdomain", "args": {}}])
    reasoning = plan.get("reasoning", "")

    # Append Planner reasoning to Decision Log
    log_copy = list(new_mission.decision_log)
    log_copy.append({
        "timestamp": datetime.utcnow().isoformat(),
        "action": "Tasks planned by AI Orchestrator",
        "reason": reasoning,
        "confidence": ""
    })
    
    # We must explicitly update JSON columns in SQLAlchemy
    new_mission.decision_log = log_copy
    db.commit()

    dispatched_scans = []

    # 3. Dispatch each planned task as an isolated Celery job
    for task in tasks:
        tool = task.get("tool")
        tool_args = task.get("args", {})

        # Ensure the Asset exists and is scoped to this org
        asset = db.query(Asset).filter(
            Asset.target == target_clean,
            Asset.organization_id == org_id
        ).first()
        if not asset:
            asset = Asset(target=target_clean, asset_type="domain_or_ip", organization_id=org_id)
            db.add(asset)
            db.commit()
            db.refresh(asset)

        # Create a queued Scan record per tool
        new_scan = Scan(
            asset_id=asset.id,
            mission_id=new_mission.id,
            status=ScanStatus.QUEUED,
            tool_used=tool
        )
        db.add(new_scan)
        db.commit()
        db.refresh(new_scan)

        # Dispatch to Celery — now includes AI-generated args
        run_scan_job.delay(new_scan.id, target_clean, tool, tool_args)
        dispatched_scans.append({
            "scan_id": new_scan.id,
            "tool": tool,
            "args": tool_args,
            "target": target_clean,
        })

    return {
        "message": "Agentic sequence initiated",
        "goal": request.goal,
        "planner_reasoning": reasoning,
        "tasks_dispatched": len(dispatched_scans),
        "scans": dispatched_scans,
        "mission_id": new_mission.id
    }

@app.get("/api/missions")
def list_missions(
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
    limit: int = 50,
    offset: int = 0,
):
    """List all autonomous missions for the authenticated user's organization."""
    org_id = current_user['org_id']
    missions = (
        db.query(Mission)
        .filter(Mission.organization_id == org_id)
        .order_by(Mission.id.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    return [
        {
            "mission_id": m.id,
            "target": m.target,
            "goal": m.goal,
            "scan_count": len(m.scans),
            "created_at": m.created_at,
        }
        for m in missions
    ]

@app.get("/api/missions/{mission_id}")
def get_mission(
    mission_id: int, 
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Get details of a specific mission, including its decision log and child scans."""
    org_id = current_user['org_id']
    mission = db.query(Mission).filter(Mission.id == mission_id, Mission.organization_id == org_id).first()
    if not mission:
        raise HTTPException(status_code=404, detail="Mission not found")
        
    return {
        "mission_id": mission.id,
        "target": mission.target,
        "goal": mission.goal,
        "decision_log": mission.decision_log,
        "created_at": mission.created_at,
        "scans": [
            {
                "scan_id": s.id,
                "status": s.status.value,
                "tool_used": s.tool_used,
                "risk_score": s.risk_score,
                "started_at": s.started_at,
                "completed_at": s.completed_at,
            }
            for s in mission.scans
        ]
    }

@app.get("/api/tools")
def list_available_tools():
    """Returns the full tool registry with descriptions and parameter schemas."""
    import yaml
    try:
        with open("engine/tools_registry.yaml", "r") as f:
            config = yaml.safe_load(f)
        tools = []
        for name, info in config.get("tools", {}).items():
            tools.append({
                "name": name,
                "description": info.get("description", ""),
                "parameters": info.get("parameters", {}),
            })
        # Add built-in tools
        tools.insert(0, {"name": "subdomain", "description": "Native DNS subdomain enumeration", "parameters": {}})
        tools.insert(0, {"name": "nmap",      "description": "Network port scanner (dedicated plugin)", "parameters": {}})
        return {"tools": tools}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/me")
def get_current_user_profile(
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Returns the authenticated user's profile and organization info."""
    from models import User, Organization
    user = db.query(User).filter(User.id == current_user["user_id"]).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    org = db.query(Organization).filter(Organization.id == user.organization_id).first()
    return {
        "user_id": user.id,
        "email": user.email,
        "role": user.role,
        "org_id": user.organization_id,
        "org_name": org.name if org else "Unknown",
        "org_tier": org.tier if org else "enterprise",
        "created_at": user.created_at,
    }


@app.get("/api/scans/{scan_id}/response")
def get_scan_response_action(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Returns the auto-generated response action (remediation script, ticket) for a scan."""
    from models import ResponseAction
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    action = db.query(ResponseAction).filter(ResponseAction.scan_id == scan_id).first()
    if not action:
        return {"scan_id": scan_id, "status": "no_action", "message": "No response action generated (risk too low or scan not completed)."}
    
    return {
        "scan_id": scan_id,
        "status": action.status,
        "script": action.script,
        "ticket_payload": action.ticket_payload,
        "slack_notified": bool(action.slack_notified),
        "created_at": action.created_at,
    }


@app.get("/api/reports/summary")
def get_reports_summary(
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Returns analytics data for the Reports page: trends, top assets, risk distribution over time."""
    from datetime import datetime, timedelta
    from sqlalchemy import func

    org_id = current_user["org_id"]

    # --- Last 7 days daily scan volume ---
    today = datetime.utcnow().date()
    daily_trend = []
    for i in range(6, -1, -1):
        day = today - timedelta(days=i)
        day_start = datetime(day.year, day.month, day.day)
        day_end = day_start + timedelta(days=1)
        count = (
            db.query(Scan)
            .join(Asset, Scan.asset_id == Asset.id)
            .filter(
                Asset.organization_id == org_id,
                Scan.started_at >= day_start,
                Scan.started_at < day_end,
            )
            .count()
        )
        daily_trend.append({
            "date": day.strftime("%b %d"),
            "scans": count,
        })

    # --- Top 5 most-scanned assets ---
    top_assets_raw = (
        db.query(Asset.target, func.count(Scan.id).label("scan_count"))
        .join(Scan, Scan.asset_id == Asset.id)
        .filter(Asset.organization_id == org_id)
        .group_by(Asset.target)
        .order_by(func.count(Scan.id).desc())
        .limit(5)
        .all()
    )
    top_assets = [{"target": r.target, "scan_count": r.scan_count} for r in top_assets_raw]

    # --- Overall risk breakdown ---
    all_scans = (
        db.query(Scan)
        .join(Asset, Scan.asset_id == Asset.id)
        .filter(Asset.organization_id == org_id)
        .all()
    )
    risk_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    tool_counts: dict = {}
    for s in all_scans:
        if s.risk_score in risk_counts:
            risk_counts[s.risk_score] += 1
        if s.tool_used:
            tool_counts[s.tool_used] = tool_counts.get(s.tool_used, 0) + 1

    top_tools = sorted(tool_counts.items(), key=lambda x: x[1], reverse=True)[:6]

    return {
        "daily_trend": daily_trend,
        "top_assets": top_assets,
        "risk_breakdown": risk_counts,
        "top_tools": [{"tool": t, "count": c} for t, c in top_tools],
        "total_scans": len(all_scans),
        "total_assets": db.query(Asset).filter(Asset.organization_id == org_id).count(),
    }