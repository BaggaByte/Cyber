import sys
import os
import asyncio
import json
import uuid
import requests

# Ensure the 'src' directory is in the Python path so local modules resolve correctly
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

import uvicorn
from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Top-level imports for async scanning pipeline and patch verification
from agents.analyzer import verify_groq_connectivity
from critic import evaluate_finding_async
from orchestrator.swarm import execute_swarm
from core.database import init_db, save_scan_record, get_scan_history, get_scan_findings

# Initialize FastAPI application
app = FastAPI(
    title="Aegis AI Security Command Center",
    description="REST API interface for static code review and automated AI patching.",
    version="2.0.0"
)

# Enable CORS so the local frontend can communicate with the backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory job tracking
SCAN_JOBS = {}

class ScanRequest(BaseModel):
    target_path: str
    model: str = "qwen2.5-coder:7b"

@app.on_event("startup")
async def startup_event():
    """Initialize database on server startup."""
    init_db()

@app.post("/api/scan")
async def trigger_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """
    Triggers the static Semgrep scan + LangGraph swarm review
    for a local path in the container.
    """
    target = request.target_path.strip()
    # Force use of 7b model to prevent hallucination issues from older UI state
    model = "qwen2.5-coder:7b"
    
    # Skip Docker path translation if running locally
    if os.name == 'nt' or not os.path.exists('/.dockerenv'):
        target = request.target_path
    else:
        # Automatically map host Windows paths pointing to demo_code to the container mounted path
        norm_target = target.replace("\\", "/").rstrip("/")
        if "demo_code" in norm_target:
            target = "/app/demo_code"
            print(f"[PATH TRANSLATOR] Auto-mapped '{request.target_path}' to container workspace path '{target}'")
    
    # Resolve API URL
    api_url = "https://api.groq.com/openai/v1"
    
    # Check if directory exists
    from pathlib import Path
    path = Path(target).resolve()
    if not path.exists():
        raise HTTPException(
            status_code=400,
            detail=f"Target path '{target}' does not exist inside the container workspace."
        )
    
    job_id = str(uuid.uuid4())
    
    # Queued state
    SCAN_JOBS[job_id] = {
        "status": "queued",
        "target": target,
        "findings": [],
        "attack_surface": {},
        "error": None
    }
    
    # Kick off background task
    background_tasks.add_task(run_async_scan, job_id, target, model, api_url, 600)
    
    return {
        "status": "queued",
        "job_id": job_id,
        "target": target
    }

@app.get("/api/scan/{job_id}")
async def get_scan_status(job_id: str):
    """Retrieves status and findings of a specific scan job."""
    if job_id in SCAN_JOBS:
        return SCAN_JOBS[job_id]
        
    # Check SQLite database for saved findings
    findings = get_scan_findings(job_id)
    if findings is not None:
        history = get_scan_history()
        target = "Unknown Target"
        for item in history:
            if item["job_id"] == job_id:
                target = item["target"]
                break
        return {
            "status": "completed",
            "target": target,
            "findings": findings,
            "attack_surface": {},
            "error": None
        }
        
    raise HTTPException(status_code=404, detail="Scan job not found.")

@app.get("/api/history")
async def get_history():
    """Retrieves all past scans from the persistent database."""
    try:
        history = get_scan_history()
        return {"status": "success", "history": history}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database retrieval failed: {str(e)}")

@app.get("/api/models")
async def get_models():
    """Returns available Groq models for selection."""
    return {"status": "success", "models": ["GPT-OSS 120B", "llama3-8b-8192", "mixtral-8x7b-32768", "gemma2-9b-it"]}


# ==============================================================
# Helper Functions and Async Scanning Pipeline
# ==============================================================

def get_grc_frameworks(cwe: str) -> dict:
    cwe_upper = str(cwe).upper()
    if "256" in cwe_upper:
        return {
            "owasp": "A02:2021 - Cryptographic Failures",
            "soc2": "CC6.1 (Logical Access)"
        }
    elif "798" in cwe_upper or "259" in cwe_upper:
        return {
            "owasp": "A07:2021 - Auth Failures",
            "soc2": "CC6.1 (Logical Access)"
        }
    elif "489" in cwe_upper or "209" in cwe_upper:
        return {
            "owasp": "A05:2021 - Security Misconfiguration",
            "soc2": "CC7.1 (Vulnerability Management)"
        }
    elif "89" in cwe_upper or "79" in cwe_upper or "injection" in cwe_upper.lower():
        return {
            "owasp": "A03:2021 - Injection",
            "soc2": "CC7.1 (Vulnerability Management)"
        }
    else:
        return {
            "owasp": "A03:2021 - Injection",
            "soc2": "CC7.1 (Vulnerability Management)"
        }

def extract_lines(filepath: str, start_line: int, end_line: int) -> str:
    if not filepath:
        return ""
    try:
        clean_path = filepath.replace("\\", "/").strip()
        if clean_path.startswith("./"):
            clean_path = clean_path[2:]
        from pathlib import Path
        path = Path(clean_path).resolve()
        if not (path.exists() and path.is_file()):
            if clean_path.startswith("/"):
                docker_path = clean_path if clean_path.startswith("/app/") else "/app/" + clean_path.lstrip("/")
            else:
                docker_path = "/" + clean_path if clean_path.startswith("app/") else "/app/" + clean_path
            path = Path(docker_path).resolve()
        
        if path.exists() and path.is_file():
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
            start_idx = max(0, start_line - 1)
            end_idx = min(len(lines), end_line)
            return "".join(lines[start_idx:end_idx])
    except Exception:
        pass
    return ""

async def map_attack_surface(target_path: str) -> dict:
    # Basic path-based surface mapping for codebases
    from pathlib import Path
    path = Path(target_path).resolve()
    files = []
    if path.exists():
        if path.is_file():
            files.append(str(path))
        elif path.is_dir():
            for root, _, filenames in os.walk(path):
                for f in filenames:
                    if f.endswith(('.py', '.js', '.java', '.go')):
                        files.append(str(Path(root) / f))
    return {
        "files_found": len(files),
        "target": target_path,
        "files": files[:100]  # limit payload size
    }

async def run_semgrep(target_path: str) -> list:
    import shutil
    if not shutil.which("semgrep"):
        print("  [!] WARNING: 'semgrep' binary not found in system PATH.")
        return []
    cmd = ["semgrep", "--config=auto", "--json", target_path]
    try:
        import os
        if os.name == 'nt':
            process = await asyncio.create_subprocess_shell(
                f'semgrep --config=auto --json "{target_path}"',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
        else:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
        stdout, stderr = await process.communicate()
        if stdout:
            data = json.loads(stdout.decode('utf-8', errors='replace'))
            return data.get("results", [])
    except Exception as e:
        print(f"  [-] Semgrep Execution Failed: {str(e)}")
    return []

async def run_async_scan(job_id: str, target: str, model: str, url: str, timeout: int):
    SCAN_JOBS[job_id]["status"] = "running"
    try:
        surface = await map_attack_surface(target)
        SCAN_JOBS[job_id]["attack_surface"] = surface
        
        # 1. Run Semgrep static analysis
        raw_findings = await run_semgrep(target)
        findings = []
        
        # Always run custom Regex Pre-Scan to catch specific weak points missing from default Semgrep rules
        import re
        for file_path in surface.get("files", []):
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                for i, line in enumerate(lines):
                    if re.search(r'password123', line, re.IGNORECASE):
                        findings.append({
                            "severity": "CRITICAL",
                            "cwe": "CWE-798",
                            "title": "Hardcoded Credentials",
                            "description": "Hardcoding credentials in source code exposes them to attackers. Use environment variables instead.",
                            "file": file_path,
                            "line": i + 1,
                            "originalCode": extract_lines(file_path, i, i + 2),
                            "fixedCode": "import os\ndb_pass = os.getenv('DB_PASSWORD')",
                            "compliance": get_grc_frameworks("CWE-798")
                        })
                        findings.append({
                            "severity": "HIGH",
                            "cwe": "CWE-256",
                            "title": "Plaintext Storage of Passwords",
                            "description": "The hardcoded password is being inserted in plaintext. It should be hashed.",
                            "file": file_path,
                            "line": i + 1,
                            "originalCode": extract_lines(file_path, i, i + 2),
                            "fixedCode": "password_hash = hash_password(db_pass)",
                            "compliance": get_grc_frameworks("CWE-256")
                        })
                    if re.search(r'debug\s*=\s*True', line):
                        findings.append({
                            "severity": "CRITICAL",
                            "cwe": "CWE-489",
                            "title": "Active Debug Code",
                            "description": "Running the application in debug mode allows attackers to access interactive tracebacks and execute arbitrary code.",
                            "file": file_path,
                            "line": i + 1,
                            "originalCode": extract_lines(file_path, i, i + 2),
                            "fixedCode": "app.run(debug=False)",
                            "compliance": get_grc_frameworks("CWE-489")
                        })
                    if re.search(r'password\s+TEXT', line, re.IGNORECASE):
                        findings.append({
                            "severity": "CRITICAL",
                            "cwe": "CWE-256",
                            "title": "Plaintext Storage of Passwords",
                            "description": "Storing passwords in plaintext allows full account compromise if the database is leaked. Use strong hashing algorithms like Argon2 or bcrypt.",
                            "file": file_path,
                            "line": i + 1,
                            "originalCode": extract_lines(file_path, i + 1, i + 4),
                            "fixedCode": line.replace("password TEXT", "password_hash TEXT"),
                            "compliance": get_grc_frameworks("CWE-256")
                        })
                    if re.search(r'str\(e\)', line) and 'error' in line.lower():
                        findings.append({
                            "severity": "MEDIUM",
                            "cwe": "CWE-209",
                            "title": "Information Exposure Through Error Messages",
                            "description": "Returning raw exception strings to the client exposes internal implementation details, file paths, or SQL syntax.",
                            "file": file_path,
                            "line": i + 1,
                            "originalCode": extract_lines(file_path, i + 1, i + 3),
                            "fixedCode": line.replace("str(e)", '"An internal server error occurred."'),
                            "compliance": get_grc_frameworks("CWE-209")
                        })
            except Exception:
                pass
        
        # Check if Groq API is connected
        connected = verify_groq_connectivity()
        if connected:
            # 2. Run LangGraph review swarm to audit vulnerabilities and generate code patches
            if raw_findings:
                swarm_findings = await execute_swarm(job_id, raw_findings, url, model)
                findings.extend(swarm_findings)
            else:
                # 2.b AI-only fallback: Semgrep found nothing, but let's scan directly
                print("[!] Semgrep returned 0 findings. Executing direct AI fallback analysis...")
                from agents.analyzer import analyze_code
                for file_path in surface.get("files", []):
                    content = extract_lines(file_path, 1, 999999) # Get full file safely
                    if content and len(content) < 50000: # Protect against massive files
                        file_findings = analyze_code(file_path, content, url, model, timeout=timeout)
                        if isinstance(file_findings, list):
                            for finding in file_findings:
                                # Standardize format
                                if not finding.get("file"):
                                    finding["file"] = file_path
                                
                                # Safely parse the line number, as the AI might return a string like "41" or "line 41"
                                raw_line = str(finding.get("line", 1))
                                import re
                                match = re.search(r'\d+', raw_line)
                                line_num = int(match.group()) if match else 1
                                
                                # Use AI provided code if available, otherwise extract it based on line number
                                finding["originalCode"] = finding.get("originalCode") or extract_lines(file_path, line_num, line_num + 10)
                                finding["fixedCode"] = finding.get("fixedCode") or "Manual remediation required."
                                finding["compliance"] = get_grc_frameworks(finding.get("cwe", "CWE-Unknown"))
                                finding["title"] = f"AI Discovered: {finding.get('description', 'Vulnerability')[:20]}"
                                findings.append(finding)
        else:
            # Fallback: Map Semgrep raw findings directly without AI critic review
            print("[!] Groq API is offline or key is invalid. Falling back to raw Semgrep findings without AI remediation.")
            findings = []
            for finding in raw_findings:
                cwe_list = finding.get("extra", {}).get("metadata", {}).get("cwe", [""])
                cwe = cwe_list[0] if isinstance(cwe_list, list) and cwe_list else "CWE-Unknown"
                
                raw_severity = finding.get("extra", {}).get("severity", "WARNING")
                severity_map = {"ERROR": "CRITICAL", "WARNING": "MEDIUM", "INFO": "LOW"}
                severity = severity_map.get(raw_severity, "LOW")
                
                filepath = finding.get("path", "Unknown")
                lines = finding.get("extra", {}).get("lines", "")
                line_number = finding.get("start", {}).get("line", 1)
                end_line = finding.get("end", {}).get("line", line_number)
                
                if not lines or lines == "requires login":
                    lines = extract_lines(filepath, line_number, end_line)
                
                findings.append({
                    "severity": severity,
                    "file": filepath,
                    "line": line_number,
                    "cwe": cwe,
                    "title": finding.get("extra", {}).get("message", "Vulnerability").split(".")[0],
                    "description": f"**[Groq Offline]** Bypassed AI verification. Raw Semgrep description: {finding.get('extra', {}).get('message')}",
                    "originalCode": lines,
                    "fixedCode": f"# Groq API was unreachable. AI patch remediation was bypassed.\n# Original code:\n{lines}",
                    "compliance": get_grc_frameworks(cwe),
                    "pr_title": f"Security Patch: Fix {cwe}",
                    "pr_description": "Groq API was unreachable during verification."
                })
        
        # 3. Store findings
        SCAN_JOBS[job_id]["findings"] = findings
        SCAN_JOBS[job_id]["status"] = "completed"
        
        # 4. Save to ChromaDB history
        save_scan_record(job_id, target, findings)
        print(f"[+] Scan job {job_id} successfully completed and saved.")
        
    except Exception as e:
        SCAN_JOBS[job_id]["status"] = "failed"
        SCAN_JOBS[job_id]["error"] = str(e)
        print(f"[-] Async scan job {job_id} failed: {e}")

if __name__ == "__main__":
    uvicorn.run("src.main:app", host="127.0.0.1", port=8001, reload=True)