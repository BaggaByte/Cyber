# src/orchestrator/mcp_orchestrator.py
"""
Enterprise Agentic Orchestrator — v2.0
========================================
Drives the Groq AI → MCP tool loop with:
  - scan_id threading (per-scan logging, DB persistence)
  - 5 configurable reasoning cycles
  - Resilient retry with exponential backoff on Groq rate limits
  - Findings persisted to DB as they are discovered
  - LangGraph-style AuditState dataclass for clean state management
  - GRC report saved with unique per-scan filename
"""
from __future__ import annotations

import asyncio
import json
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from groq import AsyncGroq, RateLimitError, APIStatusError
from dotenv import load_dotenv

from core.config import get_settings
from core.database import SessionLocal, ScanRecord, VulnerabilityFinding, update_scan_counts
from core.logger import stream_log, log_info, log_warning, log_error, log_critical

load_dotenv()
settings = get_settings()

groq_client = AsyncGroq(api_key=settings.groq_api_key or os.getenv("GROQ_API_KEY", ""))


# ── Audit State ───────────────────────────────────────────────
@dataclass
class AuditState:
    """Tracks the complete state of one autonomous audit run."""
    scan_id:         int
    target_url:      str
    cycle:           int                   = 0
    recon_done:      bool                  = False
    nuclei_done:     bool                  = False
    fuzzer_done:     bool                  = False
    hypothesis_done: bool                  = False
    findings:        list[dict]            = field(default_factory=list)
    audit_log:       str                   = ""
    endpoints_found: list[str]             = field(default_factory=list)
    pages_crawled:   int                   = 0
    phase:           str                   = "INITIALIZING"


# ── Tool Registry ─────────────────────────────────────────────
AVAILABLE_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "run_recon_crawl",
            "description": (
                "Phase 1: Crawls a target website using Playwright to map its full attack surface. "
                "Discovers endpoints, forms, JS-extracted API paths, tech stack fingerprint, "
                "robots.txt entries, and URL parameters. ALWAYS run this first."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target_url": {"type": "string", "description": "The root URL of the target application"},
                    "max_depth":  {"type": "integer", "description": "BFS crawl depth (default 3)", "default": 3},
                },
                "required": ["target_url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "execute_nuclei_fuzz",
            "description": (
                "Phase 2: Runs ProjectDiscovery Nuclei against the target using vulnerability templates. "
                "Best for finding known CVEs, misconfigurations, exposed panels, and common web vulnerabilities. "
                "Run after recon. Use tags like 'cves,sqli,xss,misconfig,exposure' for broad coverage."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target_url": {"type": "string"},
                    "tags": {
                        "type": "string",
                        "description": "Comma-separated Nuclei tags (e.g. 'cves,sqli,xss,misconfig,exposure')",
                    },
                },
                "required": ["target_url", "tags"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "execute_custom_fuzzer",
            "description": (
                "Phase 3: Runs an advanced Python fuzzer testing for: "
                "Blind SQLi (time-delay), Reflected XSS, SSTI, Path Traversal/LFI, "
                "Open Redirect, SSRF (reflected), and IDOR. "
                "Run this on specific high-value endpoints found during recon (login, search, API, file download pages)."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target_url": {
                        "type": "string",
                        "description": "A specific endpoint URL to fuzz, e.g. http://target.com/search?q=test",
                    },
                },
                "required": ["target_url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "generate_hypothesis",
            "description": (
                "Phase 4: Analyzes all collected findings and generates multi-step exploit chains. "
                "Use this AFTER running recon + nuclei + fuzzer to chain vulnerabilities into "
                "high-impact attack scenarios (e.g., XSS→CSRF→Account Takeover). "
                "Provide a summary of what was found."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "findings_summary": {
                        "type": "string",
                        "description": "Text summary of all confirmed and likely vulnerabilities found so far",
                    },
                    "target_url": {"type": "string"},
                },
                "required": ["findings_summary", "target_url"],
            },
        },
    },
]

SYSTEM_PROMPT = (
    "You are Nexus, an elite autonomous DevSecOps AI orchestrating a comprehensive security audit. "
    "You have access to 4 specialized tools. Execute them in this optimal order:\n\n"
    "1. run_recon_crawl — Map the full attack surface first\n"
    "2. execute_nuclei_fuzz — Run CVE/misconfiguration scans on discovered endpoints\n"
    "3. execute_custom_fuzzer — Actively fuzz the most interesting endpoints for logic vulnerabilities\n"
    "4. generate_hypothesis — Chain findings into exploit scenarios\n\n"
    "Be methodical and thorough. For the fuzzer, select the most vulnerable-looking endpoints "
    "(login pages, search forms, file handlers, API endpoints). "
    "After all tools have been executed, state 'AUDIT COMPLETE' to end the loop."
)


# ── GRC Report Generator ─────────────────────────────────────
async def generate_grc_report(state: AuditState) -> str | None:
    """Generate ISO 27001 GRC HTML report, save with scan-specific filename."""
    await log_info("Compiling Executive GRC Report...", scan_id=state.scan_id, component="GRC")

    severity_counts = {
        "critical": sum(1 for f in state.findings if f.get("severity") == "critical"),
        "high":     sum(1 for f in state.findings if f.get("severity") == "high"),
        "medium":   sum(1 for f in state.findings if f.get("severity") == "medium"),
        "low":      sum(1 for f in state.findings if f.get("severity") in ("low", "info")),
    }
    total_vulns = sum(severity_counts.values())

    system_prompt = """You are a Senior GRC (Governance, Risk, and Compliance) Security Analyst.
Generate a professional, executive-level HTML security report from the raw audit data.

CRITICAL FORMATTING RULES:
- Use inline CSS exclusively — no external stylesheets
- Dark mode: background #0a0f1a, text #e2e8f0, accent colors for severity badges
- Font: system-ui, -apple-system, sans-serif
- Include: Executive Summary, Risk Score, OWASP Top 10 mapping, ISO 27001 controls, Technical Findings table, Remediation Plan
- If 0 vulnerabilities: generate a "Certificate of Secure Posture" with green badge
- If vulnerabilities found: use red/orange severity badges in findings table
- Include a proper HTML head with title and charset
- Make it look like a Fortune 500 security audit report

OUTPUT RULE: Output ONLY raw HTML. Start with <!DOCTYPE html> and end with </html>. No markdown."""

    human_prompt = (
        f"Generate the GRC report for: {state.target_url}\n"
        f"Total vulnerabilities: {total_vulns}\n"
        f"Severity breakdown: Critical={severity_counts['critical']}, High={severity_counts['high']}, "
        f"Medium={severity_counts['medium']}, Low={severity_counts['low']}\n"
        f"Pages crawled: {state.pages_crawled}\n"
        f"Endpoints discovered: {len(state.endpoints_found)}\n\n"
        f"Raw Audit Log:\n{state.audit_log[:8000]}"
    )

    html_content = None
    try:
        response = await groq_client.chat.completions.create(
            model=settings.model_name,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": human_prompt},
            ],
            temperature=0.2,
            max_tokens=6000,
        )
        html_content = response.choices[0].message.content.strip()

        # Strip markdown fences if AI disobeyed
        if html_content.startswith("```html"):
            html_content = html_content[7:]
            if html_content.endswith("```"):
                html_content = html_content[:-3]
        elif html_content.startswith("```"):
            html_content = html_content[3:]
            if html_content.endswith("```"):
                html_content = html_content[:-3]
        html_content = html_content.strip()

    except Exception as e:
        await log_error(f"AI report generation failed: {e}", scan_id=state.scan_id, component="GRC")
        await log_warning("Generating fallback HTML report...", scan_id=state.scan_id, component="GRC")

        status_color = "#ef4444" if total_vulns > 0 else "#22c55e"
        status_text  = f"CRITICAL — {total_vulns} VULNERABILITIES FOUND" if total_vulns > 0 else "PASSED / SECURE"

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Nexus GRC Report — {state.target_url}</title></head>
<body style="background:#0a0f1a;color:#e2e8f0;font-family:system-ui,sans-serif;padding:40px;">
<div style="max-width:900px;margin:0 auto;">
  <h1 style="color:#38bdf8;margin-bottom:8px;">⚡ Nexus AI — Executive GRC Report</h1>
  <p style="color:#64748b;margin-bottom:32px;">Scan #{state.scan_id} | Target: {state.target_url}</p>
  <div style="background:{status_color};color:#fff;padding:16px 24px;border-radius:8px;font-weight:bold;font-size:18px;margin-bottom:32px;">
    STATUS: {status_text}
  </div>
  <h2 style="color:#94a3b8;">Severity Summary</h2>
  <table style="width:100%;border-collapse:collapse;margin-bottom:32px;">
    <tr style="background:#1e293b;">
      <th style="padding:12px;text-align:left;border:1px solid #334155;">Severity</th>
      <th style="padding:12px;text-align:center;border:1px solid #334155;">Count</th>
    </tr>
    <tr><td style="padding:12px;border:1px solid #334155;color:#ef4444;">Critical</td><td style="padding:12px;text-align:center;border:1px solid #334155;">{severity_counts['critical']}</td></tr>
    <tr><td style="padding:12px;border:1px solid #334155;color:#f97316;">High</td><td style="padding:12px;text-align:center;border:1px solid #334155;">{severity_counts['high']}</td></tr>
    <tr><td style="padding:12px;border:1px solid #334155;color:#eab308;">Medium</td><td style="padding:12px;text-align:center;border:1px solid #334155;">{severity_counts['medium']}</td></tr>
    <tr><td style="padding:12px;border:1px solid #334155;color:#22c55e;">Low</td><td style="padding:12px;text-align:center;border:1px solid #334155;">{severity_counts['low']}</td></tr>
  </table>
  <h2 style="color:#94a3b8;">Raw Audit Log</h2>
  <pre style="background:#1e293b;padding:20px;border-radius:8px;overflow-x:auto;white-space:pre-wrap;font-size:12px;">{state.audit_log[:4000]}</pre>
</div>
</body>
</html>"""

    # Save with unique scan-specific filename
    timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"Nexus_GRC_Report_{timestamp_str}_scan{state.scan_id}.html"

    base_dir = Path(__file__).resolve().parent.parent.parent
    report_dir = base_dir / "src"
    report_dir.mkdir(parents=True, exist_ok=True)
    report_path = report_dir / filename

    with open(report_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    # Also copy to frontend/public for direct serving
    public_dir = base_dir / "frontend" / "public"
    public_dir.mkdir(parents=True, exist_ok=True)
    public_path = public_dir / filename
    with open(public_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    await log_info(f"GRC Report saved -> {filename}", scan_id=state.scan_id, component="GRC")
    return str(report_path)


# ── Tool Executor ─────────────────────────────────────────────
async def _execute_tool(function_name: str, function_args: dict, state: AuditState) -> str:
    """Execute an MCP tool and return its string result."""
    try:
        if function_name == "run_recon_crawl":
            from mcp_server import run_recon_crawl
            result = await run_recon_crawl(
                function_args.get("target_url"),
                function_args.get("max_depth", settings.recon_max_depth),
                scan_id=state.scan_id,
            )
            state.recon_done = True

        elif function_name == "execute_nuclei_fuzz":
            from mcp_server import execute_nuclei_fuzz
            result = await execute_nuclei_fuzz(
                function_args.get("target_url"),
                function_args.get("tags", "cves,vuln,misconfig,exposure"),
                scan_id=state.scan_id,
            )
            state.nuclei_done = True

        elif function_name == "execute_custom_fuzzer":
            from mcp_server import execute_custom_fuzzer
            extra = json.dumps(state.endpoints_found[:20]) if state.endpoints_found else None
            result = await execute_custom_fuzzer(
                function_args.get("target_url"),
                scan_id=state.scan_id,
                extra_urls=extra,
            )
            state.fuzzer_done = True

        elif function_name == "generate_hypothesis":
            from mcp_server import generate_hypothesis
            result = await generate_hypothesis(
                function_args.get("findings_summary", ""),
                function_args.get("target_url", state.target_url),
            )
            state.hypothesis_done = True

        else:
            result = f"Unknown tool: {function_name}"

    except Exception as e:
        result = f"Tool execution error [{function_name}]: {type(e).__name__}: {e}"
        await log_error(result, scan_id=state.scan_id, component="MCP")

    return str(result)


# ── AI Call with Retry ────────────────────────────────────────
async def _call_groq_with_retry(messages: list, max_retries: int = 3):
    """Call Groq API with exponential backoff on rate limit errors."""
    for attempt in range(max_retries):
        try:
            response = await groq_client.chat.completions.create(
                model=settings.model_name,
                messages=messages,
                tools=AVAILABLE_TOOLS,
                tool_choice="auto",
                temperature=settings.ai_temperature,
                max_tokens=settings.ai_max_tokens,
            )
            return response
        except RateLimitError:
            wait_time = (2 ** attempt) * 5  # 5s, 10s, 20s
            if attempt < max_retries - 1:
                await asyncio.sleep(wait_time)
            else:
                raise
        except APIStatusError as e:
            if e.status_code >= 500 and attempt < max_retries - 1:
                await asyncio.sleep(2 ** attempt)
            else:
                raise


# ── Findings Persister ────────────────────────────────────────
def _persist_findings_from_log(audit_log: str, scan_id: int) -> None:
    """Fallback: extract vulnerability findings from tool output text."""
    db = SessionLocal()
    try:
        existing = {
            f.vuln_name
            for f in db.query(VulnerabilityFinding).filter(VulnerabilityFinding.scan_id == scan_id).all()
        }
        lines = audit_log.split("\n")
        i = 0
        while i < len(lines):
            line = lines[i]
            is_vuln_line = (
                "🔴 VULNERABLE" in line
                or "CRITICAL FINDING:" in line
                or "✅ [CRITICAL]" in line
                or "✅ [HIGH]" in line
            )
            if is_vuln_line:
                severity = "medium"
                upper = line.upper()
                if "CRITICAL" in upper:
                    severity = "critical"
                elif "HIGH" in upper:
                    severity = "high"
                elif "LOW" in upper:
                    severity = "low"

                if "🔴 VULNERABLE" in line:
                    parts = line.split("]", 1)
                    vuln_name = parts[-1].strip() if len(parts) > 1 else line.strip()
                elif "CRITICAL FINDING:" in line:
                    vuln_name = line.split("CRITICAL FINDING:")[-1].strip()
                else:
                    vuln_name = line.strip()

                payload = ""
                endpoint = ""
                cwe = None
                for j in range(i + 1, min(i + 6, len(lines))):
                    if "Payload:" in lines[j]:
                        payload = lines[j].split("Payload:")[-1].strip()
                    if "CWE:" in lines[j]:
                        cwe = lines[j].split("CWE:")[-1].strip()
                    if lines[j].strip().startswith("http"):
                        endpoint = lines[j].strip()

                key = vuln_name[:255]
                if key and key not in existing:
                    db.add(VulnerabilityFinding(
                        scan_id=scan_id,
                        vuln_name=key,
                        cwe=cwe,
                        severity=severity,
                        confidence="confirmed",
                        endpoint=endpoint[:2047] if endpoint else "unknown",
                        payload_used=payload[:2000] if payload else None,
                        source="custom_fuzzer",
                    ))
                    existing.add(key)
            i += 1
        db.commit()
        update_scan_counts(db, scan_id)
    except Exception:
        db.rollback()
    finally:
        db.close()


# ── Main Agentic Loop ─────────────────────────────────────────
async def run_enterprise_audit(target_url: str, scan_id: int = 0) -> bool:
    """
    The main autonomous AI audit loop.
    Runs for up to settings.max_agent_cycles reasoning cycles.
    """
    state = AuditState(scan_id=scan_id, target_url=target_url)

    await log_info(f"Initializing Groq AI Brain ({settings.model_name})...", scan_id=scan_id, component="ORCHESTRATOR")
    await log_info(f"Target locked: {target_url}", scan_id=scan_id, component="ORCHESTRATOR")
    await log_info(f"Max cycles: {settings.max_agent_cycles} | Tools: {len(AVAILABLE_TOOLS)}", scan_id=scan_id, component="ORCHESTRATOR")

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": f"Begin the full security audit on: {target_url}"},
    ]

    # ── Update DB phase ───────────────────────────────────────
    db = SessionLocal()
    try:
        scan = db.query(ScanRecord).filter(ScanRecord.id == scan_id).first()
        if scan:
            scan.current_phase = "RECON"
            scan.progress_pct = 5
            db.commit()
    finally:
        db.close()

    for cycle in range(settings.max_agent_cycles):
        state.cycle = cycle + 1
        await log_info(
            f"AI Reasoning Cycle {state.cycle}/{settings.max_agent_cycles}...",
            scan_id=scan_id,
            component="ORCHESTRATOR",
        )

        try:
            response = await _call_groq_with_retry(messages)
        except Exception as e:
            await log_error(f"Groq API failed after retries: {e}", scan_id=scan_id, component="ORCHESTRATOR")
            break

        response_message = response.choices[0].message

        # Serialize for the messages list (Groq API objects aren't JSON-serializable directly)
        msg_dict = {"role": "assistant", "content": response_message.content or ""}
        if response_message.tool_calls:
            msg_dict["tool_calls"] = [
                {
                    "id": tc.id,
                    "type": "function",
                    "function": {"name": tc.function.name, "arguments": tc.function.arguments},
                }
                for tc in response_message.tool_calls
            ]
        messages.append(msg_dict)

        tool_calls = response_message.tool_calls

        if not tool_calls:
            content = response_message.content or ""
            if "AUDIT COMPLETE" in content or cycle == settings.max_agent_cycles - 1:
                await log_info("AI signaled audit completion.", scan_id=scan_id, component="ORCHESTRATOR")
            else:
                await log_info(f"AI: {content[:300]}", scan_id=scan_id, component="ORCHESTRATOR")
            break

        for tool_call in tool_calls:
            function_name = tool_call.function.name
            try:
                function_args = json.loads(tool_call.function.arguments)
            except json.JSONDecodeError:
                function_args = {}

            await log_info(
                f"Tool invoked: {function_name}({json.dumps({k: str(v)[:80] for k, v in function_args.items()})})",
                scan_id=scan_id,
                component="MCP",
            )
            state.audit_log += f"\nACTION: {function_name} on {function_args.get('target_url', target_url)}\n"

            # Update progress
            phase_map = {
                "run_recon_crawl":    ("RECON",       25),
                "execute_nuclei_fuzz":("NUCLEI_SCAN", 50),
                "execute_custom_fuzzer": ("FUZZING",  75),
                "generate_hypothesis":("HYPOTHESIS",  90),
            }
            if function_name in phase_map:
                phase, pct = phase_map[function_name]
                db2 = SessionLocal()
                try:
                    s = db2.query(ScanRecord).filter(ScanRecord.id == scan_id).first()
                    if s:
                        s.current_phase = phase
                        s.progress_pct = pct
                        db2.commit()
                finally:
                    db2.close()

            tool_result = await _execute_tool(function_name, function_args, state)

            # Truncate extremely long outputs to avoid Groq token overflow
            if len(tool_result) > 5000:
                tool_result = tool_result[:5000] + "\n...[OUTPUT TRUNCATED — see full logs]"

            state.audit_log += f"RESULT:\n{tool_result}\n"

            # Parse recon results for endpoint count
            if function_name == "run_recon_crawl":
                try:
                    recon_data = json.loads(tool_result)
                    state.endpoints_found = [e.get("url", "") for e in recon_data.get("endpoints", [])]
                    state.pages_crawled   = recon_data.get("pages_crawled", 0)
                except Exception:
                    pass

            await log_info(f"Tool '{function_name}' completed.", scan_id=scan_id, component="MCP")

            messages.append({
                "tool_call_id": tool_call.id,
                "role":         "tool",
                "name":         function_name,
                "content":      tool_result,
            })

        # Check for natural completion
        if state.recon_done and state.nuclei_done and state.fuzzer_done and state.hypothesis_done:
            await log_info("All 4 phases complete. Ending agentic loop.", scan_id=scan_id, component="ORCHESTRATOR")
            break

    # ── GRC Report ────────────────────────────────────────────
    await log_info("Attack loops concluded. Generating GRC Report...", scan_id=scan_id, component="ORCHESTRATOR")
    _persist_findings_from_log(state.audit_log, scan_id)

    # Load persisted findings for accurate GRC severity counts
    db_findings = SessionLocal()
    try:
        rows = (
            db_findings.query(VulnerabilityFinding)
            .filter(VulnerabilityFinding.scan_id == scan_id, VulnerabilityFinding.is_false_positive == False)
            .all()
        )
        state.findings = [f.to_dict() for f in rows]
    finally:
        db_findings.close()

    report_path = await generate_grc_report(state)

    if report_path:
        db3 = SessionLocal()
        try:
            scan = db3.query(ScanRecord).filter(ScanRecord.id == scan_id).first()
            if scan:
                scan.report_path     = report_path
                scan.report_filename = Path(report_path).name
                scan.pages_crawled   = state.pages_crawled
                scan.endpoints_found = len(state.endpoints_found)
                db3.commit()
        finally:
            db3.close()

    await log_info("Audit Cycle Completed.", scan_id=scan_id, component="ORCHESTRATOR")
    return True


if __name__ == "__main__":
    asyncio.run(run_enterprise_audit("http://demo.testfire.net/", scan_id=0))