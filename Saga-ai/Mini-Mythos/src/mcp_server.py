# src/mcp_server.py
"""
Nexus AI — MCP Tool Server v2.0
=================================
Exposes 5 tools to the Groq AI brain:
  1. run_recon_crawl          — BFS web crawler + tech fingerprinting
  2. execute_nuclei_fuzz      — Nuclei CVE/misconfiguration scanner
  3. execute_custom_fuzzer    — 7-module logic vulnerability fuzzer
  4. generate_hypothesis      — AI-driven exploit chain analysis
  5. check_security_headers   — Dedicated HTTP security header audit
"""
from __future__ import annotations

import asyncio
import json
import subprocess
from pathlib import Path
from typing import Optional

from mcp.server.fastmcp import FastMCP

# Import scanning engines (FIXED: use correct function names)
from agents.recon_agent import active_recon_engine, ReconConfig
from agents.exploit_runner import run_full_scan, ScanConfig
from core.config import get_settings
from core.findings_store import persist_fuzz_results, persist_nuclei_findings
from core.logger import stream_log

settings = get_settings()
mcp = FastMCP("Nexus-Offensive-Suite")


# ══════════════════════════════════════════════════════════════
# TOOL 1: RECON CRAWLER
# ══════════════════════════════════════════════════════════════
@mcp.tool()
async def run_recon_crawl(
    target_url: str,
    max_depth: int = 3,
    scan_id: Optional[int] = None,
) -> str:
    """
    Phase 1: Multi-depth BFS web crawler with Playwright rendering.
    Discovers: endpoints, forms, JS API paths, robots.txt, sitemap.xml,
    tech stack fingerprint (WAF, framework, server, CMS, JS libs),
    CORS misconfigurations, and missing security headers.
    Always run this FIRST before any fuzzing.
    Returns a JSON string with the full AppModel.
    """
    # Validate URL
    if not target_url.startswith(("http://", "https://")):
        return json.dumps({"error": "target_url must start with http:// or https://"})

    try:
        cfg = ReconConfig(
            max_depth=min(max_depth, 5),
            max_pages=settings.recon_max_pages,
            rate_limit_rps=settings.recon_rate_limit_rps,
            timeout=settings.fuzzer_timeout,
            crawl_js_files=True,
            check_robots=True,
            check_sitemap=True,
            api_wordlist=True,
            export_json=False,
        )
        app_model = await active_recon_engine(target_url=target_url, cfg=cfg)
        result_dict = app_model.to_dict()

        # Truncate large lists to keep token count manageable for the LLM
        result_dict["endpoints"] = result_dict["endpoints"][:50]
        result_dict["js_endpoints"] = result_dict["js_endpoints"][:20]
        result_dict["sitemap_urls"] = result_dict["sitemap_urls"][:20]

        return json.dumps(result_dict, indent=2, default=str)

    except Exception as e:
        return json.dumps({"error": f"Recon engine failed: {type(e).__name__}: {e}"})


# ══════════════════════════════════════════════════════════════
# TOOL 2: NUCLEI SCANNER
# ══════════════════════════════════════════════════════════════
@mcp.tool()
async def execute_nuclei_fuzz(target_url: str, tags: str = "cves,sqli,xss,misconfig", scan_id: Optional[int] = None) -> str:
    """
    Phase 2: ProjectDiscovery Nuclei template scanner.
    Tests for known CVEs, SQL injection, XSS, misconfigurations, and exposed admin panels.
    Best tags: cves, sqli, xss, misconfig, exposure, rce, lfi, ssrf, xxe
    Run after recon to scan the full target with broad template coverage.
    """
    if not target_url.startswith(("http://", "https://")):
        return "Error: target_url must start with http:// or https://"

    # Sanitize tags (only allow alphanumeric and commas)
    safe_tags = ",".join(
        t.strip() for t in tags.split(",")
        if t.strip().replace("-", "").replace("_", "").isalnum()
    )

    CURRENT_DIR = Path(__file__).resolve().parent
    nuclei_exe = CURRENT_DIR / "nuclei.exe"

    if not nuclei_exe.exists():
        return f"[ERROR] nuclei.exe not found at {nuclei_exe}. Download from: https://github.com/projectdiscovery/nuclei/releases"

    try:
        # Use async subprocess so the event loop is NOT blocked while Nuclei runs.
        # subprocess.run() is synchronous and freezes the entire FastAPI server.
        proc = await asyncio.create_subprocess_exec(
            str(nuclei_exe),
            "-u", target_url,
            "-tags", safe_tags,
            "-jsonl",
            "-silent",
            "-timeout", "10",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(), timeout=300  # 5 min max
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return "Nuclei scan timed out after 5 minutes."

        stdout = stdout_bytes.decode("utf-8", errors="ignore")
        stderr = stderr_bytes.decode("utf-8", errors="ignore")

        if stdout.strip():
            lines = stdout.strip().split("\n")
            findings = []
            for line in lines[:30]:  # Cap at 30 findings
                try:
                    finding = json.loads(line)
                    findings.append({
                        "template": finding.get("template-id", "unknown"),
                        "severity": finding.get("info", {}).get("severity", "unknown"),
                        "name":     finding.get("info", {}).get("name", "Unknown"),
                        "matched":  finding.get("matched-at", target_url),
                        "type":     finding.get("type", "unknown"),
                    })
                except json.JSONDecodeError:
                    findings.append({"raw": line[:200]})

            if findings:
                if scan_id:
                    persist_nuclei_findings(scan_id, findings)
                return f"Nuclei found {len(findings)} findings:\n{json.dumps(findings, indent=2)}"
            return "Nuclei scan completed with 0 template matches."

        elif stderr.strip():
            return f"Nuclei stderr: {stderr.strip()[:500]}"
        else:
            return "Nuclei scan completed with 0 findings."

    except Exception as e:
        return f"Critical error executing Nuclei: {type(e).__name__}: {e}"


# ══════════════════════════════════════════════════════════════
# TOOL 3: CUSTOM FUZZER
# ══════════════════════════════════════════════════════════════
@mcp.tool()
async def execute_custom_fuzzer(
    target_url: str,
    scan_id: Optional[int] = None,
    extra_urls: Optional[str] = None,
) -> str:
    """
    Phase 3: Advanced Python logic fuzzer.
    Tests for: Error-based SQLi, Blind/Time-based SQLi, Reflected XSS,
    Server-Side Template Injection (SSTI), Path Traversal/LFI,
    Open Redirect, and Server-Side Request Forgery (SSRF).
    Run on specific endpoints: login pages, search forms, file handlers, API routes.
    """
    if not target_url.startswith(("http://", "https://")):
        return "Error: target_url must start with http:// or https://"

    try:
        cfg = ScanConfig(
            timeout=settings.fuzzer_timeout,
            max_retries=settings.fuzzer_max_retries,
            rate_limit_rps=5.0,
            parallel_vectors=True,
            export_json=False,
        )

        additional = []
        if extra_urls:
            try:
                additional = json.loads(extra_urls) if extra_urls.startswith("[") else [u.strip() for u in extra_urls.split(",") if u.strip()]
            except json.JSONDecodeError:
                additional = [u.strip() for u in extra_urls.split(",") if u.strip()]

        results = await run_full_scan(target_url, config=cfg, extra_urls=additional)

        if not results:
            return "Custom fuzzer returned no results — target may be unreachable."

        saved = persist_fuzz_results(scan_id, results, source="custom_fuzzer")

        output_lines = [f"Custom Fuzzer Results for: {target_url}", "=" * 50]
        vulns_found = 0

        for r in results:
            icon = "🔴 VULNERABLE" if r.is_vulnerable else "✅ CLEAN"
            output_lines.append(f"\n{icon} [{r.severity.upper()}] {r.vuln_name}")
            output_lines.append(f"   CWE: {r.cwe}")
            output_lines.append(f"   Confidence: {r.confidence}")

            if r.is_vulnerable:
                vulns_found += 1
                output_lines.append(f"   Payload: {r.payload_used[:200]}")
                output_lines.append(f"   Notes: {r.notes[:300]}")

        summary = (
            f"\n{'='*50}\n"
            f"SUMMARY: {vulns_found} vulnerabilities found out of {len(results)} tests."
        )
        if saved:
            summary += f"\nPersisted {saved} finding(s) to database (scan #{scan_id})."
        output_lines.append(summary)

        return "\n".join(output_lines)

    except Exception as e:
        return f"Critical Error in Custom Fuzzer: {type(e).__name__}: {e}"


# ══════════════════════════════════════════════════════════════
# TOOL 4: HYPOTHESIS ENGINE
# ══════════════════════════════════════════════════════════════
@mcp.tool()
async def generate_hypothesis(findings_summary: str, target_url: str) -> str:
    """
    Phase 4: AI-powered exploit chain analysis.
    Takes all confirmed/likely findings and generates multi-step attack scenarios.
    Shows how individual vulnerabilities can be chained for maximum impact
    (e.g., XSS + CSRF = Account Takeover, SQLi + LFI = Data Exfiltration).
    Use this LAST, after all scanning phases are complete.
    """
    from groq import AsyncGroq

    client = AsyncGroq(api_key=settings.groq_api_key or "")

    system_prompt = """You are a Principal Security Researcher at a top-tier offensive security firm.
Given a list of vulnerability findings, generate:
1. Multi-step exploit chain scenarios (e.g., XSS → Cookie Theft → Session Hijack)
2. Business impact assessment (data breach risk, GDPR exposure, availability risk)
3. CVSS v3.1 score estimates for each chain
4. Prioritized remediation roadmap

Be specific, technical, and actionable. Format as structured text."""

    user_prompt = f"""Target: {target_url}

Confirmed Findings:
{findings_summary[:3000]}

Generate the exploit chain analysis and business impact report."""

    try:
        response = await client.chat.completions.create(
            model=settings.model_name,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user",   "content": user_prompt},
            ],
            temperature=0.3,
            max_tokens=2048,
        )
        return response.choices[0].message.content or "Hypothesis generation returned empty response."

    except Exception as e:
        return f"Hypothesis engine error: {type(e).__name__}: {e}"


# ══════════════════════════════════════════════════════════════
# TOOL 5: SECURITY HEADERS AUDIT
# ══════════════════════════════════════════════════════════════
@mcp.tool()
async def check_security_headers(target_url: str) -> str:
    """
    Dedicated HTTP security header audit.
    Checks for presence and correct configuration of:
    CSP, HSTS, X-Frame-Options, X-Content-Type-Options,
    Referrer-Policy, Permissions-Policy, CORS misconfiguration.
    Quick and always useful — can be run independently.
    """
    import httpx

    if not target_url.startswith(("http://", "https://")):
        return "Error: target_url must start with http:// or https://"

    REQUIRED_HEADERS = {
        "content-security-policy":    "Prevents XSS and injection attacks",
        "strict-transport-security":  "Forces HTTPS connections (HSTS)",
        "x-frame-options":            "Prevents clickjacking attacks",
        "x-content-type-options":     "Prevents MIME-type sniffing",
        "referrer-policy":            "Controls referrer information leakage",
        "permissions-policy":         "Controls browser feature access",
        "x-xss-protection":           "Legacy XSS filter (deprecated but checked)",
    }

    try:
        async with httpx.AsyncClient(verify=False, timeout=10.0, follow_redirects=True) as client:
            resp = await client.get(target_url, headers={"User-Agent": "Mozilla/5.0 NexusScanner/2.0"})

        hdrs = {k.lower(): v for k, v in resp.headers.items()}

        results = [f"Security Header Audit for: {target_url}", f"HTTP Status: {resp.status_code}", ""]

        missing = []
        present = []

        for header, description in REQUIRED_HEADERS.items():
            if header in hdrs:
                present.append(f"  ✅ PRESENT  [{header}]: {hdrs[header][:100]}")
            else:
                missing.append(f"  ❌ MISSING  [{header}]: {description}")

        results.append(f"✅ Present ({len(present)}/{len(REQUIRED_HEADERS)}):")
        results.extend(present)
        results.append(f"\n❌ Missing ({len(missing)}/{len(REQUIRED_HEADERS)}):")
        results.extend(missing)

        # CORS check
        cors_origin = hdrs.get("access-control-allow-origin", "")
        results.append("")
        if cors_origin == "*":
            results.append("⚠️  CORS MISCONFIGURATION: Access-Control-Allow-Origin: * (wildcard)")
        elif cors_origin:
            results.append(f"ℹ️  CORS Origin: {cors_origin}")
        else:
            results.append("ℹ️  No CORS headers present")

        score = int((len(present) / len(REQUIRED_HEADERS)) * 100)
        results.append(f"\nHeader Security Score: {score}/100")

        return "\n".join(results)

    except Exception as e:
        return f"Security header check failed: {type(e).__name__}: {e}"


# ── Entry Point ───────────────────────────────────────────────
if __name__ == "__main__":
    print("[SYSTEM] Starting Nexus MCP Server v2.0...")
    mcp.run()