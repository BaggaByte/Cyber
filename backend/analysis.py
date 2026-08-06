import os
from groq import Groq

client = Groq(api_key=os.environ.get("GROQ_API_KEY"))

# ─── Risk Scoring ─────────────────────────────────────────────────────────────

def calculate_risk_score(findings: dict, tool_used: str) -> str:
    """
    Lightweight CVSS-inspired risk scorer.
    Returns: CRITICAL / HIGH / MEDIUM / LOW / INFO
    """
    if not findings or findings.get("error"):
        return "INFO"

    score = 0

    # Nmap: score based on number of open ports and sensitive services
    open_ports = findings.get("open_ports", [])
    if open_ports:
        score += min(len(open_ports) * 5, 30)  # up to 30 pts for port count
        sensitive_services = {"ssh", "ftp", "telnet", "rdp", "smb", "vnc", "mysql", "postgres", "mongodb", "redis"}
        for p in open_ports:
            if p.get("service", "").lower() in sensitive_services:
                score += 15  # High-risk service exposed

    # Subdomain: each exposed subdomain is a potential attack surface
    subdomains = findings.get("discovered_subdomains", [])
    if subdomains:
        score += min(len(subdomains) * 3, 20)

    # Generic tools: presence of any raw output implies findings
    if findings.get("raw_output") and len(findings.get("raw_output", "")) > 100:
        score += 25

    if score >= 70:
        return "CRITICAL"
    elif score >= 50:
        return "HIGH"
    elif score >= 25:
        return "MEDIUM"
    elif score > 0:
        return "LOW"
    return "INFO"

def calculate_confidence_score(findings: dict, cross_validated: bool, evidence_captured: bool) -> int:
    """
    Calculates the confidence score based on the SentinelAI Blueprint.
    - Base 80% if results are not empty
    - +10% if cross-validated by the Verifier Agent
    - +10% if evidence is captured
    """
    if not findings or findings.get("error"):
        return 0
        
    score = 80
    if cross_validated:
        score += 10
    if evidence_captured:
        score += 10
        
    return score


# ─── Remediation Plan (Groq/Llama3) ───────────────────────────────────────────

def generate_remediation_plan(scan_findings: dict, tool_used: str, risk_score: str) -> str:
    """
    Generates a professional remediation report using Groq/Llama3.
    Includes risk context and actionable hardening steps.
    """
    # Condense findings to avoid token limits
    findings_summary = str(scan_findings)[:2000]

    prompt = f"""You are a senior cybersecurity engineer writing a professional security report.

Tool Used: {tool_used}
Risk Level: {risk_score}
Findings Summary:
{findings_summary}

Write a concise remediation report with:
1. **Executive Summary** (2 sentences max)
2. **Key Risks Identified** (bullet list)
3. **Actionable Hardening Steps** (numbered, prioritized by severity)
4. **Immediate Actions** (what to fix in the next 24 hours)

Be specific, technical, and actionable. Avoid generic advice."""

    try:
        chat_completion = client.chat.completions.create(
            messages=[
                {"role": "system", "content": "You are a senior security engineer writing precise, actionable security reports."},
                {"role": "user", "content": prompt}
            ],
            model="llama-3.1-8b-instant",
            temperature=0.1,
            max_tokens=800,
        )
        return chat_completion.choices[0].message.content
    except Exception as e:
        return f"[Analysis unavailable: {e}]"
