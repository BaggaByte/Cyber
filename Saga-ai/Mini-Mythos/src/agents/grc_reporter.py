from langchain_openai import ChatOpenAI
from langchain_core.messages import SystemMessage, HumanMessage
from dotenv import load_dotenv
import datetime
import os

load_dotenv()

async def grc_report_node(state):
    print("\n── PHASE 4 — GRC REPORT GENERATION ─────────────────")
    target = state.get("target", "Unknown Target")
    
    # Grab BOTH sets of vulnerabilities
    ai_fuzzer_findings = state.get("confirmed_exploits", [])
    nuclei_findings = state.get("nuclei_findings", [])
    
    # Combine them into one master list for the AI
    all_findings = ai_fuzzer_findings + nuclei_findings
    
    print(f"[GRC AGENT] Connecting to Groq (Llama 3.1) to draft Executive Summary for {len(all_findings)} findings...")
    
    # Initialize Groq Llama 3
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        print("  [-] GROQ_API_KEY not set. Generating fallback report...")
        # Generate a simple fallback HTML report
        html_content = _generate_fallback_report(target, all_findings)
        _save_report(html_content)
        return {"report_generated": True}

    llm = ChatOpenAI(
        model="llama-3.1-8b-instant",
        api_key=api_key,
        base_url="https://api.groq.com/openai/v1",
        temperature=0.3,
        max_tokens=4096,
    )

    # The Master Prompt for the AI
    system_prompt = """You are a Senior GRC (Governance, Risk, and Compliance) Security Analyst.
Your job is to take raw vulnerability data and generate a professional, executive-level HTML security report.

CRITICAL INSTRUCTIONS FOR ZERO FINDINGS (CLEAN SCAN):
If the raw findings list is empty or indicates 0 vulnerabilities, DO NOT just write "no findings". You must generate a "Certificate of Secure Posture".
1. Executive Summary: Praise the hardened security posture of the application.
2. Technical Scope: Explain that the automated DAST engine actively fuzzed the endpoints for misconfigurations and exposures, and all defenses held.
3. OWASP Top 10: Explicitly state that the application demonstrates strong baseline defenses against common threats (Injection, Broken Access Control, etc.).
4. ISO 27001: Note that this automated scan satisfies continuous vulnerability management and security testing requirements (Control A.12.6.1).

STYLING & FORMATTING (MANDATORY):
- You MUST use inline CSS to create a sleek, modern, dark-mode dashboard look.
- Use a dark gray/black background with white text.
- If there are 0 findings, prominently display a bright green "STATUS: PASSED / SECURE" badge. If there are findings, use a red "STATUS: CRITICAL EXPOSURES" badge.
- Use clean tables, sans-serif fonts (like Arial or Roboto), and padded div containers.

OUTPUT RULE: 
Output ONLY raw HTML code. Do NOT wrap it in markdown blockticks (like ```html). Do NOT add conversational text before or after. Start exactly with <!DOCTYPE html> and end with </html>."""

    human_prompt = f"Generate the GRC report for target: {target}. Raw Findings: {all_findings}"

    messages = [
        SystemMessage(content=system_prompt),
        HumanMessage(content=human_prompt)
    ]

    try:
        response = await llm.ainvoke(messages)
        html_content = response.content.strip()
        
        # Clean up markdown if the AI disobeys the prompt
        if html_content.startswith("```html"):
            html_content = html_content[7:-3]
        elif html_content.startswith("```"):
            html_content = html_content[3:-3]

        _save_report(html_content)
        
    except Exception as e:
        print(f"  [-] Claude GRC Reporting Failed: {str(e)}")
        print("  [*] Generating fallback HTML report...")
        html_content = _generate_fallback_report(target, all_findings)
        _save_report(html_content)

    # Return the updated state
    return {"report_generated": True}


def _save_report(html_content: str):
    """Save the report HTML to a timestamped file."""
    report_filename = f"Nexus_GRC_Report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    report_path = os.path.join(os.getcwd(), report_filename)
    
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(html_content)
        
    print(f"  [+] SUCCESS: Executive GRC Report saved to -> {report_filename}")


def _generate_fallback_report(target: str, findings: list) -> str:
    """Generate a basic HTML report when the LLM is unavailable."""
    finding_count = len(findings)
    status_color = "#ef4444" if finding_count > 0 else "#22c55e"
    status_text = "CRITICAL EXPOSURES" if finding_count > 0 else "PASSED / SECURE"
    
    findings_html = ""
    for i, f in enumerate(findings, 1):
        name = f.get("name", f.get("cwe", "Unknown"))
        endpoint = f.get("target_endpoint", "N/A")
        severity = f.get("severity", "medium").upper()
        findings_html += f"""
        <tr>
            <td style="padding: 10px; border-bottom: 1px solid #333;">{i}</td>
            <td style="padding: 10px; border-bottom: 1px solid #333;">{name}</td>
            <td style="padding: 10px; border-bottom: 1px solid #333;">{endpoint}</td>
            <td style="padding: 10px; border-bottom: 1px solid #333; font-weight: bold;">{severity}</td>
        </tr>"""
    
    if not findings_html:
        findings_html = """
        <tr>
            <td colspan="4" style="padding: 20px; text-align: center; color: #22c55e;">
                No vulnerabilities detected. All defenses held.
            </td>
        </tr>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Nexus GRC Report — {target}</title>
</head>
<body style="background: #111; color: #e5e5e5; font-family: Arial, sans-serif; margin: 0; padding: 40px;">
    <div style="max-width: 900px; margin: 0 auto;">
        <h1 style="font-size: 28px; margin-bottom: 5px;">Nexus AI — Executive GRC Report</h1>
        <p style="color: #888; margin-bottom: 30px;">Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
        
        <div style="background: {status_color}; color: white; padding: 15px 25px; border-radius: 8px; font-size: 18px; font-weight: bold; display: inline-block; margin-bottom: 30px;">
            STATUS: {status_text}
        </div>
        
        <h2 style="border-bottom: 1px solid #333; padding-bottom: 10px;">Target: {target}</h2>
        <p>Total Findings: <strong>{finding_count}</strong></p>
        
        <table style="width: 100%; border-collapse: collapse; margin-top: 20px;">
            <thead>
                <tr style="background: #222;">
                    <th style="padding: 10px; text-align: left;">#</th>
                    <th style="padding: 10px; text-align: left;">Finding</th>
                    <th style="padding: 10px; text-align: left;">Endpoint</th>
                    <th style="padding: 10px; text-align: left;">Severity</th>
                </tr>
            </thead>
            <tbody>
                {findings_html}
            </tbody>
        </table>
        
        <p style="color: #666; margin-top: 40px; font-size: 12px;">
            Report generated by Nexus AI Autonomous GRC Orchestrator (Fallback Mode). 
            For full AI-powered executive summaries, configure ANTHROPIC_API_KEY.
        </p>
    </div>
</body>
</html>"""
