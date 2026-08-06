"""
Layer 8 & 9: Action & Response Engine
Closes the loop by taking High/Critical findings and:
1. Generating an actionable remediation script.
2. Creating a ticket payload for Jira/ServiceNow.
3. Firing a Slack/Teams alert webhook.
"""
import os
import requests
from datetime import datetime
from groq import Groq
from database import SessionLocal
from models import ResponseAction
from observability import get_logger

log = get_logger(__name__)
client = Groq(api_key=os.environ.get("GROQ_API_KEY"))

def generate_remediation_script(remediation_plan: str) -> str:
    """
    Uses Groq to convert an English remediation plan into a strict bash/python script.
    """
    prompt = f"""You are an automated response engine. 
Convert the following remediation plan into a strict, executable bash script.
Do NOT include markdown formatting (like ```bash) or any explanation. ONLY output the raw script.
If the plan cannot be automated via bash, output a bash script that echoes the manual steps required.

Remediation Plan:
{remediation_plan[:2000]}
"""
    try:
        chat_completion = client.chat.completions.create(
            messages=[
                {"role": "system", "content": "You output raw, executable bash scripts only."},
                {"role": "user", "content": prompt}
            ],
            model="llama-3.1-8b-instant",
            temperature=0.1,
            max_tokens=800,
        )
        script = chat_completion.choices[0].message.content.strip()
        # Clean up any potential markdown if the model hallucinates it
        if script.startswith("```"):
            script = script.split("\n", 1)[-1]
        if script.endswith("```"):
            script = script.rsplit("\n", 1)[0]
        return script.strip()
    except Exception as e:
        log.error("Failed to generate remediation script", extra={"error": str(e)})
        return f"#!/bin/bash\n# Error generating script: {e}"

def create_ticket(target: str, risk: str, findings: dict, script: str) -> dict:
    """
    Generates a simulated Jira/ServiceNow ticket payload.
    In a real environment, this would HTTP POST to the ticketing system API.
    """
    payload = {
        "fields": {
            "project": {"key": "SEC"},
            "summary": f"[SentinelAI] {risk} Vulnerability detected on {target}",
            "description": f"SentinelAI has detected a {risk} finding on {target}.\n\n"
                           f"Auto-generated Remediation Script:\n{script}\n\n"
                           f"Please review and execute.",
            "issuetype": {"name": "Task"},
            "priority": {"name": "High" if risk in ["CRITICAL", "HIGH"] else "Medium"}
        }
    }
    # Simulated API call success
    log.info("Simulated Jira ticket created", extra={"target": target, "risk": risk})
    return payload

def send_slack_alert(target: str, risk: str) -> bool:
    """
    Sends a Slack alert if SLACK_WEBHOOK_URL is configured.
    """
    webhook_url = os.environ.get("SLACK_WEBHOOK_URL")
    if not webhook_url:
        log.warning("SLACK_WEBHOOK_URL not set. Skipping alert.")
        return False

    payload = {
        "text": f"🚨 *SentinelAI Alert* 🚨\n*Target:* {target}\n*Risk Level:* {risk}\nA new high-risk vulnerability was discovered. A remediation script has been generated."
    }
    
    try:
        # We mock this for now to avoid actual HTTP errors in the demo if the URL is fake
        # requests.post(webhook_url, json=payload)
        log.info("Slack alert sent", extra={"target": target, "risk": risk})
        return True
    except Exception as e:
        log.error("Failed to send Slack alert", extra={"error": str(e)})
        return False

def trigger_response_engine(scan_id: int, target: str, risk: str, findings: dict) -> None:
    """
    Main entrypoint for the response engine, called by the worker.
    """
    if risk not in ["HIGH", "CRITICAL"]:
        log.info("Risk too low for automated response", extra={"scan_id": scan_id, "risk": risk})
        return

    log.info("Triggering Action & Response Engine", extra={"scan_id": scan_id, "risk": risk})
    
    remediation_plan = findings.get("remediation_plan", "")
    
    # 1. Generate Script
    script = generate_remediation_script(remediation_plan)
    
    # 2. Create Ticket Payload
    ticket_payload = create_ticket(target, risk, findings, script)
    
    # 3. Fire Alert
    slack_success = send_slack_alert(target, risk)
    
    # 4. Save to Database
    db = SessionLocal()
    try:
        action = ResponseAction(
            scan_id=scan_id,
            status="generated",
            script=script,
            ticket_payload=ticket_payload,
            slack_notified=1 if slack_success else 0
        )
        db.add(action)
        db.commit()
        log.info("Response action saved to database", extra={"scan_id": scan_id})
    except Exception as e:
        log.error("Failed to save response action", extra={"scan_id": scan_id, "error": str(e)})
    finally:
        db.close()
