from mcp.server.fastmcp import FastMCP
import sqlite3
import os
import json

# Initialize the MCP Server
mcp = FastMCP("Saga-SQLite-Intel")


@mcp.tool()
async def query_scan_history(limit: int = 10) -> str:
    """
    Queries the Nexus Enterprise scan history database.
    Returns recent scan records with target, status, and vulnerability counts.
    
    Args:
        limit: Maximum number of records to return (default: 10).
    """
    db_path = os.path.join(os.path.dirname(__file__), "..", "..", "Mini-Mythos", "src", "nexus_enterprise.db")
    
    if not os.path.exists(db_path):
        return "[INFO] No scan history database found. No scans have been executed yet."
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, target, status, vulns_found, timestamp FROM scans ORDER BY timestamp DESC LIMIT ?",
            (limit,)
        )
        rows = cursor.fetchall()
        conn.close()
        
        if not rows:
            return "[INFO] Scan history is empty. No scans have been recorded."
        
        results = []
        for row in rows:
            results.append({
                "scan_id": row[0],
                "target": row[1],
                "status": row[2],
                "vulns_found": row[3],
                "timestamp": row[4]
            })
        
        return json.dumps(results, indent=2)
        
    except Exception as e:
        return f"[ERROR] Failed to query scan history: {str(e)}"


@mcp.tool()
async def query_threat_events(event_type: str = "ALL", limit: int = 20) -> str:
    """
    Queries the Threat Intelligence event ledger for blocked attacks.
    
    Args:
        event_type: Filter by event type (e.g., "INDIRECT_PROMPT_INJECTION", "SHELL_INJECTION_ATTEMPT", or "ALL").
        limit: Maximum number of records to return (default: 20).
    """
    db_path = os.path.join(os.path.dirname(__file__), "..", "..", "Mini-Mythos", "src", "nexus_enterprise.db")
    
    if not os.path.exists(db_path):
        return "[INFO] No threat event database found."
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        if event_type == "ALL":
            cursor.execute(
                "SELECT id, timestamp, event_type, source_target, malicious_payload, mitigation_action FROM threat_intel_events ORDER BY timestamp DESC LIMIT ?",
                (limit,)
            )
        else:
            cursor.execute(
                "SELECT id, timestamp, event_type, source_target, malicious_payload, mitigation_action FROM threat_intel_events WHERE event_type = ? ORDER BY timestamp DESC LIMIT ?",
                (event_type, limit)
            )
        
        rows = cursor.fetchall()
        conn.close()
        
        if not rows:
            return "[INFO] No threat events recorded. The system has not intercepted any malicious payloads."
        
        results = []
        for row in rows:
            results.append({
                "event_id": row[0],
                "timestamp": row[1],
                "event_type": row[2],
                "source_target": row[3],
                "malicious_payload": row[4],
                "mitigation_action": row[5]
            })
        
        return json.dumps(results, indent=2)
        
    except Exception as e:
        return f"[ERROR] Failed to query threat events: {str(e)}"


if __name__ == "__main__":
    mcp.run()
