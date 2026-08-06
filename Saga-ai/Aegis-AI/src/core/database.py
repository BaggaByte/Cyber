import os
import json
import sqlite3
from datetime import datetime
from pathlib import Path

# DB Directory path
DB_DIR = Path(__file__).resolve().parent.parent.parent / "aegis_chroma_db"
DB_PATH = DB_DIR / "aegis_history.db"

def init_db():
    """Initializes the SQLite database and creates the scans table."""
    try:
        DB_DIR.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(DB_PATH))
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                job_id TEXT PRIMARY KEY,
                timestamp TEXT,
                target TEXT,
                total INTEGER,
                critical INTEGER,
                high INTEGER,
                medium INTEGER,
                low INTEGER,
                findings TEXT
            )
        """)
        conn.commit()
        conn.close()
        print("[DB] SQLite Historical Database initialized successfully.")
    except Exception as e:
        print(f"[-] Failed to initialize database: {e}")

def save_scan_record(job_id: str, target: str, findings: list):
    """Saves a complete scan record and findings to SQLite."""
    try:
        DB_DIR.mkdir(parents=True, exist_ok=True)
        
        stats = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in findings:
            sev = str(f.get("severity", "LOW")).upper()
            if sev in stats:
                stats[sev] += 1
                
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        total = len(findings)
        findings_json = json.dumps(findings)
        
        conn = sqlite3.connect(str(DB_PATH))
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO scans 
            (job_id, timestamp, target, total, critical, high, medium, low, findings)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (job_id, timestamp, target, total, stats["CRITICAL"], stats["HIGH"], stats["MEDIUM"], stats["LOW"], findings_json))
        conn.commit()
        conn.close()
        print(f"[DB] Scan {job_id} successfully archived to SQLite database.")
    except Exception as e:
        print(f"[-] Failed to save scan to SQLite: {e}")

def get_scan_history():
    """Retrieves all past scans from SQLite, ordered by newest first."""
    try:
        if not DB_PATH.exists():
            return []
            
        conn = sqlite3.connect(str(DB_PATH))
        cursor = conn.cursor()
        cursor.execute("""
            SELECT job_id, timestamp, target, total, critical, high, medium, low 
            FROM scans 
            ORDER BY timestamp DESC
        """)
        rows = cursor.fetchall()
        conn.close()
        
        history = []
        for row in rows:
            history.append({
                "job_id": row[0],
                "timestamp": row[1],
                "target": row[2],
                "total": row[3],
                "critical": row[4],
                "high": row[5],
                "medium": row[6],
                "low": row[7]
            })
        return history
    except Exception as e:
        print(f"[-] Failed to retrieve scan history from SQLite: {e}")
        return []

def get_scan_findings(job_id: str):
    """Retrieves the full findings list for a specific historical job."""
    try:
        if not DB_PATH.exists():
            return None
            
        conn = sqlite3.connect(str(DB_PATH))
        cursor = conn.cursor()
        cursor.execute("SELECT findings FROM scans WHERE job_id = ?", (job_id,))
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return json.loads(row[0])
    except Exception as e:
        print(f"[-] Failed to retrieve scan findings from SQLite: {e}")
    return None
