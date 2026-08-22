import os
import time
import uuid
import requests
import chromadb
from chromadb.config import Settings

# Configuration
CHROMA_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "aegis_chroma_db")
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Sample OWASP Top 10 Curated Baseline
OWASP_BASELINE = [
    {
        "vulnerability_id": "OWASP-2021-A01",
        "title": "Broken Access Control",
        "description": "Failures in access control policies allow attackers to act as users or administrators, or access privileged data.",
        "remediation": "1. Except for public resources, deny by default.\n2. Implement access control mechanisms once and re-use them throughout the application, including minimizing CORS usage.\n3. Model access controls should enforce record ownership, rather than accepting that the user can create, read, update, or delete any record.\n4. Disable web server directory listing and ensure file metadata (e.g., .git) and backup files are not present within web roots.\n5. Log access control failures and alert admins when appropriate."
    },
    {
        "vulnerability_id": "OWASP-2021-A03",
        "title": "Injection (SQL/NoSQL/Command)",
        "description": "User-supplied data is not validated, filtered, or sanitized by the application and is used directly in queries or commands.",
        "remediation": "1. Use a safe API, which avoids the use of the interpreter entirely or provides a parameterized interface, or migrate to Object Relational Mapping Tools (ORMs).\n2. Use positive or 'whitelist' server-side input validation.\n3. For any residual dynamic queries, escape special characters using the specific escape syntax for that interpreter.\n4. Use LIMIT and other SQL controls within queries to prevent mass disclosure of records in case of SQL injection."
    },
    {
        "vulnerability_id": "OWASP-2021-A07",
        "title": "Identification and Authentication Failures",
        "description": "Confirmation of the user's identity, authentication, and session management is not implemented correctly.",
        "remediation": "1. Where possible, implement multi-factor authentication to prevent automated, credential stuffing, brute force, and stolen credential re-use attacks.\n2. Do not ship or deploy with any default credentials, particularly for admin users.\n3. Implement weak-password checks, such as testing new or changed passwords against a list of the top 10000 worst passwords.\n4. Align password length, complexity, and rotation policies with evidence-based modern guidelines."
    }
]

def init_chroma():
    """Initializes and returns the ChromaDB collection."""
    print(f"[*] Initializing ChromaDB at {CHROMA_DB_PATH}")
    os.makedirs(CHROMA_DB_PATH, exist_ok=True)
    # Match the configuration in Saga-ai/main.py
    client = chromadb.PersistentClient(path=CHROMA_DB_PATH)
    collection = client.get_or_create_collection(name="remediations")
    return collection

def ingest_owasp(collection):
    """Ingests curated OWASP baseline into the collection."""
    print("[*] Ingesting OWASP Top 10 Baseline...")
    count = 0
    for item in OWASP_BASELINE:
        doc_content = f"Title: {item['title']}\nDescription: {item['description']}\nRemediation Strategy:\n{item['remediation']}"
        doc_id = str(uuid.uuid4())
        
        collection.add(
            documents=[doc_content],
            metadatas=[{"vulnerability_id": item['vulnerability_id'], "target": "Global Baseline"}],
            ids=[doc_id]
        )
        count += 1
    print(f"[+] Successfully ingested {count} OWASP baselines.")

def fetch_and_ingest_nvd(collection, limit=20):
    """Fetches recent critical CVEs from NVD API and ingests them."""
    print(f"[*] Fetching up to {limit} critical CVEs from NIST NVD API...")
    
    # Query parameters for CVSS V3 Base Score >= 9.0 (Critical)
    params = {
        "cvssV3Severity": "CRITICAL",
        "resultsPerPage": limit
    }
    
    try:
        response = requests.get(NVD_API_URL, params=params, timeout=30)
        
        if response.status_code != 200:
            print(f"[-] Failed to fetch from NVD API. Status Code: {response.status_code}")
            return
            
        data = response.json()
        vulnerabilities = data.get("vulnerabilities", [])
        
        if not vulnerabilities:
            print("[-] No vulnerabilities returned from API.")
            return
            
        count = 0
        for vuln in vulnerabilities:
            cve_item = vuln.get("cve", {})
            cve_id = cve_item.get("id")
            
            # Extract English description
            descriptions = cve_item.get("descriptions", [])
            desc_text = "No description available."
            for desc in descriptions:
                if desc.get("lang") == "en":
                    desc_text = desc.get("value")
                    break
                    
            if not cve_id:
                continue
                
            # Create a structured document for the LLM
            doc_content = f"CVE ID: {cve_id}\nDescription: {desc_text}\nGeneral Remediation: Ensure the affected software is patched to the latest version immediately. Check vendor advisories for specific workarounds if a patch is unavailable."
            doc_id = str(uuid.uuid4())
            
            collection.add(
                documents=[doc_content],
                metadatas=[{"vulnerability_id": cve_id, "target": "Global Baseline"}],
                ids=[doc_id]
            )
            count += 1
            
        print(f"[+] Successfully ingested {count} critical CVEs from NVD.")
        
    except Exception as e:
        print(f"[-] Error fetching or ingesting NVD data: {e}")

if __name__ == "__main__":
    print("========================================")
    print("  Aegis AI - ChromaDB Intelligence Seeder  ")
    print("========================================")
    
    col = init_chroma()
    
    ingest_owasp(col)
    
    # Pause slightly to avoid immediate rate limit if multiple runs occur
    time.sleep(1)
    
    fetch_and_ingest_nvd(col, limit=20)
    
    final_count = col.count()
    print("========================================")
    print(f"[+] Total documents in 'remediations' collection: {final_count}")
    print("[+] Seeding Complete.")
