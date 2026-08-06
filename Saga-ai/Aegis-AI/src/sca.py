import json
import urllib.request
from pathlib import Path

def fetch_epss_score(cve: str) -> float:
    """
    Fetches the EPSS score for a given CVE from FIRST.org API and returns it as a percentage.
    """
    try:
        url = f"https://api.first.org/data/v1/epss?cve={cve}"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req) as response:
            data = json.loads(response.read().decode('utf-8'))
            if "data" in data and len(data["data"]) > 0:
                epss_val = data["data"][0].get("epss")
                if epss_val:
                    return float(epss_val) * 100.0
    except Exception:
        pass
    return 0.0

def scan_dependencies(target_dir: str) -> list:
    """
    Scans Python dependencies in requirements.txt against the OSV API.
    Enriches vulnerable packages with their FIRST.org EPSS score.
    """
    req_path = Path(target_dir) / "requirements.txt"
    if not req_path.exists():
        return []
        
    results = []
    try:
        with open(req_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
            
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
                
            if "==" in line:
                parts = line.split("==")
                if len(parts) == 2:
                    name = parts[0].strip()
                    version = parts[1].strip()
                    
                    osv_url = "https://api.osv.dev/v1/query"
                    post_data = {
                        "version": version,
                        "package": {"name": name, "ecosystem": "PyPI"}
                    }
                    req_data = json.dumps(post_data).encode('utf-8')
                    req = urllib.request.Request(
                        osv_url,
                        data=req_data,
                        headers={'Content-Type': 'application/json'}
                    )
                    
                    try:
                        with urllib.request.urlopen(req) as response:
                            res_data = json.loads(response.read().decode('utf-8'))
                            vulns = res_data.get("vulns", [])
                            for vuln in vulns:
                                cve_id = ""
                                aliases = vuln.get("aliases", [])
                                for alias in aliases:
                                    if alias.startswith("CVE-"):
                                        cve_id = alias
                                        break
                                        
                                epss_score = 0.0
                                if cve_id:
                                    epss_score = fetch_epss_score(cve_id)
                                    
                                results.append({
                                    "package": name,
                                    "version": version,
                                    "cve": cve_id,
                                    "epss": epss_score,
                                    "summary": vuln.get("summary", "")
                                })
                    except Exception:
                        pass
    except Exception:
        pass
        
    return results
