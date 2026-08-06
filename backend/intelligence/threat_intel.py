import os
import requests
import json
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import threading

log = logging.getLogger(__name__)

class ThreatIntelService:
    """
    Centralized service for Threat Intelligence (IOCs) and Vulnerability Enrichment (CVEs)
    Integrates 14 free APIs:
    AlienVault OTX, NVD, CVEProject, MITRE ATT&CK, URLhaus, MalwareBazaar, 
    ThreatFox, Feodo Tracker, PhishTank, OpenPhish, Abuse.ch, CIRCL, FIRST EPSS, CISA KEV
    """
    
    def __init__(self):
        # API Keys (Optional but recommended for higher rate limits)
        self.otx_key = os.getenv("ALIENVAULT_OTX_KEY")
        self.nvd_key = os.getenv("NVD_API_KEY")
        
        # Caches for bulk feeds
        self._kev_cache = {}
        self._kev_last_update = None
        
        self._feodo_cache = set()
        self._feodo_last_update = None
        
        self._openphish_cache = set()
        self._openphish_last_update = None
        
        self.cache_lock = threading.Lock()
        self.cache_ttl = timedelta(hours=12)

    # =========================================================================
    # VULNERABILITY ENRICHMENT (CVEs)
    # =========================================================================

    def enrich_cve(self, cve_id: str) -> Dict[str, Any]:
        """Runs multiple APIs to enrich a single CVE."""
        enrichment = {
            "cve_id": cve_id,
            "epss_score": None,
            "epss_percentile": None,
            "cisa_kev": False,
            "nvd_cvss3": None,
            "circl_summary": None,
            "mitre_tactics": [],
            "cve_org_status": None
        }

        # 1. FIRST EPSS API
        try:
            res = requests.get(f"https://api.first.org/data/v1/epss?cve={cve_id}", timeout=5)
            if res.status_code == 200 and res.json().get("data"):
                data = res.json()["data"][0]
                enrichment["epss_score"] = float(data.get("epss", 0.0))
                enrichment["epss_percentile"] = float(data.get("percentile", 0.0))
        except Exception as e:
            log.warning(f"EPSS lookup failed for {cve_id}: {e}")

        # 2. CISA KEV
        enrichment["cisa_kev"] = self._is_in_kev(cve_id)

        # 3. CIRCL Vulnerability Lookup
        try:
            res = requests.get(f"https://cve.circl.lu/api/cve/{cve_id}", timeout=5)
            if res.status_code == 200:
                data = res.json()
                if data:
                    enrichment["circl_summary"] = data.get("summary")
                    # Extract MITRE tactics roughly from CIRCL tags if present
                    if "capec" in data:
                        enrichment["mitre_tactics"] = [c.get("name") for c in data["capec"]]
        except Exception as e:
            log.warning(f"CIRCL lookup failed for {cve_id}: {e}")

        # 4. NVD API
        try:
            headers = {"apiKey": self.nvd_key} if self.nvd_key else {}
            res = requests.get(f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}", headers=headers, timeout=5)
            if res.status_code == 200:
                data = res.json()
                if data.get("vulnerabilities"):
                    vuln = data["vulnerabilities"][0]["cve"]
                    metrics = vuln.get("metrics", {})
                    if "cvssMetricV31" in metrics:
                        enrichment["nvd_cvss3"] = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
        except Exception as e:
            log.warning(f"NVD lookup failed for {cve_id}: {e}")

        # 5. CVE.org API
        try:
            res = requests.get(f"https://cveawg.mitre.org/api/cve/{cve_id}", timeout=5)
            if res.status_code == 200:
                enrichment["cve_org_status"] = res.json().get("cveMetadata", {}).get("state")
        except Exception as e:
            log.warning(f"CVE.org lookup failed for {cve_id}: {e}")

        return enrichment

    def _is_in_kev(self, cve_id: str) -> bool:
        with self.cache_lock:
            now = datetime.utcnow()
            if not self._kev_last_update or (now - self._kev_last_update) > self.cache_ttl:
                try:
                    res = requests.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", timeout=10)
                    if res.status_code == 200:
                        data = res.json()
                        self._kev_cache = {vuln["cveID"]: vuln for vuln in data.get("vulnerabilities", [])}
                        self._kev_last_update = now
                except Exception as e:
                    log.error(f"Failed to fetch CISA KEV: {e}")
        return cve_id in self._kev_cache

    # =========================================================================
    # THREAT INTEL (IOCs: IPs, Domains, URLs, Hashes)
    # =========================================================================

    def lookup_ioc(self, indicator: str, ioc_type: str) -> Dict[str, Any]:
        """
        ioc_type: 'ip', 'domain', 'url', or 'hash'
        """
        result = {
            "indicator": indicator,
            "type": ioc_type,
            "malicious": False,
            "sources_flagged": [],
            "tags": [],
            "details": {}
        }

        # 1. AlienVault OTX
        if self.otx_key:
            try:
                headers = {"X-OTX-API-KEY": self.otx_key}
                otx_type = {"ip": "IPv4", "domain": "domain", "hash": "file", "url": "url"}.get(ioc_type, "IPv4")
                res = requests.get(f"https://otx.alienvault.com/api/v1/indicators/{otx_type}/{indicator}/general", headers=headers, timeout=5)
                if res.status_code == 200:
                    data = res.json()
                    pulses = data.get("pulse_info", {}).get("count", 0)
                    if pulses > 0:
                        result["malicious"] = True
                        result["sources_flagged"].append(f"AlienVault_OTX ({pulses} pulses)")
                        result["details"]["otx"] = data.get("pulse_info", {})
            except Exception as e:
                log.warning(f"OTX lookup failed for {indicator}: {e}")

        # 2. ThreatFox (Abuse.ch)
        try:
            tf_data = {"query": "search_ioc", "search_term": indicator}
            res = requests.post("https://threatfox-api.abuse.ch/api/v1/", json=tf_data, timeout=5)
            if res.status_code == 200 and res.json().get("query_status") == "ok":
                result["malicious"] = True
                result["sources_flagged"].append("ThreatFox")
                tags = res.json().get("data", [{}])[0].get("tags", [])
                if tags:
                    result["tags"].extend(tags)
        except Exception as e:
            log.warning(f"ThreatFox lookup failed for {indicator}: {e}")

        # 3. URLhaus (Abuse.ch) - For URLs and Domains
        if ioc_type in ["url", "domain"]:
            try:
                data = {ioc_type: indicator}
                endpoint = "host" if ioc_type == "domain" else "url"
                res = requests.post(f"https://urlhaus-api.abuse.ch/v1/{endpoint}/", data=data, timeout=5)
                if res.status_code == 200 and res.json().get("query_status") == "ok":
                    result["malicious"] = True
                    result["sources_flagged"].append("URLhaus")
            except Exception as e:
                log.warning(f"URLhaus lookup failed for {indicator}: {e}")

        # 4. MalwareBazaar (Abuse.ch) - For Hashes
        if ioc_type == "hash":
            try:
                data = {"query": "get_info", "hash": indicator}
                res = requests.post("https://mb-api.abuse.ch/api/v1/", data=data, timeout=5)
                if res.status_code == 200 and res.json().get("query_status") == "ok":
                    result["malicious"] = True
                    result["sources_flagged"].append("MalwareBazaar")
                    result["tags"].extend(res.json().get("data", [{}])[0].get("tags", []))
            except Exception as e:
                log.warning(f"MalwareBazaar lookup failed for {indicator}: {e}")

        # 5. Feodo Tracker - For IPs
        if ioc_type == "ip":
            if self._is_in_feodo(indicator):
                result["malicious"] = True
                result["sources_flagged"].append("FeodoTracker")
                result["tags"].append("botnet")

        # 6. OpenPhish & PhishTank - For URLs
        if ioc_type == "url":
            if self._is_in_openphish(indicator):
                result["malicious"] = True
                result["sources_flagged"].append("OpenPhish")
                result["tags"].append("phishing")
                
            try:
                pt_data = {"url": indicator, "format": "json"}
                res = requests.post("https://checkurl.phishtank.com/checkurl/", data=pt_data, timeout=5)
                if res.status_code == 200 and res.json().get("results", {}).get("in_database"):
                    result["malicious"] = True
                    result["sources_flagged"].append("PhishTank")
                    result["tags"].append("phishing")
            except Exception:
                pass

        # Deduplicate tags
        result["tags"] = list(set(result["tags"]))
        
        return result

    def _is_in_feodo(self, ip: str) -> bool:
        with self.cache_lock:
            now = datetime.utcnow()
            if not self._feodo_last_update or (now - self._feodo_last_update) > self.cache_ttl:
                try:
                    res = requests.get("https://feodotracker.abuse.ch/downloads/ipblocklist.json", timeout=10)
                    if res.status_code == 200:
                        data = res.json()
                        self._feodo_cache = {entry.get("ip_address") for entry in data if entry.get("ip_address")}
                        self._feodo_last_update = now
                except Exception as e:
                    log.error(f"Failed to fetch Feodo Tracker: {e}")
        return ip in self._feodo_cache

    def _is_in_openphish(self, url: str) -> bool:
        with self.cache_lock:
            now = datetime.utcnow()
            if not self._openphish_last_update or (now - self._openphish_last_update) > self.cache_ttl:
                try:
                    res = requests.get("https://openphish.com/feed.txt", timeout=10)
                    if res.status_code == 200:
                        self._openphish_cache = set(res.text.splitlines())
                        self._openphish_last_update = now
                except Exception as e:
                    log.error(f"Failed to fetch OpenPhish feed: {e}")
        return url in self._openphish_cache

# Initialize a global singleton instance to be used across the backend
threat_intel = ThreatIntelService()
