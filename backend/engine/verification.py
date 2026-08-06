from typing import List, Dict, Any
import hashlib
from observability import get_logger

log = get_logger(__name__)

class SelfVerificationEngine:
    """
    Phase 2: Self Verification Engine (Multi Source Validation)
    Implements validation logic to correlate findings across tools and eliminate false positives.
    """

    def __init__(self):
        self.evidence_weights = {
            "screenshot": 1.0,
            "dom_capture": 0.8,
            "nuclei_template_match": 0.9,
            "nmap_banner": 0.5,
            "ffuf_status": 0.4,
            "cve_match": 0.7
        }

    def _hash_finding(self, finding: Dict[str, Any]) -> str:
        """Create a unique identifier for a vulnerability finding based on target and type."""
        core_str = f"{finding.get('target', '')}:{finding.get('vulnerability', '')}"
        return hashlib.md5(core_str.encode()).hexdigest()

    def correlate_findings(self, raw_findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Takes raw findings from multiple tools (e.g. nmap, nuclei) and correlates them.
        Returns a list of deduplicated findings with aggregated evidence.
        """
        correlated = {}
        for finding in raw_findings:
            f_id = self._hash_finding(finding)
            
            if f_id not in correlated:
                finding["evidence_sources"] = [finding.get("source_tool", "unknown")]
                finding["confidence_score"] = 0.0
                correlated[f_id] = finding
            else:
                # Correlate and append new evidence source
                correlated[f_id]["evidence_sources"].append(finding.get("source_tool", "unknown"))
                # If severity is higher in the new finding, upgrade it
                if self._sev_to_int(finding.get("severity", "LOW")) > self._sev_to_int(correlated[f_id].get("severity", "LOW")):
                    correlated[f_id]["severity"] = finding["severity"]
                    
        return list(correlated.values())

    def calculate_confidence(self, finding: Dict[str, Any]) -> float:
        """
        Calculates a confidence score (0-100) based on the evidence available.
        """
        score = 0.0
        sources = finding.get("evidence_sources", [])
        evidence_types = finding.get("evidence_types", []) # e.g. ["nmap_banner", "nuclei_template_match"]

        # Base score on number of distinct tool corroborations (up to 40%)
        tool_score = min(len(set(sources)) * 15.0, 40.0)
        
        # Add score based on evidence quality (up to 60%)
        evidence_score = 0.0
        for e_type in evidence_types:
            weight = self.evidence_weights.get(e_type, 0.2)
            evidence_score += (weight * 60.0)
            
        score = min(tool_score + evidence_score, 100.0)
        finding["confidence_score"] = score
        
        log.info(f"Calculated confidence score {score}% for finding {finding.get('vulnerability')}")
        return score

    def _sev_to_int(self, sev: str) -> int:
        mapping = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        return mapping.get(sev.upper(), 0)

verification_engine = SelfVerificationEngine()
