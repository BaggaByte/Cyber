# core/findings_store.py
"""Persist vulnerability findings from scan engines into the database."""
from __future__ import annotations

from typing import Any

from core.database import SessionLocal, VulnerabilityFinding, update_scan_counts


def persist_fuzz_results(scan_id: int | None, results: list[Any], source: str = "custom_fuzzer") -> int:
    """Save ScanResult objects (or dicts) that flagged is_vulnerable=True."""
    if not scan_id or not results:
        return 0

    db = SessionLocal()
    saved = 0
    try:
        for item in results:
            if hasattr(item, "is_vulnerable"):
                is_vuln = item.is_vulnerable
                vuln_name = item.vuln_name
                cwe = item.cwe
                severity = item.severity
                confidence = item.confidence
                endpoint = item.target
                payload = item.payload_used
                notes = item.notes
                response = item.response_received
            elif isinstance(item, dict):
                is_vuln = item.get("is_vulnerable", False)
                vuln_name = item.get("vuln_name", item.get("name", "Unknown"))
                cwe = item.get("cwe")
                severity = item.get("severity", "medium")
                confidence = item.get("confidence", "likely")
                endpoint = item.get("endpoint", item.get("target", item.get("matched", "unknown")))
                payload = item.get("payload_used", item.get("payload", ""))
                notes = item.get("notes", "")
                response = item.get("response_received", "")
            else:
                continue

            if not is_vuln:
                continue

            db.add(VulnerabilityFinding(
                scan_id=scan_id,
                vuln_name=str(vuln_name)[:256],
                cwe=str(cwe)[:20] if cwe else None,
                severity=str(severity).lower()[:20],
                confidence=str(confidence).lower()[:20],
                endpoint=str(endpoint)[:2048],
                method="GET",
                payload_used=str(payload)[:2000] if payload else None,
                response_snippet=str(response)[:500] if response else None,
                notes=str(notes)[:2000] if notes else None,
                source=source,
            ))
            saved += 1

        if saved:
            db.commit()
            update_scan_counts(db, scan_id)
        else:
            db.rollback()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()

    return saved


def persist_nuclei_findings(scan_id: int | None, findings: list[dict]) -> int:
    """Save parsed Nuclei JSON finding dicts."""
    if not scan_id or not findings:
        return 0

    db = SessionLocal()
    saved = 0
    try:
        for f in findings:
            severity = str(f.get("severity", "medium")).lower()
            db.add(VulnerabilityFinding(
                scan_id=scan_id,
                vuln_name=str(f.get("name", f.get("template", "Nuclei Finding")))[:256],
                severity=severity[:20],
                confidence="confirmed",
                endpoint=str(f.get("matched", f.get("matched-at", "unknown")))[:2048],
                method="GET",
                notes=f"Nuclei template: {f.get('template', 'unknown')}",
                source="nuclei",
            ))
            saved += 1

        if saved:
            db.commit()
            update_scan_counts(db, scan_id)
        else:
            db.rollback()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()

    return saved
