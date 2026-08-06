import os
import tempfile
from fpdf import FPDF
from datetime import datetime

class PDFReport(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 15)
        self.cell(0, 10, 'SentinelAI Enterprise - Executive Report', 0, 1, 'C')
        self.ln(10)

    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}/{{nb}}', 0, 0, 'C')

def generate_executive_pdf(scan_record, asset_record) -> str:
    pdf = PDFReport()
    pdf.alias_nb_pages()
    pdf.add_page()
    
    # 1. Target Information
    pdf.set_font('Arial', 'B', 12)
    pdf.cell(0, 10, 'Target Information', 0, 1)
    
    pdf.set_font('Arial', '', 11)
    pdf.cell(0, 8, f'Target: {asset_record.target}', 0, 1)
    pdf.cell(0, 8, f'Scan Tool: {scan_record.tool_used}', 0, 1)
    date_str = scan_record.completed_at.strftime("%Y-%m-%d %H:%M:%S") if scan_record.completed_at else "N/A"
    pdf.cell(0, 8, f'Completed At: {date_str}', 0, 1)
    
    # 2. Risk and Confidence
    pdf.ln(5)
    pdf.set_font('Arial', 'B', 12)
    pdf.cell(0, 10, 'Scoring Metrics', 0, 1)
    
    pdf.set_font('Arial', '', 11)
    pdf.cell(0, 8, f'Risk Score: {scan_record.risk_score}', 0, 1)
    pdf.cell(0, 8, f'Confidence Score: {scan_record.confidence_score}%', 0, 1)
    pdf.cell(0, 8, f'Cross-Validated by Verifier: {"Yes" if scan_record.cross_validated else "No"}', 0, 1)
    
    # 3. Executive Summary / Remediation Plan
    pdf.ln(5)
    pdf.set_font('Arial', 'B', 12)
    pdf.cell(0, 10, 'Executive Summary & Remediation Plan', 0, 1)
    
    pdf.set_font('Arial', '', 10)
    
    findings = scan_record.findings or {}
    remediation_plan = findings.get("remediation_plan", "No remediation plan generated.")
    
    # Clean up markdown asterisks for cleaner PDF rendering
    remediation_plan = remediation_plan.replace('**', '')
    safe_text = remediation_plan.encode('latin-1', 'replace').decode('latin-1')
    pdf.multi_cell(0, 8, safe_text)
    
    # 3.5. Mission Audit & Decision Log (If available)
    if hasattr(scan_record, 'mission') and scan_record.mission and scan_record.mission.decision_log:
        pdf.add_page()
        pdf.set_font('Arial', 'B', 12)
        pdf.cell(0, 10, 'Mission Audit & Decision Log', 0, 1)
        pdf.ln(5)
        
        pdf.set_font('Courier', '', 9)
        for entry in scan_record.mission.decision_log:
            timestamp = entry.get('timestamp', '')[:19].replace("T", " ")
            action = entry.get('action', '')
            reason = entry.get('reason', '')
            conf = entry.get('confidence', '')
            
            # Format nicely
            log_line = f"[{timestamp}] {action}"
            if conf:
                log_line += f" | Confidence: {conf}"
            pdf.multi_cell(0, 6, log_line.encode('latin-1', 'replace').decode('latin-1'))
            
            if reason:
                pdf.set_text_color(100, 100, 100)
                reason_line = f"  Reason: {reason}"
                pdf.multi_cell(0, 6, reason_line.encode('latin-1', 'replace').decode('latin-1'))
                pdf.set_text_color(0, 0, 0)
            pdf.ln(2)
    
    # 4. Save and return path
    fd, path = tempfile.mkstemp(suffix=".pdf", prefix=f"scan_{scan_record.id}_")
    os.close(fd)
    
    pdf.output(path, 'F')
    return path
