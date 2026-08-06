import html
from typing import List, Dict

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Aegis AI Security Scan Report</title>
    <style>
        :root {{
            --bg-primary: #0f172a;
            --bg-secondary: #1e293b;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --critical: #ef4444;
            --high: #f97316;
            --medium: #eab308;
            --low: #3b82f6;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background-color: var(--bg-primary);
            color: var(--text-main);
            margin: 0;
            padding: 40px;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        header {{
            margin-bottom: 40px;
            border-bottom: 1px solid #334155;
            padding-bottom: 20px;
        }}
        h1 {{ margin: 0 0 10px 0; font-size: 2.5rem; }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }}
        .stat-card {{
            background-color: var(--bg-secondary);
            padding: 20px;
            border-radius: 8px;
            border-left: 5px solid #64748b;
            text-align: center;
        }}
        .stat-card.CRITICAL {{ border-left-color: var(--critical); }}
        .stat-card.HIGH {{ border-left-color: var(--high); }}
        .stat-card.MEDIUM {{ border-left-color: var(--medium); }}
        .stat-card.LOW {{ border-left-color: var(--low); }}
        .stat-num {{ font-size: 2rem; font-weight: bold; margin-bottom: 5px; }}
        .filter-container {{
            margin-bottom: 20px;
            display: flex;
            gap: 10px;
        }}
        .filter-btn {{
            background-color: var(--bg-secondary);
            color: var(--text-main);
            border: 1px solid #475569;
            padding: 8px 16px;
            border-radius: 4px;
            cursor: pointer;
            transition: all 0.2s;
        }}
        .filter-btn:hover, .filter-btn.active {{
            background-color: #334155;
            border-color: #94a3b8;
        }}
        .finding-card {{
            background-color: var(--bg-secondary);
            border-radius: 8px;
            margin-bottom: 15px;
            overflow: hidden;
            border: 1px solid #334155;
        }}
        .finding-header {{
            padding: 15px 20px;
            background-color: #1e293b;
            display: flex;
            justify-content: space-between;
            align-items: center;
            cursor: pointer;
            user-select: none;
        }}
        .finding-title {{ font-weight: 600; display: flex; align-items: center; gap: 15px; }}
        .badge {{
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: bold;
        }}
        .badge.CRITICAL {{ background-color: var(--critical); color: white; }}
        .badge.HIGH {{ background-color: var(--high); color: white; }}
        .badge.MEDIUM {{ background-color: var(--medium); color: black; }}
        .badge.LOW {{ background-color: var(--low); color: white; }}
        .finding-body {{
            padding: 20px;
            border-top: 1px solid #334155;
            display: none;
            background-color: #111827;
        }}
        .finding-body.open {{ display: block; }}
        .meta-line {{ margin-bottom: 10px; color: var(--text-muted); }}
        .meta-line strong {{ color: var(--text-main); }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Aegis AI Security Report</h1>
            <p style="color: var(--text-muted);">Automated Code Review Findings</p>
        </header>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-num">{total}</div>
                <div style="color: var(--text-muted);">Total Issues</div>
            </div>
            <div class="stat-card CRITICAL">
                <div class="stat-num" style="color: var(--critical);">{critical}</div>
                <div>Critical</div>
            </div>
            <div class="stat-card HIGH">
                <div class="stat-num" style="color: var(--high);">{high}</div>
                <div>High</div>
            </div>
            <div class="stat-card MEDIUM">
                <div class="stat-num" style="color: var(--medium);">{medium}</div>
                <div>Medium</div>
            </div>
            <div class="stat-card LOW">
                <div class="stat-num" style="color: var(--low);">{low}</div>
                <div>Low</div>
            </div>
        </div>

        <div class="filter-container">
            <button class="filter-btn active" onclick="filterFindings(this, 'ALL')">All</button>
            <button class="filter-btn" onclick="filterFindings(this, 'CRITICAL')">Critical</button>
            <button class="filter-btn" onclick="filterFindings(this, 'HIGH')">High</button>
            <button class="filter-btn" onclick="filterFindings(this, 'MEDIUM')">Medium</button>
            <button class="filter-btn" onclick="filterFindings(this, 'LOW')">Low</button>
        </div>

        <div id="findings-list">
            {findings_html}
        </div>
    </div>

    <script>
        function toggleFinding(element) {{
            const body = element.nextElementSibling;
            body.classList.toggle('open');
        }}

        function filterFindings(button, severity) {{
            // Update active button state
            document.querySelectorAll('.filter-btn').forEach(btn => btn.classList.remove('active'));
            button.classList.add('active');

            // Filter items
            const cards = document.querySelectorAll('.finding-card');
            cards.forEach(card => {{
                if (severity === 'ALL' || card.getAttribute('data-severity') === severity) {{
                    card.style.display = 'block';
                }} else {{
                    card.style.display = 'none';
                }}
            }});
        }}
    </script>
</body>
</html>
"""

def generate_html_report(findings: List[Dict], output_filename: str = "report.html"):
    """
    Counts the findings by severity, builds collapsible target items, 
    and writes out a clean, modern HTML reporting file.
    """
    # Initialize metrics tracking
    stats = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        sev = f.get("severity", "LOW").upper()
        if sev in stats:
            stats[sev] += 1
        else:
            stats["LOW"] += 1 # Fallback string normalization

    findings_html_list = []
    for f in findings:
        severity = f.get("severity", "LOW").upper()
        filename = html.escape(f.get("file", "Unknown"))
        line = html.escape(str(f.get("line", "Unknown")))
        cwe = html.escape(f.get("cwe", "N/A"))
        description = html.escape(f.get("description", "No description provided."))

        item_template = f"""
        <div class="finding-card" data-severity="{severity}">
            <div class="finding-header" onclick="toggleFinding(this)">
                <div class="finding-title">
                    <span class="badge {severity}">{severity}</span>
                    <span>{filename}</span>
                </div>
                <div style="color: var(--text-muted);">Line {line} &nbsp;▼</div>
            </div>
            <div class="finding-body">
                <div class="meta-line"><strong>CWE Identification:</strong> {cwe}</div>
                <div class="meta-line"><strong>Vulnerability Details & Remediation Strategy:</strong></div>
                <p style="line-height: 1.6; color: #cbd5e1; margin-top: 5px;">{description}</p>
            </div>
        </div>
        """
        findings_html_list.append(item_template)

    # Combine everything into the core dashboard structure
    final_html = HTML_TEMPLATE.format(
        total=len(findings),
        critical=stats["CRITICAL"],
        high=stats["HIGH"],
        medium=stats["MEDIUM"],
        low=stats["LOW"],
        findings_html="\n".join(findings_html_list)
    )

    with open(output_filename, "w", encoding="utf-8") as f:
        f.write(final_html)
        
    print(f"[+] Interactive security report compiled successfully: {output_filename}")