import re

# ==============================================================================
# CWE Few-Shot Context Templates
# ==============================================================================
CWE_TEMPLATES = {
    "CWE-89": {
        "title": "SQL Injection",
        "vuln_example": """# Vulnerable Code:
user_id = request.args.get('id')
query = f"SELECT * FROM users WHERE id = {user_id}"
cursor.execute(query)""",
        "secure_example": """# Secure Code:
user_id = request.args.get('id')
query = "SELECT * FROM users WHERE id = %s"
cursor.execute(query, (user_id,))"""
    },
    "CWE-22": {
        "title": "Path Traversal",
        "vuln_example": """# Vulnerable Code:
filename = request.args.get('file')
with open(f"/var/www/uploads/{filename}", "r") as f:
    content = f.read()""",
        "secure_example": """# Secure Code:
import os
filename = os.path.basename(request.args.get('file'))
safe_path = os.path.join("/var/www/uploads/", filename)
# Double check path remains restricted under the upload directory
if os.path.commonpath([safe_path, "/var/www/uploads/"]) == "/var/www/uploads":
    with open(safe_path, "r") as f:
        content = f.read()"""
    },
    "CWE-918": {
        "title": "Server-Side Request Forgery (SSRF)",
        "vuln_example": """# Vulnerable Code:
target_url = request.args.get('url')
response = requests.get(target_url)""",
        "secure_example": """# Secure Code:
from urllib.parse import urlparse
target_url = request.args.get('url')
parsed = urlparse(target_url)
# Allow list checking (e.g. only allow specific domains and prevent internal/localhost access)
if parsed.netloc in ['api.example.com', 'services.example.com'] and parsed.scheme in ['http', 'https']:
    response = requests.get(target_url)"""
    }
}

def get_cwe_few_shot_prompt(cwe_id: str) -> str:
    """
    Looks up the CWE ID in the few-shot template mapping and returns the prompt snippet.
    """
    if not cwe_id:
        return ""
    # Extract base CWE ID (e.g. 'CWE-89' from 'CWE-89: SQL Injection')
    cwe_match = re.search(r"CWE-\d+", cwe_id, re.IGNORECASE)
    base_cwe = cwe_match.group(0).upper() if cwe_match else "UNKNOWN"
    
    template = CWE_TEMPLATES.get(base_cwe)
    if not template:
        return ""
        
    return f"""
### Few-Shot Learning Reference for {base_cwe} ({template['title']})
Use this standard remediation pattern as guidance:

Vulnerable implementation example:
```python
{template['vuln_example']}
```

Remediated secure implementation:
```python
{template['secure_example']}
```
"""

HYPOTHESIS_SYSTEM_PROMPT = """You are Mythos, an elite Application Security Architect.
Analyze the provided Application Model Graph (Endpoints, Inputs, Trust Boundaries).
Generate highly probable vulnerability hypotheses. 

# OUTPUT FORMAT (JSON ONLY):
{
    "hypotheses": [
        {
            "cwe": "CWE-89",
            "name": "SQL Injection",
            "target_endpoint": "/search",
            "attack_strategy": "parameter_mutation",
            "reasoning": "The query parameter is reflected in the URL and likely hits the database."
        }
    ]
}"""
