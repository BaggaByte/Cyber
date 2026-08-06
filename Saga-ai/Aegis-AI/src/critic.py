import os
import json
import ast
import re
import asyncio
from openai import AsyncOpenAI
from core.config import DEFAULT_MODEL, DEFAULT_API_URL

GROQ_API_KEY = os.getenv("GROQ_API_KEY")

client = AsyncOpenAI(
    base_url=DEFAULT_API_URL, 
    api_key=GROQ_API_KEY or "dummy",
    timeout=None
)


def read_full_file(filepath: str) -> str:
    """Read a file with encoding fallback chain."""
    encodings = ["utf-8", "utf-8-sig", "latin-1", "cp1252"]
    for enc in encodings:
        try:
            with open(filepath, "r", encoding=enc) as f:
                return f.read()
        except UnicodeDecodeError:
            continue
        except Exception as e:
            return f"Error reading file '{filepath}': {e}"
    return f"Error: Could not decode '{filepath}' with any known encoding."


def robust_json_parse(raw_output: str) -> dict:
    """Multi-strategy JSON parser with graceful fallback."""
    try:
        return json.loads(raw_output.strip())
    except json.JSONDecodeError:
        pass

    # Strip markdown fences
    cleaned = re.sub(r"^```(?:json)?", "", raw_output.strip(), flags=re.MULTILINE)
    cleaned = re.sub(r"```$", "", cleaned, flags=re.MULTILINE)
    cleaned = cleaned.strip()

    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass

    # Try extracting first {...} block
    obj_match = re.search(r"\{.*\}", cleaned, re.DOTALL)
    if obj_match:
        try:
            return json.loads(obj_match.group())
        except json.JSONDecodeError:
            pass

    print("  [-] All JSON extraction strategies failed — returning safe fallback.")
    return {
        "is_true_positive": True,
        "reasoning": "AI produced non-JSON output; manual review required.",
        "secure_code": raw_output,
    }

async def evaluate_finding_async(finding: dict, api_url: str = DEFAULT_API_URL, model: str = DEFAULT_MODEL) -> dict:
    """
    Evaluates a static analysis finding.
    Determines if it's a True Positive or False Positive, and returns explanation & patch.
    """
    file_path = finding.get("file", "")
    lines = finding.get("lines", "")
    cwe_id = finding.get("cwe", "UNKNOWN")
    
    full_file = read_full_file(file_path)
    
    prompt = f"""
    You are a Senior Security Engineer preparing a secure code commit for an automated GitHub Pull Request.
    Analyze this static analysis alert:
    CWE: {cwe_id}
    
    You are provided with the full file context. Ensure your patch respects the existing file's imports and business logic.
    You are strictly forbidden from using undefined variables, referencing unimported libraries, or generating incomplete code.
    
    Full File Content:
    {full_file}
    
    Vulnerable Line(s):
    {lines}
    
    CRITICAL RULE: Be extremely vigilant. Do NOT dismiss active debug flags (e.g., debug=True), hardcoded credentials, plaintext password storage, or raw error exposure (e.g., return str(e)) as false positives. They are ALWAYS True Positives in a production audit context.
    CONVERSELY, aggressively mark speculative findings as False Positives: DO NOT report generic CWE-400 (Denial of Service), CWE-306/CWE-862 (Missing Authentication in demo apps), or generic CWE-20 (Improper Input Validation without an accompanying injection payload) unless there is explicit architectural evidence.
    REMEDIATION RULE: If patching CWE-94 (eval) in a calculator context, DO NOT simply present `ast.literal_eval()` as a complete replacement, because it cannot evaluate math expressions. Propose a robust math parsing approach (e.g. using a safe expression evaluator or library).
    REMEDIATION RULE: If patching CWE-78 (Command Injection), DO NOT propose whitelisting while still constructing shell commands. You MUST avoid shell execution entirely by using filesystem APIs like `os.listdir()` or `pathlib`.
    REMEDIATION RULE: If patching CWE-22 (Path Traversal), DO NOT propose simple string replacements (like replacing '../'). You MUST propose using `werkzeug.utils.secure_filename` or strictly validating the absolute path.
    REMEDIATION RULE: If patching CWE-1336 or CWE-79 (Template Injection / XSS), DO NOT propose regex sanitization. Propose safe templating practices, such as using `render_template` instead of `render_template_string` with user input.
    REMEDIATION RULE: If patching CWE-502 (Insecure Deserialization), DO NOT propose whitelisting classes in `pickle`. You MUST propose replacing `pickle` entirely with a safe format like `json`.
    
    Determine if this is a True Positive or False Positive. Respond ONLY in valid JSON format with keys:
    "is_true_positive": true/false,
    "reasoning": "Brief explanation of why it is real or a false positive",
    "pr_title": "Security Patch: Fix CWE-XX in [Component/Function]",
    "pr_description": "A detailed markdown explanation of the flaw, how the fix works, and the GRC/compliance impact.",
    "secure_code": "string containing the completely rewritten secure function or code patch (or null if false positive)"
    """
    
    if api_url == DEFAULT_API_URL:
        local_client = client
    else:
        local_client = AsyncOpenAI(base_url=api_url, api_key=os.getenv("GROQ_API_KEY", "dummy"), timeout=None)
        
    try:
        response = await local_client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            response_format={"type": "json_object"},
            temperature=0.1,
            timeout=None
        )
        raw_output = response.choices[0].message.content.strip()
        parsed = robust_json_parse(raw_output)
        
        # Validate python syntax for patched code
        secure_code = parsed.get("secure_code")
        if secure_code and file_path.endswith(".py"):
            try:
                ast.parse(secure_code)
            except SyntaxError:
                parsed["secure_code"] = "AI generated an invalid patch with syntax errors. Manual remediation required."
                
        return parsed
        
    except Exception as e:
        return {
            "is_true_positive": True,
            "reasoning": f"Async inference error: {str(e)}",
            "secure_code": "Inference timeout. Manual remediation required.",
            "pr_title": f"Security Patch: Fix {cwe_id}",
            "pr_description": f"Failed to run AI critic: {str(e)}"
        }
