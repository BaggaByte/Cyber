import json
import os
import requests

# The System Prompt: Sets the persona, rules, and exact JSON schema
SYSTEM_PROMPT = """
You are an expert DevSecOps engineer and strict security auditor.
Your task is to review source code and identify ALL genuine security vulnerabilities.
Pay special attention to the following classes of vulnerabilities, but do not ignore others:
- CWE-489: Active Debug Code (e.g., debug=True)
- CWE-798: Hardcoded Credentials (e.g., 'admin', 'password123')
- CWE-256: Plaintext Storage of Passwords
- CWE-209: Information Exposure Through Error Messages
- CWE-20: Improper Input Validation
- CWE-89: SQL Injection (SQLi)
- CWE-79: Cross-Site Scripting (XSS)
- CWE-22: Path Traversal
- CWE-78: Command Injection / OS Injection
- CWE-94: Unsafe Execution (e.g. unsafe eval, exec)
- Logic Flaws and Authorization Bypasses

RULES:
1. Only report genuine, demonstrable security vulnerabilities. Do not report code style issues, general bugs, or speculative weaknesses.
2. DO NOT report CWE-400 (Denial of Service), CWE-306/CWE-862 (Missing Authentication), or generic CWE-20 (Improper Input Validation) unless there is explicit evidence of a security boundary violation. Assume this is a demo app.
3. If no vulnerabilities are found, output an empty list for the "findings" key.
4. You MUST output strictly in the following JSON format, and nothing else.

REMEDIATION RULES:
1. For CWE-78 (Command Injection), DO NOT propose whitelisting or sanitization while still constructing shell commands (like `dir` or `ls`). You MUST avoid shell execution entirely and propose filesystem APIs like `os.listdir()` or `pathlib`.
2. For CWE-94 (Unsafe Execution / eval) in a calculator context, DO NOT propose `ast.literal_eval()` as it cannot evaluate math expressions like `2+2`. You MUST propose a restricted math parser or a safe evaluation library.
3. For CWE-22 (Path Traversal), DO NOT propose simple string replacements (like replacing '../'). You MUST propose using `werkzeug.utils.secure_filename` or strictly validating the absolute path.
4. For CWE-1336 or CWE-79 (Template Injection / XSS), DO NOT propose regex sanitization. Propose safe templating practices, such as using `render_template` instead of `render_template_string` with user input.
5. For CWE-502 (Insecure Deserialization), DO NOT propose whitelisting classes in `pickle`. You MUST propose replacing `pickle` entirely with a safe format like `json`.

EXPECTED JSON SCHEMA:
{
  "findings": [
    {
      "analysis_reasoning": "Step-by-step reasoning explaining how and why this code is vulnerable",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "file": "filename passed in the prompt",
      "line": "line number as an integer or string",
      "cwe": "CWE ID if applicable (e.g., CWE-89)",
      "description": "Brief explanation of the vulnerability and how to fix it",
      "originalCode": "The exact vulnerable code snippet extracted from the file",
      "fixedCode": "The completely rewritten secure code patch"
    }
  ]
}
"""

def verify_groq_connectivity() -> bool:
    """
    Verifies connection to Groq API.
    """
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        print("[-] GROQ_API_KEY is not set.")
        return False
        
    try:
        headers = {"Authorization": f"Bearer {api_key}"}
        response = requests.get("https://api.groq.com/openai/v1/models", headers=headers, timeout=5)
        if response.status_code != 200:
            print(f"[-] Groq API returned status {response.status_code}.")
            return False
        return True
    except requests.exceptions.RequestException as e:
        print(f"[-] Groq API is unavailable.")
        print(f"[-] Error: {e}")
        return False

def analyze_code(
    file_path: str, 
    code_content: str, 
    model: str = "GPT-OSS 120B", 
    timeout: int = 600
) -> list:
    api_key = os.getenv("GROQ_API_KEY")
    print(f"[*] Analyzing {file_path} using Groq model '{model}'...")
    
    # Construct the user prompt with the specific file context
    user_prompt = f"Review the following file named '{file_path}':\n\n```\n{code_content}\n```"
    
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt}
        ],
        "stream": False,
        "temperature": 0.1,
        "response_format": {"type": "json_object"}
    }
    
    chat_url = "https://api.groq.com/openai/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    
    try:
        response = requests.post(chat_url, json=payload, headers=headers, timeout=timeout)
        
        if response.status_code != 200:
            print(f"[-] Groq API returned status code {response.status_code} for {file_path}")
            return []
            
        response_data = response.json()
        result_text = response_data.get("choices", [{}])[0].get("message", {}).get("content", "").strip()
        
        if not result_text:
            print(f"[-] Groq returned empty content for {file_path}")
            return []
            
        try:
            parsed_result = json.loads(result_text)
            return parsed_result.get("findings", [])
        except json.JSONDecodeError as jde:
            print(f"[-] Invalid JSON returned by model for {file_path}: {jde}")
            print(f"[-] Raw Content: {result_text}")
            return []
            
    except requests.exceptions.Timeout:
        print(f"[-] Request timed out after {timeout}s during analysis of {file_path}.")
        return []
    except requests.exceptions.ConnectionError:
        print(f"[-] Connection error: Groq server became unreachable during analysis of {file_path}.")
        return []
    except Exception as e:
        print(f"[-] AI Analysis failed for {file_path}: {e}")
        return []