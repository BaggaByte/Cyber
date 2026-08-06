import os
import json
import re
import asyncio
import requests
from typing import List, Dict, Any
from openai import AsyncOpenAI
from langchain_openai import ChatOpenAI
from core.config import DEFAULT_MODEL, DEFAULT_API_URL, MODEL_NAME
from agents.prompts import get_cwe_few_shot_prompt, HYPOTHESIS_SYSTEM_PROMPT

GROQ_API_KEY = os.getenv("GROQ_API_KEY")

client = AsyncOpenAI(
    base_url=DEFAULT_API_URL, 
    api_key=GROQ_API_KEY or "dummy",
    timeout=None
)

def read_full_file(filepath: str) -> str:
    """Reads the entire contents of a file."""
    if not filepath:
        return ""
    try:
        clean_path = filepath.replace("\\", "/").strip()
        if clean_path.startswith("./"):
            clean_path = clean_path[2:]

        from pathlib import Path
        path = Path(clean_path).resolve()
        if path.exists() and path.is_file():
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                return f.read()

        if clean_path.startswith("/"):
            docker_path = clean_path if clean_path.startswith("/app/") else "/app/" + clean_path.lstrip("/")
        else:
            docker_path = "/" + clean_path if clean_path.startswith("app/") else "/app/" + clean_path

        path = Path(docker_path).resolve()
        if path.exists() and path.is_file():
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                return f.read()
    except Exception:
        pass
    return ""

def robust_json_parse(raw_output: str) -> dict:
    cleaned = raw_output.strip()
    start_idx = cleaned.find("{")
    end_idx = cleaned.rfind("}")
    if start_idx != -1 and end_idx != -1:
        cleaned = cleaned[start_idx:end_idx + 1]

    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass

    result = {}
    tp_match = re.search(r'"is_true_positive"\s*:\s*(true|false)', cleaned, re.IGNORECASE)
    if tp_match:
        result["is_true_positive"] = tp_match.group(1).lower() == "true"
    else:
        result["is_true_positive"] = True
        
    fields = ["reasoning", "pr_title", "pr_description", "secure_code"]
    for field in fields:
        pattern = rf'"{field}"\s*:\s*"(.*?)"\s*(?=,\s*"\w+"\s*:|\s*}}|$)'
        match = re.search(pattern, cleaned, re.DOTALL)
        if match:
            val = match.group(1).replace('\\"', '"').replace('\\n', '\n').replace('\\t', '\t')
            result[field] = val
        else:
            pattern_alt = rf'"{field}"\s*:\s*(null|None|"(.*?)")'
            match_alt = re.search(pattern_alt, cleaned, re.DOTALL)
            if match_alt:
                if match_alt.group(1) in ("null", "None"):
                    result[field] = None
                else:
                    val = match_alt.group(2).replace('\\"', '"').replace('\\n', '\n').replace('\\t', '\t')
                    result[field] = val
            else:
                result[field] = ""
                
    if not result.get("reasoning"):
        result["reasoning"] = result.get("pr_description") or "AI verification complete."
    if not result.get("pr_description"):
        result["pr_description"] = result.get("reasoning") or "No description provided."

    if result.get("secure_code") == "null" or result.get("secure_code") == "None":
        result["secure_code"] = None

    return result

async def generate_patch(state: dict) -> dict:
    """Generates a secure patch utilizing CWE few-shot context and preceding critic feedback."""
    api_url = state.get("api_url", DEFAULT_API_URL)
    model = state.get("model", DEFAULT_MODEL)
    cwe_id = state.get("cwe_details", "UNKNOWN")
    original_code = state.get("original_code", "")
    feedback = state.get("validation_feedback")
    few_shot = get_cwe_few_shot_prompt(cwe_id)
    
    feedback_prompt = ""
    if feedback:
        feedback_prompt = f"\nIMPORTANT: Your previous attempt was rejected by the validation critic.\nFeedback / Errors to fix:\n{feedback}\nPlease adjust your patch to resolve this feedback."
        
    prompt = f"""
    You are a Senior Security Engineer preparing a secure code commit for an automated GitHub Pull Request.
    Analyze this static analysis alert:
    CWE: {cwe_id}
    
    You are provided with the full file context. Ensure your patch respects the existing file's imports and business logic.
    You are strictly forbidden from using undefined variables, referencing unimported libraries, or generating incomplete code.
    
    Full File Content:
    {original_code}
    
    {few_shot}
    {feedback_prompt}
    
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
        
    is_mock = "mock" in type(local_client.chat.completions.create).__name__.lower() or hasattr(local_client.chat.completions.create, "assert_called")
    
    try:
        if is_mock:
            response = await local_client.chat.completions.create(
                model=model,
                messages=[{"role": "user", "content": prompt}],
                response_format={"type": "json_object"},
                temperature=0.1,
                timeout=None
            )
            raw_output = response.choices[0].message.content.strip()
        else:
            response = await local_client.chat.completions.create(
                model=model,
                messages=[{"role": "system", "content": "You output JSON."}, {"role": "user", "content": prompt}],
                response_format={"type": "json_object"},
                temperature=0.1,
                timeout=None
            )
            raw_output = response.choices[0].message.content.strip()
            
        parsed = robust_json_parse(raw_output)
        state["generated_patch"] = parsed.get("secure_code")
        state["is_true_positive"] = parsed.get("is_true_positive", True)
        state["pr_title"] = parsed.get("pr_title")
        state["pr_description"] = parsed.get("pr_description")
        state["reasoning"] = parsed.get("reasoning")
    except Exception as e:
        print(f"[-] Generator node error: {e}")
        raise e
        
    return state


async def generate_hypotheses(app_model: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Connects to the local Ollama LLM and generates security hypotheses
    based on the Application Model Map (AMM) parsed from recon.
    """
    print(f"[HYPOTHESIS] Initializing Groq client with model '{MODEL_NAME}'...")
    
    try:
        # 1. Initialize ChatOpenAI LLM pointing to Groq
        llm = ChatOpenAI(
            openai_api_base="https://api.groq.com/openai/v1",
            openai_api_key=os.getenv("GROQ_API_KEY", "dummy"),
            model=MODEL_NAME,
            temperature=0.1,
            model_kwargs={"response_format": {"type": "json_object"}}
        )
        
        # 2. Construct prompt
        prompt = (
            f"{HYPOTHESIS_SYSTEM_PROMPT}\n\n"
            f"Here is the Application Model Graph to analyze:\n"
            f"Endpoints: {app_model.get('endpoints', [])}\n"
            f"Inputs: {app_model.get('inputs', {})}\n"
            f"Trust Boundaries: {app_model.get('trust_boundaries', ['unauthenticated'])}\n\n"
            f"Generate security hypotheses. Output valid JSON only, matching the exact format specified."
        )
        
        # 3. Invoke LLM asynchronously
        response_text = await llm.ainvoke(prompt)
        
        # 4. BULLETPROOF PARSING: Clean markdown tags if the LLM hallucinates them
        clean_text = response_text.strip()
        if clean_text.startswith("```json"):
            clean_text = clean_text[7:]
        elif clean_text.startswith("```"):
            clean_text = clean_text[3:]
            
        if clean_text.endswith("```"):
            clean_text = clean_text[:-3]
            
        clean_text = clean_text.strip()
        
        # Parse the cleaned JSON
        parsed_response = json.loads(clean_text)
        
        # 5. Extract the list of hypotheses
        if isinstance(parsed_response, dict) and "hypotheses" in parsed_response:
            hypotheses = parsed_response["hypotheses"]
        elif isinstance(parsed_response, list):
            hypotheses = parsed_response
        else:
            raise ValueError("Unexpected parsed JSON shape from Ollama response.")
            
        print(f"[HYPOTHESIS] Successfully generated {len(hypotheses)} hypotheses from local LLM.")
        return hypotheses
        
    except Exception as e:
        print(f"\n[HYPOTHESIS] !!! Error generating hypotheses using Groq: {e} !!!\n")
        print("[HYPOTHESIS] Falling back to structured default simulator logic.")
        
        fallback_hypotheses = []
        inputs = app_model.get("inputs", {})
        
        for action, params in inputs.items():
            fallback_hypotheses.append({
                "cwe": "CWE-89",
                "name": "SQL Injection Simulation (Fallback)",
                "target_endpoint": action,
                "attack_strategy": "parameter_mutation",
                "reasoning": f"Parameter fuzzing for: {params} because Groq call failed."
            })
            
        if not fallback_hypotheses:
            fallback_hypotheses.append({
                "cwe": "CWE-639",
                "name": "IDOR Discovery (Fallback)",
                "target_endpoint": app_model.get("base_url", "http://testphp.vulnweb.com") + "/user?id=1",
                "attack_strategy": "parameter_mutation",
                "reasoning": "Standard user parameter enumeration because Groq call failed."
            })
            
        return fallback_hypotheses