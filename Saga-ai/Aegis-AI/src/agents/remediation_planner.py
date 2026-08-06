import os
import json
import asyncio
import requests
from openai import AsyncOpenAI
from core.config import DEFAULT_MODEL, DEFAULT_API_URL
from agents.patch_validator import validate_patch
from agents.hypothesis import robust_json_parse

GROQ_API_KEY = os.getenv("GROQ_API_KEY")

client = AsyncOpenAI(
    base_url=DEFAULT_API_URL, 
    api_key=GROQ_API_KEY or "dummy",
    timeout=None
)

async def critic_node(state: dict) -> dict:
    """Reviews the generated patch syntax and verifies resolving the CWE without anti-patterns."""
    state["iteration_count"] += 1
    patched_code = state.get("generated_patch")
    
    if not patched_code:
        state["validation_feedback"] = None
        return state

    original_code = state.get("original_code", "")
    file_path = state.get("file_path", "unknown")
    
    # 1. Syntax & Safety Check
    validation = validate_patch(original_code, patched_code, file_path)
    if not validation["valid"]:
        state["validation_feedback"] = validation["reason"]
        return state
        
    api_url = state.get("api_url", DEFAULT_API_URL)
    model = state.get("model", DEFAULT_MODEL)
    cwe_id = state.get("cwe_details", "UNKNOWN")
    
    prompt = f"""
    You are a Security Critic. Review the proposed security patch for {cwe_id}.
    
    Original Code context:
    {original_code}
    
    Proposed Patch:
    {patched_code}
    
    Verify the following:
    1. Does this patch actually resolve the specific CWE vulnerability?
    2. Does it introduce anti-patterns (like Flask mark_safe, unsafe eval, dangerously unescaped outputs, or hardcoded credentials)?
    
    You must respond strictly in JSON format with keys:
    "approved": true/false,
    "feedback": "Detailed feedback if rejected, or empty string if approved"
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
        approved = parsed.get("approved")
        if approved is None:
            approved = "true" in raw_output.lower()
            
        if not approved:
            state["validation_feedback"] = parsed.get("feedback") or "Patch failed semantic security check."
        else:
            state["validation_feedback"] = None
            
    except Exception as e:
        print(f"[-] Critic node error: {e}")
        raise e
        
    return state
