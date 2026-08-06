import operator
from typing import TypedDict, List, Dict, Any, Annotated
from langgraph.graph import StateGraph, END
from critic import evaluate_finding_async


def read_full_file(filepath: str) -> str:
    """Read a file with encoding fallback chain. 
    (Moved here from hypothesis.py which was refactored in v3)"""
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

# ==========================================
# 1. THE SWARM MEMORY (STATE)
# ==========================================
class SwarmState(TypedDict):
    job_id: str
    url: str
    model: str
    raw_findings: List[Dict[str, Any]]
    
    # Using operator.add allows parallel agents to safely append to the same list simultaneously
    secrets_queue: Annotated[List[Dict[str, Any]], operator.add]
    code_queue: Annotated[List[Dict[str, Any]], operator.add]
    
    draft_analysis: Annotated[List[Dict[str, Any]], operator.add]
    verified_findings: List[Dict[str, Any]]

# ==========================================
# 2. THE AGENTS (NODES)
# ==========================================
async def planner_agent(state: SwarmState):
    """Triage Agent: Looks at raw Semgrep findings and routes them to specialists."""
    print("[PLANNER AGENT] Triaging raw findings...")
    secrets = []
    code = []
    
    for finding in state["raw_findings"]:
        cwe_list = finding.get("extra", {}).get("metadata", {}).get("cwe", ["CWE-Unknown"])
        cwe = cwe_list[0] if isinstance(cwe_list, list) and cwe_list else "CWE-Unknown"
        # Route CWE-798 and CWE-259 (Secrets) to the Secrets Agent, everything else to Code Security
        if "798" in cwe or "259" in cwe:
            secrets.append(finding)
        else:
            code.append(finding)
            
    print(f"[PLANNER AGENT] Routed {len(secrets)} to Secrets Agent, {len(code)} to Code Agent.")
    return {"secrets_queue": secrets, "code_queue": code}

async def secrets_agent(state: SwarmState):
    """Specialist Agent: Focuses purely on credential leaks."""
    if not state.get("secrets_queue"):
        return {"draft_analysis": []}
        
    print(f"[SECRETS AGENT] Analyzing {len(state['secrets_queue'])} potential credential leaks...")
    drafts = []
    
    from main import extract_lines
    
    for finding in state["secrets_queue"]:
        filepath = finding.get("path", "Unknown")
        lines = finding.get("extra", {}).get("lines", "")
        line_number = finding.get("start", {}).get("line", 1)
        end_line = finding.get("end", {}).get("line", line_number)
        
        # If lines is masked or empty, extract from file directly
        if not lines or lines == "requires login":
            lines = extract_lines(filepath, line_number, end_line)

        # Skip if code snippet is extremely large to avoid prompt blowing
        if len(lines) > 10000:
            print(f"[SECRETS AGENT] Skipping finding (Code context block too large)")
            continue
            
        payload = {
            "cwe": "CWE-798", 
            "file": filepath, 
            "lines": lines,
            "full_file_content": read_full_file(filepath)
        }
        
        critic_api_url = state["url"].rstrip('/').removesuffix('/v1') + "/v1"
        try:
            analysis = await evaluate_finding_async(payload, api_url=critic_api_url, model=state["model"])
        except TypeError:
            analysis = await evaluate_finding_async(payload)
            
        analysis["raw_finding"] = finding  # Keep the original data attached
        drafts.append(analysis)
        
    return {"draft_analysis": drafts}

async def code_security_agent(state: SwarmState):
    """Specialist Agent: Focuses on data-flow and logic flaws (SQLi, Traversal, etc)."""
    if not state.get("code_queue"):
        return {"draft_analysis": []}
        
    print(f"[CODE AGENT] Analyzing {len(state['code_queue'])} application vulnerabilities...")
    drafts = []
    
    from main import extract_lines
    
    for finding in state["code_queue"]:
        filepath = finding.get("path", "Unknown")
        lines = finding.get("extra", {}).get("lines", "")
        line_number = finding.get("start", {}).get("line", 1)
        end_line = finding.get("end", {}).get("line", line_number)
        
        # If lines is masked or empty, extract from file directly
        if not lines or lines == "requires login":
            lines = extract_lines(filepath, line_number, end_line)

        # Skip if code snippet is extremely large to avoid prompt blowing
        if len(lines) > 10000:
            print(f"[CODE AGENT] Skipping finding (Code context block too large)")
            continue
            
        cwe_list = finding.get("extra", {}).get("metadata", {}).get("cwe", [""])
        cwe = cwe_list[0] if isinstance(cwe_list, list) and cwe_list else "CWE-Unknown"
        payload = {
            "cwe": cwe, 
            "file": filepath, 
            "lines": lines,
            "full_file_content": read_full_file(filepath)
        }
        
        critic_api_url = state["url"].rstrip('/').removesuffix('/v1') + "/v1"
        try:
            analysis = await evaluate_finding_async(payload, api_url=critic_api_url, model=state["model"])
        except TypeError:
            analysis = await evaluate_finding_async(payload)
            
        analysis["raw_finding"] = finding
        drafts.append(analysis)
        
    return {"draft_analysis": drafts}

async def critic_agent(state: SwarmState):
    """Review Agent: Filters false positives from specialists and formats final output."""
    print(f"[CRITIC AGENT] Reviewing {len(state['draft_analysis'])} draft analyses from specialists...")
    final_verified = []
    
    # Import compliance mapper & line extraction locally to avoid circular imports
    from main import get_grc_frameworks, extract_lines
    
    for draft in state["draft_analysis"]:
        if draft.get("is_true_positive", False):
            raw = draft["raw_finding"]
            cwe_list = raw.get("extra", {}).get("metadata", {}).get("cwe", ["CWE-Unknown"])
            cwe = cwe_list[0] if isinstance(cwe_list, list) and cwe_list else "CWE-Unknown"
            
            # Map raw Semgrep severities to frontend visual categories
            raw_severity = raw.get("extra", {}).get("severity", "WARNING")
            severity_map = {"ERROR": "CRITICAL", "WARNING": "MEDIUM", "INFO": "LOW"}
            severity = severity_map.get(raw_severity, "LOW")
            
            filepath = raw.get("path", "Unknown")
            lines = raw.get("extra", {}).get("lines", "")
            line_number = raw.get("start", {}).get("line", 1)
            end_line = raw.get("end", {}).get("line", line_number)
            
            if not lines or lines == "requires login":
                lines = extract_lines(filepath, line_number, end_line)
            
            final_verified.append({
                "severity": severity,
                "file": filepath,
                "line": line_number,
                "cwe": cwe,
                "title": draft.get("pr_title") or raw.get("extra", {}).get("message", "Vulnerability").split(".")[0],
                "description": draft.get("pr_description") or f"**Swarm Intelligence Reasoning:** {draft.get('reasoning')}",
                "originalCode": lines,
                "fixedCode": draft.get("secure_code", "AI failed to generate a patch."),
                "compliance": get_grc_frameworks(cwe),
                "pr_title": draft.get("pr_title"),
                "pr_description": draft.get("pr_description")
            })
            
    print(f"[CRITIC AGENT] Verification complete. {len(final_verified)} True Positives confirmed.")
    return {"verified_findings": final_verified}

# ==========================================
# 3. COMPILE THE LANGGRAPH STATE MACHINE
# ==========================================
workflow = StateGraph(SwarmState)

# Add Nodes
workflow.add_node("planner", planner_agent)
workflow.add_node("secrets_agent", secrets_agent)
workflow.add_node("code_agent", code_security_agent)
workflow.add_node("critic", critic_agent)

# Define the flow (Edges)
workflow.set_entry_point("planner")

# Planner pushes to both specialists in parallel
workflow.add_edge("planner", "secrets_agent")
workflow.add_edge("planner", "code_agent")

# Both specialists push their drafts to the critic
workflow.add_edge("secrets_agent", "critic")
workflow.add_edge("code_agent", "critic")

# Critic finishes the cycle
workflow.add_edge("critic", END)

# Compile the Swarm
aegis_swarm = workflow.compile()

async def execute_swarm(job_id: str, raw_findings: list, url: str, model: str) -> list:
    """Wrapper to trigger the compiled LangGraph execution."""
    initial_state = {
        "job_id": job_id,
        "url": url,
        "model": model,
        "raw_findings": raw_findings,
        "secrets_queue": [],
        "code_queue": [],
        "draft_analysis": [],
        "verified_findings": []
    }
    
    print("\n[*] [SWARM] Initiating Multi-Agent Architecture...")
    final_state = await aegis_swarm.ainvoke(initial_state)
    return final_state["verified_findings"]
