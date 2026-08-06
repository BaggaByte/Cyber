import os
import json
import yaml
from typing import TypedDict, List, Dict, Any, Optional
from langgraph.graph import StateGraph, END
from langchain_groq import ChatGroq
from langchain_core.messages import SystemMessage, HumanMessage
from intelligence.agents import SentinelAgents, SentinelTasks
from crewai import Crew, Process

# ─── Load tool descriptions from YAML (used to inform the AI) ────────────────
def _load_tool_descriptions() -> str:
    try:
        with open("engine/tools_registry.yaml", "r") as f:
            config = yaml.safe_load(f)
        lines = []
        for name, info in config.get("tools", {}).items():
            desc = info.get("description", "")
            params = info.get("parameters", {})
            param_summary = ", ".join(
                f"{k}={v.get('default')} ({v.get('description','')})"
                for k, v in params.items()
            )
            lines.append(f"- {name}: {desc}" + (f" | params: {param_summary}" if param_summary else ""))
        # Add built-in tools not in YAML
        lines.append("- subdomain: Native DNS enumeration of common subdomains")
        return "\n".join(lines)
    except Exception:
        return "nmap, subdomain, nikto, nuclei, ffuf, gobuster, httpx"

TOOL_DESCRIPTIONS = _load_tool_descriptions()

APPROVED_TOOLS = [
    "nmap", "subdomain", "masscan", "amass", "sublist3r", "httpx",
    "nuclei", "nikto", "trivy", "grype", "ffuf", "gobuster", "wfuzz",
    "certcheck",
]

# ─── Keyword → tool+args fast-path profiles ──────────────────────────────────
GOAL_PROFILES: Dict[str, List[Dict]] = {
    "web":       [
        {"tool": "nikto",   "args": {}},
        {"tool": "nuclei",  "args": {"severity": "medium"}},
        {"tool": "ffuf",    "args": {"match_codes": "200,301,302,403"}},
        {"tool": "httpx",   "args": {}},
    ],
    "port":      [
        {"tool": "nmap",    "args": {"speed": 4, "ports": "1-1000", "extra_flags": "-sV"}},
        {"tool": "masscan", "args": {"ports": "1-65535", "rate": 1000}},
    ],
    "subdomain": [
        {"tool": "subdomain", "args": {}},
        {"tool": "amass",     "args": {"mode": "passive"}},
        {"tool": "sublist3r", "args": {"threads": 10}},
    ],
    "recon":     [
        {"tool": "nmap",    "args": {"speed": 4, "ports": "1-1000", "extra_flags": "-sV"}},
        {"tool": "subdomain", "args": {}},
        {"tool": "httpx",   "args": {}},
    ],
    "full":      [
        {"tool": "nmap",    "args": {"speed": 4, "ports": "1-65535", "extra_flags": "-sV"}},
        {"tool": "subdomain", "args": {}},
        {"tool": "nikto",   "args": {}},
        {"tool": "nuclei",  "args": {"severity": "medium"}},
        {"tool": "ffuf",    "args": {}},
    ],
    "vuln":      [
        {"tool": "nuclei",  "args": {"severity": "medium"}},
        {"tool": "nikto",   "args": {}},
        {"tool": "grype",   "args": {"fail_on": "high"}},
        {"tool": "trivy",   "args": {"severity": "HIGH,CRITICAL"}},
    ],
    "stealth":   [
        {"tool": "nmap",    "args": {"speed": 1, "ports": "80,443,22,21", "extra_flags": ""}},
        {"tool": "subdomain", "args": {}},
    ],
    "cert":      [
        {"tool": "certcheck", "args": {"port": 443}},
        {"tool": "subdomain", "args": {}},
    ],
    "tls":       [
        {"tool": "certcheck", "args": {"port": 443}},
    ],
    "ssl":       [
        {"tool": "certcheck", "args": {"port": 443}},
    ],
    "container": [
        {"tool": "trivy",   "args": {"severity": "HIGH,CRITICAL"}},
        {"tool": "grype",   "args": {"fail_on": "high"}},
    ],
    "fuzz":      [
        {"tool": "ffuf",    "args": {"match_codes": "200,301,302,403"}},
        {"tool": "gobuster","args": {}},
    ],
}

# ─── Shared LLM ───────────────────────────────────────────────────────────────
llm = ChatGroq(
    api_key=os.environ.get("GROQ_API_KEY"),
    model="llama-3.1-8b-instant",
    temperature=0.0,
)

# ─── AgentState ───────────────────────────────────────────────────────────────
class AgentState(TypedDict):
    target: str
    goal: str
    tasks: List[Dict[str, Any]]   # [{"tool": "nmap", "args": {"speed": 4, ...}}, ...]
    reasoning: str


# ─── Node 1: Fast keyword planner (zero API cost) ─────────────────────────────
def plan_with_keywords(state: AgentState) -> AgentState:
    goal_lower = state["goal"].lower()
    for keyword, tasks in GOAL_PROFILES.items():
        if keyword in goal_lower:
            print(f"[PLANNER] Keyword '{keyword}' matched → {[t['tool'] for t in tasks]}")
            return {
                **state,
                "tasks": tasks,
                "reasoning": f"Keyword match: '{keyword}' profile applied with default args.",
            }
    return {**state, "tasks": [], "reasoning": "No keyword match; escalating to AI."}


# ─── Node 2: AI planner (Groq/LangChain) ─────────────────────────────────────
def plan_with_ai(state: AgentState) -> AgentState:
    print(f"[PLANNER] Invoking CrewAI for goal: '{state['goal']}'")

    recon_agent = SentinelAgents.recon_agent()
    vuln_agent = SentinelAgents.vuln_agent()
    dns_agent = SentinelAgents.dns_agent()
    certificate_agent = SentinelAgents.certificate_agent()
    fingerprint_agent = SentinelAgents.fingerprint_agent()
    
    # We define a single task for the crew to output the JSON task list
    # The agents will collaborate to determine the right tools based on the goal.
    from crewai import Task
    planning_task = Task(
        description=f"Analyze the goal '{state['goal']}' for target '{state['target']}'. Choose the best security tools to use. Only use tools from this list: {', '.join(APPROVED_TOOLS)}, subdomain. Output ONLY a valid JSON array of tasks. Each task must have 'tool' and 'args' (object with overrides or empty {{}} for defaults). No markdown formatting or extra text.",
        expected_output="JSON array of tools to run.",
        agent=vuln_agent
    )
    
    crew = Crew(
        agents=[recon_agent, vuln_agent, dns_agent, certificate_agent, fingerprint_agent],
        tasks=[planning_task],
        process=Process.sequential,
        verbose=False
    )
    
    try:
        result = crew.kickoff()
        raw = str(result).strip()

        # Strip markdown code fences if present
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]

        tasks = json.loads(raw)

        # Validate: keep only approved tools with dict args
        validated = [
            t for t in tasks
            if isinstance(t, dict)
            and t.get("tool") in APPROVED_TOOLS + ["subdomain"]
            and isinstance(t.get("args", {}), dict)
        ]

        if not validated:
            raise ValueError(f"No valid tasks in AI response: '{raw}'")

        print(f"[PLANNER] AI selected: {[t['tool'] for t in validated]}")
        return {
            **state,
            "tasks": validated,
            "reasoning": f"AI selection (Llama3): {[t['tool'] for t in validated]}",
        }

    except Exception as e:
        print(f"[PLANNER] AI planner failed: {e}. Using default recon.")
        default = [
            {"tool": "nmap",      "args": {"speed": 4, "ports": "1-1000", "extra_flags": "-sV"}},
            {"tool": "subdomain", "args": {}},
        ]
        return {**state, "tasks": default, "reasoning": f"Fallback (AI error: {e})"}


# ─── Router ───────────────────────────────────────────────────────────────────
def route_after_keywords(state: AgentState) -> str:
    return "done" if state.get("tasks") else "ai_planner"


# ─── Compile the LangGraph ────────────────────────────────────────────────────
workflow = StateGraph(AgentState)
workflow.add_node("keyword_planner", plan_with_keywords)
workflow.add_node("ai_planner", plan_with_ai)
workflow.set_entry_point("keyword_planner")
workflow.add_conditional_edges(
    "keyword_planner",
    route_after_keywords,
    {"done": END, "ai_planner": "ai_planner"},
)
workflow.add_edge("ai_planner", END)

orchestrator = workflow.compile()
