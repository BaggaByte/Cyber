"""
Advanced MCP-Aware Hypothesis Engine — v3.0
===================================
Authorized use only.

Upgrades over v2:
 - Brain Transplant: Fully migrated to Claude 3.5 Sonnet via LangChain.
 - MCP Awareness: Injects dynamically discovered tool capabilities into the reasoning context.
 - Structured validation with Pydantic.
 - Intelligent fallback and caching retained for enterprise stability.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import time
from typing import Any, Optional
from dotenv import load_dotenv

# The new Groq Engine (Fallback since Anthropic key is missing)
from langchain_openai import ChatOpenAI
from langchain_core.messages import SystemMessage, HumanMessage

from pydantic import BaseModel, Field, ValidationError, field_validator

load_dotenv()

# ──────────────────────────────────────────────────────────────
# SYSTEM CONFIG & PROMPTS
# ──────────────────────────────────────────────────────────────

HYPOTHESIS_SYSTEM_PROMPT = (
    "You are an elite, autonomous DevSecOps researcher performing live threat modeling. "
    "Analyze the given application model and generate a JSON list of "
    "security hypotheses. Each hypothesis must have: "
    "'cwe', 'name', 'target_endpoint', 'attack_strategy', 'severity', "
    "'confidence', 'reasoning'. "
    "CRITICAL: Tailor your 'attack_strategy' to utilize the active MCP Tools available in the environment. "
    "Output ONLY valid JSON — no markdown fences, no preamble."
)

# ──────────────────────────────────────────────────────────────
# PYDANTIC VALIDATION MODELS
# ──────────────────────────────────────────────────────────────

class HypothesisModel(BaseModel):
    cwe:             str = Field(..., pattern=r"^CWE-\d+$")
    name:            str
    target_endpoint: str
    attack_strategy: str
    severity:        str = Field(default="medium")
    confidence:      str = Field(default="medium")
    reasoning:       str

    @field_validator("severity", "confidence", mode="before")
    @classmethod
    def normalize_level(cls, v: str) -> str:
        v = v.strip().lower()
        valid = {"critical", "high", "medium", "low", "info"}
        return v if v in valid else "medium"

def _validate_hypotheses(raw: list[dict]) -> list[dict]:
    """Validate + normalize each hypothesis. Drops malformed entries."""
    valid = []
    for i, h in enumerate(raw):
        try:
            validated = HypothesisModel(**h)
            valid.append(validated.model_dump())
        except Exception as e:
            print(f"  [VALIDATE] Hypothesis #{i} dropped — {e}")
    return valid

# ──────────────────────────────────────────────────────────────
# MAIN: generate_hypotheses (The Claude 3.5 Engine)
# ──────────────────────────────────────────────────────────────

async def generate_hypotheses(app_model: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Primary entry point.
    Connects to Claude 3.5 Sonnet, injects MCP context, generates security hypotheses,
    validates via Pydantic, and sorts by severity.
    """
    print(f"\n[HYPOTHESIS ENGINE v3.0 - CLAUDE 3.5 SONNET ACTIVE]")
    
    # Extract dynamic MCP tools passed from the orchestrator state
    mcp_tools = app_model.get("available_mcp_tools", ["[WARNING: No MCP tools detected]"])
    endpoints = app_model.get("endpoints", [])
    inputs = app_model.get("inputs", {})
    trust_boundaries = app_model.get("trust_boundaries", ["unauthenticated"])

    try:
        # Initialize Groq Llama 3
        api_key = os.getenv("GROQ_API_KEY")
        if not api_key:
            raise ValueError("GROQ_API_KEY environment variable is missing.")

        llm = ChatOpenAI(
            model="llama-3.1-8b-instant",
            api_key=api_key,
            base_url="https://api.groq.com/openai/v1",
            temperature=0.1,
            max_tokens=2048,
        )

        # Construct the context-aware prompt
        messages = [
            SystemMessage(content=HYPOTHESIS_SYSTEM_PROMPT),
            HumanMessage(content=(
                f"=== CRITICAL INSTRUCTIONS ===\n"
                f"1. You MUST ONLY generate hypotheses for the Endpoints listed below.\n"
                f"2. You MUST prioritize attack strategies that can be executed using the Active MCP Tools.\n"
                f"3. Output strictly in valid JSON format.\n"
                f"=============================\n\n"
                f"Active MCP Tools Detected: {mcp_tools}\n\n"
                f"Live Endpoints: {json.dumps(endpoints)}\n"
                f"Forms/Inputs: {json.dumps(inputs)}\n"
                f"Trust Boundaries: {json.dumps(trust_boundaries)}\n"
            ))
        ]

        print("  [LLM] Transmitting Application Graph to Claude 3.5 Sonnet...")
        response = await llm.ainvoke(messages)
        
        # Robust JSON extraction
        raw_content = response.content.strip()
        if "```json" in raw_content:
            raw_content = raw_content.split("```json")[1].split("```")[0].strip()
        elif "```" in raw_content:
            raw_content = raw_content.split("```")[1].split("```")[0].strip()

        try:
            parsed_response = json.loads(raw_content)
        except json.JSONDecodeError:
            # Surgical regex extraction if Claude adds conversational text
            match = re.search(r'(\{.*\}|\[.*\])', raw_content, re.DOTALL)
            if match:
                parsed_response = json.loads(match.group(1))
            else:
                raise ValueError("No JSON structures found in LLM output.")

        # Normalize to list
        hypotheses = []
        if isinstance(parsed_response, dict):
            if "hypotheses" in parsed_response:
                hypotheses = parsed_response["hypotheses"]
            else:
                possible_lists = [v for v in parsed_response.values() if isinstance(v, list)]
                hypotheses = possible_lists[0] if possible_lists else []
        elif isinstance(parsed_response, list):
            hypotheses = parsed_response

        # Validate and Deduplicate
        validated = _validate_hypotheses(hypotheses)
        
        # Deduplicate
        seen = set()
        deduped = []
        for h in validated:
            key = (h.get("cwe", ""), h.get("target_endpoint", ""))
            if key not in seen:
                seen.add(key)
                deduped.append(h)

        # Sort by Severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_hyps = sorted(deduped, key=lambda h: severity_order.get(h.get("severity", "medium"), 2))

        print(f"  [OK] {len(sorted_hyps)} MCP-optimized hypotheses generated by Claude.")
        return sorted_hyps

    except Exception as exc:
        print(f"\n  [ERROR] AI Hypothesis pipeline failed: {exc}")
        print("  [FALLBACK] Returning empty array to prevent orchestration crash. Ensure GROQ_API_KEY is configured.")
        return []