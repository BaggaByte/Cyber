# Saga-AI Security Assistant

An AI-driven, production-ready security research assistant designed to parse codebases, identify vulnerabilities, and suggest actionable patches. 

## Core Architecture
*   **Phase 1 (Current):** Local CLI scanner utilizing LLM APIs for context-aware code review and HTML/JSON reporting.
*   **Phase 2:** Integration with Semgrep, CVE enrichment, and AI-driven false-positive filtering.
*   **Phase 3:** Multi-agent system (Planner, Critic) with GitHub App integration for automated PR reviews.
*   **Phase 4:** Autonomous research lab with sandbox verification and natural language querying.

## Tech Stack
*   **Language:** Python (CLI & Backend)
*   **AI Integration:** Anthropic/OpenAI APIs (moving to DSPy & Local LLMs)
*   **Future Tooling:** Semgrep, ChromaDB, Docker (Sandboxing)