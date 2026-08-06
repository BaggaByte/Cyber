import unittest
import asyncio
from unittest.mock import patch, MagicMock, AsyncMock
import json
import sys
import os

# Adjust paths to import from src
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src/orchestrator')))

from swarm import SwarmState, planner_agent, secrets_agent, code_security_agent, critic_agent, execute_swarm

class TestSwarmArchitecture(unittest.IsolatedAsyncioTestCase):

    async def test_planner_routing(self):
        state = {
            "job_id": "test_123",
            "url": "http://localhost:11434/v1",
            "model": "qwen2.5-coder:7b",
            "raw_findings": [
                {"extra": {"metadata": {"cwe": ["CWE-798"]}}}, # secrets
                {"extra": {"metadata": {"cwe": ["CWE-259"]}}}, # secrets
                {"extra": {"metadata": {"cwe": ["CWE-89"]}}},  # code
            ]
        }
        res = await planner_agent(state)
        
        self.assertEqual(len(res["secrets_queue"]), 2)
        self.assertEqual(len(res["code_queue"]), 1)

    @patch('swarm.evaluate_finding_async')
    async def test_secrets_agent_processing(self, mock_eval):
        mock_eval.return_value = {
            "is_true_positive": True,
            "reasoning": "Leak found",
            "secure_code": "new_key"
        }
        
        state = {
            "job_id": "test_123",
            "url": "http://localhost:11434/v1",
            "model": "qwen2.5-coder:7b",
            "secrets_queue": [
                {"path": "auth.py", "extra": {"lines": "API_KEY = 'leak'", "metadata": {"cwe": ["CWE-798"]}}}
            ]
        }
        
        res = await secrets_agent(state)
        self.assertEqual(len(res["draft_analysis"]), 1)
        self.assertEqual(res["draft_analysis"][0]["is_true_positive"], True)

    @patch('swarm.evaluate_finding_async')
    async def test_code_security_agent_processing(self, mock_eval):
        mock_eval.return_value = {
            "is_true_positive": True,
            "reasoning": "SQLi found",
            "secure_code": "safe_sql"
        }
        
        state = {
            "job_id": "test_123",
            "url": "http://localhost:11434/v1",
            "model": "qwen2.5-coder:7b",
            "code_queue": [
                {"path": "db.py", "extra": {"lines": "select * from users", "metadata": {"cwe": ["CWE-89"]}}}
            ]
        }
        
        res = await code_security_agent(state)
        self.assertEqual(len(res["draft_analysis"]), 1)
        self.assertEqual(res["draft_analysis"][0]["is_true_positive"], True)

    async def test_critic_agent_verification_and_mapping(self):
        state = {
            "job_id": "test_123",
            "url": "http://localhost:11434/v1",
            "model": "qwen2.5-coder:7b",
            "draft_analysis": [
                {
                    "is_true_positive": True,
                    "reasoning": "Valid injection vulnerability",
                    "secure_code": "safe_query",
                    "raw_finding": {
                        "path": "db.py",
                        "extra": {
                            "severity": "ERROR",
                            "message": "SQL Injection found. Concatenated values.",
                            "lines": "sql_query",
                            "metadata": {"cwe": ["CWE-89"]}
                        },
                        "start": {"line": 10}
                    }
                },
                {
                    "is_true_positive": False,
                    "reasoning": "Mitigated in helper function",
                    "raw_finding": {
                        "path": "safe.py",
                        "extra": {"severity": "WARNING", "message": "SQL warning", "metadata": {"cwe": ["CWE-89"]}}
                    }
                }
            ]
        }
        
        res = await critic_agent(state)
        
        # Critic must filter out False Positives
        self.assertEqual(len(res["verified_findings"]), 1)
        
        verified = res["verified_findings"][0]
        self.assertEqual(verified["severity"], "CRITICAL") # mapped from ERROR
        self.assertEqual(verified["cwe"], "CWE-89")
        self.assertEqual(verified["compliance"]["owasp"], "A03:2021 - Injection")
        self.assertEqual(verified["fixedCode"], "safe_query")

    @patch('swarm.evaluate_finding_async')
    async def test_execute_swarm_integration(self, mock_eval):
        mock_eval.return_value = {
            "is_true_positive": True,
            "reasoning": "Exploit confirmed by specialists",
            "secure_code": "patched_version"
        }
        
        raw_findings = [
            {
                "path": "auth.py",
                "extra": {
                    "severity": "WARNING",
                    "message": "Hardcoded AWS secrets.",
                    "lines": "AWS_SECRET = 'leak'",
                    "metadata": {"cwe": ["CWE-798"]}
                },
                "start": {"line": 15}
            }
        ]
        
        findings = await execute_swarm("job_123", raw_findings, "http://localhost:11434", "qwen2.5-coder:7b")
        
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["cwe"], "CWE-798")
        self.assertEqual(findings[0]["severity"], "MEDIUM") # WARNING maps to MEDIUM
        self.assertEqual(findings[0]["compliance"]["soc2"], "CC6.1 (Logical Access)")

if __name__ == '__main__':
    unittest.main()
