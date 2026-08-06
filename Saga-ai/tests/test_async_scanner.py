import unittest
import asyncio
from unittest.mock import patch, MagicMock, AsyncMock
import json
import sys
import os

# Adjust paths to import from src
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from critic import evaluate_finding_async, robust_json_parse
from main import process_single_finding_worker, run_async_scan, SCAN_JOBS

class TestAsyncSagaScanner(unittest.IsolatedAsyncioTestCase):

    @patch('critic.client')
    async def test_evaluate_finding_async_success(self, mock_client):
        mock_response = MagicMock()
        mock_choice = MagicMock()
        mock_message = MagicMock()
        
        mock_message.content = json.dumps({
            "is_true_positive": True,
            "reasoning": "This is a real SQL Injection vulnerability.",
            "secure_code": "cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))"
        })
        mock_choice.message = mock_message
        mock_response.choices = [mock_choice]
        
        # Async method mocking
        mock_client.chat.completions.create = AsyncMock(return_value=mock_response)
        
        payload = {
            "cwe": "CWE-89",
            "file": "src/auth.py",
            "lines": "query = f'SELECT * FROM users WHERE id = {user_id}'"
        }
        
        res = await evaluate_finding_async(payload)
        
        self.assertTrue(res.get("is_true_positive"))
        self.assertEqual(res.get("reasoning"), "This is a real SQL Injection vulnerability.")
        self.assertIn("execute", res.get("secure_code"))

    @patch('critic.client')
    async def test_evaluate_finding_async_ast_syntax_error(self, mock_client):
        mock_response = MagicMock()
        mock_choice = MagicMock()
        mock_message = MagicMock()
        
        mock_message.content = json.dumps({
            "is_true_positive": True,
            "reasoning": "Real syntax-error vulnerability.",
            "secure_code": "def invalid_syntax_here(:"
        })
        mock_choice.message = mock_message
        mock_response.choices = [mock_choice]
        
        mock_client.chat.completions.create = AsyncMock(return_value=mock_response)
        
        payload = {
            "cwe": "CWE-89",
            "file": "src/auth.py",
            "lines": "query = f'SELECT * FROM users WHERE id = {user_id}'"
        }
        
        res = await evaluate_finding_async(payload)
        
        self.assertTrue(res.get("is_true_positive"))
        self.assertEqual(res.get("secure_code"), "AI generated an invalid patch with syntax errors. Manual remediation required.")

    @patch('critic.client')
    @patch('critic.read_full_file')
    async def test_evaluate_finding_async_context_injection(self, mock_read_full_file, mock_client):
        mock_response = MagicMock()
        mock_choice = MagicMock()
        mock_message = MagicMock()
        
        mock_message.content = json.dumps({
            "is_true_positive": False,
            "reasoning": "Mocked context logic check.",
            "secure_code": ""
        })
        mock_choice.message = mock_message
        mock_response.choices = [mock_choice]
        
        mock_client.chat.completions.create = AsyncMock(return_value=mock_response)
        mock_read_full_file.return_value = "import test\n# some dummy file content\n"
        
        payload = {
            "cwe": "CWE-79",
            "file": "src/auth.py",
            "lines": "print('hello')"
        }
        
        res = await evaluate_finding_async(payload)
        
        # Verify read_full_file was called
        mock_read_full_file.assert_called_with("src/auth.py")
        
        # Verify the prompt contained the injected full file context
        called_args, called_kwargs = mock_client.chat.completions.create.call_args
        called_prompt = called_kwargs['messages'][0]['content']
        self.assertIn("dummy file content", called_prompt)
        self.assertIn("Ensure your patch respects the existing file's imports and business logic", called_prompt)

    @patch('critic.client')
    async def test_evaluate_finding_async_failure_fallback(self, mock_client):
        # Setup mock client to raise exception
        mock_client.chat.completions.create = AsyncMock(side_effect=Exception("Ollama offline"))
        
        payload = {
            "cwe": "CWE-89",
            "file": "src/auth.py",
            "lines": "query = f'SELECT * FROM users WHERE id = {user_id}'"
        }
        
        res = await evaluate_finding_async(payload)
        
        # Must fail-secure (assume True Positive)
        self.assertTrue(res.get("is_true_positive"))
        self.assertIn("Async inference error", res.get("reasoning"))
        self.assertIn("timeout", res.get("secure_code"))

    def test_robust_json_parse_malformed(self):
        malformed_json = """
        {
          "is_true_positive": true,
          "reasoning": "This is unescaped "quotes" and has
new lines",
          "pr_title": "Security Patch: Fix CWE-79",
          "pr_description": "Multi-line description
line 2
line 3",
          "secure_code": "def patch():\n    return True"
        }
        """
        parsed = robust_json_parse(malformed_json)
        self.assertTrue(parsed.get("is_true_positive"))
        self.assertEqual(parsed.get("pr_title"), "Security Patch: Fix CWE-79")
        self.assertIn("Multi-line description", parsed.get("pr_description"))
        self.assertIn("unescaped", parsed.get("reasoning"))
        self.assertIn("def patch()", parsed.get("secure_code"))


    @patch('main.evaluate_finding_async')
    async def test_process_single_finding_worker_true_positive(self, mock_eval):
        mock_eval.return_value = {
            "is_true_positive": True,
            "reasoning": "Real vulnerable API",
            "secure_code": "patched_code"
        }
        
        finding = {
            "path": "demo.py",
            "extra": {
                "lines": "vulnerable_line()",
                "message": "Direct exposure.",
                "severity": "WARNING",
                "metadata": {
                    "cwe": ["CWE-798"]
                }
            },
            "start": {"line": 5},
            "end": {"line": 5}
        }
        
        validated_list = []
        await process_single_finding_worker(
            finding=finding,
            index=1,
            total_flags=1,
            url="http://localhost:11434",
            model="qwen2.5-coder:7b",
            validated_list=validated_list
        )
        
        self.assertEqual(len(validated_list), 1)
        self.assertEqual(validated_list[0]["severity"], "MEDIUM")
        self.assertEqual(validated_list[0]["file"], "demo.py")
        self.assertEqual(validated_list[0]["cwe"], "CWE-798")
        self.assertEqual(validated_list[0]["fixedCode"], "patched_code")
        self.assertEqual(validated_list[0]["compliance"]["owasp"], "A07:2021 - Auth Failures")

    @patch('main.evaluate_finding_async')
    async def test_process_single_finding_worker_false_positive(self, mock_eval):
        mock_eval.return_value = {
            "is_true_positive": False,
            "reasoning": "Mocked test context, safe code.",
            "secure_code": ""
        }
        
        finding = {
            "path": "demo.py",
            "extra": {
                "lines": "vulnerable_line()",
                "message": "Direct exposure.",
                "severity": "WARNING",
                "metadata": {
                    "cwe": ["CWE-798"]
                }
            },
            "start": {"line": 5},
            "end": {"line": 5}
        }
        
        validated_list = []
        await process_single_finding_worker(
            finding=finding,
            index=1,
            total_flags=1,
            url="http://localhost:11434",
            model="qwen2.5-coder:7b",
            validated_list=validated_list
        )
        
        # False positives must be discarded/filtered out
        self.assertEqual(len(validated_list), 0)

    @patch('main.execute_swarm')
    @patch('main.run_semgrep')
    @patch('main.map_attack_surface')
    @patch('main.verify_groq_connectivity')
    async def test_run_async_scan_workflow(self, mock_verify, mock_recon, mock_semgrep, mock_execute_swarm):
        # Mock connectivity and engines
        mock_verify.return_value = True
        mock_recon.return_value = {"ips": ["1.1.1.1"], "urls": [], "endpoints": []}
        mock_semgrep.return_value = [
            {"path": "f1.py", "extra": {"severity": "ERROR", "message": "msg", "metadata": {"cwe": ["CWE-89"]}}},
            {"path": "f2.py", "extra": {"severity": "WARNING", "message": "msg", "metadata": {"cwe": ["CWE-79"]}}}
        ]
        
        # Mock swarm execution
        mock_execute_swarm.return_value = [
            {"file": "f1.py", "severity": "CRITICAL"},
            {"file": "f2.py", "severity": "MEDIUM"}
        ]
        
        job_id = "test_job_123"
        SCAN_JOBS[job_id] = {
            "status": "queued",
            "target": ".",
            "findings": [],
            "attack_surface": {},
            "error": None
        }
        
        await run_async_scan(job_id, ".", "qwen2.5-coder:7b", "http://localhost:11434", 120)
        
        self.assertEqual(SCAN_JOBS[job_id]["status"], "completed")
        self.assertEqual(len(SCAN_JOBS[job_id]["findings"]), 2)
        self.assertEqual(SCAN_JOBS[job_id]["attack_surface"]["ips"], ["1.1.1.1"])

if __name__ == '__main__':
    unittest.main()
