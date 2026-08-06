import unittest
from unittest.mock import patch, MagicMock
import requests
import json
import sys
import os

# Adjust paths to import from src
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src/agents')))

from analyzer import verify_groq_connectivity, analyze_code

class TestSagaScanner(unittest.TestCase):

    @patch('requests.get')
    def test_verify_connectivity_success(self, mock_get):
        # Mock responses
        mock_response_base = MagicMock()
        mock_response_base.status_code = 200
        
        mock_response_tags = MagicMock()
        mock_response_tags.status_code = 200
        mock_response_tags.json.return_value = {
            "models": [{"name": "qwen2.5-coder:7b"}]
        }
        
        mock_get.side_effect = [mock_response_base, mock_response_tags]
        
        res = verify_groq_connectivity()
        self.assertTrue(res)
        self.assertEqual(mock_get.call_count, 2)

    @patch('requests.get')
    def test_verify_connectivity_model_missing_warning(self, mock_get):
        mock_response_base = MagicMock()
        mock_response_base.status_code = 200
        
        mock_response_tags = MagicMock()
        mock_response_tags.status_code = 200
        mock_response_tags.json.return_value = {
            "models": [{"name": "llama3:latest"}]
        }
        
        mock_get.side_effect = [mock_response_base, mock_response_tags]
        
        # Should return True but print warnings
        res = verify_groq_connectivity()
        self.assertTrue(res)

    @patch('requests.get')
    def test_verify_connectivity_offline(self, mock_get):
        mock_get.side_effect = requests.exceptions.ConnectionError("Connection refused")
        
        res = verify_groq_connectivity()
        self.assertFalse(res)

    @patch('requests.post')
    def test_analyze_code_success(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "message": {
                "content": json.dumps({
                    "findings": [
                        {
                            "severity": "HIGH",
                            "file": "test.py",
                            "line": "10",
                            "cwe": "CWE-89",
                            "description": "SQL Injection"
                        }
                    ]
                })
            }
        }
        mock_post.return_value = mock_response
        
        findings = analyze_code("test.py", "select * from users", "GPT-OSS 120B")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "HIGH")
        self.assertEqual(findings[0]["cwe"], "CWE-89")

    @patch('requests.post')
    def test_analyze_code_invalid_json(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "message": {
                "content": "Not a JSON structure at all"
            }
        }
        mock_post.return_value = mock_response
        
        findings = analyze_code("test.py", "some code", "GPT-OSS 120B")
        self.assertEqual(findings, [])

    @patch('requests.post')
    def test_analyze_code_timeout(self, mock_post):
        mock_post.side_effect = requests.exceptions.Timeout("Timeout")
        
        findings = analyze_code("test.py", "some code", "GPT-OSS 120B")
        self.assertEqual(findings, [])

    def test_extract_lines_success(self):
        from main import extract_lines
        # Let's test on tests/app.py which exists
        content = extract_lines('tests/app.py', 4, 7)
        self.assertIn("AWS_SECRET_KEY", content)
        self.assertIn("get_user_profile", content)

if __name__ == '__main__':
    unittest.main()
