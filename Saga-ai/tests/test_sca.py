import unittest
from unittest.mock import patch, MagicMock, mock_open
import json
import sys
import os
from pathlib import Path

# Adjust paths to import from src
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from sca import fetch_epss_score, scan_dependencies

class TestScaEngine(unittest.TestCase):

    @patch('urllib.request.urlopen')
    def test_fetch_epss_score_success(self, mock_urlopen):
        # Mock FIRST.org response
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({
            "data": [{"epss": "0.85"}]
        }).encode('utf-8')
        mock_urlopen.return_value.__enter__.return_value = mock_response

        score = fetch_epss_score("CVE-2018-18074")
        self.assertEqual(score, 85.0)

    @patch('urllib.request.urlopen')
    def test_fetch_epss_score_failure(self, mock_urlopen):
        mock_urlopen.side_effect = Exception("API offline")
        score = fetch_epss_score("CVE-2018-18074")
        self.assertEqual(score, 0.0)

    @patch('pathlib.Path.exists')
    def test_scan_dependencies_no_requirements(self, mock_exists):
        mock_exists.return_value = False
        res = scan_dependencies(".")
        self.assertEqual(res, [])

    @patch('urllib.request.urlopen')
    @patch('pathlib.Path.exists')
    @patch('builtins.open', new_callable=mock_open, read_data="requests==2.19.1\n# some comment\njunk-line\n")
    def test_scan_dependencies_with_vulnerabilities(self, mock_file, mock_exists, mock_urlopen):
        mock_exists.return_value = True
        
        # Mock response for OSV API and EPSS API sequentially
        mock_osv_res = MagicMock()
        mock_osv_res.read.return_value = json.dumps({
            "vulns": [{
                "id": "GHSA-xxxx-yyyy-zzzz",
                "aliases": ["CVE-2018-18074"],
                "summary": "Unsafe redirect handling in requests"
            }]
        }).encode('utf-8')
        
        mock_epss_res = MagicMock()
        mock_epss_res.read.return_value = json.dumps({
            "data": [{"epss": "0.75"}]
        }).encode('utf-8')
        
        # Set return value sequentially for urlopen calls
        mock_urlopen.return_value.__enter__.side_effect = [mock_osv_res, mock_epss_res]
        
        res = scan_dependencies(".")
        
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]["package"], "requests")
        self.assertEqual(res[0]["version"], "2.19.1")
        self.assertEqual(res[0]["cve"], "CVE-2018-18074")
        self.assertEqual(res[0]["epss"], 75.0)
        self.assertEqual(res[0]["summary"], "Unsafe redirect handling in requests")

if __name__ == '__main__':
    unittest.main()
