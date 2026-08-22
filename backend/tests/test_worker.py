import pytest
from unittest.mock import patch, MagicMock
from database import SessionLocal
import models
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from worker import run_recon_scan

@pytest.fixture
def mock_db():
    return MagicMock()

@patch('worker.SessionLocal')
@patch('subprocess.run')
def test_run_recon_scan_success(mock_subprocess, mock_session_local, mock_db):
    mock_session_local.return_value = mock_db
    
    # Mock database scan record
    mock_scan = MagicMock()
    mock_scan.id = 1
    mock_scan.target_id = 1
    
    # Mock vuln properties for json.dumps
    mock_vuln = MagicMock()
    mock_vuln.cve_id = "CVE-TEST"
    mock_vuln.severity = "HIGH"
    
    mock_db.query.return_value.filter.return_value.first.side_effect = [mock_scan, mock_vuln]
    
    # Mock nmap output
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = "<nmaprun><host><ports><port portid='80' protocol='tcp'><state state='open'/><service name='http' version='1.0'/></port></ports></host></nmaprun>"
    mock_subprocess.return_value = mock_result
    
    # Mock Celery task execution
    task_mock = MagicMock()
    task_mock.retry = MagicMock()
    
    result = run_recon_scan(1, "test.com")
    
    assert result == True
    mock_subprocess.assert_called_once()
    assert mock_scan.status == models.ScanStatus.COMPLETED
