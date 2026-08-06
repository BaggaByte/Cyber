import unittest
from unittest.mock import patch, MagicMock
import sys
import os
import shutil
from datetime import datetime
from pathlib import Path

# Adjust paths to import from src
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src/core')))

import database

TEST_DB_PATH = Path(__file__).resolve().parent / "test_aegis_history.db"

class TestDatabase(unittest.TestCase):

    def _clear_collection(self):
        try:
            col = database._get_collection()
            if col:
                results = col.get()
                if results and results.get("ids"):
                    col.delete(ids=results["ids"])
        except Exception:
            pass

    def setUp(self):
        # Redirect DB_PATH to a test database file
        self.db_path_patcher = patch('database.DB_PATH', TEST_DB_PATH)
        self.db_path_patcher.start()
        self._clear_collection()

    def tearDown(self):
        self._clear_collection()
        # Stop patcher
        self.db_path_patcher.stop()
        # Clean up database directory if possible
        if TEST_DB_PATH.exists():
            try:
                if TEST_DB_PATH.is_dir():
                    shutil.rmtree(TEST_DB_PATH)
                else:
                    TEST_DB_PATH.unlink()
            except Exception:
                pass

    def test_init_db(self):
        # Database should be initialized
        database.init_db()
        self.assertTrue(TEST_DB_PATH.exists())
        self.assertTrue(TEST_DB_PATH.is_dir())

        # Check if collection exists
        col = database._get_collection()
        self.assertIsNotNone(col)
        self.assertEqual(col.name, 'scan_history')

    def test_save_and_get_scan_record(self):
        database.init_db()

        # Save record
        job_id = "test-job-uuid"
        target = "/path/to/target"
        findings = [
            {"severity": "CRITICAL", "cwe": "CWE-89"},
            {"severity": "HIGH", "cwe": "CWE-798"},
            {"severity": "MEDIUM", "cwe": "CWE-79"},
            {"severity": "LOW", "cwe": "CWE-22"},
            {"severity": "LOW", "cwe": "CWE-Unknown"},  # Both this and above should map to LOW
        ]

        database.save_scan_record(job_id, target, findings)

        # Retrieve history
        history = database.get_scan_history()
        self.assertEqual(len(history), 1)

        record = history[0]
        self.assertEqual(record["job_id"], job_id)
        self.assertEqual(record["target"], target)
        self.assertEqual(record["total"], 5)
        self.assertEqual(record["critical"], 1)
        self.assertEqual(record["high"], 1)
        self.assertEqual(record["medium"], 1)
        self.assertEqual(record["low"], 2)
        self.assertIsNotNone(record["timestamp"])

    @patch('database.datetime')
    def test_get_scan_history_ordering(self, mock_datetime):
        database.init_db()

        # Mock now() to return sequential dates/times
        mock_datetime.now.side_effect = [
            datetime(2026, 5, 31, 12, 0, 0),
            datetime(2026, 5, 31, 12, 0, 5)
        ]

        # Save two records
        database.save_scan_record("job-1", "/target/1", [{"severity": "CRITICAL"}])
        database.save_scan_record("job-2", "/target/2", [{"severity": "HIGH"}])

        history = database.get_scan_history()
        self.assertEqual(len(history), 2)
        # job-2 was saved second (later timestamp), so it should be first in results due to timestamp DESC ordering
        self.assertEqual(history[0]["job_id"], "job-2")
        self.assertEqual(history[1]["job_id"], "job-1")

    def test_save_scan_record_handles_exception(self):
        # Call save_scan_record with mocked PersistentClient that raises an exception
        with patch('database.chromadb.PersistentClient', side_effect=Exception("Mock connection error")):
            try:
                database.save_scan_record("job-err", "target", [])
            except Exception as e:
                self.fail(f"save_scan_record raised an unexpected exception: {e}")

if __name__ == '__main__':
    unittest.main()
