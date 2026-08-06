import os
from typing import Dict, Any
from opensearchpy import OpenSearch
from observability import get_logger
from datetime import datetime

log = get_logger(__name__)

OPENSEARCH_HOST = os.environ.get("OPENSEARCH_HOST", "opensearch")
OPENSEARCH_PORT = int(os.environ.get("OPENSEARCH_PORT", "9200"))

class SearchIndex:
    """
    Phase 4: OpenSearch Integration
    Handles indexing of scan results, evidence, and telemetry for rapid searching.
    """
    def __init__(self):
        try:
            self.client = OpenSearch(
                hosts=[{"host": OPENSEARCH_HOST, "port": OPENSEARCH_PORT}],
                http_compress=True,
                use_ssl=False,
                verify_certs=False,
                ssl_assert_hostname=False,
                ssl_show_warn=False
            )
            # Check connection
            if self.client.ping():
                log.info("Successfully connected to OpenSearch Search Index.")
                self._ensure_indices()
            else:
                log.error("Failed to ping OpenSearch.")
                self.client = None
        except Exception as e:
            log.error(f"Failed to connect to OpenSearch: {e}")
            self.client = None

    def _ensure_indices(self):
        """Creates required index schemas if they don't exist."""
        if not self.client: return
        
        index_name = "sentinel-findings"
        if not self.client.indices.exists(index=index_name):
            body = {
                "settings": {
                    "index": {
                        "number_of_shards": 1,
                        "number_of_replicas": 0
                    }
                },
                "mappings": {
                    "properties": {
                        "scan_id": {"type": "integer"},
                        "target": {"type": "keyword"},
                        "tool": {"type": "keyword"},
                        "vulnerability": {"type": "text"},
                        "severity": {"type": "keyword"},
                        "confidence_score": {"type": "float"},
                        "timestamp": {"type": "date"}
                    }
                }
            }
            try:
                self.client.indices.create(index=index_name, body=body)
                log.info(f"Created OpenSearch index: {index_name}")
            except Exception as e:
                log.error(f"Error creating index {index_name}: {e}")

    def index_finding(self, scan_id: int, target: str, tool: str, finding: Dict[str, Any]):
        """Indexes a single finding/evidence into OpenSearch."""
        if not self.client: return
        
        doc = {
            "scan_id": scan_id,
            "target": target,
            "tool": tool,
            "vulnerability": finding.get("vulnerability", finding.get("name", "Unknown")),
            "severity": finding.get("severity", "INFO").upper(),
            "confidence_score": finding.get("confidence_score", 0.0),
            "timestamp": datetime.utcnow().isoformat(),
            "raw_evidence": str(finding)
        }
        
        try:
            self.client.index(
                index="sentinel-findings",
                body=doc,
                refresh=True
            )
        except Exception as e:
            log.error(f"Failed to index finding into OpenSearch: {e}")

search_index = SearchIndex()
