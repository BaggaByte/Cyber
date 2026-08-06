import chromadb
from typing import List, Dict

class MythosMemory:
    def __init__(self):
        # Initialize local vector database (persists to disk)
        try:
            self.client = chromadb.PersistentClient(path="./mythos_db")
            self.collection = self.client.get_or_create_collection(name="exploit_patterns")
            self.is_active = True
        except Exception as e:
            print(f"[MEMORY] ChromaDB failed to initialize. Memory will be disabled. Error: {e}")
            self.is_active = False

    def store_successful_exploit(self, cwe: str, target_endpoint: str, payload: str, context: str):
        """Stores a confirmed exploit into long-term memory for future chaining."""
        if not self.is_active:
            return
            
        doc_id = f"{cwe}_{hash(payload)}_{hash(target_endpoint)}"
        
        # Check if already exists to prevent duplication
        existing = self.collection.get(ids=[doc_id])
        if not existing['ids']:
            self.collection.add(
                documents=[context],
                metadatas=[{"cwe": cwe, "endpoint": target_endpoint, "payload": payload}],
                ids=[doc_id]
            )
            print(f"[MEMORY] Saved successful payload for {cwe} to ChromaDB.")

    def retrieve_payload_patterns(self, cwe: str, limit: int = 3) -> List[Dict]:
        """Fetches historically successful payloads for a specific vulnerability."""
        if not self.is_active:
            return []
            
        try:
            results = self.collection.query(
                query_texts=[f"Successful payloads and context for {cwe}"],
                n_results=limit
            )
            return results.get("metadatas", [[]])[0]
        except Exception:
            return []

# Singleton instance exported for graph.py to use!
memory_store = MythosMemory()